#include <sys-cert-store/sys-cert-store.h>
#include "crypto.h"
#include <openssl/err.h>
#include <openssl/evp.h>
#include <openssl/pem.h>
#include <openssl/pkcs7.h>
#include <openssl/pkcs12.h>
#include <openssl/provider.h>
#include <openssl/rand.h>
#include <openssl/x509v3.h>
#include <sqlite3.h>
#include <array>
#include <atomic>
#include <arpa/inet.h>
#include <chrono>
#include <cstdlib>
#include <cstdint>
#include <cstring>
#include <ctime>
#include <filesystem>
#include <fstream>
#include <fcntl.h>
#include <grp.h>
#include <iomanip>
#include <iostream>
#include <memory>
#include <netinet/in.h>
#include <poll.h>
#include <pwd.h>
#include <set>
#include <sstream>
#include <stdexcept>
#include <string>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/wait.h>
#include <thread>
#include <unistd.h>
#include <vector>

namespace {
#define CHECK(condition) do { if (!(condition)) throw std::runtime_error(std::string(__FILE__) + ":" + \
    std::to_string(__LINE__) + ": " #condition " [error=" + std::to_string(GetLastError()) + ": " + \
    SysCertGetLastErrorMessage() + "]"); } while (false)
using Bytes = std::vector<BYTE>;
using Key = std::unique_ptr<EVP_PKEY, decltype(&EVP_PKEY_free)>;
using X509Handle = std::unique_ptr<X509, decltype(&X509_free)>;
struct Store {
    HCERTSTORE value = nullptr;
    explicit Store(HCERTSTORE handle) : value(handle) { CHECK(value); }
    ~Store() { if (value) CertCloseStore(value, 0); }
    Store(const Store&) = delete;
    Store& operator=(const Store&) = delete;
};
struct Certificate {
    PCCERT_CONTEXT value = nullptr;
    explicit Certificate(PCCERT_CONTEXT context) : value(context) { CHECK(value); }
    ~Certificate() { if (value) CertFreeCertificateContext(value); }
    Certificate(const Certificate&) = delete;
    Certificate& operator=(const Certificate&) = delete;
};
struct Chain {
    PCCERT_CHAIN_CONTEXT value = nullptr;
    explicit Chain(PCCERT_CHAIN_CONTEXT context) : value(context) { CHECK(value); }
    ~Chain() { if (value) CertFreeCertificateChain(value); }
    Chain(const Chain&) = delete;
    Chain& operator=(const Chain&) = delete;
};
struct TempDir {
    std::filesystem::path path;
    TempDir() {
        char pattern[] = "/tmp/sys-cert-store-tests-XXXXXX";
        char* result = mkdtemp(pattern);
        CHECK(result);
        path = result;
    }
    ~TempDir() {
        std::error_code error;
        std::filesystem::remove_all(path, error);
        if (error) std::cerr << "Temporary fixture cleanup failed: " << error.message() << '\n';
    }
};
struct PrivateUmask {
    mode_t previous = umask(0077);
    ~PrivateUmask() { umask(previous); }
};
struct EnvironmentVariable {
    std::string name;
    std::string previous;
    bool existed;
    EnvironmentVariable(const char* variable, const std::string& value) : name(variable) {
        const char* current = std::getenv(variable);
        existed = current != nullptr;
        if (current) previous = current;
        CHECK(setenv(variable, value.c_str(), 1) == 0);
    }
    ~EnvironmentVariable() {
        if (existed) setenv(name.c_str(), previous.c_str(), 1);
        else unsetenv(name.c_str());
    }
};

void write_file(const std::filesystem::path& path, const std::string& data) {
    std::filesystem::create_directories(path.parent_path());
    std::ofstream output(path, std::ios::binary);
    output << data;
    output.close();
    CHECK(output);
}
std::string read_file(const std::filesystem::path& path) {
    std::ifstream input(path);
    CHECK(input);
    return std::string((std::istreambuf_iterator<char>(input)), {});
}
Key key() {
    Key result(EVP_EC_gen("prime256v1"), EVP_PKEY_free);
    CHECK(result);
    CHECK(std::strcmp(OSSL_PROVIDER_get0_name(EVP_PKEY_get0_provider(result.get())), "symcryptprovider") == 0);
    return result;
}
Key signing_key(const char* algorithm) {
    if (!algorithm) return key();
    std::unique_ptr<EVP_PKEY_CTX, decltype(&EVP_PKEY_CTX_free)> context(
        EVP_PKEY_CTX_new_from_name(nullptr, algorithm, nullptr), EVP_PKEY_CTX_free);
    CHECK(context && EVP_PKEY_keygen_init(context.get()) == 1);
    EVP_PKEY* generated = nullptr;
    CHECK(EVP_PKEY_generate(context.get(), &generated) == 1);
    Key result(generated, EVP_PKEY_free);
    CHECK(std::strcmp(OSSL_PROVIDER_get0_name(EVP_PKEY_get0_provider(result.get())), "symcryptprovider") == 0);
    return result;
}
X509Handle make_x509(EVP_PKEY* subject_key, long serial, const char* name, bool ca,
    X509* issuer = nullptr, EVP_PKEY* issuer_key = nullptr, long not_before = -60,
    const EVP_MD* digest = EVP_sha256(), const char* crl_url = nullptr,
    long not_after = 86400, int path_length = -1, int key_cert_sign = -1) {
    X509Handle result(X509_new(), X509_free);
    CHECK(result);
    CHECK(X509_set_version(result.get(), 2) == 1);
    CHECK(ASN1_INTEGER_set(X509_get_serialNumber(result.get()), serial) == 1);
    CHECK(X509_gmtime_adj(X509_getm_notBefore(result.get()), not_before));
    CHECK(X509_gmtime_adj(X509_getm_notAfter(result.get()), not_after));
    CHECK(X509_set_pubkey(result.get(), subject_key) == 1);
    auto* subject = X509_get_subject_name(result.get());
    CHECK(X509_NAME_add_entry_by_txt(subject, "CN", MBSTRING_UTF8,
        reinterpret_cast<const BYTE*>(name), -1, -1, 0) == 1);
    CHECK(X509_set_issuer_name(result.get(), issuer ? X509_get_subject_name(issuer) : subject) == 1);
    X509V3_CTX context{};
    X509V3_set_ctx(&context, issuer ? issuer : result.get(), result.get(), nullptr, nullptr, 0);
    std::string constraints = ca ? "critical,CA:TRUE" : "critical,CA:FALSE";
    if (path_length >= 0) constraints += ",pathlen:" + std::to_string(path_length);
    std::unique_ptr<X509_EXTENSION, decltype(&X509_EXTENSION_free)> extension(
        X509V3_EXT_conf_nid(nullptr, &context, NID_basic_constraints, constraints.c_str()), X509_EXTENSION_free);
    CHECK(extension && X509_add_ext(result.get(), extension.get(), -1) == 1);
    if (key_cert_sign >= 0) {
        extension.reset(X509V3_EXT_conf_nid(nullptr, &context, NID_key_usage,
            key_cert_sign ? "critical,keyCertSign" : "critical,digitalSignature"));
        CHECK(extension && X509_add_ext(result.get(), extension.get(), -1) == 1);
    }
    if (crl_url) {
        std::string value = "URI:";
        value += crl_url;
        extension.reset(X509V3_EXT_conf_nid(nullptr, &context,
            NID_crl_distribution_points, value.c_str()));
        CHECK(extension && X509_add_ext(result.get(), extension.get(), -1) == 1);
    }
    CHECK(X509_sign(result.get(), issuer_key ? issuer_key : subject_key, digest) > 0);
    return result;
}
Bytes der(X509* certificate) {
    int size = i2d_X509(certificate, nullptr);
    CHECK(size > 0);
    Bytes result(static_cast<std::size_t>(size));
    auto* cursor = result.data();
    CHECK(i2d_X509(certificate, &cursor) == size);
    return result;
}
Bytes pfx_bytes(X509* certificate, EVP_PKEY* private_key) {
    std::unique_ptr<PKCS12, decltype(&PKCS12_free)> pfx(
        PKCS12_create("password", "scope test", private_key, certificate, nullptr, 0, 0, 0, 0, 0), PKCS12_free);
    if (!pfx) ERR_print_errors_fp(stderr);
    CHECK(pfx);
    int size = i2d_PKCS12(pfx.get(), nullptr);
    CHECK(size > 0);
    Bytes result(static_cast<std::size_t>(size));
    BYTE* cursor = result.data();
    CHECK(i2d_PKCS12(pfx.get(), &cursor) == size);
    return result;
}
std::string pem(X509* certificate) {
    std::unique_ptr<BIO, decltype(&BIO_free)> buffer(BIO_new(BIO_s_mem()), BIO_free);
    CHECK(buffer && PEM_write_bio_X509(buffer.get(), certificate) == 1);
    char* pointer = nullptr;
    auto size = BIO_get_mem_data(buffer.get(), &pointer);
    return std::string(pointer, static_cast<std::size_t>(size));
}
std::vector<BYTE> crl_der(X509_CRL* crl) {
    int size = i2d_X509_CRL(crl, nullptr);
    CHECK(size > 0);
    std::vector<BYTE> result(static_cast<std::size_t>(size));
    auto* cursor = result.data();
    CHECK(i2d_X509_CRL(crl, &cursor) == size);
    return result;
}
std::unique_ptr<X509_CRL, decltype(&X509_CRL_free)> make_crl(
    X509* issuer, EVP_PKEY* issuer_key) {
    std::unique_ptr<X509_CRL, decltype(&X509_CRL_free)> result(X509_CRL_new(), X509_CRL_free);
    CHECK(result && X509_CRL_set_version(result.get(), 1) == 1);
    CHECK(X509_CRL_set_issuer_name(result.get(), X509_get_subject_name(issuer)) == 1);
    std::unique_ptr<ASN1_TIME, decltype(&ASN1_TIME_free)> last(
        ASN1_TIME_adj(nullptr, std::time(nullptr), 0, -60), ASN1_TIME_free);
    std::unique_ptr<ASN1_TIME, decltype(&ASN1_TIME_free)> next(
        ASN1_TIME_adj(nullptr, std::time(nullptr), 1, 0), ASN1_TIME_free);
    CHECK(last && next);
    CHECK(X509_CRL_set1_lastUpdate(result.get(), last.get()) == 1);
    CHECK(X509_CRL_set1_nextUpdate(result.get(), next.get()) == 1);
    CHECK(X509_CRL_sign(result.get(), issuer_key, EVP_sha256()) > 0);
    return result;
}
struct HttpServer {
    int socket = -1;
    pid_t child = -1;
    int request_ready = -1;
    int response_release = -1;
    unsigned short port = 0;
    HttpServer() {
        socket = ::socket(AF_INET, SOCK_STREAM | SOCK_CLOEXEC, 0);
        CHECK(socket >= 0);
        int reuse = 1;
        CHECK(setsockopt(socket, SOL_SOCKET, SO_REUSEADDR, &reuse, sizeof(reuse)) == 0);
        sockaddr_in address{};
        address.sin_family = AF_INET;
        address.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
        CHECK(bind(socket, reinterpret_cast<sockaddr*>(&address), sizeof(address)) == 0);
        socklen_t size = sizeof(address);
        CHECK(getsockname(socket, reinterpret_cast<sockaddr*>(&address), &size) == 0);
        port = ntohs(address.sin_port);
        CHECK(listen(socket, 1) == 0);
    }
    void start(const std::vector<BYTE>& body, bool block_response = false) {
        int ready_pipe[2]{-1, -1};
        int release_pipe[2]{-1, -1};
        if (block_response) {
            CHECK(pipe2(ready_pipe, O_CLOEXEC) == 0);
            CHECK(pipe2(release_pipe, O_CLOEXEC) == 0);
        }
        child = fork();
        CHECK(child >= 0);
        if (child == 0) {
            alarm(15);
            if (block_response) {
                close(ready_pipe[0]);
                close(release_pipe[1]);
            }
            int client = accept4(socket, nullptr, nullptr, SOCK_CLOEXEC);
            if (client < 0) _exit(1);
            std::array<char, 4096> request{};
            if (read(client, request.data(), request.size()) <= 0) _exit(2);
            if (block_response) {
                char signal = 1;
                if (write(ready_pipe[1], &signal, 1) != 1) _exit(4);
                close(ready_pipe[1]);
                if (read(release_pipe[0], &signal, 1) != 1) _exit(5);
                close(release_pipe[0]);
            }
            std::string header = "HTTP/1.0 200 OK\r\nContent-Type: application/pkix-crl\r\nContent-Length: " +
                std::to_string(body.size()) + "\r\nConnection: close\r\n\r\n";
            auto send_all = [&](const void* input, std::size_t length) {
                auto* cursor = static_cast<const BYTE*>(input);
                while (length) {
                    auto written = send(client, cursor, length, MSG_NOSIGNAL);
                    if (written <= 0) _exit(3);
                    cursor += written;
                    length -= static_cast<std::size_t>(written);
                }
            };
            send_all(header.data(), header.size());
            send_all(body.data(), body.size());
            close(client);
            close(socket);
            _exit(0);
        }
        if (block_response) {
            close(ready_pipe[1]);
            close(release_pipe[0]);
            request_ready = ready_pipe[0];
            response_release = release_pipe[1];
        }
        close(socket);
        socket = -1;
    }
    bool wait_for_request() {
        if (request_ready < 0) return false;
        pollfd descriptor{request_ready, POLLIN, 0};
        bool ready = poll(&descriptor, 1, 5000) == 1 && (descriptor.revents & POLLIN);
        char signal = 0;
        bool received = ready && read(request_ready, &signal, 1) == 1;
        close(request_ready);
        request_ready = -1;
        return received;
    }
    bool release_response() {
        if (response_release < 0) return false;
        char signal = 1;
        bool released = write(response_release, &signal, 1) == 1;
        close(response_release);
        response_release = -1;
        return released;
    }
    void wait() {
        if (child <= 0) return;
        int status = 0;
        CHECK(waitpid(child, &status, 0) == child);
        CHECK(WIFEXITED(status) && WEXITSTATUS(status) == 0);
        child = -1;
    }
    ~HttpServer() {
        if (socket >= 0) close(socket);
        if (request_ready >= 0) close(request_ready);
        if (response_release >= 0) {
            char signal = 1;
            auto ignored = write(response_release, &signal, 1);
            (void)ignored;
            close(response_release);
        }
        if (child > 0) {
            int status = 0;
            waitpid(child, &status, 0);
        }
    }
};
bool wait_for_flag(const std::atomic<bool>& flag, std::chrono::milliseconds timeout) {
    auto deadline = std::chrono::steady_clock::now() + timeout;
    while (!flag.load() && std::chrono::steady_clock::now() < deadline)
        std::this_thread::sleep_for(std::chrono::milliseconds(1));
    return flag.load();
}
PCCERT_CONTEXT create(const Bytes& encoded) {
    return CertCreateCertificateContext(X509_ASN_ENCODING, encoded.data(), static_cast<DWORD>(encoded.size()));
}
PCCERT_CONTEXT add(HCERTSTORE store, PCCERT_CONTEXT input, DWORD disposition = CERT_STORE_ADD_ALWAYS) {
    PCCERT_CONTEXT result = nullptr;
    CHECK(CertAddCertificateContextToStore(store, input, disposition, &result));
    return result;
}
Bytes property(PCCERT_CONTEXT certificate, DWORD id) {
    DWORD size = 0;
    CHECK(CertGetCertificateContextProperty(certificate, id, nullptr, &size));
    Bytes result(size);
    CHECK(CertGetCertificateContextProperty(certificate, id, result.data(), &size));
    return result;
}
void set_property(PCCERT_CONTEXT certificate, DWORD id, const Bytes& value) {
    CRYPT_DATA_BLOB blob{static_cast<DWORD>(value.size()), const_cast<BYTE*>(value.data())};
    CHECK(CertSetCertificateContextProperty(certificate, id, 0, &blob));
}
unsigned enumerate(HCERTSTORE store) {
    unsigned total = 0;
    PCCERT_CONTEXT certificate = nullptr;
    while ((certificate = CertEnumCertificatesInStore(store, certificate))) ++total;
    CHECK(GetLastError() == CRYPT_E_NOT_FOUND);
    return total;
}
std::filesystem::path material_path(PCCERT_CONTEXT context, BOOL private_key = FALSE) {
    DWORD size = 0;
    CHECK(SysCertGetCertificateFilePath(context, private_key, nullptr, &size));
    std::vector<char> result(size);
    CHECK(SysCertGetCertificateFilePath(context, private_key, result.data(), &size));
    return result.data();
}
HCERTSTORE memory() { return CertOpenStore(CERT_STORE_PROV_MEMORY, 0, 0, 0, nullptr); }
PCCERT_CHAIN_CONTEXT build_chain(PCCERT_CONTEXT certificate, HCERTSTORE additional = nullptr) {
    CERT_CHAIN_PARA parameters{};
    parameters.cbSize = sizeof(parameters);
    PCCERT_CHAIN_CONTEXT result = nullptr;
    CHECK(CertGetCertificateChain(nullptr, certificate, nullptr, additional, &parameters, 0, nullptr, &result));
    return result;
}
CERT_CHAIN_POLICY_STATUS verify_base_policy(PCCERT_CHAIN_CONTEXT chain) {
    CERT_CHAIN_POLICY_PARA parameters{};
    parameters.cbSize = sizeof(parameters);
    CERT_CHAIN_POLICY_STATUS status{};
    status.cbSize = sizeof(status);
    CHECK(CertVerifyCertificateChainPolicy(CERT_CHAIN_POLICY_BASE, chain, &parameters, &status));
    return status;
}

void memory_tests() {
    auto signer = key();
    auto ca = make_x509(signer.get(), 0x1234, "Test Root", true);
    Certificate source(create(der(ca.get())));
    CHECK(source.value->pCertInfo->dwVersion == 2);
    CHECK(source.value->pCertInfo->SerialNumber.cbData == 2);
    CHECK(source.value->pCertInfo->SerialNumber.pbData[0] == 0x34);
    CHECK(source.value->pCertInfo->SerialNumber.pbData[1] == 0x12);
    CHECK(source.value->pCertInfo->cExtension == 1);
    CHECK(std::strcmp(source.value->pCertInfo->SignatureAlgorithm.pszObjId, "1.2.840.10045.4.3.2") == 0);
    CHECK(source.value->pCertInfo->SubjectPublicKeyInfo.PublicKey.cbData > 0);
    CHECK(source.value->pCertInfo->NotBefore.dwHighDateTime > 0);
    Store store(memory());
    Certificate added(add(store.value, source.value, CERT_STORE_ADD_NEW));
    CHECK(added.value != source.value && added.value->hCertStore == store.value);
    CHECK(!CertAddCertificateContextToStore(store.value, source.value, CERT_STORE_ADD_NEW, nullptr));
    CHECK(GetLastError() == CRYPT_E_EXISTS);
    CHECK(enumerate(store.value) == 1);
    CHECK(CertDuplicateCertificateContext(added.value) == added.value);
    CHECK(CertFreeCertificateContext(added.value));
    auto hash = property(added.value, CERT_SHA256_HASH_PROP_ID);
    CHECK(hash.size() == 32);
    BYTE sentinel = 0x5a;
    DWORD short_size = 1;
    CHECK(!CertGetCertificateContextProperty(added.value, CERT_SHA256_HASH_PROP_ID, &sentinel, &short_size));
    CHECK(GetLastError() == ERROR_MORE_DATA && short_size == 32 && sentinel == 0x5a);
    CRYPT_HASH_BLOB needle{static_cast<DWORD>(hash.size()), hash.data()};
    Certificate found(CertFindCertificateInStore(store.value, X509_ASN_ENCODING, 0, CERT_FIND_SHA256_HASH, &needle, nullptr));
    Certificate identity(CertGetSubjectCertificateFromStore(store.value, X509_ASN_ENCODING, source.value->pCertInfo));
    Certificate by_name(CertFindCertificateInStore(store.value, X509_ASN_ENCODING, 0, CERT_FIND_SUBJECT_STR_W, L"test ROOT", nullptr));
    Certificate by_dn(CertFindCertificateInStore(store.value, X509_ASN_ENCODING, 0, CERT_FIND_SUBJECT_NAME,
        &source.value->pCertInfo->Subject, nullptr));
    set_property(added.value, CERT_FIRST_USER_PROP_ID, {1, 2, 3});
    CHECK(property(found.value, CERT_FIRST_USER_PROP_ID) == Bytes({1, 2, 3}));
    CHECK(CertEnumCertificateContextProperties(added.value, 0) == CERT_FIRST_USER_PROP_ID);
    CHECK(CertEnumCertificateContextProperties(added.value, CERT_FIRST_USER_PROP_ID) == 0);
    CHECK(CertSetCertificateContextProperty(added.value, CERT_FIRST_USER_PROP_ID, 0, nullptr));
    DWORD size = 0;
    CHECK(!CertGetCertificateContextProperty(found.value, CERT_FIRST_USER_PROP_ID, nullptr, &size));
    CHECK(GetLastError() == CRYPT_E_NOT_FOUND);

    auto leaf_key = key();
    auto leaf = make_x509(leaf_key.get(), 2, "Leaf", false, ca.get(), signer.get());
    Certificate leaf_context(create(der(leaf.get())));
    DWORD flags = CERT_STORE_SIGNATURE_FLAG | CERT_STORE_TIME_VALIDITY_FLAG;
    Certificate issuer(CertGetIssuerCertificateFromStore(store.value, leaf_context.value, nullptr, &flags));
    CHECK(flags == 0);
    flags = 0;
    CHECK(!CertGetIssuerCertificateFromStore(store.value, source.value, nullptr, &flags));
    CHECK(GetLastError() == CRYPT_E_SELF_SIGNED);

    CRYPT_DATA_BLOB saved{};
    CHECK(CertSaveStore(store.value, PKCS_7_ASN_ENCODING, CERT_STORE_SAVE_AS_PKCS7, CERT_STORE_SAVE_TO_MEMORY, &saved, 0));
    Bytes output(saved.cbData);
    saved.pbData = output.data();
    CHECK(CertSaveStore(store.value, PKCS_7_ASN_ENCODING, CERT_STORE_SAVE_AS_PKCS7, CERT_STORE_SAVE_TO_MEMORY, &saved, 0));
    const BYTE* cursor = output.data();
    std::unique_ptr<PKCS7, decltype(&PKCS7_free)> message(d2i_PKCS7(nullptr, &cursor, saved.cbData), PKCS7_free);
    CHECK(message && PKCS7_type_is_signed(message.get()));
    CHECK(sk_X509_num(message->d.sign->cert) == 1);
    CHECK(cursor == output.data() + output.size());
    CHECK(CertDuplicateStore(store.value) == store.value);
    CHECK(CertCloseStore(store.value, 0));
    CHECK(CertCloseStore(store.value, 0));
    store.value = nullptr;
    CHECK(property(added.value, CERT_SHA256_HASH_PROP_ID) == hash);
    set_property(added.value, CERT_FIRST_USER_PROP_ID, {4});
    CHECK(property(added.value, CERT_FIRST_USER_PROP_ID) == Bytes({4}));

    Store pending(memory());
    Certificate outstanding(add(pending.value, source.value));
    CHECK(!CertCloseStore(pending.value, CERT_CLOSE_STORE_CHECK_FLAG));
    CHECK(GetLastError() == CRYPT_E_PENDING_CLOSE);
    auto closed = pending.value;
    pending.value = nullptr;
    CHECK(!CertDuplicateStore(closed));
    CHECK(GetLastError() == ERROR_INVALID_HANDLE);
    CHECK(outstanding.value->cbCertEncoded == source.value->cbCertEncoded);
}

void disposition_tests() {
    auto signer = key();
    auto old = make_x509(signer.get(), 1, "Same identity", true, nullptr, nullptr, -3600);
    auto newer = make_x509(signer.get(), 1, "Same identity", true, nullptr, nullptr, -60);
    Certificate first(create(der(old.get())));
    Certificate second(create(der(newer.get())));
    set_property(first.value, CERT_FIRST_USER_PROP_ID, {1});
    set_property(second.value, CERT_FIRST_USER_PROP_ID + 1, {2});
    for (DWORD disposition = 1; disposition <= 7; ++disposition) {
        Store store(memory());
        Certificate original(add(store.value, first.value));
        if (disposition == CERT_STORE_ADD_NEW) {
            CHECK(!CertAddCertificateContextToStore(store.value, second.value, disposition, nullptr));
            CHECK(GetLastError() == CRYPT_E_EXISTS);
            continue;
        }
        Certificate result(add(store.value, second.value, disposition));
        CHECK(enumerate(store.value) == (disposition == CERT_STORE_ADD_ALWAYS ? 2u : 1u));
        CHECK(property(result.value, CERT_FIRST_USER_PROP_ID + 1) == Bytes({2}));
        if (disposition == CERT_STORE_ADD_USE_EXISTING ||
            disposition == CERT_STORE_ADD_NEWER_INHERIT_PROPERTIES ||
            disposition == CERT_STORE_ADD_REPLACE_EXISTING_INHERIT_PROPERTIES)
            CHECK(property(result.value, CERT_FIRST_USER_PROP_ID) == Bytes({1}));
        auto expected = disposition == CERT_STORE_ADD_USE_EXISTING ||
            disposition == CERT_STORE_ADD_REPLACE_EXISTING_INHERIT_PROPERTIES ? der(old.get()) : der(newer.get());
        CHECK(Bytes(result.value->pbCertEncoded, result.value->pbCertEncoded + result.value->cbCertEncoded) == expected);
        if (disposition == CERT_STORE_ADD_NEWER || disposition == CERT_STORE_ADD_NEWER_INHERIT_PROPERTIES) {
            CHECK(!CertAddCertificateContextToStore(store.value, first.value, disposition, nullptr));
            CHECK(GetLastError() == CRYPT_E_EXISTS && enumerate(store.value) == 1);
            CHECK(!CertAddCertificateContextToStore(store.value, second.value, disposition, nullptr));
            CHECK(GetLastError() == CRYPT_E_EXISTS);
        }
    }
}

int child_read(const char* path) {
    Store store(CertOpenStore(SYS_CERT_STORE_PROV_SQLITE, 0, 0, CERT_STORE_OPEN_EXISTING_FLAG, path));
    CHECK(enumerate(store.value) == 1);
    Certificate certificate(CertEnumCertificatesInStore(store.value, nullptr));
    CHECK(property(certificate.value, CERT_FIRST_USER_PROP_ID) == Bytes({9, 8, 7}));
    set_property(certificate.value, CERT_FIRST_USER_PROP_ID, {6, 5, 4});
    return 0;
}

void persistent_tests() {
    TempDir temp;
    auto path = (temp.path / "persistent.db").string();
    auto signer = key();
    auto x = make_x509(signer.get(), 7, "Persistent", true);
    Certificate input(create(der(x.get())));
    {
        Store store(CertOpenStore(SYS_CERT_STORE_PROV_SQLITE, 0, 0, CERT_STORE_CREATE_NEW_FLAG, path.c_str()));
        Certificate added(add(store.value, input.value));
        auto file = material_path(added.value);
        CHECK(read_file(file) == pem(x.get()));
        set_property(added.value, CERT_FIRST_USER_PROP_ID, {9, 8, 7});
        WCHAR friendly[] = L"Persistent certificate";
        CRYPT_DATA_BLOB text{sizeof(friendly), reinterpret_cast<BYTE*>(friendly)};
        CHECK(CertSetCertificateContextProperty(added.value, CERT_FRIENDLY_NAME_PROP_ID, 0, &text));
        CHECK(CertSetStoreProperty(store.value, CERT_STORE_LOCALIZED_NAME_PROP_ID, 0, &text));
        CHECK(CertControlStore(store.value, 0, CERT_STORE_CTRL_COMMIT, nullptr));
    }
    struct stat mode{};
    CHECK(stat(path.c_str(), &mode) == 0 && (mode.st_mode & 0777) == 0600);
    sqlite3* raw_database = nullptr;
    CHECK(sqlite3_open_v2(path.c_str(), &raw_database, SQLITE_OPEN_READONLY, nullptr) == SQLITE_OK);
    std::unique_ptr<sqlite3, decltype(&sqlite3_close)> database(raw_database, sqlite3_close);
    sqlite3_stmt* raw_query = nullptr;
    CHECK(sqlite3_prepare_v2(database.get(), "SELECT name FROM pragma_table_info('certificates') ORDER BY cid", -1, &raw_query, nullptr) == SQLITE_OK);
    {
        std::unique_ptr<sqlite3_stmt, decltype(&sqlite3_finalize)> query(raw_query, sqlite3_finalize);
        CHECK(sqlite3_step(query.get()) == SQLITE_ROW && std::string(reinterpret_cast<const char*>(sqlite3_column_text(query.get(), 0))) == "id");
        CHECK(sqlite3_step(query.get()) == SQLITE_ROW && std::string(reinterpret_cast<const char*>(sqlite3_column_text(query.get(), 0))) == "object");
        CHECK(sqlite3_step(query.get()) == SQLITE_DONE);
    }
    database.reset();
    pid_t child = fork();
    CHECK(child >= 0);
    if (child == 0) {
        execl("/proc/self/exe", "store-tests", "--child-read", path.c_str(), static_cast<char*>(nullptr));
        _exit(127);
    }
    int status = 0;
    CHECK(waitpid(child, &status, 0) == child && WIFEXITED(status) && WEXITSTATUS(status) == 0);
    Store store(CertOpenStore(SYS_CERT_STORE_PROV_SQLITE, 0, 0, 0, path.c_str()));
    Certificate certificate(CertEnumCertificatesInStore(store.value, nullptr));
    CHECK(property(certificate.value, CERT_FIRST_USER_PROP_ID) == Bytes({6, 5, 4}));
    DWORD size = 0;
    CHECK(CertGetStoreProperty(store.value, CERT_STORE_LOCALIZED_NAME_PROP_ID, nullptr, &size));
    CHECK(size > sizeof(WCHAR));
    CHECK(!CertOpenStore(SYS_CERT_STORE_PROV_SQLITE, 0, 0, CERT_STORE_CREATE_NEW_FLAG, path.c_str()));
    CHECK(GetLastError() == CRYPT_E_EXISTS);
    Store readonly(CertOpenStore(SYS_CERT_STORE_PROV_SQLITE, 0, 0, CERT_STORE_READONLY_FLAG, path.c_str()));
    CHECK(!CertAddCertificateContextToStore(readonly.value, input.value, CERT_STORE_ADD_ALWAYS, nullptr));
    CHECK(GetLastError() == ERROR_ACCESS_DENIED);
    auto to_delete = CertEnumCertificatesInStore(readonly.value, nullptr);
    CHECK(to_delete && !CertDeleteCertificateFromStore(to_delete));
    CHECK(GetLastError() == ERROR_ACCESS_DENIED);
    CHECK(!CertDuplicateCertificateContext(to_delete));
    CHECK(GetLastError() == ERROR_INVALID_HANDLE);
    CHECK(enumerate(store.value) == 1);
    CRYPT_DATA_BLOB archived{};
    CHECK(CertSetCertificateContextProperty(certificate.value, CERT_ARCHIVED_PROP_ID, 0, &archived));
    CHECK(enumerate(store.value) == 0);
    {
        Certificate explicit_match(CertGetSubjectCertificateFromStore(store.value, X509_ASN_ENCODING, input.value->pCertInfo));
        CHECK(explicit_match.value);
    }
    Store all(CertOpenStore(SYS_CERT_STORE_PROV_SQLITE, 0, 0, CERT_STORE_ENUM_ARCHIVED_FLAG, path.c_str()));
    CHECK(enumerate(all.value) == 1);
    CHECK(CertSetCertificateContextProperty(certificate.value, CERT_ARCHIVED_PROP_ID, 0, nullptr));
    CHECK(enumerate(store.value) == 1);
    auto certificate_file = material_path(certificate.value);
    CHECK(CertDeleteCertificateFromStore(CertEnumCertificatesInStore(store.value, nullptr)));
    CHECK(!std::filesystem::exists(certificate_file));
    CHECK(!std::filesystem::exists(certificate_file.parent_path()));
    CHECK(enumerate(store.value) == 0);
    CHECK(property(certificate.value, CERT_FIRST_USER_PROP_ID) == Bytes({6, 5, 4}));
    auto missing = (temp.path / "missing.db").string();
    CHECK(!CertOpenStore(SYS_CERT_STORE_PROV_SQLITE, 0, 0, CERT_STORE_OPEN_EXISTING_FLAG, missing.c_str()));
    CHECK(GetLastError() == ERROR_FILE_NOT_FOUND && !std::filesystem::exists(missing));
    auto invalid = temp.path / "invalid.db";
    write_file(invalid, "not sqlite");
    CHECK(!CertOpenStore(SYS_CERT_STORE_PROV_SQLITE, 0, 0, 0, invalid.c_str()));
    CHECK(GetLastError() == ERROR_INVALID_DATA);
    auto symlink = temp.path / "link.db";
    std::filesystem::create_symlink(path, symlink);
    CHECK(!CertOpenStore(SYS_CERT_STORE_PROV_SQLITE, 0, 0, 0, symlink.c_str()));
    CHECK(GetLastError() == ERROR_ACCESS_DENIED);
}

void pfx_tests() {
    TempDir temp;
    auto signer = key();
    auto ca = make_x509(signer.get(), 1, "PFX CA", true);
    auto leaf_key = key();
    auto leaf = make_x509(leaf_key.get(), 2, "PFX leaf", false, ca.get(), signer.get());
    auto free_chain = [](STACK_OF(X509)* chain) { sk_X509_free(chain); };
    std::unique_ptr<STACK_OF(X509), decltype(free_chain)> chain(sk_X509_new_null(), free_chain);
    CHECK(chain && sk_X509_push(chain.get(), ca.get()));
    std::unique_ptr<PKCS12, decltype(&PKCS12_free)> pfx(
        PKCS12_create("password", "test", leaf_key.get(), leaf.get(), chain.get(), 0, 0, 0, 0, 0), PKCS12_free);
    CHECK(pfx);
    int size = i2d_PKCS12(pfx.get(), nullptr);
    CHECK(size > 0);
    Bytes encoded(static_cast<std::size_t>(size));
    BYTE* cursor = encoded.data();
    CHECK(i2d_PKCS12(pfx.get(), &cursor) == size);
    CRYPT_DATA_BLOB blob{static_cast<DWORD>(encoded.size()), encoded.data()};
    auto path = (temp.path / "MY.db").string();
    Store store(CertOpenStore(SYS_CERT_STORE_PROV_SQLITE, 0, 0, 0, path.c_str()));
    CHECK(!SysCertImportPfxToStore(store.value, &blob, L"wrong", 0));
    CHECK(GetLastError() == ERROR_INVALID_DATA && enumerate(store.value) == 0);
    CHECK(std::filesystem::is_empty(path + ".objects"));
    CHECK(!SysCertImportPfxToStore(store.value, &blob, L"password", PKCS12_NO_PERSIST_KEY));
    CHECK(GetLastError() == ERROR_NOT_SUPPORTED);
    CHECK(SysCertImportPfxToStore(store.value, &blob, L"password", 0));
    CHECK(enumerate(store.value) == 2);
    CHECK(CertCloseStore(store.value, 0));
    store.value = nullptr;
    Store reopened(CertOpenStore(SYS_CERT_STORE_PROV_SQLITE, 0, 0, CERT_STORE_OPEN_EXISTING_FLAG, path.c_str()));
    Certificate certificate(CertFindCertificateInStore(reopened.value, X509_ASN_ENCODING, 0, CERT_FIND_SUBJECT_STR_W, L"PFX leaf", nullptr));
    auto cert_file = material_path(certificate.value);
    auto key_file = material_path(certificate.value, TRUE);
    CHECK(cert_file.parent_path() == key_file.parent_path());
    CHECK(read_file(cert_file) == pem(leaf.get()));
    CHECK(read_file(key_file).starts_with("-----BEGIN PRIVATE KEY-----"));
    struct stat status{};
    CHECK(stat(key_file.c_str(), &status) == 0 && (status.st_mode & 0777) == 0600);
    CHECK(stat(cert_file.parent_path().c_str(), &status) == 0 && (status.st_mode & 0777) == 0700);
    auto close_file = [](FILE* file) { std::fclose(file); };
    std::unique_ptr<FILE, decltype(close_file)> input(std::fopen(key_file.c_str(), "rb"), close_file);
    CHECK(input);
    Key imported(PEM_read_PrivateKey(input.get(), nullptr, nullptr, nullptr), EVP_PKEY_free);
    CHECK(imported && EVP_PKEY_eq(imported.get(), leaf_key.get()) == 1);
    input.reset();
    auto second_path = (temp.path / "other.db").string();
    Store second(CertOpenStore(SYS_CERT_STORE_PROV_SQLITE, 0, 0, 0, second_path.c_str()));
    Certificate copied(add(second.value, certificate.value));
    auto copied_key = material_path(copied.value, TRUE);
    CHECK(copied_key != key_file && read_file(copied_key) == read_file(key_file));
    CHECK(CertDeleteCertificateFromStore(CertDuplicateCertificateContext(certificate.value)));
    CHECK(!std::filesystem::exists(key_file) && !std::filesystem::exists(cert_file));
    CHECK(std::filesystem::exists(copied_key));
    CHECK(enumerate(reopened.value) == 1);
    Certificate intermediate(CertEnumCertificatesInStore(reopened.value, nullptr));
    CHECK(std::filesystem::exists(material_path(intermediate.value)));
    DWORD path_size = 0;
    CHECK(!SysCertGetCertificateFilePath(intermediate.value, TRUE, nullptr, &path_size));
    CHECK(GetLastError() == CRYPT_E_NOT_FOUND);
    std::unique_ptr<PKCS12, decltype(&PKCS12_free)> cert_only(
        PKCS12_create("", nullptr, nullptr, nullptr, chain.get(), 0, 0, 0, 0, 0), PKCS12_free);
    CHECK(cert_only);
    size = i2d_PKCS12(cert_only.get(), nullptr);
    CHECK(size > 0);
    encoded.resize(static_cast<std::size_t>(size));
    cursor = encoded.data();
    CHECK(i2d_PKCS12(cert_only.get(), &cursor) == size);
    blob = {static_cast<DWORD>(encoded.size()), encoded.data()};
    CHECK(SysCertImportPfxToStore(reopened.value, &blob, nullptr, 0));
    CHECK(enumerate(reopened.value) == 2);
}

void native_tests() {
    auto signer = key();
    auto x = make_x509(signer.get(), 1, "Fixture CA", true);
    auto encoded = pem(x.get());
    Certificate certificate(create(der(x.get())));
    for (const auto* distro : {"ubuntu", "rhel", "mariner", "azurelinux", "rocky"}) {
        TempDir temp;
        bool debian = std::strcmp(distro, "ubuntu") == 0;
        auto bundle = temp.path / (debian ? "etc/ssl/certs/ca-certificates.crt" :
            "etc/pki/ca-trust/extracted/pem/tls-ca-bundle.pem");
        auto anchors = temp.path / (debian ? "usr/local/share/ca-certificates" : "etc/pki/ca-trust/source/anchors");
        auto updater = temp.path / (debian ? "usr/sbin/update-ca-certificates" : "usr/bin/update-ca-trust");
        auto observed = temp.path / "observed-anchor-count";
        auto successful_updater = "#!/bin/sh\ngrep -rl -- '-----BEGIN CERTIFICATE-----' '" +
            anchors.string() + "' | wc -l > '" + observed.string() + "'\n: > '" + bundle.string() +
            "'\nfor file in '" + anchors.string() + "'/*.crt; do [ ! -f \"$file\" ] || cat \"$file\" >> '" +
            bundle.string() + "'; done\n";
        write_file(temp.path / "etc/os-release", std::string("ID=\"") + distro + "\"\n");
        write_file(bundle, "# fixture\n" + encoded + encoded);
        std::filesystem::create_directories(anchors);
        write_file(updater, successful_updater);
        CHECK(chmod(updater.c_str(), 0700) == 0);
        auto root = temp.path.string();
        SYS_CERT_NATIVE_OPTIONS options{sizeof(options), root.c_str()};
        Store store(CertOpenStore(SYS_CERT_STORE_PROV_NATIVE, 0, 0, 0, &options));
        CHECK(enumerate(store.value) == 1);
        CHECK(!CertAddCertificateContextToStore(store.value, certificate.value, CERT_STORE_ADD_ALWAYS, nullptr));
        CHECK(GetLastError() == ERROR_ACCESS_DENIED);
        CHECK(!SysCertUpdateTrustAnchor(certificate.value, TRUE, &options, 0));
        CHECK(GetLastError() == ERROR_ACCESS_DENIED);
        CHECK(SysCertUpdateTrustAnchor(certificate.value, TRUE, &options, SYS_CERT_TRUST_UPDATE_ALLOW));
        CHECK(std::stoi(read_file(observed)) == 1);
        CHECK(!SysCertUpdateTrustAnchor(certificate.value, TRUE, &options, SYS_CERT_TRUST_UPDATE_ALLOW));
        CHECK(GetLastError() == CRYPT_E_EXISTS);
        std::filesystem::path owned;
        for (const auto& entry : std::filesystem::directory_iterator(anchors))
            if (entry.path().extension() == ".crt") owned = entry.path();
        CHECK(!owned.empty() && read_file(owned) == encoded);
        CHECK(SysCertUpdateTrustAnchor(certificate.value, FALSE, &options, SYS_CERT_TRUST_UPDATE_ALLOW));
        CHECK(std::stoi(read_file(observed)) == 0);
        CHECK(!std::filesystem::exists(owned));
        CHECK(!SysCertUpdateTrustAnchor(certificate.value, FALSE, &options, SYS_CERT_TRUST_UPDATE_ALLOW));
        CHECK(GetLastError() == CRYPT_E_NOT_FOUND);
        write_file(updater, "#!/bin/sh\nexit 7\n");
        CHECK(!SysCertUpdateTrustAnchor(certificate.value, TRUE, &options, SYS_CERT_TRUST_UPDATE_ALLOW));
        CHECK(GetLastError() == ERROR_GEN_FAILURE && !std::filesystem::exists(owned));
        CHECK(std::string(SysCertGetLastErrorMessage()).find("regeneration failed") != std::string::npos);
        write_file(updater, successful_updater);
        CHECK(SysCertUpdateTrustAnchor(certificate.value, TRUE, &options, SYS_CERT_TRUST_UPDATE_ALLOW));
        write_file(updater, "#!/bin/sh\nexit 7\n");
        CHECK(!SysCertUpdateTrustAnchor(certificate.value, FALSE, &options, SYS_CERT_TRUST_UPDATE_ALLOW));
        CHECK(std::filesystem::exists(owned) && read_file(owned) == encoded);
        write_file(updater, successful_updater);
        CHECK(SysCertUpdateTrustAnchor(certificate.value, FALSE, &options, SYS_CERT_TRUST_UPDATE_ALLOW));
        {
            Certificate outstanding(CertEnumCertificatesInStore(store.value, nullptr));
            CHECK(!CertControlStore(store.value, 0, CERT_STORE_CTRL_RESYNC, nullptr));
            CHECK(GetLastError() == ERROR_BUSY);
        }
        write_file(bundle, encoded + "-----BEGIN CERTIFICATE-----\ninvalid\n");
        CHECK(!CertControlStore(store.value, 0, CERT_STORE_CTRL_RESYNC, nullptr));
        CHECK(GetLastError() == ERROR_INVALID_DATA);
        CHECK(enumerate(store.value) == 1);
        write_file(bundle, "");
        CHECK(CertControlStore(store.value, 0, CERT_STORE_CTRL_RESYNC, nullptr));
        CHECK(enumerate(store.value) == 0);
    }

    TempDir unknown;
    write_file(unknown.path / "etc/os-release", "ID=unknown\n");
    auto root = unknown.path.string();
    SYS_CERT_NATIVE_OPTIONS options{sizeof(options), root.c_str()};
    CHECK(!CertOpenStore(SYS_CERT_STORE_PROV_NATIVE, 0, 0, 0, &options));
    CHECK(GetLastError() == ERROR_NOT_SUPPORTED);
}

void native_api_tests() {
    auto signer = key();
    auto x = make_x509(signer.get(), 2, "Vendor Root", true);
    auto other = make_x509(signer.get(), 3, "Unrelated Root", true);
    Certificate certificate(create(der(x.get())));
    for (bool debian : {true, false}) {
        TempDir temp;
        write_file(temp.path / "etc/os-release", debian ? "ID=ubuntu\n" : "ID=azurelinux\n");
        auto bundle = temp.path / (debian ? "etc/ssl/certs/ca-certificates.crt" :
            "etc/pki/ca-trust/extracted/pem/tls-ca-bundle.pem");
        auto anchors = temp.path / (debian ? "usr/local/share/ca-certificates" : "etc/pki/ca-trust/source/anchors");
        auto updater = temp.path / (debian ? "usr/sbin/update-ca-certificates" : "usr/bin/update-ca-trust");
        std::filesystem::create_directories(anchors);
        auto vendor = temp.path / (debian ? "usr/share/ca-certificates/vendor/root.crt" : "usr/share/pki/ca-trust-source/anchors/root.pem");
        auto unrelated = vendor.parent_path() / (debian ? "other.crt" : "other.pem");
        write_file(vendor, pem(x.get()));
        write_file(unrelated, pem(other.get()));
        auto config = temp.path / "etc/ca-certificates.conf";
        if (debian) write_file(config, "# fixture\nvendor/root.crt\nvendor/other.crt\n");
        write_file(bundle, pem(x.get()) + pem(other.get()));
        if (debian && access("/usr/sbin/update-ca-certificates", X_OK) == 0) {
            auto hooks = temp.path / "empty-hooks";
            std::filesystem::create_directory(hooks);
            write_file(updater, "#!/bin/sh\nexec /usr/sbin/update-ca-certificates --fresh --certsconf '" +
                config.string() + "' --certsdir '" + vendor.parent_path().parent_path().string() +
                "' --localcertsdir '" + anchors.string() + "' --etccertsdir '" +
                bundle.parent_path().string() + "' --hooksdir '" + hooks.string() + "'\n");
        } else {
            auto blocklist = temp.path / "etc/pki/ca-trust/source/blocklist";
            std::filesystem::create_directories(blocklist);
            std::string enabled = debian ? "grep -q '^vendor/root.crt$' '" + config.string() + "'" :
                "[ -z \"$(find '" + blocklist.string() + "' -type f -name '*.crt' -print)\" ]";
            write_file(updater, "#!/bin/sh\ncat '" + unrelated.string() + "' > '" + bundle.string() +
                "'\nif " + enabled + "; then cat '" + vendor.string() + "' >> '" + bundle.string() +
                "'; fi\nfor file in '" + anchors.string() + "'/*.crt; do [ ! -f \"$file\" ] || cat \"$file\" >> '" +
                bundle.string() + "'; done\n");
        }
        CHECK(chmod(updater.c_str(), 0700) == 0);
        auto root = temp.path.string();
        SYS_CERT_NATIVE_OPTIONS options{sizeof(options), root.c_str()};
        Store store(CertOpenStore(SYS_CERT_STORE_PROV_NATIVE, 0, 0, SYS_CERT_STORE_NATIVE_WRITE_FLAG, &options));
        CHECK(CertDeleteCertificateFromStore(CertEnumCertificatesInStore(store.value, nullptr)));
        CHECK(enumerate(store.value) == 1);
        CHECK(read_file(vendor) == pem(x.get()));
        CHECK(read_file(bundle).find(pem(x.get())) == std::string::npos);
        {
            Store fresh(CertOpenStore(SYS_CERT_STORE_PROV_NATIVE, 0, 0, 0, &options));
            CHECK(enumerate(fresh.value) == 1);
        }
        if (debian) CHECK(read_file(config).find("!vendor/root.crt") != std::string::npos);
        else {
            unsigned blocked = 0;
            for (const auto& file : std::filesystem::directory_iterator(temp.path / "etc/pki/ca-trust/source/blocklist"))
                if (read_file(file.path()) == pem(x.get())) ++blocked;
            CHECK(blocked == 1);
        }
        Certificate installed(add(store.value, certificate.value, CERT_STORE_ADD_NEW));
        CHECK(enumerate(store.value) == 2);
        CHECK(read_file(bundle).find(pem(x.get())) != std::string::npos);
        if (!debian) CHECK(std::filesystem::is_empty(temp.path / "etc/pki/ca-trust/source/blocklist"));
        unsigned files = 0;
        for (const auto& file : std::filesystem::directory_iterator(anchors))
            if (file.path().extension() == ".crt") ++files;
        CHECK(files == 1);
        CHECK(CertDeleteCertificateFromStore(CertDuplicateCertificateContext(installed.value)));
        CHECK(enumerate(store.value) == 1 && std::filesystem::is_empty(anchors));
        CHECK(read_file(bundle).find(pem(x.get())) == std::string::npos);
    }
}

void error_tests() {
    Store store(memory());
    CHECK(!CertFindCertificateInStore(store.value, X509_ASN_ENCODING, 0, 0xffffffff, nullptr, nullptr));
    CHECK(GetLastError() == ERROR_NOT_SUPPORTED);
    CHECK(!CertCreateCertificateContext(X509_ASN_ENCODING, nullptr, 5));
    CHECK(GetLastError() == E_INVALIDARG);
    CHECK(!CertCreateCertificateContext(X509_ASN_ENCODING, nullptr, 0));
    CHECK(GetLastError() == ERROR_INVALID_DATA);
    CHECK(!CertOpenStore(reinterpret_cast<LPCSTR>(4), 0, 0, 0, nullptr));
    CHECK(GetLastError() == ERROR_NOT_SUPPORTED);
    CHECK(!CertOpenStore(CERT_STORE_PROV_SYSTEM_W, 0, 0, CERT_SYSTEM_STORE_CURRENT_USER, L"../escape"));
    CHECK(GetLastError() == E_INVALIDARG);
    auto signer = key();
    auto x = make_x509(signer.get(), 1, "Errors", true);
    auto encoded = der(x.get());
    encoded.push_back(0);
    CHECK(!create(encoded));
    CHECK(GetLastError() == ERROR_INVALID_DATA);
    encoded.pop_back();
    Certificate input(create(encoded));
    Certificate added(add(store.value, input.value));
    DWORD size = 0;
    CHECK(!CertGetCertificateContextProperty(added.value, CERT_NCRYPT_KEY_HANDLE_PROP_ID, nullptr, &size));
    CHECK(GetLastError() == ERROR_NOT_SUPPORTED);
    auto previous = CertEnumCertificatesInStore(store.value, nullptr);
    CHECK(previous);
    CHECK(!CertFindCertificateInStore(store.value, 0, 0, CERT_FIND_ANY, nullptr, previous));
    CHECK(GetLastError() == ERROR_NOT_SUPPORTED);
    CHECK(!CertDuplicateCertificateContext(previous));
    CHECK(GetLastError() == ERROR_INVALID_HANDLE);
    Store other(memory());
    previous = CertEnumCertificatesInStore(store.value, nullptr);
    CHECK(!CertEnumCertificatesInStore(other.value, previous));
    CHECK(GetLastError() == E_INVALIDARG);
    CHECK(!CertDuplicateCertificateContext(previous));
    CHECK(!CertCloseStore(store.value, CERT_CLOSE_STORE_FORCE_FLAG));
    CHECK(GetLastError() == ERROR_NOT_SUPPORTED);
    CHECK(enumerate(store.value) == 1);
    CHECK(CertFreeCertificateContext(nullptr));
}

void thread_tests() {
    SetLastError(123);
    std::atomic<bool> good{true};
    std::vector<std::thread> threads;
    for (DWORD i = 0; i < 8; ++i) threads.emplace_back([&, i] {
        SetLastError(i);
        auto handle = memory();
        if (!handle || !CertCloseStore(handle, 0) || GetLastError() != i) good = false;
    });
    for (auto& thread : threads) thread.join();
    CHECK(good && GetLastError() == 123);
}

BOOL collect_stores(const void* name, DWORD, PCERT_SYSTEM_STORE_INFO info, void* reserved, void* argument) {
    CHECK(info && info->cbSize == sizeof(*info) && !reserved);
    static_cast<std::set<std::wstring>*>(argument)->insert(static_cast<LPCWSTR>(name));
    return TRUE;
}
BOOL collect_locations(LPCWSTR, DWORD location, void* reserved, void* argument) {
    CHECK(!reserved);
    static_cast<std::set<DWORD>*>(argument)->insert(location);
    return TRUE;
}
struct BlockingEnumeration {
    std::atomic<bool> entered{false};
    std::atomic<bool> release{false};
};
BOOL block_store_enumeration(const void*, DWORD, PCERT_SYSTEM_STORE_INFO, void*, void* argument) {
    auto* state = static_cast<BlockingEnumeration*>(argument);
    state->entered = true;
    while (!state->release.load())
        std::this_thread::sleep_for(std::chrono::milliseconds(1));
    return TRUE;
}
DWORD location(PCCERT_CONTEXT certificate) {
    DWORD result = 0;
    CHECK(SysCertGetCertificateStoreLocation(certificate, &result));
    return result;
}
HCERTSTORE scoped(LPCWSTR name, DWORD scope, DWORD flags = 0) {
    return CertOpenStore(CERT_STORE_PROV_SYSTEM_W, 0, 0, scope | flags, name);
}
void system_scope_tests() {
    TempDir temp;
    auto first_user = (temp.path / "alice").string();
    auto second_user = (temp.path / "bob").string();
    auto machine = (temp.path / "computer").string();
    auto root = (temp.path / "system").string();
    auto signer = key();
    auto native_root = make_x509(signer.get(), 41, "Machine Root", true);
    auto user_root = make_x509(signer.get(), 42, "User Root", true);
    auto intermediate = make_x509(signer.get(), 43, "Intermediate", true);
    auto personal = make_x509(signer.get(), 44, "Personal", false);
    std::wstring computer_import_name;
    auto bundle = std::filesystem::path(root) / "etc/ssl/certs/ca-certificates.crt";
    write_file(std::filesystem::path(root) / "etc/os-release", "ID=ubuntu\n");
    write_file(bundle, pem(native_root.get()));
    SYS_CERT_STORE_CONFIGURATION configuration{sizeof(configuration), first_user.c_str(), machine.c_str(), root.c_str()};
    CHECK(SysCertConfigureSystemStores(&configuration));
    {
        std::set<DWORD> locations;
        CHECK(CertEnumSystemStoreLocation(0, &locations, collect_locations));
        CHECK(locations == std::set<DWORD>({CERT_SYSTEM_STORE_CURRENT_USER, CERT_SYSTEM_STORE_LOCAL_MACHINE}));
        std::set<std::wstring> names;
        CHECK(CertEnumSystemStore(CERT_SYSTEM_STORE_CURRENT_USER, nullptr, &names, collect_stores));
        CHECK(names == std::set<std::wstring>({L"CA", L"MY", L"ROOT"}));
        BlockingEnumeration enumeration_state;
        std::atomic<bool> enumeration_result{false};
        std::thread enumeration([&] {
            enumeration_result = CertEnumSystemStore(
                CERT_SYSTEM_STORE_CURRENT_USER, nullptr, &enumeration_state,
                block_store_enumeration) != FALSE;
        });
        bool callback_entered = wait_for_flag(
            enumeration_state.entered, std::chrono::seconds(5));
        std::atomic<bool> operation_result{false};
        std::atomic<bool> operation_finished{false};
        std::thread operation([&] {
            auto handle = memory();
            operation_result = handle && CertCloseStore(handle, 0);
            operation_finished = true;
        });
        bool operation_was_concurrent = wait_for_flag(
            operation_finished, std::chrono::seconds(2));
        enumeration_state.release = true;
        enumeration.join();
        operation.join();
        CHECK(callback_entered && operation_was_concurrent &&
            enumeration_result && operation_result);
        CHECK(!std::filesystem::exists(first_user) && !std::filesystem::exists(machine));
        auto stop = [](const void*, DWORD, PCERT_SYSTEM_STORE_INFO, void*, void*) -> BOOL {
            SetLastError(1234);
            return FALSE;
        };
        CHECK(!CertEnumSystemStore(CERT_SYSTEM_STORE_CURRENT_USER, nullptr, nullptr, stop));
        CHECK(GetLastError() == 1234);
        CHECK(!CertEnumSystemStore(0, nullptr, nullptr, collect_stores));
        CHECK(GetLastError() == ERROR_NOT_SUPPORTED);
        CHECK(!scoped(L"MY", CERT_SYSTEM_STORE_CURRENT_USER, CERT_STORE_CREATE_NEW_FLAG));
        CHECK(GetLastError() == CRYPT_E_EXISTS);
        CHECK(!scoped(L"ROOT", CERT_SYSTEM_STORE_CURRENT_USER, SYS_CERT_STORE_NATIVE_WRITE_FLAG));
        CHECK(GetLastError() == E_INVALIDARG);
        Store user_my(scoped(L"MY", CERT_SYSTEM_STORE_CURRENT_USER, CERT_STORE_OPEN_EXISTING_FLAG));
        Store machine_my(scoped(L"MY", CERT_SYSTEM_STORE_LOCAL_MACHINE));
        Store user_ca(scoped(L"CA", CERT_SYSTEM_STORE_CURRENT_USER));
        Store machine_ca(scoped(L"CA", CERT_SYSTEM_STORE_LOCAL_MACHINE));
        Store user_roots(CertOpenSystemStoreW(0, L"ROOT"));
        CHECK(!SysCertConfigureSystemStores(nullptr));
        CHECK(GetLastError() == ERROR_BUSY);
        CHECK(enumerate(user_my.value) == 0 && enumerate(machine_my.value) == 0 && enumerate(user_ca.value) == 0);
        CHECK(!std::filesystem::exists(first_user) && !std::filesystem::exists(machine));
        CHECK(enumerate(user_roots.value) == 1);
        Certificate source(create(der(personal.get())));
        Certificate computer_personal(add(machine_my.value, source.value));
        CHECK(location(computer_personal.value) == CERT_SYSTEM_STORE_LOCAL_MACHINE);
        CHECK(enumerate(user_my.value) == 0);
        Certificate user_personal(add(user_my.value, source.value));
        CHECK(location(user_personal.value) == CERT_SYSTEM_STORE_CURRENT_USER);
        CHECK(material_path(user_personal.value) != material_path(computer_personal.value));
        Certificate ca_source(create(der(intermediate.get())));
        Certificate computer_ca(add(machine_ca.value, ca_source.value));
        CHECK(enumerate(user_ca.value) == 1);
        Certificate inherited(CertEnumCertificatesInStore(user_ca.value, nullptr));
        CHECK(inherited.value->hCertStore == user_ca.value);
        CHECK(location(inherited.value) == CERT_SYSTEM_STORE_LOCAL_MACHINE);
        CHECK(material_path(inherited.value) == material_path(computer_ca.value));
        CRYPT_DATA_BLOB empty{};
        CHECK(!CertSetCertificateContextProperty(inherited.value, CERT_FIRST_USER_PROP_ID, 0, &empty));
        CHECK(GetLastError() == ERROR_ACCESS_DENIED);
        CHECK(!CertDeleteCertificateFromStore(CertDuplicateCertificateContext(inherited.value)));
        CHECK(GetLastError() == ERROR_ACCESS_DENIED && enumerate(machine_ca.value) == 1);
        Certificate local_ca(add(user_ca.value, ca_source.value));
        CHECK(location(local_ca.value) == CERT_SYSTEM_STORE_CURRENT_USER);
        CHECK(enumerate(user_ca.value) == 2);
        CHECK(read_file(bundle) == pem(native_root.get()));
        Certificate local_source(create(der(user_root.get())));
        Certificate local_root(add(user_roots.value, local_source.value, CERT_STORE_ADD_NEW));
        CHECK(location(local_root.value) == CERT_SYSTEM_STORE_CURRENT_USER);
        CHECK(enumerate(user_roots.value) == 2);
        CHECK(read_file(bundle) == pem(native_root.get()));
        Certificate machine_root(CertFindCertificateInStore(user_roots.value, X509_ASN_ENCODING, 0,
            CERT_FIND_SUBJECT_STR_W, L"Machine Root", nullptr));
        CHECK(location(machine_root.value) == CERT_SYSTEM_STORE_LOCAL_MACHINE);
        CHECK(!CertDeleteCertificateFromStore(CertDuplicateCertificateContext(machine_root.value)));
        CHECK(GetLastError() == ERROR_ACCESS_DENIED);
        CRYPT_DATA_BLOB saved{};
        CHECK(CertSaveStore(user_roots.value, PKCS_7_ASN_ENCODING, CERT_STORE_SAVE_AS_PKCS7,
            CERT_STORE_SAVE_TO_MEMORY, &saved, 0));
        Bytes output(saved.cbData);
        saved.pbData = output.data();
        CHECK(CertSaveStore(user_roots.value, PKCS_7_ASN_ENCODING, CERT_STORE_SAVE_AS_PKCS7,
            CERT_STORE_SAVE_TO_MEMORY, &saved, 0));
        const BYTE* cursor = output.data();
        std::unique_ptr<PKCS7, decltype(&PKCS7_free)> exported(d2i_PKCS7(nullptr, &cursor, saved.cbData), PKCS7_free);
        CHECK(exported && sk_X509_num(exported->d.sign->cert) == 2);
        CHECK(!CertControlStore(user_roots.value, 0, CERT_STORE_CTRL_RESYNC, nullptr));
        CHECK(GetLastError() == ERROR_BUSY);
        Store custom(scoped(L"Custom", CERT_SYSTEM_STORE_CURRENT_USER));
        names.clear();
        CHECK(CertEnumSystemStore(CERT_SYSTEM_STORE_CURRENT_USER, nullptr, &names, collect_stores));
        CHECK(names.contains(L"CUSTOM"));
        CHECK(!names.contains(L"INTERMEDIATE"));
    }

    {
        auto directory = std::filesystem::path(first_user);
        std::filesystem::rename(directory / "CUSTOM.db", directory / "custom.db");
        std::filesystem::rename(directory / "CUSTOM.db.objects", directory / "custom.db.objects");
        Store legacy_name(scoped(L"CUSTOM", CERT_SYSTEM_STORE_CURRENT_USER, CERT_STORE_OPEN_EXISTING_FLAG));
        CHECK(enumerate(legacy_name.value) == 0);
    }
    {
        PrivateUmask mask;
        auto encoded = pfx_bytes(personal.get(), signer.get());
        CRYPT_DATA_BLOB blob{static_cast<DWORD>(encoded.size()), encoded.data()};
        Store computer_import(PFXImportCertStore(&blob, L"password", CRYPT_MACHINE_KEYSET));
        std::set<std::wstring> imports;
        CHECK(CertEnumSystemStore(CERT_SYSTEM_STORE_LOCAL_MACHINE, nullptr, &imports, collect_stores));
        for (const auto& name : imports) if (name.starts_with(L"IMPORT-")) computer_import_name = name;
        CHECK(!computer_import_name.empty());
        Certificate imported(CertEnumCertificatesInStore(computer_import.value, nullptr));
        CHECK(location(imported.value) == CERT_SYSTEM_STORE_LOCAL_MACHINE);
        auto key_file = material_path(imported.value, TRUE);
        auto cert_file = material_path(imported.value);
        CHECK(key_file.parent_path() == cert_file.parent_path() / "keys");
        struct stat mode{};
        CHECK(stat(cert_file.c_str(), &mode) == 0 && (mode.st_mode & 0777) == 0644);
        CHECK(stat(cert_file.parent_path().c_str(), &mode) == 0 && (mode.st_mode & 0777) == 0755);
        CHECK(stat(cert_file.parent_path().parent_path().c_str(), &mode) == 0 && (mode.st_mode & 0777) == 0755);
        CHECK(stat((std::filesystem::path(machine) / (computer_import_name + L".db")).c_str(), &mode) == 0 &&
            (mode.st_mode & 0777) == 0644);
        CHECK(stat(key_file.c_str(), &mode) == 0 && (mode.st_mode & 0777) == 0600);
        CHECK(stat(key_file.parent_path().c_str(), &mode) == 0 && (mode.st_mode & 0777) == 0700);
        Store computer_ca(scoped(L"CA", CERT_SYSTEM_STORE_LOCAL_MACHINE));
        CHECK(SysCertImportPfxToStore(computer_ca.value, &blob, L"password", CRYPT_MACHINE_KEYSET));
        CHECK(!SysCertImportPfxToStore(computer_ca.value, &blob, L"password", CRYPT_USER_KEYSET));
        CHECK(GetLastError() == E_INVALIDARG);
        Store user_ca(scoped(L"CA", CERT_SYSTEM_STORE_CURRENT_USER));
        CHECK(!SysCertImportPfxToStore(user_ca.value, &blob, L"password", CRYPT_MACHINE_KEYSET));
        CHECK(GetLastError() == E_INVALIDARG);
        CHECK(!PFXImportCertStore(&blob, L"password", CRYPT_USER_KEYSET | CRYPT_MACHINE_KEYSET));
        CHECK(GetLastError() == E_INVALIDARG);
        Store user_import(PFXImportCertStore(&blob, L"password", CRYPT_USER_KEYSET));
        Certificate user_imported(CertEnumCertificatesInStore(user_import.value, nullptr));
        CHECK(location(user_imported.value) == CERT_SYSTEM_STORE_CURRENT_USER);
        CHECK(material_path(user_imported.value, TRUE).parent_path() == material_path(user_imported.value).parent_path());
        CHECK(stat(material_path(user_imported.value).c_str(), &mode) == 0 && (mode.st_mode & 0777) == 0600);
        Certificate inherited_key(CertFindCertificateInStore(user_ca.value, X509_ASN_ENCODING, 0,
            CERT_FIND_SUBJECT_STR_W, L"Personal", nullptr));
        CHECK(location(inherited_key.value) == CERT_SYSTEM_STORE_LOCAL_MACHINE);
        DWORD size = 0;
        CHECK(!SysCertGetCertificateFilePath(inherited_key.value, TRUE, nullptr, &size));
        CHECK(GetLastError() == ERROR_ACCESS_DENIED);
        CHECK(!CertAddCertificateContextToStore(user_ca.value, inherited_key.value, CERT_STORE_ADD_ALWAYS, nullptr));
        CHECK(GetLastError() == ERROR_ACCESS_DENIED);
        auto computer_key = CertFindCertificateInStore(computer_ca.value, X509_ASN_ENCODING, 0,
            CERT_FIND_SUBJECT_STR_W, L"Personal", nullptr);
        CHECK(computer_key);
        auto stored_key = material_path(computer_key, TRUE);
        CHECK(CertDeleteCertificateFromStore(computer_key));
        CHECK(!std::filesystem::exists(stored_key) && !std::filesystem::exists(stored_key.parent_path()));
    }
    configuration.userStoreDirectory = second_user.c_str();
    CHECK(SysCertConfigureSystemStores(&configuration));
    {
        Store user_my(scoped(L"MY", CERT_SYSTEM_STORE_CURRENT_USER, CERT_STORE_READONLY_FLAG));
        Store user_ca(scoped(L"CA", CERT_SYSTEM_STORE_CURRENT_USER, CERT_STORE_READONLY_FLAG));
        Store user_roots(scoped(L"ROOT", CERT_SYSTEM_STORE_CURRENT_USER, CERT_STORE_READONLY_FLAG));
        CHECK(enumerate(user_my.value) == 0 && enumerate(user_ca.value) == 1 && enumerate(user_roots.value) == 1);
        CHECK(!std::filesystem::exists(second_user));
        CHECK(!scoped(L"CUSTOM", CERT_SYSTEM_STORE_CURRENT_USER, CERT_STORE_OPEN_EXISTING_FLAG));
        CHECK(GetLastError() == ERROR_FILE_NOT_FOUND);
        CHECK(CertControlStore(user_roots.value, 0, CERT_STORE_CTRL_RESYNC, nullptr));
    }
    configuration.userStoreDirectory = first_user.c_str();
    CHECK(SysCertConfigureSystemStores(&configuration));
    {
        Store user_my(scoped(L"MY", CERT_SYSTEM_STORE_CURRENT_USER));
        Store user_ca(scoped(L"CA", CERT_SYSTEM_STORE_CURRENT_USER));
        Store user_roots(scoped(L"ROOT", CERT_SYSTEM_STORE_CURRENT_USER));
        CHECK(enumerate(user_my.value) == 1 && enumerate(user_ca.value) == 2 && enumerate(user_roots.value) == 2);
        auto selected = CertFindCertificateInStore(user_roots.value, X509_ASN_ENCODING, 0,
            CERT_FIND_SUBJECT_STR_W, L"User Root", nullptr);
        CHECK(selected);
        auto file = material_path(selected);
        CHECK(CertDeleteCertificateFromStore(selected));
        CHECK(!std::filesystem::exists(file));
        CHECK(enumerate(user_roots.value) == 1 && read_file(bundle) == pem(native_root.get()));
        auto inherited = CertEnumCertificatesInStore(user_roots.value, nullptr);
        CHECK(inherited && location(inherited) == CERT_SYSTEM_STORE_LOCAL_MACHINE);
        CHECK(!CertCloseStore(user_roots.value, CERT_CLOSE_STORE_CHECK_FLAG));
        CHECK(GetLastError() == CRYPT_E_PENDING_CLOSE);
        user_roots.value = nullptr;
        CHECK(property(inherited, CERT_SHA256_HASH_PROP_ID).size() == 32);
        CHECK(CertFreeCertificateContext(inherited));
    }
    if (geteuid() == 0) {
        CHECK(chmod(temp.path.c_str(), 0755) == 0);
        pid_t child = fork();
        CHECK(child >= 0);
        if (child == 0) {
            try {
                CHECK(setgroups(0, nullptr) == 0 && setgid(65534) == 0 && setuid(65534) == 0);
                CHECK(!scoped(L"MY", CERT_SYSTEM_STORE_CURRENT_USER, CERT_STORE_READONLY_FLAG));
                CHECK(GetLastError() == ERROR_ACCESS_DENIED);
                configuration.userStoreDirectory = second_user.c_str();
                CHECK(SysCertConfigureSystemStores(&configuration));
                Store ca(scoped(L"CA", CERT_SYSTEM_STORE_CURRENT_USER, CERT_STORE_READONLY_FLAG));
                CHECK(enumerate(ca.value) == 1);
                Store computer(scoped(computer_import_name.c_str(), CERT_SYSTEM_STORE_LOCAL_MACHINE, CERT_STORE_READONLY_FLAG));
                Certificate certificate(CertEnumCertificatesInStore(computer.value, nullptr));
                CHECK(std::filesystem::exists(material_path(certificate.value)));
                DWORD size = 0;
                CHECK(!SysCertGetCertificateFilePath(certificate.value, TRUE, nullptr, &size));
                CHECK(GetLastError() == ERROR_ACCESS_DENIED);
                CHECK(!CertDeleteCertificateFromStore(CertDuplicateCertificateContext(certificate.value)));
                CHECK(GetLastError() == ERROR_ACCESS_DENIED);
                _exit(0);
            } catch (const std::exception& error) {
                std::cerr << error.what() << '\n';
                _exit(1);
            }
        }
        int status = 0;
        CHECK(waitpid(child, &status, 0) == child && WIFEXITED(status) && WEXITSTATUS(status) == 0);
    }
    CHECK(SysCertConfigureSystemStores(nullptr));
}

void chain_tests() {
    TempDir temp;
    auto system = temp.path / "system";
    write_file(system / "etc/os-release", "ID=ubuntu\n");

    auto expired_trusted_key = key();
    auto expired_trusted = make_x509(expired_trusted_key.get(), 101, "Expired Trusted Root", true,
        nullptr, nullptr, -10 * 86400, EVP_sha256(), nullptr, -5 * 86400, -1, 1);
    auto expired_untrusted_key = key();
    auto expired_untrusted = make_x509(expired_untrusted_key.get(), 102, "Expired Untrusted Root", true,
        nullptr, nullptr, -10 * 86400, EVP_sha256(), nullptr, -5 * 86400, -1, 1);
    auto non_ca_key = key();
    auto non_ca = make_x509(non_ca_key.get(), 103, "Not A CA", false,
        nullptr, nullptr, -60, EVP_sha256(), nullptr, 86400, -1, 0);
    auto non_ca_leaf_key = key();
    auto non_ca_leaf = make_x509(non_ca_leaf_key.get(), 104, "Non-CA Issued Leaf", false,
        non_ca.get(), non_ca_key.get());
    auto path_root_key = key();
    auto path_root = make_x509(path_root_key.get(), 105, "Path Length Root", true,
        nullptr, nullptr, -60, EVP_sha256(), nullptr, 86400, 0, 1);
    auto intermediate_key = key();
    auto intermediate = make_x509(intermediate_key.get(), 106, "Intermediate", true,
        path_root.get(), path_root_key.get(), -60, EVP_sha256(), nullptr, 86400, -1, 1);
    auto path_leaf_key = key();
    auto path_leaf = make_x509(path_leaf_key.get(), 107, "Path Length Leaf", false,
        intermediate.get(), intermediate_key.get());
    auto missing_key = key();
    auto missing_issuer = make_x509(missing_key.get(), 108, "Missing Issuer", true);
    auto partial_leaf_key = key();
    auto partial_leaf = make_x509(partial_leaf_key.get(), 109, "Partial Leaf", false,
        missing_issuer.get(), missing_key.get());
    auto no_sign_ca_key = key();
    auto no_sign_ca = make_x509(no_sign_ca_key.get(), 110, "No Certificate Sign CA", true,
        nullptr, nullptr, -60, EVP_sha256(), nullptr, 86400, -1, 0);
    auto no_sign_leaf_key = key();
    auto no_sign_leaf = make_x509(no_sign_leaf_key.get(), 111, "No Certificate Sign Leaf", false,
        no_sign_ca.get(), no_sign_ca_key.get());
    auto valid_root_key = key();
    auto valid_root = make_x509(valid_root_key.get(), 112, "Valid Trusted Root", true,
        nullptr, nullptr, -60, EVP_sha256(), nullptr, 86400, -1, 1);
    auto signature_root_key = key();
    auto signature_root = make_x509(signature_root_key.get(), 113, "Signature Root", true,
        nullptr, nullptr, -60, EVP_sha256(), nullptr, 86400, -1, 1);
    auto wrong_signing_key = key();
    auto invalid_signature_leaf_key = key();
    auto invalid_signature_leaf = make_x509(invalid_signature_leaf_key.get(), 114,
        "Invalid Signature Leaf", false, signature_root.get(), wrong_signing_key.get());

    std::string trusted_bundle;
    for (auto* certificate : {expired_trusted.get(), non_ca.get(), path_root.get(),
        no_sign_ca.get(), valid_root.get(), signature_root.get()})
        trusted_bundle += pem(certificate);
    write_file(system / "etc/ssl/certs/ca-certificates.crt", trusted_bundle);
    auto user = (temp.path / "user").string();
    auto machine = (temp.path / "machine").string();
    auto root = system.string();
    SYS_CERT_STORE_CONFIGURATION configuration{
        sizeof(configuration), user.c_str(), machine.c_str(), root.c_str()};
    CHECK(SysCertConfigureSystemStores(&configuration));
    {
        Certificate context(create(der(expired_untrusted.get())));
        Chain chain(build_chain(context.value));
        CHECK(chain.value->TrustStatus.dwErrorStatus ==
            (CERT_TRUST_IS_NOT_TIME_VALID | CERT_TRUST_IS_UNTRUSTED_ROOT));
        auto policy = verify_base_policy(chain.value);
        CHECK(policy.dwError == CERT_E_UNTRUSTEDROOT && policy.lChainIndex == 0 &&
            policy.lElementIndex == 0);
    }
    {
        Certificate context(create(der(expired_trusted.get())));
        Chain chain(build_chain(context.value));
        CHECK(chain.value->TrustStatus.dwErrorStatus == CERT_TRUST_IS_NOT_TIME_VALID);
        auto policy = verify_base_policy(chain.value);
        CHECK(policy.dwError == CERT_E_EXPIRED && policy.lElementIndex == 0);
    }
    {
        Store candidates(memory());
        Certificate issuer(create(der(non_ca.get())));
        Certificate added(add(candidates.value, issuer.value));
        Certificate leaf(create(der(non_ca_leaf.get())));
        Chain chain(build_chain(leaf.value, candidates.value));
        auto* simple = chain.value->rgpChain[0];
        CHECK(simple->TrustStatus.dwErrorStatus ==
            (CERT_TRUST_IS_NOT_VALID_FOR_USAGE | CERT_TRUST_INVALID_BASIC_CONSTRAINTS));
        CHECK(simple->rgpElement[1]->TrustStatus.dwErrorStatus ==
            (CERT_TRUST_IS_NOT_VALID_FOR_USAGE | CERT_TRUST_INVALID_BASIC_CONSTRAINTS));
        auto policy = verify_base_policy(chain.value);
        CHECK(policy.dwError == CERT_E_WRONG_USAGE && policy.lElementIndex == 1);
    }
    {
        Store candidates(memory());
        Certificate issuer(create(der(no_sign_ca.get())));
        Certificate added(add(candidates.value, issuer.value));
        Certificate leaf(create(der(no_sign_leaf.get())));
        Chain chain(build_chain(leaf.value, candidates.value));
        CHECK(chain.value->TrustStatus.dwErrorStatus == CERT_TRUST_IS_NOT_VALID_FOR_USAGE);
        auto policy = verify_base_policy(chain.value);
        CHECK(policy.dwError == CERT_E_WRONG_USAGE && policy.lElementIndex == 1);
    }
    {
        Store candidates(memory());
        Certificate issuer(create(der(intermediate.get())));
        Certificate added(add(candidates.value, issuer.value));
        Certificate leaf(create(der(path_leaf.get())));
        Chain chain(build_chain(leaf.value, candidates.value));
        CHECK(chain.value->TrustStatus.dwErrorStatus == CERT_TRUST_INVALID_BASIC_CONSTRAINTS);
        CHECK(chain.value->rgpChain[0]->rgpElement[2]->TrustStatus.dwErrorStatus ==
            CERT_TRUST_INVALID_BASIC_CONSTRAINTS);
        auto policy = verify_base_policy(chain.value);
        CHECK(policy.dwError == TRUST_E_BASIC_CONSTRAINTS && policy.lElementIndex == 2);
    }
    {
        Store candidates(memory());
        Certificate issuer(create(der(signature_root.get())));
        Certificate added(add(candidates.value, issuer.value));
        Certificate leaf(create(der(invalid_signature_leaf.get())));
        Chain chain(build_chain(leaf.value, candidates.value));
        CHECK(chain.value->TrustStatus.dwErrorStatus == CERT_TRUST_IS_NOT_SIGNATURE_VALID);
        CHECK(chain.value->rgpChain[0]->rgpElement[0]->TrustStatus.dwErrorStatus ==
            CERT_TRUST_IS_NOT_SIGNATURE_VALID);
        auto policy = verify_base_policy(chain.value);
        CHECK(policy.dwError == TRUST_E_CERT_SIGNATURE && policy.lElementIndex == 0);
    }
    {
        Certificate context(create(der(valid_root.get())));
        Chain chain(build_chain(context.value));
        CHECK(chain.value->TrustStatus.dwErrorStatus == 0);
        CHECK(chain.value->TrustStatus.dwInfoStatus == CERT_TRUST_IS_SELF_SIGNED);
        auto policy = verify_base_policy(chain.value);
        CHECK(policy.dwError == ERROR_SUCCESS && policy.lChainIndex == -1 &&
            policy.lElementIndex == -1);
    }
    {
        Certificate context(create(der(partial_leaf.get())));
        Chain chain(build_chain(context.value));
        CHECK(chain.value->TrustStatus.dwErrorStatus == CERT_TRUST_IS_PARTIAL_CHAIN);
        auto policy = verify_base_policy(chain.value);
        CHECK(policy.dwError == CERT_E_CHAINING && policy.lChainIndex == 0 &&
            policy.lElementIndex == -1);
    }
    {
        auto* context = create(der(valid_root.get()));
        CHECK(context);
        auto* chain = build_chain(context);
        CHECK(CertFreeCertificateContext(context));
        CHECK(chain->rgpChain[0]->rgpElement[0]->pCertContext->cbCertEncoded ==
            der(valid_root.get()).size());
        CertFreeCertificateChain(chain);
    }
    {
        Certificate context(create(der(valid_root.get())));
        CERT_CHAIN_PARA parameters{};
        parameters.cbSize = sizeof(parameters);
        parameters.dwUrlRetrievalTimeout = 1;
        PCCERT_CHAIN_CONTEXT chain = nullptr;
        CHECK(!CertGetCertificateChain(nullptr, context.value, nullptr, nullptr,
            &parameters, 0, nullptr, &chain));
        CHECK(GetLastError() == ERROR_NOT_SUPPORTED && !chain);
        CERT_CHAIN_POLICY_PARA policy_parameters{};
        policy_parameters.cbSize = sizeof(policy_parameters);
        CERT_CHAIN_POLICY_STATUS status{};
        status.cbSize = sizeof(status);
        CHECK(!CertVerifyCertificateChainPolicy(reinterpret_cast<LPCSTR>(2),
            nullptr, &policy_parameters, &status));
        CHECK(GetLastError() == E_INVALIDARG);
    }
    CertFreeCertificateChain(nullptr);
    CHECK(SysCertConfigureSystemStores(nullptr));
}

void dotnet_crl_cache_tests() {
    TempDir temp;
    auto issuer_key = key();
    auto leaf_key = key();
    auto issuer = make_x509(issuer_key.get(), 201, "CRL Cache Root", true);
    HttpServer server;
    auto url = "http://127.0.0.1:" + std::to_string(server.port) + "/issuer.crl";
    auto leaf = make_x509(leaf_key.get(), 202, "CRL Cache Leaf", false,
        issuer.get(), issuer_key.get(), -60, EVP_sha256(), url.c_str());
    auto crl = make_crl(issuer.get(), issuer_key.get());
    server.start(crl_der(crl.get()), true);

    auto user_store = (temp.path / "user-store").string();
    auto machine_store = (temp.path / "machine-store").string();
    auto system = (temp.path / "system").string();
    write_file(std::filesystem::path(system) / "etc/os-release", "ID=ubuntu\n");
    write_file(std::filesystem::path(system) / "etc/ssl/certs/ca-certificates.crt",
        pem(issuer.get()));
    SYS_CERT_STORE_CONFIGURATION configuration{
        sizeof(configuration), user_store.c_str(), machine_store.c_str(), system.c_str()};
    CHECK(SysCertConfigureSystemStores(&configuration));
    {
        Store personal(scoped(L"MY", CERT_SYSTEM_STORE_CURRENT_USER));
        Certificate context(create(der(leaf.get())));
        Certificate added(add(personal.value, context.value));
    }

    auto home = temp.path / "home";
    std::filesystem::create_directory(home);
    EnvironmentVariable home_variable("HOME", home.string());
    EnvironmentVariable no_proxy("no_proxy", "127.0.0.1,localhost");
    EnvironmentVariable no_proxy_upper("NO_PROXY", "127.0.0.1,localhost");
    auto* account = getpwuid(geteuid());
    CHECK(account && account->pw_name);
    std::string account_name(account->pw_name);
    std::atomic<bool> populate_result{false};
    std::thread populate([&] {
        populate_result = SysCertPopulateDotNetCrlCache(account_name.c_str()) != FALSE;
    });
    bool request_received = server.wait_for_request();
    std::atomic<bool> operation_result{false};
    std::atomic<bool> operation_finished{false};
    std::thread operation([&] {
        auto handle = memory();
        operation_result = handle && CertCloseStore(handle, 0);
        operation_finished = true;
    });
    bool operation_was_concurrent = wait_for_flag(
        operation_finished, std::chrono::seconds(2));
    bool response_released = server.release_response();
    populate.join();
    operation.join();
    server.wait();
    CHECK(request_received && response_released && operation_was_concurrent &&
        operation_result && populate_result);

    std::vector<unsigned char> utf16;
    for (auto byte : url) {
        utf16.push_back(static_cast<unsigned char>(byte));
        utf16.push_back(0);
    }
    std::array<unsigned char, EVP_MAX_MD_SIZE> digest{};
    unsigned digest_size = 0;
    CHECK(EVP_Digest(utf16.data(), utf16.size(), digest.data(), &digest_size,
        EVP_sha256(), nullptr) == 1 && digest_size >= 4);
    std::uint32_t url_hash = static_cast<std::uint32_t>(digest[0]) |
        (static_cast<std::uint32_t>(digest[1]) << 8) |
        (static_cast<std::uint32_t>(digest[2]) << 16) |
        (static_cast<std::uint32_t>(digest[3]) << 24);
    std::ostringstream filename;
    filename << std::hex << std::setfill('0') << std::nouppercase
        << std::setw(8) << (X509_issuer_name_hash(leaf.get()) & 0xffffffffUL)
        << '.' << std::setw(8) << url_hash << ".crl";
    auto directory = home / ".dotnet/corefx/cryptography/crls";
    auto cache_file = directory / filename.str();
    CHECK(std::filesystem::is_regular_file(cache_file));
    struct stat status{};
    CHECK(stat(directory.c_str(), &status) == 0 && (status.st_mode & 0777) == 0700);
    CHECK(stat(cache_file.c_str(), &status) == 0 && (status.st_mode & 0777) == 0600);
    auto close_file = [](FILE* file) { std::fclose(file); };
    std::unique_ptr<FILE, decltype(close_file)> input(std::fopen(cache_file.c_str(), "rb"), close_file);
    CHECK(input);
    std::unique_ptr<X509_CRL, decltype(&X509_CRL_free)> cached(
        PEM_read_X509_CRL(input.get(), nullptr, nullptr, nullptr), X509_CRL_free);
    CHECK(cached && X509_CRL_cmp(cached.get(), crl.get()) == 0);
    CHECK(SysCertConfigureSystemStores(nullptr));

    const char invalid_name[] = {static_cast<char>(0xff), '\0'};
    CHECK(!SysCertPopulateDotNetCrlCache(invalid_name));
    CHECK(GetLastError() == E_INVALIDARG);
}

void certutil_tests(const char* executable, const char* algorithm = nullptr) {
    TempDir temp;
    auto user = (temp.path / "user").string();
    auto machine = (temp.path / "machine").string();
    auto system = (temp.path / "system").string();
    auto log = (temp.path / "command.log").string();
    const EVP_MD* digest = algorithm ? nullptr : EVP_sha256();
    auto ca_key = signing_key(algorithm);
    auto ca = make_x509(ca_key.get(), 100, "Tool Root", true, nullptr, nullptr, -60, digest);
    auto leaf_key = signing_key(algorithm);
    auto leaf = make_x509(leaf_key.get(), 101, "Tool Leaf", false, ca.get(), ca_key.get(), -60, digest);
    auto leaf_der = der(leaf.get());
    std::string leaf_binary(leaf_der.begin(), leaf_der.end());
    auto other = make_x509(leaf_key.get(), 102, "Tool Leaf", false, ca.get(), ca_key.get(), -60, digest);
    auto native_bundle = std::filesystem::path(system) / "etc/ssl/certs/ca-certificates.crt";
    write_file(std::filesystem::path(system) / "etc/os-release", "ID=ubuntu\n");
    write_file(native_bundle, pem(ca.get()));
    auto root_file = (temp.path / "root.pem").string();
    auto leaf_file = (temp.path / "leaf.pem").string();
    auto other_file = (temp.path / "other.der").string();
    auto bundle_file = (temp.path / "bundle.pem").string();
    auto pfx_file = (temp.path / "leaf.pfx").string();
    auto password_file = (temp.path / "password").string();
    auto output_file = (temp.path / "output.der").string();
    write_file(root_file, pem(ca.get()));
    write_file(leaf_file, pem(leaf.get()));
    auto encoded = der(other.get());
    write_file(other_file, std::string(encoded.begin(), encoded.end()));
    write_file(bundle_file, pem(ca.get()) + pem(leaf.get()));
    encoded = pfx_bytes(leaf.get(), leaf_key.get());
    write_file(pfx_file, std::string(encoded.begin(), encoded.end()));
    write_file(password_file, "password\n");
    CHECK(chmod(password_file.c_str(), 0600) == 0);
    auto run = [&](std::vector<std::string> arguments, int expected = 0) {
        std::vector<std::string> command{executable, "--user-store-dir", user, "--machine-store-dir", machine,
            "--system-root", system};
        command.insert(command.end(), arguments.begin(), arguments.end());
        std::vector<char*> argv;
        for (auto& argument : command) argv.push_back(argument.data());
        argv.push_back(nullptr);
        pid_t child = fork();
        CHECK(child >= 0);
        if (child == 0) {
            int output = open(log.c_str(), O_WRONLY | O_CREAT | O_TRUNC, 0600);
            int input = open("/dev/null", O_RDONLY);
            if (output < 0 || input < 0 || dup2(output, STDOUT_FILENO) < 0 ||
                dup2(output, STDERR_FILENO) < 0 || dup2(input, STDIN_FILENO) < 0) _exit(126);
            close(output);
            close(input);
            execv(executable, argv.data());
            _exit(127);
        }
        int status = 0;
        CHECK(waitpid(child, &status, 0) == child);
        auto output = read_file(log);
        if (!WIFEXITED(status) || WEXITSTATUS(status) != expected) {
            std::cerr << "certutil command:";
            for (const auto& arg : arguments) std::cerr << ' ' << arg;
            std::cerr << "\n" << output << '\n';
            CHECK(WIFEXITED(status) && WEXITSTATUS(status) == expected);
        }
        return output;
    };
    CHECK(run({"-?"}).find("not NSS certutil") != std::string::npos);
    CHECK(run({"-enumstore"}).find("ROOT") != std::string::npos);
    CHECK(!std::filesystem::exists(user) && !std::filesystem::exists(machine));
    CHECK(run({"-store", "MY"}).find("0 certificate(s)") != std::string::npos);
    CHECK(!std::filesystem::exists(machine));
    CHECK(run({"-dump", leaf_file, "-v"}).find("Tool Leaf") != std::string::npos);
    CHECK(run({other_file}).find("Serial Number: 66") != std::string::npos);
    CHECK(run({"-dump", bundle_file}).find("Certificate 1") != std::string::npos);
    run({"-unknown"}, 2);
    run({"-store", "MY", "--format", "pem"}, 2);
    run({"-store", "-p"}, 2);
    run({"-user", "-machine", "-store"}, 2);
    run({"-user", "--allow-native-write", "-addstore", "ROOT", root_file}, 2);
    run({"-addstore", "ROOT", leaf_file}, 2);
    CHECK(read_file(native_bundle) == pem(ca.get()));

    run({"-user", "-addstore", "MY", leaf_file});
    CHECK(run({"-store", "MY"}).find("0 certificate(s)") != std::string::npos);
    auto shown = run({"-user", "-store", "MY"});
    CHECK(shown.find("CurrentUser") != std::string::npos && shown.find("Tool Leaf") != std::string::npos);
    const std::string hash_marker = "Cert Hash(sha256): ";
    auto hash_start = shown.find(hash_marker);
    CHECK(hash_start != std::string::npos);
    auto hash = shown.substr(hash_start + hash_marker.size(), 64);
    run({"-user", "-store", "MY", "sha256:" + hash, output_file});
    CHECK(read_file(output_file) == leaf_binary);
    run({"-user", "-store", "MY", "serial:65", output_file}, 1);
    run({"-user", "-f", "-store", "MY", "serial:65", output_file});
    run({"-user", "-exportPFX", "MY", "serial:65", (temp.path / "no-key.pfx").string(), "NoChain",
        "--password-file", password_file}, 1);
    CHECK(!std::filesystem::exists(temp.path / "no-key.pfx"));
    run({"-user", "-addstore", "MY", leaf_file}, 1);
    run({"-user", "-f", "-addstore", "MY", leaf_file});
    run({"-user", "-addstore", "MY", other_file});
    run({"-user", "-delstore", "MY", "subject:Tool Leaf"}, 1);
    run({"-user", "-store", "MY", "*", output_file, "-f"}, 1);
    run({"-user", "-delstore", "MY", "serial:66"});
    run({"-user", "-store", "MY", "serial:66"}, 1);

    auto malformed = (temp.path / "malformed.pem").string();
    write_file(malformed, pem(ca.get()) + "-----BEGIN PRIVATE KEY-----\nnot a certificate\n");
    run({"-user", "-addstore", "CA", malformed}, 1);
    CHECK(run({"-user", "-store", "CA"}).find("0 certificate(s)") != std::string::npos);
    auto trailing = (temp.path / "trailing.der").string();
    write_file(trailing, read_file(other_file) + "trailing garbage");
    run({"-dump", trailing}, 1);
    run({"-addstore", "CA", root_file});
    CHECK(run({"-user", "-store", "CA"}).find("inherited, read-only") != std::string::npos);
    run({"-user", "-delstore", "CA", "index:0"}, 1);
    run({"-user", "-addstore", "ROOT", leaf_file});
    CHECK(run({"-user", "-store", "ROOT"}).find("2 certificate(s)") != std::string::npos);
    CHECK(read_file(native_bundle) == pem(ca.get()));
    run({"-user", "-delstore", "ROOT", "serial:65"});
    run({"-user", "-delstore", "ROOT", "serial:64"}, 1);

    run({"-user", "-addstore", "BUNDLE", bundle_file});
    auto public_bundle = (temp.path / "export.p7b").string();
    run({"-user", "-store", "BUNDLE", "*", public_bundle, "--format", "pkcs7"});
    CHECK(run({"-dump", public_bundle}).find("Certificate 1") != std::string::npos);
    run({"-user", "-addstore", "COPY", public_bundle});
    CHECK(run({"-user", "-store", "COPY"}).find("2 certificate(s)") != std::string::npos);
    auto public_pem = (temp.path / "export.pem").string();
    run({"-user", "-store", "COPY", "*", public_pem, "--format", "pem"});
    CHECK(read_file(public_pem) == read_file(bundle_file));
    auto link = temp.path / "output-link";
    std::filesystem::create_symlink(output_file, link);
    run({"-user", "-f", "-store", "MY", "index:0", link.string()}, 1);
    CHECK(read_file(output_file) == leaf_binary);

    run({"-user", "-delstore", "MY", "serial:65"});
    run({"-user", "-importPFX", pfx_file}, 1);
    run({"-user", "-importPFX", pfx_file, "-p", "wrong"}, 1);
    CHECK(run({"-user", "-store", "MY"}).find("0 certificate(s)") != std::string::npos);
    run({"-user", "-importPFX", pfx_file, "--password-file", password_file});
    CHECK(run({"-user", "-store", "MY"}).find("1 certificate(s)") != std::string::npos);
    auto exported_pfx = (temp.path / "export.pfx").string();
    run({"-user", "-exportPFX", "serial:65", exported_pfx, "--password-file", password_file});
    struct stat status{};
    CHECK(stat(exported_pfx.c_str(), &status) == 0 && (status.st_mode & 0777) == 0600);
    auto pfx_data = read_file(exported_pfx);
    const BYTE* cursor = reinterpret_cast<const BYTE*>(pfx_data.data());
    std::unique_ptr<PKCS12, decltype(&PKCS12_free)> pfx(d2i_PKCS12(nullptr, &cursor, static_cast<long>(pfx_data.size())), PKCS12_free);
    CHECK(pfx && PKCS12_verify_mac(pfx.get(), "password", -1) == 1);
    EVP_PKEY* raw_key = nullptr;
    X509* raw_certificate = nullptr;
    STACK_OF(X509)* raw_chain = nullptr;
    CHECK(PKCS12_parse(pfx.get(), "password", &raw_key, &raw_certificate, &raw_chain) == 1);
    Key imported_key(raw_key, EVP_PKEY_free);
    X509Handle imported_certificate(raw_certificate, X509_free);
    auto free_chain = [](STACK_OF(X509)* value) { sk_X509_pop_free(value, X509_free); };
    std::unique_ptr<STACK_OF(X509), decltype(free_chain)> imported_chain(raw_chain, free_chain);
    CHECK(imported_key && EVP_PKEY_eq(imported_key.get(), leaf_key.get()) == 1);
    CHECK(imported_certificate && X509_cmp(imported_certificate.get(), leaf.get()) == 0);
    CHECK(sk_X509_num(imported_chain.get()) == 1 && X509_cmp(sk_X509_value(imported_chain.get(), 0), ca.get()) == 0);
    run({"-user", "-exportPFX", "serial:65", exported_pfx, "--password-file", password_file}, 1);
    run({"-user", "-exportPFX", "serial:65", exported_pfx, "NoChain", "-f", "-p", "different"});
    run({"-importPFX", "MY", exported_pfx, "-p", "different"});
    CHECK(run({"-store", "MY"}).find("LocalMachine") != std::string::npos);
    run({"-user", "-importPFX", "RESTORED", exported_pfx, "-p", "different"});
    CHECK(run({"-user", "-store", "RESTORED"}).find("1 certificate(s)") != std::string::npos);
    run({"-user", "-exportPFX", "serial:65", exported_pfx, "NoRoot", "-f", "-p", "different"});
    run({"-user", "-importPFX", "NO_ROOT", exported_pfx, "-p", "different"});
    CHECK(run({"-user", "-store", "NO_ROOT"}).find("1 certificate(s)") != std::string::npos);
    run({"-user", "-exportPFX", "serial:65", exported_pfx, "NoChain", "-f", "-p", ""}, 2);
    CHECK(chmod(password_file.c_str(), 0644) == 0);
    run({"-user", "-importPFX", pfx_file, "--password-file", password_file}, 1);
    CHECK(chmod(password_file.c_str(), 0600) == 0);
    auto orphan_key = signing_key(algorithm);
    auto orphan = make_x509(orphan_key.get(), 103, "Orphan", false, other.get(), leaf_key.get(), -60, digest);
    encoded = pfx_bytes(orphan.get(), orphan_key.get());
    auto orphan_pfx = (temp.path / "orphan.pfx").string();
    write_file(orphan_pfx, std::string(encoded.begin(), encoded.end()));
    run({"-user", "-importPFX", "ORPHAN", orphan_pfx, "--password-file", password_file});
    run({"-user", "-exportPFX", "ORPHAN", "index:0", exported_pfx, "-f", "--password-file", password_file}, 1);
    run({"-user", "-exportPFX", "ORPHAN", "index:0", exported_pfx, "NoChain", "-f", "--password-file", password_file});

    auto extra_root = make_x509(ca_key.get(), 104, "Extra Root", true, nullptr, nullptr, -60, digest);
    auto extra_file = (temp.path / "extra.pem").string();
    write_file(extra_file, pem(extra_root.get()));
    auto anchors = std::filesystem::path(system) / "usr/local/share/ca-certificates";
    std::filesystem::create_directories(anchors);
    auto updater = std::filesystem::path(system) / "usr/sbin/update-ca-certificates";
    write_file(updater, "#!/bin/sh\ncat '" + root_file + "' '" + anchors.string() + "'/*.crt > '" + native_bundle.string() + "'\n");
    CHECK(chmod(updater.c_str(), 0700) == 0);
    run({"--allow-native-write", "-addstore", "ROOT", extra_file});
    CHECK(run({"-store", "ROOT"}).find("Extra Root") != std::string::npos);
    write_file(updater, "#!/bin/sh\ncat '" + root_file + "' > '" + native_bundle.string() + "'\n");
    run({"--allow-native-write", "-delstore", "ROOT", "serial:68"});
    CHECK(read_file(native_bundle) == pem(ca.get()));
    for (const auto& entry : std::filesystem::directory_iterator(temp.path))
        CHECK(!entry.path().filename().string().starts_with(".certutil-"));
}

void pqc_tests() {
    CHECK(OPENSSL_VERSION_MAJOR == 3 && OPENSSL_VERSION_MINOR >= 5);
    CHECK(std::strcmp(OpenSSL_version(OPENSSL_VERSION), OPENSSL_VERSION_TEXT) == 0);
    CHECK(!OSSL_PROVIDER_available(nullptr, "composite"));
    std::unique_ptr<EVP_MD, decltype(&EVP_MD_free)> digest(
        EVP_MD_fetch(nullptr, "SHA256", nullptr), EVP_MD_free);
    CHECK(digest && std::strcmp(OSSL_PROVIDER_get0_name(EVP_MD_get0_provider(digest.get())), "symcryptprovider") == 0);
    std::unique_ptr<EVP_CIPHER, decltype(&EVP_CIPHER_free)> cipher(
        EVP_CIPHER_fetch(nullptr, "AES-256-CBC", nullptr), EVP_CIPHER_free);
    CHECK(cipher && std::strcmp(OSSL_PROVIDER_get0_name(EVP_CIPHER_get0_provider(cipher.get())), "symcryptprovider") == 0);
    auto* random = RAND_get0_private(nullptr);
    CHECK(random && std::strcmp(OSSL_PROVIDER_get0_name(
        EVP_RAND_get0_provider(EVP_RAND_CTX_get0_rand(random))), "symcryptprovider") == 0);
    std::unique_ptr<EVP_MD, decltype(&EVP_MD_free)> fips_digest(
        EVP_MD_fetch(nullptr, "SHA256", "provider=symcryptprovider,fips=yes"), EVP_MD_free);
    CHECK(!fips_digest);
    ERR_clear_error();
    for (const char* unsupported : {"MLDSA65-ECDSA-brainpoolP256r1-SHA512",
            "MLDSA87-ECDSA-brainpoolP384r1-SHA512", "MLDSA87-ECDSA-P521-SHA512",
            "1.3.6.1.5.5.7.6.47", "1.3.6.1.5.5.7.6.50", "1.3.6.1.5.5.7.6.54"}) {
        std::unique_ptr<EVP_PKEY_CTX, decltype(&EVP_PKEY_CTX_free)> context(
            EVP_PKEY_CTX_new_from_name(nullptr, unsupported, nullptr), EVP_PKEY_CTX_free);
        CHECK(!context);
        ERR_clear_error();
    }
    struct Algorithm { const char* name; const char* oid; };
    const Algorithm algorithms[] = {
        {"ML-DSA-44", "2.16.840.1.101.3.4.3.17"},
        {"ML-DSA-65", "2.16.840.1.101.3.4.3.18"},
        {"ML-DSA-87", "2.16.840.1.101.3.4.3.19"},
        {"MLDSA44-ECDSA-P256-SHA256", "1.3.6.1.5.5.7.6.40"},
        {"MLDSA65-ECDSA-P256-SHA512", "1.3.6.1.5.5.7.6.45"},
        {"MLDSA65-ECDSA-P384-SHA512", "1.3.6.1.5.5.7.6.46"},
        {"MLDSA87-ECDSA-P384-SHA512", "1.3.6.1.5.5.7.6.49"},
    };
    for (const auto& algorithm : algorithms) {
        std::cout << "PQC: " << algorithm.name << std::endl;
        TempDir temp;
        auto issuer_key = signing_key(algorithm.name);
        auto subject_key = signing_key(algorithm.name);
        auto root = make_x509(issuer_key.get(), 1, "PQC Root", true, nullptr, nullptr, -60, nullptr);
        auto leaf = make_x509(subject_key.get(), 2, "PQC Leaf", false, root.get(), issuer_key.get(), -60, nullptr);
        CHECK(X509_verify(root.get(), issuer_key.get()) == 1);
        CHECK(X509_verify(leaf.get(), issuer_key.get()) == 1);
        CHECK(X509_verify(leaf.get(), subject_key.get()) != 1);
        ERR_clear_error();
        auto check_algorithm = [&](const X509_ALGOR* value) {
            const ASN1_OBJECT* object = nullptr;
            int parameter_type = 0;
            X509_ALGOR_get0(&object, &parameter_type, nullptr, value);
            std::array<char, 100> oid{};
            CHECK(OBJ_obj2txt(oid.data(), static_cast<int>(oid.size()), object, 1) > 0);
            CHECK(std::string(oid.data()) == algorithm.oid && parameter_type == V_ASN1_UNDEF);
        };
        X509_ALGOR* public_algorithm = nullptr;
        CHECK(X509_PUBKEY_get0_param(nullptr, nullptr, nullptr, &public_algorithm, X509_get_X509_PUBKEY(leaf.get())) == 1);
        check_algorithm(public_algorithm);
        check_algorithm(X509_get0_tbs_sigalg(leaf.get()));
        const ASN1_BIT_STRING* signature = nullptr;
        const X509_ALGOR* outer_algorithm = nullptr;
        X509_get0_signature(&signature, &outer_algorithm, leaf.get());
        check_algorithm(outer_algorithm);
        CHECK(signature && ASN1_STRING_length(signature) > 2000);

        Store memory_store(memory());
        Certificate root_context(create(der(root.get())));
        Certificate added_root(add(memory_store.value, root_context.value));
        auto leaf_der = der(leaf.get());
        Certificate leaf_context(create(leaf_der));
        DWORD flags = CERT_STORE_SIGNATURE_FLAG;
        Certificate issuer(CertGetIssuerCertificateFromStore(memory_store.value, leaf_context.value, nullptr, &flags));
        CHECK(flags == 0);
        // Composite signatures concatenate ML-DSA then ECDSA. Corrupt both ends
        // independently to ensure verification requires both components.
        auto signature_size = static_cast<std::size_t>(ASN1_STRING_length(signature));
        for (auto offset : {leaf_der.size() - signature_size, leaf_der.size() - 1}) {
            auto corrupt = leaf_der;
            corrupt[offset] ^= 1;
            const BYTE* cursor = corrupt.data();
            X509Handle broken(d2i_X509(nullptr, &cursor, static_cast<long>(corrupt.size())), X509_free);
            CHECK(broken && X509_verify(broken.get(), issuer_key.get()) != 1);
            ERR_clear_error();
            Certificate broken_context(create(corrupt));
            flags = CERT_STORE_SIGNATURE_FLAG;
            Certificate found(CertGetIssuerCertificateFromStore(memory_store.value, broken_context.value, nullptr, &flags));
            CHECK(flags == CERT_STORE_SIGNATURE_FLAG);
        }
        auto encoded_pfx = pfx_bytes(leaf.get(), subject_key.get());
        CRYPT_DATA_BLOB blob{static_cast<DWORD>(encoded_pfx.size()), encoded_pfx.data()};
        auto database = (temp.path / "PQC.db").string();
        {
            Store persistent(CertOpenStore(SYS_CERT_STORE_PROV_SQLITE, 0, 0, 0, database.c_str()));
            CHECK(SysCertImportPfxToStore(persistent.value, &blob, L"password", 0));
        }
        Store reopened(CertOpenStore(SYS_CERT_STORE_PROV_SQLITE, 0, 0, CERT_STORE_OPEN_EXISTING_FLAG, database.c_str()));
        Certificate stored(CertEnumCertificatesInStore(reopened.value, nullptr));
        CHECK(std::strcmp(stored.value->pCertInfo->SubjectPublicKeyInfo.Algorithm.pszObjId, algorithm.oid) == 0);
        CHECK(Bytes(stored.value->pbCertEncoded, stored.value->pbCertEncoded + stored.value->cbCertEncoded) == leaf_der);
        CHECK(read_file(material_path(stored.value)) == pem(leaf.get()));
        auto private_path = material_path(stored.value, TRUE);
        auto close_file = [](FILE* file) { std::fclose(file); };
        std::unique_ptr<FILE, decltype(close_file)> input(std::fopen(private_path.c_str(), "rb"), close_file);
        CHECK(input);
        Key recovered(PEM_read_PrivateKey(input.get(), nullptr, nullptr, nullptr), EVP_PKEY_free);
        CHECK(recovered && EVP_PKEY_eq(recovered.get(), subject_key.get()) == 1);
        CHECK(std::strcmp(OSSL_PROVIDER_get0_name(EVP_PKEY_get0_provider(recovered.get())), "symcryptprovider") == 0);
        auto signed_again = make_x509(recovered.get(), 3, "Reloaded PQC", true, nullptr, nullptr, -60, nullptr);
        CHECK(X509_verify(signed_again.get(), subject_key.get()) == 1);
        CHECK(CertDeleteCertificateFromStore(CertDuplicateCertificateContext(stored.value)));
        CHECK(!std::filesystem::exists(private_path) && enumerate(reopened.value) == 0);
    }
}
void interop_tests(const char* directory) {
    for (const char* name : {"MLDSA44-ECDSA-P256-SHA256", "MLDSA65-ECDSA-P256-SHA512",
            "MLDSA65-ECDSA-P384-SHA512", "MLDSA87-ECDSA-P384-SHA512"}) {
        auto path = std::filesystem::path(directory) / name;
        auto public_bytes = read_file(path / "public.der");
        const BYTE* cursor = reinterpret_cast<const BYTE*>(public_bytes.data());
        Key public_key(d2i_PUBKEY(nullptr, &cursor, static_cast<long>(public_bytes.size())), EVP_PKEY_free);
        CHECK(public_key && cursor == reinterpret_cast<const BYTE*>(public_bytes.data()) + public_bytes.size());
        auto private_bytes = read_file(path / "private.der");
        cursor = reinterpret_cast<const BYTE*>(private_bytes.data());
        std::unique_ptr<PKCS8_PRIV_KEY_INFO, decltype(&PKCS8_PRIV_KEY_INFO_free)> info(
            d2i_PKCS8_PRIV_KEY_INFO(nullptr, &cursor, static_cast<long>(private_bytes.size())), PKCS8_PRIV_KEY_INFO_free);
        CHECK(info && cursor == reinterpret_cast<const BYTE*>(private_bytes.data()) + private_bytes.size());
        Key private_key(EVP_PKCS82PKEY(info.get()), EVP_PKEY_free);
        OPENSSL_cleanse(private_bytes.data(), private_bytes.size());
        CHECK(private_key && EVP_PKEY_eq(private_key.get(), public_key.get()) == 1);
        auto message = read_file(path / "message.bin");
        auto signature = read_file(path / "signature.bin");
        std::unique_ptr<EVP_MD_CTX, decltype(&EVP_MD_CTX_free)> context(EVP_MD_CTX_new(), EVP_MD_CTX_free);
        CHECK(context && EVP_DigestVerifyInit(context.get(), nullptr, nullptr, nullptr, public_key.get()) == 1);
        CHECK(EVP_DigestVerifyUpdate(context.get(), message.data(), message.size()) == 1);
        CHECK(EVP_DigestVerifyFinal(context.get(), reinterpret_cast<const BYTE*>(signature.data()), signature.size()) == 1);
        auto certificate = make_x509(private_key.get(), 1, "Composite interoperability", true, nullptr, nullptr, -60, nullptr);
        auto encoded = der(certificate.get());
        Certificate parsed(create(encoded));
        CHECK(parsed.value->cbCertEncoded == encoded.size());
        write_file(path / "certificate.der", std::string(encoded.begin(), encoded.end()));
        std::cout << "interop: " << name << '\n';
    }
}
}

int main(int argc, char** argv) {
    try {
        scs::initialize_crypto();
        if (argc == 3 && std::string(argv[1]) == "--interop") {
            interop_tests(argv[2]);
            return 0;
        }
        if (argc == 2 && std::string(argv[1]) == "--pqc") {
            pqc_tests();
            return 0;
        }
        if (argc == 3 && std::string(argv[1]) == "--child-read") return child_read(argv[2]);
        if ((argc == 3 || argc == 4) && std::string(argv[1]) == "--certutil") {
            certutil_tests(argv[2], argc == 4 ? argv[3] : nullptr);
            std::cout << "All certutil tests passed\n";
            return 0;
        }
        memory_tests();
        disposition_tests();
        persistent_tests();
        pfx_tests();
        native_tests();
        native_api_tests();
        error_tests();
        thread_tests();
        system_scope_tests();
        chain_tests();
        dotnet_crl_cache_tests();
        std::cout << "All certificate-store tests passed\n";
        return 0;
    } catch (const std::exception& error) {
        std::cerr << error.what() << '\n';
        ERR_print_errors_fp(stderr);
        return 1;
    }
}
