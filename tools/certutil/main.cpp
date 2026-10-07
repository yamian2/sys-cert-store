#include <sys-cert-store/sys-cert-store.h>
#include "crypto.h"
#include <openssl/err.h>
#include <openssl/pem.h>
#include <openssl/pkcs12.h>
#include <openssl/x509v3.h>
#include <algorithm>
#include <array>
#include <cerrno>
#include <charconv>
#include <climits>
#include <cstdio>
#include <cstring>
#include <filesystem>
#include <fstream>
#include <iostream>
#include <map>
#include <memory>
#include <optional>
#include <set>
#include <sstream>
#include <stdexcept>
#include <string>
#include <string_view>
#include <vector>
#include <fcntl.h>
#include <sys/stat.h>
#include <unistd.h>

namespace {
using Bytes = std::vector<BYTE>;
using X509Ptr = std::unique_ptr<X509, decltype(&X509_free)>;
using BioPtr = std::unique_ptr<BIO, decltype(&BIO_free)>;
using PfxPtr = std::unique_ptr<PKCS12, decltype(&PKCS12_free)>;
using KeyPtr = std::unique_ptr<EVP_PKEY, decltype(&EVP_PKEY_free)>;
struct UsageError : std::runtime_error { using std::runtime_error::runtime_error; };
void require(bool condition, const std::string& message) {
    if (!condition) throw std::runtime_error(message);
}
void usage_require(bool condition, const std::string& message) {
    if (!condition) throw UsageError(message);
}
void api_check(bool condition, const char* operation) {
    if (!condition) {
        std::ostringstream message;
        message << operation << " failed (0x" << std::hex << GetLastError() << "): " << SysCertGetLastErrorMessage();
        throw std::runtime_error(message.str());
    }
}
struct Store {
    HCERTSTORE value;
    explicit Store(HCERTSTORE handle) : value(handle) { api_check(value, "Open store"); }
    ~Store() { CertCloseStore(value, 0); }
    Store(const Store&) = delete;
    Store& operator=(const Store&) = delete;
};
struct FreeContext { void operator()(PCCERT_CONTEXT context) const { CertFreeCertificateContext(context); } };
using ContextPtr = std::unique_ptr<const CERT_CONTEXT, FreeContext>;
struct Secret {
    std::string value;
    ~Secret() { OPENSSL_cleanse(value.data(), value.size()); }
};
struct WideSecret {
    std::wstring value;
    ~WideSecret() { OPENSSL_cleanse(value.data(), value.size() * sizeof(wchar_t)); }
};
struct Options {
    std::string command;
    std::vector<std::string> args;
    DWORD scope = CERT_SYSTEM_STORE_LOCAL_MACHINE;
    bool force = false, verbose = false, native_write = false, help = false;
    std::optional<std::string> format, password_file;
    const char* password = nullptr;
    const char* user_directory = nullptr;
    const char* machine_directory = nullptr;
    const char* system_root = nullptr;
};
std::string lower(std::string text) {
    for (auto& c : text) if (c >= 'A' && c <= 'Z') c = static_cast<char>(c + ('a' - 'A'));
    return text;
}
constexpr std::string_view help = R"(sys-cert-store certutil (Linux; not NSS certutil)
Usage: certutil [options] command [arguments]
  -enumstore                           List stores (ROOT, CA, MY and custom)
  -store [Store [CertId [OutFile]]]      Show certificates; default store CA
  -addstore Store InFile                Import PEM/DER certificates or PKCS#7
  -delstore Store CertId                Delete exactly one matching certificate
  -importPFX [Store] InFile             Import a PFX and its key; default MY
  -exportPFX [Store] CertId OutFile [NoChain|NoRoot]
                                       Export one key and certificate chain
  -dump InFile                         Show PEM/DER certificates or PKCS#7
  -? | --help                          Show this help

Options:
  -user | -machine                     User or computer scope (default computer)
  -f                                   Replace an addstore match or output file
  -v                                   Full certificate details for store/dump
  -p Password                          PFX password (visible in process arguments)
  --password-file File                 Read password from a private UTF-8 file
  --format der|pem|pkcs7                Format for -store OutFile (default DER)
  --allow-native-write                 Explicit permission for computer ROOT writes
  --user-store-dir Dir                  Relocate user metadata (absolute path)
  --machine-store-dir Dir               Relocate computer metadata (absolute path)
  --system-root Dir                    Relocate native trust paths, NOT a sandbox
  --                                   End options; remaining tokens are arguments

CertId: zero-based index, serial hex, SHA-1/SHA-256 hash, subject substring, or *.
Disambiguate with index:, serial:, sha1:, sha256:, or subject: prefixes.
Deletion and PFX export require one match. Inherited entries
are read-only. PEM/PKCS#7 exports may contain multiple public certificates.
PFX export requires a nonempty password and a complete offline issuer chain,
unless NoChain is specified. No trust/revocation validation or network fetching.
Without -p/--password-file, PFX commands prompt on a terminal (no echo).
Unknown commands, flags and modifiers fail; this is not full Windows certutil.
)";

Options parse_options(int argc, char** argv) {
    Options result;
    bool positional = false, scope_set = false;
    const std::set<std::string> commands{"-enumstore", "-store", "-addstore", "-delstore", "-importpfx", "-exportpfx", "-dump"};
    for (int i = 1; i < argc; ++i) {
        std::string token(argv[i]);
        auto name = lower(token);
        auto value = [&]() -> const char* {
            usage_require(i + 1 < argc, "Missing value for " + token);
            return argv[++i];
        };
        if (positional) result.args.push_back(token);
        else if (name == "--") positional = true;
        else if (name == "-?" || name == "--help" || name == "-h") result.help = true;
        else if (commands.contains(name)) {
            usage_require(result.command.empty(), "Specify exactly one command");
            result.command = name;
        } else if (name == "-user" || name == "-machine") {
            usage_require(!scope_set, "Specify scope only once");
            result.scope = name == "-user" ? CERT_SYSTEM_STORE_CURRENT_USER : CERT_SYSTEM_STORE_LOCAL_MACHINE;
            scope_set = true;
        } else if (name == "-f") result.force = true;
        else if (name == "-v") result.verbose = true;
        else if (name == "--allow-native-write") result.native_write = true;
        else if (name == "-p") {
            usage_require(!result.password && !result.password_file, "Specify one password source");
            result.password = value();
        } else if (name == "--password-file") {
            usage_require(!result.password && !result.password_file, "Specify one password source");
            result.password_file = value();
        } else if (name == "--format") result.format = lower(value());
        else if (name == "--user-store-dir") result.user_directory = value();
        else if (name == "--machine-store-dir") result.machine_directory = value();
        else if (name == "--system-root") result.system_root = value();
        else if (token.starts_with("-")) throw UsageError("Unsupported command or option: " + token);
        else result.args.push_back(token);
    }
    if (result.help || argc == 1) { result.help = true; return result; }
    if (result.command.empty() && result.args.size() == 1) result.command = "-dump";
    usage_require(!result.command.empty(), "Missing command; use -? for help");
    const auto& cmd = result.command;
    auto n = result.args.size();
    usage_require((cmd == "-enumstore" && n == 0) || (cmd == "-store" && n <= 3) ||
        ((cmd == "-addstore" || cmd == "-delstore") && n == 2) ||
        (cmd == "-importpfx" && n >= 1 && n <= 2) || (cmd == "-exportpfx" && n >= 2 && n <= 4) ||
        (cmd == "-dump" && n == 1), "Invalid arguments for " + cmd + "; use -? for syntax");
    usage_require(!result.format || (cmd == "-store" && n == 3), "--format requires -store with an output file");
    usage_require(!result.format || *result.format == "der" || *result.format == "pem" || *result.format == "pkcs7",
        "Unsupported output format");
    usage_require(!result.verbose || cmd == "-store" || cmd == "-dump", "-v requires -store or -dump");
    usage_require((!result.password && !result.password_file) || cmd == "-importpfx" || cmd == "-exportpfx",
        "Password options require a PFX command");
    usage_require(!result.force || cmd == "-addstore" || cmd == "-exportpfx" || (cmd == "-store" && n == 3),
        "-f is supported only for -addstore and output-file replacement");
    usage_require(!result.native_write || (result.scope == CERT_SYSTEM_STORE_LOCAL_MACHINE &&
        (cmd == "-addstore" || cmd == "-delstore") && lower(result.args[0]) == "root"),
        "--allow-native-write requires computer ROOT -addstore or -delstore");
    return result;
}

Bytes read_file(const std::filesystem::path& path) {
    std::ifstream file(path, std::ios::binary | std::ios::ate);
    require(file.good(), "Cannot open input file: " + path.string());
    auto size = file.tellg();
    require(size > 0 && size <= INT_MAX, "Input must contain 1..INT_MAX bytes: " + path.string());
    Bytes result(static_cast<std::size_t>(size));
    file.seekg(0);
    require(static_cast<bool>(file.read(reinterpret_cast<char*>(result.data()), size)), "Cannot read input: " + path.string());
    return result;
}
void write_file(const std::filesystem::path& target, const Bytes& data, bool force) {
    struct stat status{};
    if (lstat(target.c_str(), &status) == 0) {
        require(S_ISREG(status.st_mode), "Output must be a regular file, not a symlink");
        require(force, "Output already exists; use -f to replace it");
    } else require(errno == ENOENT, "Cannot inspect output path");
    auto directory = target.has_parent_path() ? target.parent_path() : std::filesystem::path(".");
    auto pattern = (directory / ".certutil-XXXXXX").string();
    std::vector<char> name(pattern.begin(), pattern.end());
    name.push_back('\0');
    int fd = mkstemp(name.data());
    require(fd >= 0, "Cannot create output file: " + std::string(std::strerror(errno)));
    struct Temporary {
        int fd;
        const char* name;
        ~Temporary() {
            if (fd >= 0) close(fd);
            if (name && unlink(name) != 0 && errno != ENOENT)
                std::cerr << "CertUtil: cannot remove temporary output: " << std::strerror(errno) << '\n';
        }
    } temp{fd, name.data()};
    for (std::size_t offset = 0; offset < data.size();) {
        auto written = write(fd, data.data() + offset, data.size() - offset);
        if (written < 0 && errno == EINTR) continue;
        require(written > 0, "Cannot write output file");
        offset += static_cast<std::size_t>(written);
    }
    require(fsync(fd) == 0, "Cannot flush output file");
    int closed = close(fd);
    temp.fd = -1;
    require(closed == 0, "Cannot close output file");
    if (force) require(rename(name.data(), target.c_str()) == 0, "Cannot replace output file");
    else require(link(name.data(), target.c_str()) == 0, "Cannot publish output (it may already exist)");
    if (!force) require(unlink(name.data()) == 0, "Output published, but temporary-file cleanup failed");
    temp.name = nullptr;
    int parent = open(directory.c_str(), O_RDONLY | O_DIRECTORY | O_CLOEXEC);
    require(parent >= 0, "Output published, but cannot open its directory for flushing");
    int flushed = fsync(parent);
    close(parent);
    require(flushed == 0, "Output published, but cannot flush its directory");
}
BioPtr bio(const Bytes& input) {
    BioPtr result(BIO_new_mem_buf(input.data(), static_cast<int>(input.size())), BIO_free);
    require(result != nullptr, "Cannot allocate input buffer");
    return result;
}
BioPtr output_bio() {
    BioPtr result(BIO_new(BIO_s_mem()), BIO_free);
    require(result != nullptr, "Cannot allocate output buffer");
    return result;
}
Bytes bio_bytes(BIO* buffer) {
    char* data = nullptr;
    long size = BIO_get_mem_data(buffer, &data);
    require(size >= 0, "Cannot read output buffer");
    if (!size) return {};
    return Bytes(data, data + size);
}
Bytes der(X509* certificate) {
    auto buffer = output_bio();
    require(i2d_X509_bio(buffer.get(), certificate) == 1, "Cannot encode certificate");
    return bio_bytes(buffer.get());
}
void append_pkcs7(PKCS7* container, std::vector<X509Ptr>& result) {
    require(container && PKCS7_type_is_signed(container), "Only signed-data PKCS#7 certificate containers are supported");
    require(sk_X509_CRL_num(container->d.sign->crl) <= 0, "CRL-bearing PKCS#7 is unsupported; no material was imported");
    auto certificates = container->d.sign->cert;
    require(sk_X509_num(certificates) > 0, "PKCS#7 contains no certificates");
    for (int i = 0; i < sk_X509_num(certificates); ++i) {
        X509Ptr copy(X509_dup(sk_X509_value(certificates, i)), X509_free);
        require(copy != nullptr, "Cannot copy PKCS#7 certificate");
        result.push_back(std::move(copy));
    }
}
std::vector<X509Ptr> certificates(const Bytes& input) {
    std::vector<X509Ptr> result;
    std::string_view text(reinterpret_cast<const char*>(input.data()), input.size());
    auto trim = [&] {
        auto first = text.find_first_not_of(" \r\n\t");
        text.remove_prefix(first == std::string_view::npos ? text.size() : first);
    };
    trim();
    if (text.starts_with("-----BEGIN ")) {
        while (!text.empty()) {
            bool cert = text.starts_with("-----BEGIN CERTIFICATE-----");
            require(cert || text.starts_with("-----BEGIN PKCS7-----"), "Unsupported PEM block; expected CERTIFICATE or PKCS7");
            std::string_view end = cert ? "-----END CERTIFICATE-----" : "-----END PKCS7-----";
            auto last = text.find(end);
            require(last != std::string_view::npos, "Truncated PEM block");
            auto block = text.substr(0, last + end.size());
            Bytes encoded(block.begin(), block.end());
            auto buffer = bio(encoded);
            if (cert) {
                X509Ptr parsed(PEM_read_bio_X509(buffer.get(), nullptr, nullptr, nullptr), X509_free);
                require(parsed != nullptr, "Invalid PEM certificate");
                result.push_back(std::move(parsed));
            } else {
                std::unique_ptr<PKCS7, decltype(&PKCS7_free)> parsed(
                    PEM_read_bio_PKCS7(buffer.get(), nullptr, nullptr, nullptr), PKCS7_free);
                append_pkcs7(parsed.get(), result);
            }
            text.remove_prefix(block.size());
            trim();
        }
        return result;
    }
    const BYTE* cursor = input.data();
    X509Ptr parsed(d2i_X509(nullptr, &cursor, static_cast<long>(input.size())), X509_free);
    if (parsed && cursor == input.data() + input.size()) {
        result.push_back(std::move(parsed));
        return result;
    }
    ERR_clear_error();
    cursor = input.data();
    std::unique_ptr<PKCS7, decltype(&PKCS7_free)> container(
        d2i_PKCS7(nullptr, &cursor, static_cast<long>(input.size())), PKCS7_free);
    require(container && cursor == input.data() + input.size(), "Input is not a complete PEM/DER certificate or PKCS#7 container");
    append_pkcs7(container.get(), result);
    return result;
}

std::string hex(const BYTE* data, std::size_t size) {
    constexpr char digits[] = "0123456789abcdef";
    std::string result;
    for (std::size_t i = 0; i < size; ++i) {
        result += digits[data[i] >> 4];
        result += digits[data[i] & 15];
    }
    return result;
}
std::string fingerprint(X509* certificate, const EVP_MD* algorithm) {
    std::array<BYTE, EVP_MAX_MD_SIZE> digest{};
    unsigned size = 0;
    require(X509_digest(certificate, algorithm, digest.data(), &size) == 1, "Cannot compute certificate hash");
    return hex(digest.data(), size);
}
std::string serial(X509* certificate) {
    const auto* value = X509_get0_serialNumber(certificate);
    return hex(ASN1_STRING_get0_data(value), static_cast<std::size_t>(ASN1_STRING_length(value)));
}
std::string text_of(BIO* buffer) {
    auto data = bio_bytes(buffer);
    std::string result;
    for (BYTE c : data) {
        if ((c < 32 && c != '\n' && c != '\t') || c == 127) result += "\\x" + hex(&c, 1);
        else result += static_cast<char>(c);
    }
    return result;
}
std::string name_of(X509_NAME* name) {
    auto buffer = output_bio();
    require(X509_NAME_print_ex(buffer.get(), name, 0, XN_FLAG_RFC2253) >= 0, "Cannot display certificate name");
    return text_of(buffer.get());
}
std::string time_of(const ASN1_TIME* time) {
    auto buffer = output_bio();
    require(ASN1_TIME_print(buffer.get(), time) == 1, "Cannot display certificate validity");
    return text_of(buffer.get());
}
void show(X509* certificate, std::size_t index, bool verbose, DWORD origin = 0, DWORD scope = 0) {
    std::cout << "================ Certificate " << index << " ================\n"
        << "Serial Number: " << serial(certificate) << "\nIssuer: " << name_of(X509_get_issuer_name(certificate))
        << "\n NotBefore: " << time_of(X509_get0_notBefore(certificate))
        << "\n NotAfter: " << time_of(X509_get0_notAfter(certificate))
        << "\nSubject: " << name_of(X509_get_subject_name(certificate))
        << "\nCert Hash(sha1): " << fingerprint(certificate, EVP_sha1())
        << "\nCert Hash(sha256): " << fingerprint(certificate, EVP_sha256()) << '\n';
    if (origin) std::cout << "Location: " << (origin == CERT_SYSTEM_STORE_CURRENT_USER ? "CurrentUser" : "LocalMachine")
        << (origin != scope ? " (inherited, read-only)" : "") << '\n';
    if (verbose) {
        auto buffer = output_bio();
        require(X509_print_ex(buffer.get(), certificate, XN_FLAG_RFC2253, 0) == 1, "Cannot display certificate details");
        std::cout << text_of(buffer.get());
    }
}
struct Entry {
    ContextPtr context;
    X509Ptr certificate{nullptr, X509_free};
    std::size_t index;
    DWORD origin;
};
std::vector<Entry> entries(HCERTSTORE store) {
    std::vector<Entry> result;
    ContextPtr cursor;
    for (;;) {
        cursor.reset(CertEnumCertificatesInStore(store, cursor.release()));
        if (!cursor) {
            api_check(GetLastError() == CRYPT_E_NOT_FOUND, "Enumerate certificates");
            break;
        }
        ContextPtr copy(CertDuplicateCertificateContext(cursor.get()));
        api_check(copy != nullptr, "Retain certificate");
        const BYTE* data = copy->pbCertEncoded;
        X509Ptr certificate(d2i_X509(nullptr, &data, copy->cbCertEncoded), X509_free);
        require(certificate != nullptr, "Cannot decode stored certificate");
        DWORD origin = 0;
        api_check(SysCertGetCertificateStoreLocation(copy.get(), &origin), "Get certificate location");
        result.push_back({std::move(copy), std::move(certificate), result.size(), origin});
    }
    return result;
}
std::string normalized_hex(std::string input) {
    input = lower(input);
    input.erase(std::remove_if(input.begin(), input.end(), [](char c) { return c == ':' || c == ' '; }), input.end());
    if (input.find_first_not_of("0123456789abcdef") != std::string::npos) return {};
    return input;
}
std::string normalized_serial(std::string input) {
    input = normalized_hex(std::move(input));
    if (input.empty()) return {};
    auto first = input.find_first_not_of('0');
    return first == std::string::npos ? "0" : input.substr(first);
}
bool matches(const Entry& entry, const std::string& selector) {
    if (selector == "*") return true;
    std::string type, token = selector;
    auto colon = selector.find(':');
    if (colon != std::string::npos) {
        auto prefix = lower(selector.substr(0, colon));
        if (prefix == "index" || prefix == "serial" || prefix == "sha1" || prefix == "sha256" || prefix == "subject") {
            type = prefix;
            token = selector.substr(colon + 1);
        }
    }
    usage_require(!token.empty(), "Empty certificate selector");
    std::size_t index = 0;
    auto parsed = std::from_chars(token.data(), token.data() + token.size(), index);
    if ((type.empty() || type == "index") && parsed.ec == std::errc{} &&
        parsed.ptr == token.data() + token.size() && index == entry.index) return true;
    auto* certificate = entry.certificate.get();
    auto digits = normalized_hex(token);
    if ((type.empty() || type == "serial") && !digits.empty() &&
        normalized_serial(token) == normalized_serial(serial(certificate))) return true;
    if ((type.empty() || type == "sha1") && digits == fingerprint(certificate, EVP_sha1())) return true;
    if ((type.empty() || type == "sha256") && digits == fingerprint(certificate, EVP_sha256())) return true;
    return (type.empty() || type == "subject") &&
        lower(name_of(X509_get_subject_name(certificate))).find(lower(token)) != std::string::npos;
}
Store open_store(const Options& options, const std::string& name, bool write = false) {
    if (write && options.scope == CERT_SYSTEM_STORE_LOCAL_MACHINE && lower(name) == "root")
        usage_require(options.native_write, "Computer ROOT changes require --allow-native-write (and OS permission)");
    return Store(CertOpenStore(CERT_STORE_PROV_SYSTEM_A, 0, 0, options.scope |
        (write ? 0 : CERT_STORE_READONLY_FLAG) | (options.native_write ? SYS_CERT_STORE_NATIVE_WRITE_FLAG : 0), name.c_str()));
}
void password(const Options& options, Secret& result, bool exporting) {
    if (options.password) {
        std::cerr << "CertUtil: warning: -p passwords are visible in process arguments; prefer --password-file or a terminal prompt.\n";
        result.value = options.password;
    } else if (options.password_file) {
        int fd = open(options.password_file->c_str(), O_RDONLY | O_NOFOLLOW | O_CLOEXEC);
        require(fd >= 0, "Cannot open password file");
        struct stat status{};
        bool safe = fstat(fd, &status) == 0 && S_ISREG(status.st_mode) && status.st_uid == geteuid() &&
            (status.st_mode & 077) == 0 && status.st_size >= 0 && status.st_size <= 4096;
        if (!safe) { close(fd); throw std::runtime_error("Password file must be private, owned by this user, and at most 4096 bytes"); }
        result.value.resize(static_cast<std::size_t>(status.st_size));
        std::size_t offset = 0;
        while (offset < result.value.size()) {
            auto size = read(fd, result.value.data() + offset, result.value.size() - offset);
            if (size < 0 && errno == EINTR) continue;
            if (size <= 0) { close(fd); throw std::runtime_error("Cannot read password file"); }
            offset += static_cast<std::size_t>(size);
        }
        close(fd);
        if (result.value.ends_with("\n")) {
            result.value.pop_back();
            if (result.value.ends_with("\r")) result.value.pop_back();
        }
    } else {
        require(isatty(STDIN_FILENO), "A PFX password is required: use --password-file or -p when not running on a terminal");
        std::array<char, 4096> buffer{};
        int rc = EVP_read_pw_string(buffer.data(), static_cast<int>(buffer.size()), "PFX password: ", exporting ? 1 : 0);
        if (rc == 0) result.value = buffer.data();
        OPENSSL_cleanse(buffer.data(), buffer.size());
        require(rc == 0, "Cannot read or confirm PFX password");
    }
    usage_require(result.value.find('\0') == std::string::npos, "Password must not contain NUL bytes");
    usage_require(!exporting || !result.value.empty(), "PFX export requires a nonempty password");
}
void wide_password(const Secret& source, WideSecret& destination) {
    for (std::size_t i = 0; i < source.value.size();) {
        auto first = static_cast<unsigned char>(source.value[i++]);
        unsigned cp = first, more = 0, minimum = 0;
        if (first >= 0xc2 && first <= 0xdf) { cp = first & 31; more = 1; minimum = 0x80; }
        else if (first >= 0xe0 && first <= 0xef) { cp = first & 15; more = 2; minimum = 0x800; }
        else if (first >= 0xf0 && first <= 0xf4) { cp = first & 7; more = 3; minimum = 0x10000; }
        else usage_require(first < 0x80, "Password is not valid UTF-8");
        usage_require(i + more <= source.value.size(), "Truncated UTF-8 password");
        for (unsigned j = 0; j < more; ++j) {
            auto c = static_cast<unsigned char>(source.value[i++]);
            usage_require((c & 0xc0) == 0x80, "Password is not valid UTF-8");
            cp = (cp << 6) | (c & 63);
        }
        usage_require(cp >= minimum && cp <= 0x10ffff && !(cp >= 0xd800 && cp <= 0xdfff), "Password is not valid UTF-8");
        destination.value += static_cast<wchar_t>(cp);
    }
}
KeyPtr private_key(PCCERT_CONTEXT certificate) {
    DWORD size = 0;
    api_check(SysCertGetCertificateFilePath(certificate, TRUE, nullptr, &size), "Access certificate private key");
    std::vector<char> path(size);
    api_check(SysCertGetCertificateFilePath(certificate, TRUE, path.data(), &size), "Get private-key path");
    int fd = open(path.data(), O_RDONLY | O_CLOEXEC | O_NOFOLLOW);
    require(fd >= 0, "Cannot open private-key file");
    struct stat status{};
    bool safe = fstat(fd, &status) == 0 && S_ISREG(status.st_mode) && status.st_nlink == 1 &&
        status.st_uid == geteuid() && (status.st_mode & 077) == 0;
    if (!safe) { close(fd); throw std::runtime_error("Unsafe private-key file ownership or permissions"); }
    FILE* raw = fdopen(fd, "rb");
    if (!raw) { close(fd); throw std::runtime_error("Cannot read private-key file"); }
    auto close_file = [](FILE* value) { std::fclose(value); };
    std::unique_ptr<FILE, decltype(close_file)> file(raw, close_file);
    KeyPtr key(PEM_read_PrivateKey(file.get(), nullptr, [](char*, int, int, void*) { return 0; }, nullptr), EVP_PKEY_free);
    require(key != nullptr, "Cannot decode private key");
    return key;
}
bool self_signed(X509* certificate) {
    if (X509_NAME_cmp(X509_get_issuer_name(certificate), X509_get_subject_name(certificate)) != 0) return false;
    auto key = X509_get0_pubkey(certificate);
    bool result = key && X509_verify(certificate, key) == 1;
    ERR_clear_error();
    return result;
}
std::vector<X509Ptr> chain(const Options& options, const std::string& name, const std::vector<Entry>& source,
    X509* leaf, bool no_chain, bool no_root) {
    std::vector<X509Ptr> result;
    if (no_chain || self_signed(leaf)) return result;
    std::vector<Entry> candidates;
    for (const char* extra : {"CA", "ROOT"}) {
        if (lower(name) == lower(extra)) continue;
        auto store = open_store(options, extra);
        auto found = entries(store.value);
        for (auto& entry : found) candidates.push_back(std::move(entry));
    }
    std::set<std::string> seen{fingerprint(leaf, EVP_sha256())};
    auto current = leaf;
    while (!self_signed(current)) {
        std::map<std::string, X509*> issuers;
        auto scan = [&](const auto& list) {
            for (const auto& entry : list) {
                auto candidate = entry.certificate.get();
                if (X509_check_issued(candidate, current) != X509_V_OK) continue;
                auto key = X509_get0_pubkey(candidate);
                if (key && X509_verify(current, key) == 1) issuers.emplace(fingerprint(candidate, EVP_sha256()), candidate);
                ERR_clear_error();
            }
        };
        scan(source);
        scan(candidates);
        require(issuers.size() == 1, "Cannot build an unambiguous complete offline issuer chain; use NoChain for a leaf-only export");
        auto [hash, issuer] = *issuers.begin();
        require(seen.insert(hash).second, "Cycle in certificate issuer chain");
        X509Ptr copy(X509_dup(issuer), X509_free);
        require(copy != nullptr, "Cannot copy issuer certificate");
        if (no_root && self_signed(copy.get())) break;
        current = copy.get();
        result.push_back(std::move(copy));
    }
    return result;
}
Bytes public_export(const std::vector<Entry*>& selected, const std::string& format) {
    if (format == "der") {
        require(selected.size() == 1, "DER output requires exactly one certificate; use --format pem or pkcs7 for multiple matches");
        return der(selected.front()->certificate.get());
    }
    auto buffer = output_bio();
    if (format == "pem") {
        for (auto* entry : selected)
            require(PEM_write_bio_X509(buffer.get(), entry->certificate.get()) == 1, "Cannot encode PEM certificate");
    } else {
        std::unique_ptr<PKCS7, decltype(&PKCS7_free)> container(PKCS7_new(), PKCS7_free);
        require(container && PKCS7_set_type(container.get(), NID_pkcs7_signed) == 1 &&
            PKCS7_content_new(container.get(), NID_pkcs7_data) == 1, "Cannot create PKCS#7 container");
        for (auto* entry : selected)
            require(PKCS7_add_certificate(container.get(), entry->certificate.get()) == 1, "Cannot add PKCS#7 certificate");
        require(i2d_PKCS7_bio(buffer.get(), container.get()) == 1, "Cannot encode PKCS#7");
    }
    return bio_bytes(buffer.get());
}
void execute(Options options) {
    SYS_CERT_STORE_CONFIGURATION config{sizeof(config), options.user_directory, options.machine_directory, options.system_root};
    api_check(SysCertConfigureSystemStores(&config), "Configure store paths");
    const auto& cmd = options.command;
    auto& args = options.args;
    if (cmd == "-enumstore") {
        auto callback = [](const void* name, DWORD, PCERT_SYSTEM_STORE_INFO, void*, void*) -> BOOL {
            auto* wide = static_cast<LPCWSTR>(name);
            while (*wide) std::cout << static_cast<char>(*wide++);
            std::cout << '\n';
            return TRUE;
        };
        api_check(CertEnumSystemStore(options.scope, nullptr, nullptr, callback), "Enumerate stores");
    } else if (cmd == "-dump") {
        auto input = certificates(read_file(args[0]));
        for (std::size_t i = 0; i < input.size(); ++i) show(input[i].get(), i, options.verbose);
    } else if (cmd == "-addstore") {
        auto input = certificates(read_file(args[1]));
        std::vector<ContextPtr> parsed;
        for (const auto& certificate : input) {
            auto encoded = der(certificate.get());
            ContextPtr context(CertCreateCertificateContext(X509_ASN_ENCODING, encoded.data(), static_cast<DWORD>(encoded.size())));
            api_check(context != nullptr, "Validate certificate");
            parsed.push_back(std::move(context));
        }
        auto store = open_store(options, args[0], true);
        for (const auto& certificate : parsed) {
            api_check(CertAddCertificateContextToStore(store.value, certificate.get(),
                options.force ? CERT_STORE_ADD_REPLACE_EXISTING : CERT_STORE_ADD_NEW, nullptr), "Add certificate (earlier additions, if any, remain)");
            std::cout << "Certificate added to " << args[0] << ".\n";
        }
    } else if (cmd == "-importpfx") {
        auto name = args.size() == 2 ? args[0] : "MY";
        usage_require(lower(name) != "root" || options.scope == CERT_SYSTEM_STORE_CURRENT_USER,
            "Computer ROOT does not store private keys; use -addstore for public trust anchors");
        Secret secret;
        password(options, secret, false);
        WideSecret wide;
        wide_password(secret, wide);
        auto input = read_file(args.back());
        CRYPT_DATA_BLOB blob{static_cast<DWORD>(input.size()), input.data()};
        auto store = open_store(options, name, true);
        api_check(SysCertImportPfxToStore(store.value, &blob, wide.value.c_str(),
            options.scope == CERT_SYSTEM_STORE_CURRENT_USER ? CRYPT_USER_KEYSET : CRYPT_MACHINE_KEYSET), "Import PFX");
        std::cout << "PFX imported into " << name << ".\n";
    } else {
        bool exporting = cmd == "-exportpfx";
        bool no_chain = false, no_root = false;
        if (exporting && args.size() >= 3) {
            auto modifier = lower(args.back());
            if (modifier == "nochain" || modifier == "noroot") {
                no_chain = modifier == "nochain";
                no_root = modifier == "noroot";
                args.pop_back();
            }
        }
        usage_require(!exporting || args.size() == 2 || args.size() == 3, "Unsupported PFX export modifier or arguments");
        auto name = exporting ? (args.size() == 3 ? args[0] : "MY") : (args.empty() ? "CA" : args[0]);
        auto selector = exporting ? args[args.size() - 2] : (args.size() >= 2 ? args[1] : "*");
        usage_require(!selector.empty(), "Empty certificate selector");
        auto store = open_store(options, name, cmd == "-delstore");
        auto contents = entries(store.value);
        std::vector<Entry*> selected;
        for (auto& entry : contents) if (matches(entry, selector)) selected.push_back(&entry);
        bool all = cmd == "-store" && args.size() < 2;
        require(!selected.empty() || all, "No certificate matches the selector");
        if (cmd == "-delstore" || exporting)
            require(selected.size() == 1, "Ambiguous certificate selector; use a hash or explicit index");
        if (cmd == "-delstore") {
            require(selected[0]->origin == options.scope, "Inherited certificates cannot be deleted from a user view; open the computer store explicitly");
            api_check(CertDeleteCertificateFromStore(selected[0]->context.release()), "Delete certificate");
            std::cout << "Certificate deleted from " << name << ".\n";
        } else if (exporting) {
            auto* entry = selected[0];
            auto key = private_key(entry->context.get());
            require(X509_check_private_key(entry->certificate.get(), key.get()) == 1, "Private key does not match certificate");
            auto issuers = chain(options, name, contents, entry->certificate.get(), no_chain, no_root);
            auto free_stack = [](STACK_OF(X509)* stack) { sk_X509_free(stack); };
            std::unique_ptr<STACK_OF(X509), decltype(free_stack)> stack(sk_X509_new_null(), free_stack);
            require(stack != nullptr, "Cannot allocate certificate chain");
            for (const auto& issuer : issuers) require(sk_X509_push(stack.get(), issuer.get()) > 0, "Cannot build PFX chain");
            Secret secret;
            password(options, secret, true);
            WideSecret validated;
            wide_password(secret, validated);
            PfxPtr pfx(PKCS12_create(secret.value.c_str(), nullptr, key.get(), entry->certificate.get(),
                stack.get(), NID_aes_256_cbc, NID_aes_256_cbc, PKCS12_DEFAULT_ITER, PKCS12_DEFAULT_ITER, 0), PKCS12_free);
            require(pfx != nullptr, "Cannot create encrypted PFX");
            auto buffer = output_bio();
            require(i2d_PKCS12_bio(buffer.get(), pfx.get()) == 1, "Cannot encode PFX");
            write_file(args.back(), bio_bytes(buffer.get()), options.force);
            std::cout << "Encrypted PFX exported (" << 1 + issuers.size() << " certificates).\n";
        } else {
            for (auto* entry : selected) show(entry->certificate.get(), entry->index, options.verbose, entry->origin, options.scope);
            if (args.size() == 3) write_file(args[2], public_export(selected, options.format.value_or("der")), options.force);
            std::cout << selected.size() << " certificate(s).\n";
        }
    }
    require(static_cast<bool>(std::cout), "Cannot write command output");
}
} // namespace

int main(int argc, char** argv) {
    try {
        auto options = parse_options(argc, argv);
        if (options.help) { std::cout << help; return std::cout ? 0 : 1; }
        scs::initialize_crypto();
        execute(std::move(options));
        return 0;
    } catch (const UsageError& error) {
        std::cerr << "CertUtil: " << error.what() << '\n';
        return 2;
    } catch (const std::exception& error) {
        std::cerr << "CertUtil: " << error.what() << '\n';
        return 1;
    }
}
