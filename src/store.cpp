#include "internal.h"
#include "crypto.h"
#include <openssl/asn1.h>
#include <openssl/evp.h>
#include <openssl/pem.h>
#include <openssl/pkcs7.h>
#include <openssl/pkcs12.h>
#include <openssl/rand.h>
#include <openssl/x509v3.h>
#include <sqlite3.h>
#include <algorithm>
#include <array>
#include <cerrno>
#include <climits>
#include <cctype>
#include <cstdio>
#include <cstring>
#include <ctime>
#include <deque>
#include <fcntl.h>
#include <limits>
#include <map>
#include <mutex>
#include <set>
#include <pwd.h>
#include <string_view>
#include <sys/stat.h>
#include <unistd.h>
#include <unordered_map>
#include <utility>

namespace scs {
namespace {
thread_local DWORD last_error = 0;
thread_local std::array<char, 1024> last_message{};
std::recursive_mutex api_mutex;
struct SystemPaths {
    std::filesystem::path user;
    std::filesystem::path machine = "/var/lib/sys-cert-store";
    std::filesystem::path root = "/";
};
SystemPaths system_paths;

void report(DWORD code, const char* message) noexcept {
    last_error = code;
    std::snprintf(last_message.data(), last_message.size(), "%s", message);
}

template<class R, class F> R api_boundary(R failure, F&& function) noexcept {
    try {
        return function();
    } catch (const Error& error) {
        report(error.code, error.what());
    } catch (const std::bad_alloc&) {
        report(ERROR_NOT_ENOUGH_MEMORY, "Memory allocation failed");
    } catch (const std::filesystem::filesystem_error& error) {
        report(error.code() == std::errc::permission_denied ? ERROR_ACCESS_DENIED : ERROR_GEN_FAILURE, error.what());
    } catch (const std::exception& error) {
        report(ERROR_GEN_FAILURE, error.what());
    } catch (...) {
        report(ERROR_GEN_FAILURE, "Unexpected exception at the C API boundary");
    }
    return failure;
}

template<class F> auto with_api_lock(F&& function) {
    std::lock_guard lock(api_mutex);
    initialize_crypto();
    return function();
}

template<class R, class F> R boundary(R failure, F&& function) noexcept {
    return api_boundary<R>(failure, [&] {
        return with_api_lock(std::forward<F>(function));
    });
}

DWORD count(std::size_t size) {
    require(size <= std::numeric_limits<DWORD>::max(), ERROR_INVALID_DATA, "Value exceeds DWORD capacity");
    return static_cast<DWORD>(size);
}

Bytes bytes(const BYTE* data, std::size_t size) {
    require(data || size == 0, E_INVALIDARG, "Null buffer with nonzero size");
    return size ? Bytes(data, data + size) : Bytes{};
}

void encoding_check(DWORD encoding) {
    require((encoding & X509_ASN_ENCODING) != 0 &&
        (encoding & ~(X509_ASN_ENCODING | PKCS_7_ASN_ENCODING)) == 0,
        ERROR_NOT_SUPPORTED, "Only X.509 certificate encoding is supported");
}

std::string utf8(LPCWSTR input) {
    require(input != nullptr, E_INVALIDARG, "Null wide string");
    std::string result;
    for (; *input; ++input) {
        auto cp = static_cast<std::uint32_t>(*input);
        require(cp <= 0x10ffff && !(cp >= 0xd800 && cp <= 0xdfff), E_INVALIDARG, "Invalid Unicode scalar");
        if (cp < 0x80) result += static_cast<char>(cp);
        else if (cp < 0x800) {
            result += static_cast<char>(0xc0 | (cp >> 6));
            result += static_cast<char>(0x80 | (cp & 63));
        } else if (cp < 0x10000) {
            result += static_cast<char>(0xe0 | (cp >> 12));
            result += static_cast<char>(0x80 | ((cp >> 6) & 63));
            result += static_cast<char>(0x80 | (cp & 63));
        } else {
            result += static_cast<char>(0xf0 | (cp >> 18));
            result += static_cast<char>(0x80 | ((cp >> 12) & 63));
            result += static_cast<char>(0x80 | ((cp >> 6) & 63));
            result += static_cast<char>(0x80 | (cp & 63));
        }
    }
    return result;
}

void db_check(sqlite3* db, int result) {
    if (result == SQLITE_OK || result == SQLITE_DONE || result == SQLITE_ROW) return;
    DWORD code = ERROR_GEN_FAILURE;
    switch (result & 0xff) {
    case SQLITE_READONLY: case SQLITE_PERM: case SQLITE_AUTH: code = ERROR_ACCESS_DENIED; break;
    case SQLITE_BUSY: case SQLITE_LOCKED: code = ERROR_BUSY; break;
    case SQLITE_NOMEM: code = ERROR_NOT_ENOUGH_MEMORY; break;
    case SQLITE_CORRUPT: case SQLITE_NOTADB: code = ERROR_INVALID_DATA; break;
    }
    throw Error(code, db ? sqlite3_errmsg(db) : "SQLite initialization failed");
}

struct Statement {
    sqlite3* db;
    sqlite3_stmt* value = nullptr;
    Statement(sqlite3* database, const char* sql) : db(database) {
        db_check(db, sqlite3_prepare_v2(db, sql, -1, &value, nullptr));
    }
    ~Statement() { sqlite3_finalize(value); }
    Statement(const Statement&) = delete;
    Statement& operator=(const Statement&) = delete;
    void integer(int index, sqlite3_int64 number) { db_check(db, sqlite3_bind_int64(value, index, number)); }
    void blob(int index, const Bytes& data) {
        db_check(db, sqlite3_bind_blob64(value, index, data.empty() ? "" : static_cast<const void*>(data.data()),
            data.size(), SQLITE_TRANSIENT));
    }
    void text(int index, const std::string& data) {
        db_check(db, sqlite3_bind_text64(value, index, data.data(), data.size(), SQLITE_TRANSIENT, SQLITE_UTF8));
    }
    std::string text_column(int column) {
        auto* data = sqlite3_column_text(value, column);
        require(data, ERROR_INVALID_DATA, "Null object path in metadata");
        return reinterpret_cast<const char*>(data);
    }
    bool step() {
        int rc = sqlite3_step(value);
        db_check(db, rc);
        return rc == SQLITE_ROW;
    }
    Bytes blob_column(int column) {
        auto size = sqlite3_column_bytes(value, column);
        return bytes(static_cast<const BYTE*>(sqlite3_column_blob(value, column)), static_cast<std::size_t>(size));
    }
};

struct Database {
    sqlite3* value = nullptr;
    Database(const std::string& path, bool readonly, bool initialize) {
        sqlite3* raw = nullptr;
        int rc = sqlite3_open_v2(path.c_str(), &raw,
            (readonly ? SQLITE_OPEN_READONLY : SQLITE_OPEN_READWRITE | SQLITE_OPEN_CREATE) |
            SQLITE_OPEN_FULLMUTEX | SQLITE_OPEN_NOFOLLOW, nullptr);
        std::unique_ptr<sqlite3, decltype(&sqlite3_close)> guard(raw, sqlite3_close);
        db_check(raw, rc);
        value = raw;
        db_check(value, sqlite3_busy_timeout(value, 5000));
        exec("PRAGMA foreign_keys=ON");
        if (initialize) {
            exec("BEGIN IMMEDIATE");
            exec("CREATE TABLE IF NOT EXISTS certificates(id INTEGER PRIMARY KEY AUTOINCREMENT,object TEXT NOT NULL)");
            exec("CREATE TABLE IF NOT EXISTS properties(cert INTEGER NOT NULL REFERENCES certificates(id) ON DELETE CASCADE,"
                "property INTEGER NOT NULL,value BLOB NOT NULL,PRIMARY KEY(cert,property))");
            exec("CREATE TABLE IF NOT EXISTS store_properties(property INTEGER PRIMARY KEY,value BLOB NOT NULL)");
            exec("CREATE TABLE IF NOT EXISTS garbage(object TEXT PRIMARY KEY)");
            exec("PRAGMA application_id=1396921137");
            exec("PRAGMA user_version=2");
            exec("COMMIT");
        }
        Statement app(value, "PRAGMA application_id");
        require(app.step() && sqlite3_column_int(app.value, 0) == 1396921137,
            ERROR_INVALID_DATA, "Not a sys-cert-store database");
        Statement version(value, "PRAGMA user_version");
        require(version.step() && sqlite3_column_int(version.value, 0) == 2,
            ERROR_NOT_SUPPORTED, "Unsupported sys-cert-store schema version");
        guard.release();
    }
    ~Database() { sqlite3_close(value); }
    Database(const Database&) = delete;
    Database& operator=(const Database&) = delete;
    void exec(const char* sql) { db_check(value, sqlite3_exec(value, sql, nullptr, nullptr, nullptr)); }
};

struct Transaction {
    Database& db;
    bool committed = false;
    explicit Transaction(Database& database) : db(database) { db.exec("BEGIN IMMEDIATE"); }
    ~Transaction() {
        if (!committed && sqlite3_exec(db.value, "ROLLBACK", nullptr, nullptr, nullptr) != SQLITE_OK)
            std::fputs("sys-cert-store: SQLite rollback failed\n", stderr);
    }
    void commit() { db.exec("COMMIT"); committed = true; }
};

using Properties = std::map<DWORD, Bytes>;
using SharedKey = std::shared_ptr<EVP_PKEY>;
struct Material {
    Bytes der;
    SharedKey key;
};
struct Store {
    std::unique_ptr<Database> db;
    bool readonly = false;
    bool archived = false;
    bool native = false;
    NativeLayout layout{};
    DWORD location = 0;
    std::string name;
    std::filesystem::path pending_path;
    bool public_material = false;
    uid_t owner = geteuid();
    std::vector<std::shared_ptr<Store>> inherited;
    std::filesystem::path objects;
    std::map<sqlite3_int64, Material> memory;
    std::size_t references = 1;
    std::size_t contexts = 0;
};

struct Context {
    CERT_CONTEXT pub{};
    CERT_INFO info{};
    X509Ptr certificate{nullptr, X509_free};
    Bytes der;
    std::deque<Bytes> buffers;
    std::deque<std::string> strings;
    std::vector<CERT_EXTENSION> extensions;
    Properties properties;
    SharedKey private_key;
    std::filesystem::path object_path;
    std::filesystem::path key_path;
    std::shared_ptr<Store> store;
    std::shared_ptr<Store> view;
    sqlite3_int64 row = 0;
    std::size_t references = 1;
    uid_t owner = geteuid();

    CRYPT_DATA_BLOB keep(Bytes data) {
        buffers.push_back(std::move(data));
        return {count(buffers.back().size()), buffers.back().data()};
    }
    char* oid(const ASN1_OBJECT* object) {
        int length = OBJ_obj2txt(nullptr, 0, object, 1);
        require(length > 0, ERROR_INVALID_DATA, "Invalid object identifier");
        std::string result(static_cast<std::size_t>(length) + 1, '\0');
        OBJ_obj2txt(result.data(), length + 1, object, 1);
        result.resize(static_cast<std::size_t>(length));
        strings.push_back(std::move(result));
        return strings.back().data();
    }
    template<class T, class F> CRYPT_DATA_BLOB encode(T* object, F encoder) {
        int length = encoder(object, nullptr);
        require(length > 0, ERROR_INVALID_DATA, "ASN.1 encoding failed");
        Bytes result(static_cast<std::size_t>(length));
        auto* cursor = result.data();
        require(encoder(object, &cursor) == length, ERROR_INVALID_DATA, "ASN.1 encoding failed");
        return keep(std::move(result));
    }
    CRYPT_ALGORITHM_IDENTIFIER algorithm(const X509_ALGOR* alg) {
        const ASN1_OBJECT* object = nullptr;
        int type = V_ASN1_UNDEF;
        const void* parameter = nullptr;
        X509_ALGOR_get0(&object, &type, &parameter, alg);
        CRYPT_ALGORITHM_IDENTIFIER result{oid(object), {}};
        if (type != V_ASN1_UNDEF) {
            std::unique_ptr<ASN1_TYPE, decltype(&ASN1_TYPE_free)> value(ASN1_TYPE_new(), ASN1_TYPE_free);
            require(value != nullptr, ERROR_NOT_ENOUGH_MEMORY, "ASN.1 allocation failed");
            require(ASN1_TYPE_set1(value.get(), type, parameter) == 1, ERROR_INVALID_DATA, "Invalid algorithm parameters");
            result.Parameters = encode(value.get(), i2d_ASN1_TYPE);
        }
        return result;
    }
    CRYPT_BIT_BLOB bit_blob(const ASN1_BIT_STRING* bits) {
        if (!bits) return {};
        auto blob = keep(bytes(ASN1_STRING_get0_data(bits), static_cast<std::size_t>(ASN1_STRING_length(bits))));
        return {blob.cbData, blob.pbData, static_cast<DWORD>((bits->flags & ASN1_STRING_FLAG_BITS_LEFT) ? bits->flags & 7 : 0)};
    }
    static FILETIME time(const ASN1_TIME* input) {
        std::tm value{};
        require(ASN1_TIME_to_tm(input, &value) == 1, ERROR_INVALID_DATA, "Invalid certificate validity time");
        auto seconds = static_cast<std::int64_t>(timegm(&value)) + 11644473600LL;
        require(seconds >= 0, ERROR_NOT_SUPPORTED, "Certificate time predates FILETIME epoch");
        auto ticks = static_cast<std::uint64_t>(seconds) * 10000000;
        return {static_cast<DWORD>(ticks), static_cast<DWORD>(ticks >> 32)};
    }
    explicit Context(Bytes input) : der(std::move(input)) {
        require(!der.empty() && der.size() <= static_cast<std::size_t>(LONG_MAX),
            ERROR_INVALID_DATA, "Empty or oversized certificate");
        const auto* cursor = der.data();
        certificate.reset(d2i_X509(nullptr, &cursor, static_cast<long>(der.size())));
        require(certificate && cursor == der.data() + der.size(), ERROR_INVALID_DATA, "Invalid DER certificate or trailing bytes");
        auto* x = certificate.get();
        info.dwVersion = static_cast<DWORD>(X509_get_version(x));
        const auto* serial = X509_get0_serialNumber(x);
        require(ASN1_STRING_type(serial) != V_ASN1_NEG_INTEGER, ERROR_NOT_SUPPORTED, "Negative certificate serial numbers are unsupported");
        auto serial_bytes = bytes(ASN1_STRING_get0_data(serial), static_cast<std::size_t>(ASN1_STRING_length(serial)));
        std::reverse(serial_bytes.begin(), serial_bytes.end());
        info.SerialNumber = keep(std::move(serial_bytes));
        info.SignatureAlgorithm = algorithm(X509_get0_tbs_sigalg(x));
        info.Issuer = encode(X509_get_issuer_name(x), i2d_X509_NAME);
        info.Subject = encode(X509_get_subject_name(x), i2d_X509_NAME);
        info.NotBefore = time(X509_get0_notBefore(x));
        info.NotAfter = time(X509_get0_notAfter(x));
        X509_ALGOR* pub_alg = nullptr;
        const BYTE* public_key = nullptr;
        int public_size = 0;
        require(X509_PUBKEY_get0_param(nullptr, &public_key, &public_size, &pub_alg, X509_get_X509_PUBKEY(x)) == 1,
            ERROR_INVALID_DATA, "Invalid certificate public key");
        info.SubjectPublicKeyInfo.Algorithm = algorithm(pub_alg);
        info.SubjectPublicKeyInfo.PublicKey = bit_blob(X509_get0_pubkey_bitstr(x));
        const ASN1_BIT_STRING* issuer_id = nullptr;
        const ASN1_BIT_STRING* subject_id = nullptr;
        X509_get0_uids(x, &issuer_id, &subject_id);
        info.IssuerUniqueId = bit_blob(issuer_id);
        info.SubjectUniqueId = bit_blob(subject_id);
        for (int i = 0; i < X509_get_ext_count(x); ++i) {
            auto* extension = X509_get_ext(x, i);
            auto* data = X509_EXTENSION_get_data(extension);
            extensions.push_back({oid(X509_EXTENSION_get_object(extension)), X509_EXTENSION_get_critical(extension),
                keep(bytes(ASN1_STRING_get0_data(data), static_cast<std::size_t>(ASN1_STRING_length(data))))});
        }
        info.cExtension = count(extensions.size());
        info.rgExtension = extensions.data();
        pub = {X509_ASN_ENCODING, der.data(), count(der.size()), &info, nullptr};
    }
    ~Context() {
        if (store) --store->contexts;
        if (view) --view->contexts;
    }
};

std::unordered_map<HCERTSTORE, std::shared_ptr<Store>> stores;
std::unordered_map<PCCERT_CONTEXT, std::unique_ptr<Context>> contexts;

struct OwnedChain {
    CERT_CHAIN_CONTEXT public_context{};
    CERT_SIMPLE_CHAIN simple{};
    std::vector<CERT_SIMPLE_CHAIN*> chain_pointers;
    std::vector<CERT_CHAIN_ELEMENT> elements;
    std::vector<CERT_CHAIN_ELEMENT*> element_pointers;
    std::vector<PCCERT_CONTEXT> contexts;
};
std::unordered_map<PCCERT_CHAIN_CONTEXT, std::unique_ptr<OwnedChain>> chains;

std::shared_ptr<Store> get_store(HCERTSTORE handle) {
    auto found = stores.find(handle);
    require(found != stores.end(), ERROR_INVALID_HANDLE, "Invalid or closed certificate store handle");
    return found->second;
}
Context& get_context(PCCERT_CONTEXT context) {
    auto found = contexts.find(context);
    require(found != contexts.end(), ERROR_INVALID_HANDLE, "Invalid or freed certificate context");
    return *found->second;
}
void release(PCCERT_CONTEXT context) {
    if (context && --get_context(context).references == 0) contexts.erase(context);
}
struct Consume {
    PCCERT_CONTEXT context;
    explicit Consume(PCCERT_CONTEXT input) : context(input) { if (context) get_context(context); }
    ~Consume() { if (context) release(context); }
};

PCCERT_CONTEXT publish(std::unique_ptr<Context> context, std::shared_ptr<Store> store = {}, sqlite3_int64 row = 0,
    std::shared_ptr<Store> view = {}) {
    auto* result = &context->pub;
    context->store = std::move(store);
    if (context->store) ++context->store->contexts;
    context->view = std::move(view);
    if (context->view) ++context->view->contexts;
    context->pub.hCertStore = context->view ? context->view.get() : context->store.get();
    context->row = row;
    contexts.emplace(result, std::move(context));
    return result;
}

std::unique_ptr<Context> load_context(Store& store, sqlite3_int64 row);
void materialize(Store& store, bool create);
void scoped_backing(Store& store, const std::filesystem::path& directory, DWORD flags);
std::shared_ptr<Store> machine_backing(const std::string& name, DWORD flags);
std::filesystem::path user_data_directory();

using Fingerprint = std::array<BYTE, 32>;
struct ChainCertificate {
    Bytes der;
    X509Ptr certificate{nullptr, X509_free};

    explicit ChainCertificate(Bytes input) : der(std::move(input)) {
        const auto* cursor = der.data();
        certificate.reset(d2i_X509(nullptr, &cursor, static_cast<long>(der.size())));
        require(certificate && cursor == der.data() + der.size(), ERROR_INVALID_DATA,
            "Invalid DER certificate in chain candidate");
    }
    ChainCertificate(ChainCertificate&&) noexcept = default;
    ChainCertificate& operator=(ChainCertificate&&) noexcept = default;
    ChainCertificate(const ChainCertificate&) = delete;
    ChainCertificate& operator=(const ChainCertificate&) = delete;
};

Fingerprint fingerprint(X509* certificate) {
    Fingerprint result{};
    unsigned size = 0;
    require(X509_digest(certificate, EVP_sha256(), result.data(), &size) == 1 &&
        size == result.size(), ERROR_GEN_FAILURE, "Cannot compute certificate fingerprint");
    return result;
}
bool verifies(X509* certificate, X509* issuer) {
    auto* key = X509_get0_pubkey(issuer);
    return key && X509_verify(certificate, key) == 1;
}
bool same_name(X509_NAME* left, X509_NAME* right) {
    int left_size = i2d_X509_NAME(left, nullptr);
    int right_size = i2d_X509_NAME(right, nullptr);
    require(left_size > 0 && right_size > 0, ERROR_INVALID_DATA, "Cannot encode certificate name");
    if (left_size != right_size) return false;
    Bytes left_der(static_cast<std::size_t>(left_size));
    Bytes right_der(static_cast<std::size_t>(right_size));
    auto* left_cursor = left_der.data();
    auto* right_cursor = right_der.data();
    require(i2d_X509_NAME(left, &left_cursor) == left_size &&
        i2d_X509_NAME(right, &right_cursor) == right_size,
        ERROR_INVALID_DATA, "Cannot encode certificate name");
    return left_der == right_der;
}
bool self_signed(X509* certificate) {
    return same_name(X509_get_subject_name(certificate), X509_get_issuer_name(certificate)) &&
        verifies(certificate, certificate);
}
void append_chain_candidates(std::vector<ChainCertificate>& result, Store& view) {
    std::vector<Store*> sources{&view};
    for (const auto& source : view.inherited) sources.push_back(source.get());
    for (auto* source : sources) {
        materialize(*source, false);
        Statement query(source->db->value, "SELECT id FROM certificates ORDER BY id");
        while (query.step()) {
            auto context = load_context(*source, sqlite3_column_int64(query.value, 0));
            result.emplace_back(context->der);
        }
    }
}
std::vector<ChainCertificate> chain_candidates(HCERTSTORE handle) {
    std::vector<ChainCertificate> result;
    if (handle) append_chain_candidates(result, *get_store(handle));
    return result;
}
std::vector<ChainCertificate> system_chain_candidates(const char* name) {
    auto view = std::make_shared<Store>();
    view->name = name;
    view->location = CERT_SYSTEM_STORE_CURRENT_USER;
    view->readonly = true;
    scoped_backing(*view, user_data_directory(), CERT_STORE_READONLY_FLAG);
    view->inherited.push_back(machine_backing(name, CERT_STORE_READONLY_FLAG));
    std::vector<ChainCertificate> result;
    append_chain_candidates(result, *view);
    return result;
}
void insert_chain_candidates(std::map<Fingerprint, ChainCertificate>& destination,
    std::vector<ChainCertificate> source) {
    for (auto& certificate : source)
        destination.try_emplace(fingerprint(certificate.certificate.get()), std::move(certificate));
}
std::pair<std::vector<CERT_TRUST_STATUS>, CERT_TRUST_STATUS> chain_statuses(
    const std::vector<X509*>& certificates, const std::set<Fingerprint>& trusted_roots,
    const std::set<std::size_t>& invalid_signatures, bool partial, bool cyclic) {
    std::vector<CERT_TRUST_STATUS> elements(certificates.size());
    for (std::size_t index = 0; index < certificates.size(); ++index) {
        auto* certificate = certificates[index];
        if (X509_cmp_current_time(X509_get0_notBefore(certificate)) > 0 ||
            X509_cmp_current_time(X509_get0_notAfter(certificate)) < 0)
            elements[index].dwErrorStatus |= CERT_TRUST_IS_NOT_TIME_VALID;
        if (invalid_signatures.contains(index))
            elements[index].dwErrorStatus |= CERT_TRUST_IS_NOT_SIGNATURE_VALID;
        if (self_signed(certificate))
            elements[index].dwInfoStatus |= CERT_TRUST_IS_SELF_SIGNED;
        if (index == 0) continue;

        std::unique_ptr<BASIC_CONSTRAINTS, decltype(&BASIC_CONSTRAINTS_free)> constraints(
            static_cast<BASIC_CONSTRAINTS*>(X509_get_ext_d2i(
                certificate, NID_basic_constraints, nullptr, nullptr)), BASIC_CONSTRAINTS_free);
        bool is_ca = constraints && constraints->ca;
        if (!is_ca)
            elements[index].dwErrorStatus |=
                CERT_TRUST_INVALID_BASIC_CONSTRAINTS | CERT_TRUST_IS_NOT_VALID_FOR_USAGE;

        std::unique_ptr<ASN1_BIT_STRING, decltype(&ASN1_BIT_STRING_free)> usage(
            static_cast<ASN1_BIT_STRING*>(X509_get_ext_d2i(
                certificate, NID_key_usage, nullptr, nullptr)), ASN1_BIT_STRING_free);
        if (usage && ASN1_BIT_STRING_get_bit(usage.get(), 5) == 0)
            elements[index].dwErrorStatus |= CERT_TRUST_IS_NOT_VALID_FOR_USAGE;

        if (constraints && constraints->ca && constraints->pathlen) {
            auto limit = ASN1_INTEGER_get(constraints->pathlen);
            require(limit >= 0, ERROR_INVALID_DATA, "Invalid negative CA path-length constraint");
            long subordinate_ca_count = 0;
            for (std::size_t subordinate = 1; subordinate < index; ++subordinate) {
                auto* candidate = certificates[subordinate];
                std::unique_ptr<BASIC_CONSTRAINTS, decltype(&BASIC_CONSTRAINTS_free)> candidate_constraints(
                    static_cast<BASIC_CONSTRAINTS*>(X509_get_ext_d2i(
                        candidate, NID_basic_constraints, nullptr, nullptr)), BASIC_CONSTRAINTS_free);
                if (candidate_constraints && candidate_constraints->ca &&
                    !same_name(X509_get_subject_name(candidate), X509_get_issuer_name(candidate)))
                    ++subordinate_ca_count;
            }
            if (subordinate_ca_count > limit)
                elements[index].dwErrorStatus |= CERT_TRUST_INVALID_BASIC_CONSTRAINTS;
        }
    }

    CERT_TRUST_STATUS chain{};
    if (partial) chain.dwErrorStatus |= CERT_TRUST_IS_PARTIAL_CHAIN;
    else if (cyclic) chain.dwErrorStatus |= CERT_TRUST_IS_CYCLIC;
    else if (!certificates.empty() && self_signed(certificates.back()) &&
        !trusted_roots.contains(fingerprint(certificates.back())))
        elements.back().dwErrorStatus |= CERT_TRUST_IS_UNTRUSTED_ROOT;
    for (const auto& status : elements) {
        chain.dwErrorStatus |= status.dwErrorStatus;
        chain.dwInfoStatus |= status.dwInfoStatus;
    }
    return {std::move(elements), chain};
}

std::string object_id() {
    std::array<BYTE, 16> random{};
    require(RAND_bytes(random.data(), static_cast<int>(random.size())) == 1, ERROR_GEN_FAILURE, "Cannot generate object identifier");
    constexpr char digits[] = "0123456789abcdef";
    std::string result;
    for (BYTE ch : random) { result += digits[ch >> 4]; result += digits[ch & 15]; }
    return result;
}
std::filesystem::path object_directory(const Store& store, const std::string& id) {
    require(id.size() == 32 && id.find_first_not_of("0123456789abcdef") == std::string::npos,
        ERROR_INVALID_DATA, "Invalid object reference in metadata");
    return store.objects / id;
}
void private_directory(const std::filesystem::path& path, bool shared = false) {
    if (mkdir(path.c_str(), shared ? 0755 : 0700) == 0) {
        if (shared) require(chmod(path.c_str(), 0755) == 0, ERROR_ACCESS_DENIED, "Cannot set public object-directory permissions");
    } else
        require(errno == EEXIST, ERROR_ACCESS_DENIED, "Cannot create private object directory");
    struct stat status{};
    require(lstat(path.c_str(), &status) == 0 && S_ISDIR(status.st_mode) &&
        status.st_uid == geteuid() && (status.st_mode & (shared ? 022 : 077)) == 0,
        ERROR_ACCESS_DENIED, "Object directory has unsafe ownership or permissions");
}
void flush_directory(const std::filesystem::path& path) {
    int fd = open(path.c_str(), O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC);
    require(fd >= 0, ERROR_GEN_FAILURE, "Cannot open object directory for flush");
    int result = fsync(fd);
    close(fd);
    require(result == 0, ERROR_GEN_FAILURE, "Cannot flush object directory");
}
void erase_object(const std::filesystem::path& path) {
    struct stat status{};
    if (lstat(path.c_str(), &status) != 0) {
        require(errno == ENOENT, ERROR_GEN_FAILURE, "Cannot inspect retired certificate object");
        return;
    }
    require(S_ISDIR(status.st_mode) && status.st_uid == geteuid(), ERROR_ACCESS_DENIED, "Unsafe retired object directory");
    std::filesystem::remove(path / "certificate.pem");
    std::filesystem::remove(path / "private-key.pem");
    auto keys = path / "keys";
    if (lstat(keys.c_str(), &status) == 0) {
        require(S_ISDIR(status.st_mode) && status.st_uid == geteuid(), ERROR_ACCESS_DENIED, "Unsafe private-key directory");
        std::filesystem::remove(keys / "private-key.pem");
        std::filesystem::remove(keys);
    } else require(errno == ENOENT, ERROR_GEN_FAILURE, "Cannot inspect private-key directory");
    require(std::filesystem::remove(path), ERROR_GEN_FAILURE, "Cannot remove retired object directory");
    flush_directory(path.parent_path());
}
void collect_garbage(Store& store) {
    if (store.objects.empty() || store.readonly) return;
    Statement query(store.db->value, "SELECT object FROM garbage");
    std::vector<std::string> pending;
    while (query.step()) pending.push_back(query.text_column(0));
    for (const auto& id : pending) {
        erase_object(object_directory(store, id));
        Statement remove(store.db->value, "DELETE FROM garbage WHERE object=?");
        remove.text(1, id);
        remove.step();
    }
}
void retire_row(Store& store, sqlite3_int64 row) {
    if (!store.objects.empty()) {
        Statement retire(store.db->value, "INSERT OR IGNORE INTO garbage SELECT object FROM certificates WHERE id=?");
        retire.integer(1, row);
        retire.step();
    }
    Statement remove(store.db->value, "DELETE FROM certificates WHERE id=?");
    remove.integer(1, row);
    remove.step();
}

struct CloseFile { void operator()(FILE* file) const { std::fclose(file); } };
using FileHandle = std::unique_ptr<FILE, CloseFile>;
FileHandle open_material_file(const std::filesystem::path& path, bool write,
    bool shared = false, uid_t owner = geteuid()) {
    int fd = open(path.c_str(), (write ? O_WRONLY | O_CREAT | O_EXCL : O_RDONLY) | O_CLOEXEC | O_NOFOLLOW, shared ? 0644 : 0600);
    require(fd >= 0, errno == EACCES ? ERROR_ACCESS_DENIED : ERROR_GEN_FAILURE, "Cannot open certificate/key object file");
    if (write && shared && fchmod(fd, 0644) != 0) {
        close(fd);
        throw Error(ERROR_ACCESS_DENIED, "Cannot set public certificate-file permissions");
    }
    struct stat status{};
    bool safe = fstat(fd, &status) == 0 && S_ISREG(status.st_mode) && status.st_nlink == 1 &&
        (status.st_uid == owner || (shared && status.st_uid == 0)) &&
        (status.st_mode & (shared ? 022 : 077)) == 0;
    if (!safe) { close(fd); throw Error(ERROR_ACCESS_DENIED, "Object file must be private, regular and owned by the current user"); }
    FILE* file = fdopen(fd, write ? "wb" : "rb");
    if (!file) { close(fd); throw Error(ERROR_GEN_FAILURE, "Cannot open object file stream"); }
    return FileHandle(file);
}
void flush_file(FILE* file) {
    require(std::fflush(file) == 0 && fsync(fileno(file)) == 0, ERROR_GEN_FAILURE, "Cannot persist certificate/key object");
}
struct NewObject {
    std::filesystem::path path;
    Store* memory_store = nullptr;
    sqlite3_int64 memory_row = 0;
    bool committed = false;
    ~NewObject() {
        if (!committed && memory_store) memory_store->memory.erase(memory_row);
        if (!committed && !path.empty()) {
            try { erase_object(path); }
            catch (const std::exception& error) { std::fprintf(stderr, "sys-cert-store: object cleanup failed: %s\n", error.what()); }
        }
    }
};
std::string create_object(Store& store, Context& source, NewObject& pending) {
    auto id = object_id();
    auto directory = object_directory(store, id);
    require(mkdir(directory.c_str(), store.public_material ? 0755 : 0700) == 0, ERROR_GEN_FAILURE, "Cannot create certificate object directory");
    pending.path = directory;
    if (store.public_material)
        require(chmod(directory.c_str(), 0755) == 0, ERROR_ACCESS_DENIED, "Cannot set public certificate-directory permissions");
    {
        auto file = open_material_file(pending.path / "certificate.pem", true, store.public_material);
        require(PEM_write_X509(file.get(), source.certificate.get()) == 1, ERROR_GEN_FAILURE, "Cannot encode certificate file");
        flush_file(file.get());
    }
    if (source.private_key) {
        require(X509_check_private_key(source.certificate.get(), source.private_key.get()) == 1,
            ERROR_INVALID_DATA, "Private key does not match certificate");
        auto key_directory = pending.path;
        if (store.public_material) {
            key_directory /= "keys";
            private_directory(key_directory);
        }
        auto file = open_material_file(key_directory / "private-key.pem", true);
        require(PEM_write_PKCS8PrivateKey(file.get(), source.private_key.get(), nullptr, nullptr, 0, nullptr, nullptr) == 1,
            ERROR_GEN_FAILURE, "Cannot encode PKCS#8 key file");
        flush_file(file.get());
        if (store.public_material) flush_directory(key_directory);
    }
    flush_directory(pending.path);
    flush_directory(store.objects);
    return id;
}
std::unique_ptr<Context> load_context(Store& store, sqlite3_int64 row) {
    if (store.objects.empty()) {
        auto found = store.memory.find(row);
        require(found != store.memory.end(), ERROR_INVALID_DATA, "Missing memory-store certificate");
        auto result = std::make_unique<Context>(found->second.der);
        result->private_key = found->second.key;
        return result;
    }
    Statement query(store.db->value, "SELECT object FROM certificates WHERE id=?");
    query.integer(1, row);
    require(query.step(), CRYPT_E_NOT_FOUND, "Certificate object was removed");
    auto directory = object_directory(store, query.text_column(0));
    struct stat status{};
    require(lstat(directory.c_str(), &status) == 0 && S_ISDIR(status.st_mode) &&
        (status.st_uid == store.owner || (store.public_material && status.st_uid == 0)) &&
        (status.st_mode & (store.public_material ? 022 : 077)) == 0, ERROR_ACCESS_DENIED, "Unsafe certificate object directory");
    auto file = open_material_file(
        directory / "certificate.pem", false, store.public_material, store.owner);
    X509Ptr certificate(PEM_read_X509(file.get(), nullptr, nullptr, nullptr), X509_free);
    require(certificate != nullptr, ERROR_INVALID_DATA, "Invalid certificate PEM object");
    auto result = std::make_unique<Context>(encode_x509(certificate.get()));
    result->owner = store.owner;
    result->object_path = directory;
    auto key_path = directory / "private-key.pem";
    if (lstat((directory / "keys").c_str(), &status) == 0) {
        require(S_ISDIR(status.st_mode), ERROR_ACCESS_DENIED, "Unsafe private-key directory");
        result->key_path = directory / "keys/private-key.pem";
    } else {
        require(errno == ENOENT, ERROR_GEN_FAILURE, "Cannot inspect private-key directory");
        if (lstat(key_path.c_str(), &status) == 0) result->key_path = key_path;
        else require(errno == ENOENT, ERROR_GEN_FAILURE, "Cannot inspect private-key object");
    }
    return result;
}
void load_private_key(Context& context) {
    if (context.private_key || context.key_path.empty()) return;
    auto file = open_material_file(context.key_path, false, false, context.owner);
    SharedKey key(PEM_read_PrivateKey(file.get(), nullptr, [](char*, int, int, void*) { return 0; }, nullptr), EVP_PKEY_free);
    require(key && X509_check_private_key(context.certificate.get(), key.get()) == 1,
        ERROR_INVALID_DATA, "Invalid or mismatched PKCS#8 private-key object");
    context.private_key = std::move(key);
}

bool row_exists(Context& context) {
    if (!context.store || context.store->references == 0 || (context.view && context.view->references == 0)) return false;
    Statement query(context.store->db->value, "SELECT 1 FROM certificates WHERE id=?");
    query.integer(1, context.row);
    return query.step();
}
void refresh_properties(Context& context) {
    if (!row_exists(context)) return;
    Properties result;
    Statement query(context.store->db->value, "SELECT property,value FROM properties WHERE cert=? ORDER BY property");
    query.integer(1, context.row);
    while (query.step())
        result.emplace(static_cast<DWORD>(sqlite3_column_int64(query.value, 0)), query.blob_column(1));
    context.properties = std::move(result);
}
void snapshot_row(const std::shared_ptr<Store>& store, sqlite3_int64 row) {
    for (auto& [key, context] : contexts) {
        (void)key;
        if (context->store == store && context->row == row) refresh_properties(*context);
    }
}
void write_properties(Store& store, sqlite3_int64 row, const Properties& properties) {
    for (const auto& [id, data] : properties) {
        Statement insert(store.db->value, "INSERT OR REPLACE INTO properties(cert,property,value) VALUES(?,?,?)");
        insert.integer(1, row);
        insert.integer(2, id);
        insert.blob(3, data);
        insert.step();
    }
}
void materialize(Store& store, bool create = false);
void writable(Store& store) {
    require(!store.readonly, ERROR_ACCESS_DENIED, "Store is read-only; native stores require explicit SYS_CERT_STORE_NATIVE_WRITE_FLAG");
    materialize(store, true);
}
sqlite3_int64 insert_material(Store& store, Context& source, NewObject& pending) {
    auto object = store.objects.empty() ? std::string{} : create_object(store, source, pending);
    Statement insert(store.db->value, "INSERT INTO certificates(object) VALUES(?)");
    insert.text(1, object);
    insert.step();
    auto row = sqlite3_last_insert_rowid(store.db->value);
    if (store.objects.empty()) {
        pending.memory_store = &store;
        pending.memory_row = row;
        store.memory.emplace(row, Material{source.der, source.private_key});
    }
    return row;
}
void load_native(Store& store) {
    auto certificates = read_native(store.layout);
    auto replacement = std::make_unique<Database>(":memory:", false, true);
    std::map<sqlite3_int64, Material> material;
    Transaction transaction(*replacement);
    for (auto& der : certificates) {
        Context validate(der);
        Statement insert(replacement->value, "INSERT INTO certificates(object) VALUES('')");
        insert.step();
        material.emplace(sqlite3_last_insert_rowid(replacement->value), Material{std::move(der), {}});
    }
    transaction.commit();
    store.db = std::move(replacement);
    store.memory = std::move(material);
}
HCERTSTORE publish_store(std::shared_ptr<Store> store) {
    auto* result = store.get();
    stores.emplace(result, std::move(store));
    return result;
}

bool equal_blob(const CRYPT_DATA_BLOB& left, const CRYPT_DATA_BLOB& right) {
    require((left.pbData || left.cbData == 0) && (right.pbData || right.cbData == 0), E_INVALIDARG, "Invalid blob");
    return left.cbData == right.cbData &&
        (left.cbData == 0 || std::memcmp(left.pbData, right.pbData, left.cbData) == 0);
}
bool same_identity(Context& left, Context& right) {
    return X509_NAME_cmp(X509_get_issuer_name(left.certificate.get()), X509_get_issuer_name(right.certificate.get())) == 0 &&
        ASN1_INTEGER_cmp(X509_get0_serialNumber(left.certificate.get()), X509_get0_serialNumber(right.certificate.get())) == 0;
}
bool name_matches(X509_NAME* name, const CRYPT_DATA_BLOB& blob) {
    require(blob.pbData && blob.cbData, E_INVALIDARG, "Empty encoded name");
    const auto* cursor = blob.pbData;
    std::unique_ptr<X509_NAME, decltype(&X509_NAME_free)> parsed(
        d2i_X509_NAME(nullptr, &cursor, blob.cbData), X509_NAME_free);
    require(parsed && cursor == blob.pbData + blob.cbData, ERROR_INVALID_DATA, "Invalid encoded distinguished name");
    return X509_NAME_cmp(name, parsed.get()) == 0;
}
std::string lower_ascii(std::string input) {
    for (auto& ch : input) if (ch >= 'A' && ch <= 'Z') ch = static_cast<char>(ch + ('a' - 'A'));
    return input;
}
std::string simple_name(X509_NAME* name) {
    std::string result;
    for (int i = 0; i < X509_NAME_entry_count(name); ++i) {
        auto* entry = X509_NAME_get_entry(name, i);
        BYTE* output = nullptr;
        int size = ASN1_STRING_to_UTF8(&output, X509_NAME_ENTRY_get_data(entry));
        require(size >= 0, ERROR_INVALID_DATA, "Unable to decode certificate name");
        std::unique_ptr<BYTE, decltype([](BYTE* p) { OPENSSL_free(p); })> guard(output);
        if (!result.empty()) result += ", ";
        result.append(reinterpret_cast<const char*>(output), static_cast<std::size_t>(size));
    }
    return result;
}
bool supported_property(DWORD property) {
    return property == CERT_FRIENDLY_NAME_PROP_ID || property == CERT_DESCRIPTION_PROP_ID ||
        property == CERT_ARCHIVED_PROP_ID || property == CERT_KEY_IDENTIFIER_PROP_ID ||
        property == CERT_SHA1_HASH_PROP_ID || property == CERT_SHA256_HASH_PROP_ID || property == CERT_MD5_HASH_PROP_ID ||
        (property >= CERT_FIRST_USER_PROP_ID && property <= CERT_LAST_USER_PROP_ID);
}
Bytes property_value(Context& context, DWORD property) {
    require(supported_property(property), ERROR_NOT_SUPPORTED, "Certificate property is not supported");
    refresh_properties(context);
    auto found = context.properties.find(property);
    if (found != context.properties.end()) return found->second;
    const EVP_MD* algorithm = nullptr;
    if (property == CERT_SHA1_HASH_PROP_ID) algorithm = EVP_sha1();
    if (property == CERT_SHA256_HASH_PROP_ID) algorithm = EVP_sha256();
    if (property == CERT_MD5_HASH_PROP_ID) algorithm = EVP_md5();
    if (algorithm) {
        Bytes digest(static_cast<std::size_t>(EVP_MD_get_size(algorithm)));
        unsigned int size = 0;
        require(X509_digest(context.certificate.get(), algorithm, digest.data(), &size) == 1,
            ERROR_GEN_FAILURE, "Certificate digest computation failed");
        digest.resize(size);
        return digest;
    }
    if (property == CERT_KEY_IDENTIFIER_PROP_ID) {
        const auto* identifier = X509_get0_subject_key_id(context.certificate.get());
        if (identifier) return bytes(ASN1_STRING_get0_data(identifier), static_cast<std::size_t>(ASN1_STRING_length(identifier)));
        Bytes digest(20);
        unsigned int size = 0;
        require(X509_pubkey_digest(context.certificate.get(), EVP_sha1(), digest.data(), &size) == 1,
            ERROR_GEN_FAILURE, "Public-key identifier computation failed");
        digest.resize(size);
        return digest;
    }
    throw Error(CRYPT_E_NOT_FOUND, "Certificate property is not set");
}

void copy_out(const Bytes& value, void* data, DWORD* size) {
    require(size, E_INVALIDARG, "Null output size");
    DWORD capacity = *size;
    *size = count(value.size());
    if (!data) return;
    require(capacity >= value.size(), ERROR_MORE_DATA, "Output buffer is too small");
    if (!value.empty()) std::memcpy(data, value.data(), value.size());
}

bool matches(Context& candidate, DWORD type, const void* parameter) {
    auto* x = candidate.certificate.get();
    if (type == CERT_FIND_ANY) return true;
    require(parameter, E_INVALIDARG, "Null search parameter");
    switch (type) {
    case CERT_FIND_EXISTING: return same_identity(candidate, get_context(static_cast<PCCERT_CONTEXT>(parameter)));
    case CERT_FIND_SUBJECT_CERT: {
        const auto& id = *static_cast<const CERT_INFO*>(parameter);
        return equal_blob(candidate.info.SerialNumber, id.SerialNumber) && name_matches(X509_get_issuer_name(x), id.Issuer);
    }
    case CERT_FIND_ISSUER_OF:
        return X509_NAME_cmp(X509_get_subject_name(x),
            X509_get_issuer_name(get_context(static_cast<PCCERT_CONTEXT>(parameter)).certificate.get())) == 0;
    case CERT_FIND_SUBJECT_NAME: case CERT_FIND_ISSUER_NAME:
        return name_matches(type == CERT_FIND_SUBJECT_NAME ? X509_get_subject_name(x) : X509_get_issuer_name(x),
            *static_cast<const CRYPT_DATA_BLOB*>(parameter));
    case CERT_FIND_SUBJECT_STR_A: case CERT_FIND_SUBJECT_STR_W:
    case CERT_FIND_ISSUER_STR_A: case CERT_FIND_ISSUER_STR_W: {
        bool wide = type == CERT_FIND_SUBJECT_STR_W || type == CERT_FIND_ISSUER_STR_W;
        bool subject = type == CERT_FIND_SUBJECT_STR_A || type == CERT_FIND_SUBJECT_STR_W;
        auto needle = wide ? utf8(static_cast<LPCWSTR>(parameter)) : std::string(static_cast<LPCSTR>(parameter));
        auto haystack = simple_name(subject ? X509_get_subject_name(x) : X509_get_issuer_name(x));
        return lower_ascii(haystack).find(lower_ascii(needle)) != std::string::npos;
    }
    case CERT_FIND_SHA1_HASH: case CERT_FIND_SHA256_HASH: case CERT_FIND_MD5_HASH: case CERT_FIND_KEY_IDENTIFIER: {
        DWORD id = type == CERT_FIND_SHA1_HASH ? CERT_SHA1_HASH_PROP_ID :
            type == CERT_FIND_SHA256_HASH ? CERT_SHA256_HASH_PROP_ID :
            type == CERT_FIND_MD5_HASH ? CERT_MD5_HASH_PROP_ID : CERT_KEY_IDENTIFIER_PROP_ID;
        auto value = property_value(candidate, id);
        CRYPT_DATA_BLOB blob{count(value.size()), value.data()};
        return equal_blob(blob, *static_cast<const CRYPT_DATA_BLOB*>(parameter));
    }
    case CERT_FIND_PROPERTY: {
        DWORD id = *static_cast<const DWORD*>(parameter);
        require(supported_property(id), ERROR_NOT_SUPPORTED, "Search property is not supported");
        refresh_properties(candidate);
        return candidate.properties.contains(id);
    }
    default: throw Error(ERROR_NOT_SUPPORTED, "Certificate search type is not supported");
    }
}

void check_find_type(DWORD type) {
    switch (type) {
    case CERT_FIND_ANY: case CERT_FIND_EXISTING: case CERT_FIND_SUBJECT_CERT: case CERT_FIND_ISSUER_OF:
    case CERT_FIND_SUBJECT_NAME: case CERT_FIND_ISSUER_NAME: case CERT_FIND_SUBJECT_STR_A: case CERT_FIND_SUBJECT_STR_W:
    case CERT_FIND_ISSUER_STR_A: case CERT_FIND_ISSUER_STR_W: case CERT_FIND_SHA1_HASH: case CERT_FIND_SHA256_HASH:
    case CERT_FIND_MD5_HASH: case CERT_FIND_KEY_IDENTIFIER: case CERT_FIND_PROPERTY: return;
    default: throw Error(ERROR_NOT_SUPPORTED, "Certificate search type is not supported");
    }
}
PCCERT_CONTEXT find(HCERTSTORE handle, DWORD type, const void* parameter, PCCERT_CONTEXT previous) {
    auto store = get_store(handle);
    sqlite3_int64 after = 0;
    std::vector<std::shared_ptr<Store>> sources{store};
    sources.insert(sources.end(), store->inherited.begin(), store->inherited.end());
    std::size_t first = 0;
    if (previous) {
        auto& old = get_context(previous);
        require((old.view ? old.view : old.store) == store, E_INVALIDARG, "Previous context belongs to a different store");
        auto found = std::find(sources.begin(), sources.end(), old.store);
        require(found != sources.end(), E_INVALIDARG, "Previous context belongs to a removed physical store");
        first = static_cast<std::size_t>(found - sources.begin());
        after = old.row;
    }
    check_find_type(type);
    require(type == CERT_FIND_ANY || parameter, E_INVALIDARG, "Null search parameter");
    for (std::size_t i = first; i < sources.size(); ++i) {
        auto source = sources[i];
        materialize(*source);
        Statement query(source->db->value, "SELECT id FROM certificates WHERE id>? ORDER BY id");
        query.integer(1, i == first ? after : 0);
        while (query.step()) {
            auto row = sqlite3_column_int64(query.value, 0);
            auto candidate = load_context(*source, row);
            candidate->store = source;
            ++source->contexts;
            candidate->row = row;
            refresh_properties(*candidate);
            if (type == CERT_FIND_ANY && !store->archived && candidate->properties.contains(CERT_ARCHIVED_PROP_ID)) continue;
            if (!matches(*candidate, type, parameter)) continue;
            --source->contexts;
            candidate->store.reset();
            return publish(std::move(candidate), source, row, i == 0 ? nullptr : store);
        }
    }
    throw Error(CRYPT_E_NOT_FOUND, "No matching certificate");
}

std::string store_name(std::string name) {
    require(!name.empty() && name.size() <= 64, E_INVALIDARG, "Store name must contain 1 to 64 ASCII letters, digits, '-' or '_'");
    for (auto& ch : name) {
        if (ch >= 'a' && ch <= 'z') ch = static_cast<char>(ch - ('a' - 'A'));
        require((ch >= 'A' && ch <= 'Z') || (ch >= '0' && ch <= '9') || ch == '-' || ch == '_',
            E_INVALIDARG, "Invalid logical store name");
    }
    return name;
}
std::filesystem::path user_data_directory() {
    if (!system_paths.user.empty()) return system_paths.user;
    std::array<char, 16384> buffer{};
    passwd entry{};
    passwd* result = nullptr;
    require(getpwuid_r(geteuid(), &entry, buffer.data(), buffer.size(), &result) == 0 && result,
        ERROR_GEN_FAILURE, "Cannot resolve the current user's home directory");
    return std::filesystem::path(entry.pw_dir) / ".local/share/sys-cert-store";
}

std::unique_ptr<Database> open_database(const std::filesystem::path& path, DWORD flags, bool shared = false) {
    require(path.is_absolute(), E_INVALIDARG, "SQLite store path must be absolute");
    bool readonly = (flags & CERT_STORE_READONLY_FLAG) != 0;
    bool existing_only = (flags & CERT_STORE_OPEN_EXISTING_FLAG) != 0 || readonly;
    bool create_only = (flags & CERT_STORE_CREATE_NEW_FLAG) != 0;
    require(!(existing_only && create_only), E_INVALIDARG, "Conflicting store open flags");
    bool created = false;
    if (!existing_only) {
        int fd = open(path.c_str(), O_WRONLY | O_CREAT | O_EXCL | O_CLOEXEC | O_NOFOLLOW, shared ? 0644 : 0600);
        if (fd >= 0) {
            int permissions = shared ? fchmod(fd, 0644) : 0;
            close(fd);
            require(permissions == 0, ERROR_ACCESS_DENIED, "Cannot set public metadata-file permissions");
            created = true;
        }
        else if (errno != EEXIST) throw Error(errno == EACCES ? ERROR_ACCESS_DENIED : ERROR_GEN_FAILURE,
            "Cannot create SQLite store: " + std::string(std::strerror(errno)));
        else require(!create_only, CRYPT_E_EXISTS, "Store already exists");
    }
    struct stat status{};
    require(lstat(path.c_str(), &status) == 0, ERROR_FILE_NOT_FOUND, "SQLite store does not exist");
    require(S_ISREG(status.st_mode), ERROR_ACCESS_DENIED, "SQLite store must be a regular non-symlink file");
    return std::make_unique<Database>(path.string(), readonly, created);
}

void persistent_store(Store& store, const std::filesystem::path& path, DWORD flags) {
    store.db = open_database(path, flags, store.public_material);
    store.objects = path.string() + ".objects";
    if (!store.readonly) private_directory(store.objects, store.public_material);
    collect_garbage(store);
}

void materialize(Store& store, bool create) {
    if (store.pending_path.empty()) return;
    auto path = store.pending_path;
    if (std::filesystem::exists(path)) {
        persistent_store(store, path, store.readonly ? CERT_STORE_READONLY_FLAG : 0);
        store.pending_path.clear();
    } else if (create && !store.readonly) {
        if (std::filesystem::create_directories(path.parent_path()))
            std::filesystem::permissions(path.parent_path(), store.public_material ?
                std::filesystem::perms::owner_all | std::filesystem::perms::group_read |
                std::filesystem::perms::group_exec | std::filesystem::perms::others_read |
                std::filesystem::perms::others_exec : std::filesystem::perms::owner_all);
        persistent_store(store, path, 0);
        store.pending_path.clear();
    }
}
bool standard_store(const std::string& name) {
    return name == "ROOT" || name == "CA" || name == "MY";
}
void scoped_backing(Store& store, const std::filesystem::path& directory, DWORD flags) {
    auto path = directory / (store.name + ".db");
    if (!std::filesystem::exists(path) && std::filesystem::exists(directory)) {
        bool matched = false;
        for (const auto& entry : std::filesystem::directory_iterator(directory)) {
            if (entry.is_symlink() || !entry.is_regular_file() || entry.path().extension() != ".db") continue;
            if (store_name(entry.path().stem().string()) != store.name) continue;
            require(!matched, ERROR_INVALID_DATA, "Multiple metadata files map to the same system-store name");
            path = entry.path();
            matched = true;
        }
    }
    bool exists = std::filesystem::exists(path);
    require(!(standard_store(store.name) && (flags & CERT_STORE_CREATE_NEW_FLAG)), CRYPT_E_EXISTS,
        "Standard system store already exists");
    if (!exists && standard_store(store.name)) {
        store.db = std::make_unique<Database>(":memory:", false, true);
        store.pending_path = path;
        return;
    }
    if (!exists && !(flags & (CERT_STORE_READONLY_FLAG | CERT_STORE_OPEN_EXISTING_FLAG))) {
        if (std::filesystem::create_directories(directory))
            std::filesystem::permissions(directory, store.public_material ?
                std::filesystem::perms::owner_all | std::filesystem::perms::group_read |
                std::filesystem::perms::group_exec | std::filesystem::perms::others_read |
                std::filesystem::perms::others_exec : std::filesystem::perms::owner_all);
        private_directory(directory, store.public_material);
    }
    persistent_store(store, path, flags);
}
std::shared_ptr<Store> machine_backing(const std::string& name, DWORD flags) {
    auto store = std::make_shared<Store>();
    store->name = name;
    store->location = CERT_SYSTEM_STORE_LOCAL_MACHINE;
    store->readonly = (flags & CERT_STORE_READONLY_FLAG) != 0;
    store->public_material = true;
    if (name == "ROOT") {
        store->native = true;
        store->readonly = !(flags & SYS_CERT_STORE_NATIVE_WRITE_FLAG);
        auto root = system_paths.root.string();
        SYS_CERT_NATIVE_OPTIONS options{sizeof(options), root.c_str()};
        store->layout = native_layout(&options);
        load_native(*store);
    } else scoped_backing(*store, system_paths.machine, flags);
    return store;
}

HCERTSTORE open_store(LPCSTR provider, DWORD encoding, HCRYPTPROV_LEGACY legacy, DWORD flags, const void* parameter) {
    require(legacy == 0, ERROR_NOT_SUPPORTED, "Legacy cryptographic providers are unsupported");
    require(encoding == 0 || encoding == X509_ASN_ENCODING || encoding == (X509_ASN_ENCODING | PKCS_7_ASN_ENCODING),
        ERROR_NOT_SUPPORTED, "Unsupported store encoding");
    constexpr DWORD allowed = CERT_STORE_READONLY_FLAG | CERT_STORE_OPEN_EXISTING_FLAG |
        CERT_STORE_CREATE_NEW_FLAG | CERT_STORE_ENUM_ARCHIVED_FLAG | 0xff0000 | SYS_CERT_STORE_NATIVE_WRITE_FLAG;
    require((flags & ~allowed) == 0, ERROR_NOT_SUPPORTED, "Unsupported store open flags");
    require(!((flags & CERT_STORE_CREATE_NEW_FLAG) && (flags & CERT_STORE_OPEN_EXISTING_FLAG)),
        E_INVALIDARG, "Conflicting store open flags");
    auto result = std::make_shared<Store>();
    result->readonly = (flags & CERT_STORE_READONLY_FLAG) != 0;
    bool native_write = (flags & SYS_CERT_STORE_NATIVE_WRITE_FLAG) != 0;
    require(!(native_write && result->readonly), E_INVALIDARG, "Conflicting native-write and read-only flags");
    result->archived = (flags & CERT_STORE_ENUM_ARCHIVED_FLAG) != 0;
    auto id = reinterpret_cast<std::uintptr_t>(provider);
    if (id > 0xffff && std::strcmp(provider, "Memory") == 0) id = 2;
    if (id > 0xffff && std::strcmp(provider, "System") == 0) id = 10;
    if (id == 2) {
        require(!parameter && !(flags & 0xff0000) && !native_write, E_INVALIDARG, "Invalid memory store parameters");
        require(!(flags & CERT_STORE_OPEN_EXISTING_FLAG), ERROR_NOT_SUPPORTED, "Memory stores cannot open existing storage");
        result->db = std::make_unique<Database>(":memory:", false, true);
    } else if (id == 9 || id == 10) {
        require(parameter, E_INVALIDARG, "Missing system store name");
        auto name = store_name(id == 10 ? utf8(static_cast<LPCWSTR>(parameter)) : static_cast<LPCSTR>(parameter));
        DWORD location = flags & 0xff0000;
        require(location == CERT_SYSTEM_STORE_CURRENT_USER || location == CERT_SYSTEM_STORE_LOCAL_MACHINE,
            ERROR_NOT_SUPPORTED, "Only current-user and local-machine locations are supported");
        require(!(native_write && (location != CERT_SYSTEM_STORE_LOCAL_MACHINE || name != "ROOT")),
            E_INVALIDARG, "Native-write flag is only valid for computer ROOT");
        require(!(standard_store(name) && (flags & CERT_STORE_CREATE_NEW_FLAG)), CRYPT_E_EXISTS, "Standard system store already exists");
        if (location == CERT_SYSTEM_STORE_LOCAL_MACHINE) {
            result = machine_backing(name, flags);
            result->archived = (flags & CERT_STORE_ENUM_ARCHIVED_FLAG) != 0;
        } else {
            result->name = name;
            result->location = location;
            scoped_backing(*result, user_data_directory(), flags);
            if (name == "ROOT" || name == "CA")
                result->inherited.push_back(machine_backing(name, CERT_STORE_READONLY_FLAG));
        }
    } else if (id > 0xffff && std::strcmp(provider, SYS_CERT_STORE_PROV_SQLITE) == 0) {
        require(parameter && !(flags & 0xff0000) && !native_write, E_INVALIDARG, "SQLite provider requires an absolute UTF-8 path and no location/native flags");
        persistent_store(*result, static_cast<LPCSTR>(parameter), flags);
    } else if (id > 0xffff && std::strcmp(provider, SYS_CERT_STORE_PROV_NATIVE) == 0) {
        require(!(flags & (0xff0000 | CERT_STORE_CREATE_NEW_FLAG)), E_INVALIDARG, "Invalid native store flags");
        result->native = true;
        result->readonly = !native_write;
        result->layout = native_layout(static_cast<const SYS_CERT_NATIVE_OPTIONS*>(parameter));
        load_native(*result);
    } else throw Error(ERROR_NOT_SUPPORTED, "Store provider is not supported");
    return publish_store(std::move(result));
}

PCCERT_CONTEXT add(Store& store, std::shared_ptr<Store> owner, Context& source, DWORD disposition, bool output) {
    writable(store);
    require(!source.view || source.key_path.empty(), ERROR_ACCESS_DENIED,
        "Inherited certificate views do not grant access to machine private keys");
    load_private_key(source);
    require(disposition >= 1 && disposition <= 7, E_INVALIDARG, "Invalid certificate add disposition");
    refresh_properties(source);
    Transaction transaction(*store.db);
    NewObject pending;
    std::unique_ptr<Context> existing;
    sqlite3_int64 old_row = 0;
    if (disposition != CERT_STORE_ADD_ALWAYS) {
        Statement query(store.db->value, "SELECT id FROM certificates ORDER BY id");
        while (query.step()) {
            auto candidate = load_context(store, sqlite3_column_int64(query.value, 0));
            if (!same_identity(*candidate, source)) continue;
            old_row = sqlite3_column_int64(query.value, 0);
            candidate->store = owner;
            ++store.contexts;
            candidate->row = old_row;
            refresh_properties(*candidate);
            existing = std::move(candidate);
            break;
        }
    }
    if (existing) {
        require(disposition != CERT_STORE_ADD_NEW, CRYPT_E_EXISTS, "Certificate already exists");
        if (disposition == CERT_STORE_ADD_NEWER || disposition == CERT_STORE_ADD_NEWER_INHERIT_PROPERTIES)
            require(ASN1_TIME_compare(X509_get0_notBefore(source.certificate.get()),
                X509_get0_notBefore(existing->certificate.get())) == 1, CRYPT_E_EXISTS, "Existing certificate is not older");
    }
    if (store.native) {
        require(!source.private_key, ERROR_NOT_SUPPORTED, "Private keys cannot be installed into the system ROOT store");
        require(source.properties.empty(), ERROR_NOT_SUPPORTED, "Native ROOT certificate properties are not persisted in this release");
        require(disposition != CERT_STORE_ADD_ALWAYS, ERROR_NOT_SUPPORTED, "Native trust anchors are unique; use ADD_NEW or ADD_REPLACE_EXISTING");
        require(!existing || source.der == existing->der, ERROR_NOT_SUPPORTED,
            "Replacing a native root with different certificate bytes requires explicit deletion first");
        if (!existing) update_anchor(source.certificate.get(), true, store.layout);
    }
    Properties properties = source.properties;
    bool use_existing = existing && (disposition == CERT_STORE_ADD_USE_EXISTING ||
        disposition == CERT_STORE_ADD_REPLACE_EXISTING_INHERIT_PROPERTIES);
    if (existing && (disposition == CERT_STORE_ADD_REPLACE_EXISTING_INHERIT_PROPERTIES ||
        disposition == CERT_STORE_ADD_NEWER_INHERIT_PROPERTIES || use_existing)) {
        auto merged = existing->properties;
        for (const auto& [id, value] : properties) merged[id] = value;
        properties = std::move(merged);
    }
    sqlite3_int64 row = old_row;
    if (!use_existing || (source.private_key && !store.objects.empty())) {
        if (existing) {
            snapshot_row(owner, old_row);
            retire_row(store, old_row);
        }
        Context material(use_existing ? existing->der : source.der);
        if (existing && !source.private_key) load_private_key(*existing);
        material.private_key = source.private_key ? source.private_key : (existing ? existing->private_key : SharedKey{});
        row = insert_material(store, material, pending);
    } else if (source.private_key && store.objects.empty()) {
        store.memory.at(row).key = source.private_key;
    }
    write_properties(store, row, properties);
    std::unique_ptr<Context> result;
    if (output) {
        result = load_context(store, row);
        result->properties = properties;
    }
    transaction.commit();
    pending.committed = true;
    if (existing && row != old_row) store.memory.erase(old_row);
    collect_garbage(store);
    return output ? publish(std::move(result), std::move(owner), row) : nullptr;
}

struct PfxBagCount { unsigned keys = 0; unsigned certificates = 0; };
void inspect_bags(const STACK_OF(PKCS12_SAFEBAG)* bags, PfxBagCount& count, unsigned depth) {
    require(depth < 16, ERROR_INVALID_DATA, "PKCS#12 safe nesting is too deep");
    for (int i = 0; i < sk_PKCS12_SAFEBAG_num(bags); ++i) {
        auto* bag = sk_PKCS12_SAFEBAG_value(bags, i);
        switch (PKCS12_SAFEBAG_get_nid(bag)) {
        case NID_keyBag: case NID_pkcs8ShroudedKeyBag: ++count.keys; break;
        case NID_certBag:
            require(PKCS12_SAFEBAG_get_bag_nid(bag) == NID_x509Certificate, ERROR_NOT_SUPPORTED, "Unsupported PKCS#12 certificate bag");
            ++count.certificates;
            break;
        case NID_safeContentsBag: inspect_bags(PKCS12_SAFEBAG_get0_safes(bag), count, depth + 1); break;
        default: throw Error(ERROR_NOT_SUPPORTED, "Unsupported PKCS#12 bag; import would lose data");
        }
    }
}
std::vector<std::unique_ptr<Context>> parse_pfx(const CRYPT_DATA_BLOB* blob, LPCWSTR password, DWORD flags) {
    require((flags & ~(CRYPT_EXPORTABLE | CRYPT_USER_KEYSET | CRYPT_MACHINE_KEYSET)) == 0, ERROR_NOT_SUPPORTED,
        "Only user/computer-keyset, filesystem-protected PKCS#12 imports are supported");
    require(!((flags & CRYPT_USER_KEYSET) && (flags & CRYPT_MACHINE_KEYSET)), E_INVALIDARG, "Conflicting PKCS#12 keyset flags");
    require(blob && blob->pbData && blob->cbData, E_INVALIDARG, "Empty PKCS#12 input");
    auto secret = password ? utf8(password) : std::string{};
    struct Cleanse { std::string& value; ~Cleanse() { OPENSSL_cleanse(value.data(), value.size()); } } cleanse{secret};
    require(secret.size() <= static_cast<std::size_t>(INT_MAX), E_INVALIDARG, "PKCS#12 password is too long");
    const BYTE* cursor = blob->pbData;
    std::unique_ptr<PKCS12, decltype(&PKCS12_free)> pfx(d2i_PKCS12(nullptr, &cursor, blob->cbData), PKCS12_free);
    require(pfx && cursor == blob->pbData + blob->cbData, ERROR_INVALID_DATA, "Invalid PKCS#12 encoding or trailing bytes");
    require(PKCS12_mac_present(pfx.get()), ERROR_NOT_SUPPORTED, "Unauthenticated PKCS#12 input is not supported");
    const char* pass = secret.c_str();
    if (PKCS12_verify_mac(pfx.get(), pass, static_cast<int>(secret.size())) != 1) {
        require(secret.empty() && PKCS12_verify_mac(pfx.get(), nullptr, 0) == 1,
            ERROR_INVALID_DATA, "PKCS#12 password or integrity check failed");
        pass = nullptr;
    }
    auto free_safes = [](STACK_OF(PKCS7)* value) { sk_PKCS7_pop_free(value, PKCS7_free); };
    std::unique_ptr<STACK_OF(PKCS7), decltype(free_safes)> safes(PKCS12_unpack_authsafes(pfx.get()), free_safes);
    require(safes != nullptr, ERROR_INVALID_DATA, "Invalid PKCS#12 authenticated safes");
    PfxBagCount count;
    for (int i = 0; i < sk_PKCS7_num(safes.get()); ++i) {
        auto* safe = sk_PKCS7_value(safes.get(), i);
        require(PKCS7_type_is_data(safe) || PKCS7_type_is_encrypted(safe), ERROR_NOT_SUPPORTED, "Unsupported PKCS#12 safe type");
        auto free_bags = [](STACK_OF(PKCS12_SAFEBAG)* value) { sk_PKCS12_SAFEBAG_pop_free(value, PKCS12_SAFEBAG_free); };
        std::unique_ptr<STACK_OF(PKCS12_SAFEBAG), decltype(free_bags)> bags(
            PKCS7_type_is_data(safe) ? PKCS12_unpack_p7data(safe) :
                PKCS12_unpack_p7encdata(safe, pass, static_cast<int>(secret.size())), free_bags);
        require(bags != nullptr, ERROR_INVALID_DATA, "Cannot decrypt PKCS#12 safe");
        inspect_bags(bags.get(), count, 0);
    }
    require(count.keys <= 1, ERROR_NOT_SUPPORTED, "Multiple private keys in one PKCS#12 file are not supported");
    EVP_PKEY* raw_key = nullptr;
    X509* raw_leaf = nullptr;
    STACK_OF(X509)* raw_chain = nullptr;
    int parsed = PKCS12_parse(pfx.get(), pass, &raw_key, &raw_leaf, &raw_chain);
    SharedKey key(raw_key, EVP_PKEY_free);
    X509Ptr leaf(raw_leaf, X509_free);
    auto free_chain = [](STACK_OF(X509)* value) { sk_X509_pop_free(value, X509_free); };
    std::unique_ptr<STACK_OF(X509), decltype(free_chain)> chain(raw_chain, free_chain);
    require(parsed == 1, ERROR_INVALID_DATA, "Cannot parse PKCS#12 certificate/key contents");
    require(!key || (leaf && X509_check_private_key(leaf.get(), key.get()) == 1), ERROR_INVALID_DATA, "PKCS#12 key has no matching certificate");
    std::vector<std::unique_ptr<Context>> result;
    if (leaf) {
        auto context = std::make_unique<Context>(encode_x509(leaf.get()));
        context->private_key = key;
        result.push_back(std::move(context));
    }
    for (int i = 0; i < sk_X509_num(chain.get()); ++i)
        result.push_back(std::make_unique<Context>(encode_x509(sk_X509_value(chain.get(), i))));
    require(!result.empty() && result.size() == count.certificates && count.keys == (key ? 1u : 0u),
        ERROR_NOT_SUPPORTED, "PKCS#12 contains material that cannot be preserved by this importer");
    return result;
}
void import_pfx(Store& store, std::vector<std::unique_ptr<Context>>& certificates) {
    writable(store);
    require(!store.objects.empty() && !store.native, ERROR_NOT_SUPPORTED, "PKCS#12 imports require a file-backed logical store");
    std::vector<std::unique_ptr<NewObject>> objects;
    Transaction transaction(*store.db);
    for (const auto& context : certificates) {
        auto pending = std::make_unique<NewObject>();
        insert_material(store, *context, *pending);
        objects.push_back(std::move(pending));
    }
    transaction.commit();
    for (auto& object : objects) object->committed = true;
}
std::vector<std::unique_ptr<Context>> export_contexts(Store& store, bool load_keys) {
    std::vector<std::unique_ptr<Context>> result;
    auto append = [&](Store& source) {
        materialize(source);
        Statement query(source.db->value, "SELECT id FROM certificates ORDER BY id");
        while (query.step()) {
            auto context = load_context(source, sqlite3_column_int64(query.value, 0));
            if (load_keys) load_private_key(*context);
            result.push_back(std::move(context));
        }
    };
    append(store);
    for (const auto& source : store.inherited) append(*source);
    require(!result.empty(), CRYPT_E_NOT_FOUND, "Certificate store is empty");
    return result;
}
Bytes encode_pfx(Store& store, LPCWSTR password, DWORD flags) {
    constexpr DWORD supported = REPORT_NO_PRIVATE_KEY |
        REPORT_NOT_ABLE_TO_EXPORT_PRIVATE_KEY | EXPORT_PRIVATE_KEYS;
    require((flags & ~supported) == 0, ERROR_NOT_SUPPORTED, "PKCS#12 export flags are unsupported");
    bool inspect_keys = (flags & supported) != 0;
    auto contexts = export_contexts(store, inspect_keys);
    std::vector<std::size_t> key_indices;
    for (std::size_t i = 0; i < contexts.size(); ++i)
        if (contexts[i]->private_key) key_indices.push_back(i);
    bool export_key = (flags & EXPORT_PRIVATE_KEYS) != 0;
    if (export_key) {
        require(!key_indices.empty(), CRYPT_E_NOT_FOUND, "Certificate store contains no private key");
        require(key_indices.size() == 1, ERROR_NOT_SUPPORTED,
            "PKCS#12 export with multiple private keys is unsupported");
    }

    auto secret = password ? utf8(password) : std::string{};
    struct CleanseString {
        std::string& value;
        ~CleanseString() { OPENSSL_cleanse(value.data(), value.size()); }
    } cleanse_secret{secret};
    require(secret.size() <= static_cast<std::size_t>(INT_MAX), E_INVALIDARG, "PKCS#12 password is too long");

    auto free_chain = [](STACK_OF(X509)* value) { sk_X509_free(value); };
    std::unique_ptr<STACK_OF(X509), decltype(free_chain)> chain(sk_X509_new_null(), free_chain);
    require(chain != nullptr, ERROR_NOT_ENOUGH_MEMORY, "Cannot allocate PKCS#12 certificate stack");
    std::size_t primary = export_key ? key_indices.front() : contexts.size();
    for (std::size_t i = 0; i < contexts.size(); ++i) {
        if (i == primary) continue;
        require(sk_X509_push(chain.get(), contexts[i]->certificate.get()) != 0,
            ERROR_NOT_ENOUGH_MEMORY, "Cannot add certificate to PKCS#12 export");
    }
    EVP_PKEY* key = export_key ? contexts[primary]->private_key.get() : nullptr;
    X509* certificate = export_key ? contexts[primary]->certificate.get() : nullptr;
    std::unique_ptr<PKCS12, decltype(&PKCS12_free)> pfx(
        PKCS12_create(secret.c_str(), export_key ? "sys-cert-store" : nullptr, key, certificate, chain.get(),
            NID_aes_256_cbc, NID_aes_256_cbc, 0, 0, 0), PKCS12_free);
    require(pfx != nullptr, ERROR_GEN_FAILURE, "Cannot create PKCS#12 export");
    int size = i2d_PKCS12(pfx.get(), nullptr);
    require(size > 0, ERROR_GEN_FAILURE, "Cannot encode PKCS#12 export");
    Bytes encoded(static_cast<std::size_t>(size));
    auto* cursor = encoded.data();
    require(i2d_PKCS12(pfx.get(), &cursor) == size, ERROR_GEN_FAILURE, "Cannot encode PKCS#12 export");
    return encoded;
}
} // namespace

Bytes encode_x509(X509* certificate) {
    int length = i2d_X509(certificate, nullptr);
    require(length > 0, ERROR_INVALID_DATA, "Cannot encode certificate");
    Bytes result(static_cast<std::size_t>(length));
    auto* cursor = result.data();
    require(i2d_X509(certificate, &cursor) == length, ERROR_INVALID_DATA, "Cannot encode certificate");
    return result;
}
void initialize_api() { with_api_lock([] {}); }
void report_api_failure(DWORD code, const char* message) noexcept { report(code, message); }
std::filesystem::path current_user_store_directory() {
    return with_api_lock([] { return user_data_directory(); });
}
std::vector<Bytes> read_user_store_certificates(
    const std::filesystem::path& directory, uid_t owner) {
    return with_api_lock([&] {
        std::vector<Bytes> result;
        for (const auto* name : {"MY", "CA", "ROOT"}) {
            Store store;
            store.name = name;
            store.location = CERT_SYSTEM_STORE_CURRENT_USER;
            store.readonly = true;
            store.owner = owner;
            scoped_backing(store, directory, CERT_STORE_READONLY_FLAG);
            materialize(store);
            Statement query(store.db->value, "SELECT id FROM certificates ORDER BY id");
            while (query.step()) {
                auto certificate = load_context(
                    store, sqlite3_column_int64(query.value, 0));
                result.push_back(certificate->der);
            }
        }
        return result;
    });
}
} // namespace scs

using namespace scs;

extern "C" {
DWORD GetLastError() noexcept { return last_error; }
void SetLastError(DWORD error) noexcept { report(error, ""); }
const char* SysCertGetLastErrorMessage() noexcept { return last_message.data(); }

BOOL SysCertConfigureSystemStores(const SYS_CERT_STORE_CONFIGURATION* configuration) noexcept {
    return boundary<BOOL>(FALSE, [&] {
        require(stores.empty() && contexts.empty(), ERROR_BUSY, "Close all stores and contexts before changing system-store paths");
        SystemPaths updated;
        if (configuration) {
            require(configuration->cbSize == sizeof(*configuration), E_INVALIDARG, "Invalid system-store configuration size");
            auto path = [](const char* value, const std::filesystem::path& fallback) {
                if (!value) return fallback;
                std::filesystem::path result(value);
                require(result.is_absolute(), E_INVALIDARG, "System-store paths must be absolute");
                return result.lexically_normal();
            };
            updated.user = path(configuration->userStoreDirectory, {});
            updated.machine = path(configuration->machineStoreDirectory, updated.machine);
            updated.root = path(configuration->systemRoot, updated.root);
            require(updated.user.empty() || updated.user != updated.machine, E_INVALIDARG,
                "User and computer store directories must differ");
        }
        system_paths = std::move(updated);
        return TRUE;
    });
}
BOOL SysCertGetCertificateStoreLocation(PCCERT_CONTEXT certificate, DWORD* location) noexcept {
    return boundary<BOOL>(FALSE, [&] {
        require(location, E_INVALIDARG, "Missing store-location output");
        auto& context = get_context(certificate);
        require(context.store && context.store->location, ERROR_NOT_SUPPORTED, "Context does not belong to a scoped system store");
        *location = context.store->location;
        return TRUE;
    });
}
BOOL CertEnumSystemStoreLocation(DWORD flags, void* argument, PFN_CERT_ENUM_SYSTEM_STORE_LOCATION callback) noexcept {
    return api_boundary<BOOL>(FALSE, [&] {
        require(flags == 0, ERROR_NOT_SUPPORTED, "System-store location enumeration flags are unsupported");
        require(callback, E_INVALIDARG, "Missing location enumeration callback");
        if (!callback(L"CurrentUser", CERT_SYSTEM_STORE_CURRENT_USER, nullptr, argument)) return FALSE;
        return callback(L"LocalMachine", CERT_SYSTEM_STORE_LOCAL_MACHINE, nullptr, argument) ? TRUE : FALSE;
    });
}
BOOL CertEnumSystemStore(DWORD flags, void* locationParameter, void* argument, PFN_CERT_ENUM_SYSTEM_STORE callback) noexcept {
    return api_boundary<BOOL>(FALSE, [&] {
        require(flags == CERT_SYSTEM_STORE_CURRENT_USER || flags == CERT_SYSTEM_STORE_LOCAL_MACHINE,
            ERROR_NOT_SUPPORTED, "Only current-user and computer store enumeration is supported");
        require(!locationParameter, ERROR_NOT_SUPPORTED, "Remote and relocated Win32 enumeration parameters are unsupported");
        require(callback, E_INVALIDARG, "Missing store enumeration callback");
        std::set<std::string> names{"ROOT", "CA", "MY"};
        auto directory = with_api_lock([&] {
            return flags == CERT_SYSTEM_STORE_CURRENT_USER ? user_data_directory() : system_paths.machine;
        });
        if (std::filesystem::exists(directory)) {
            for (const auto& entry : std::filesystem::directory_iterator(directory)) {
                if (entry.is_symlink() || !entry.is_regular_file() || entry.path().extension() != ".db") continue;
                names.insert(store_name(entry.path().stem().string()));
            }
        }
        CERT_SYSTEM_STORE_INFO information{sizeof(information)};
        for (const auto& name : names) {
            std::wstring wide(name.begin(), name.end());
            if (!callback(wide.c_str(), flags, &information, nullptr, argument)) return FALSE;
        }
        return TRUE;
    });
}

HCERTSTORE CertOpenStore(LPCSTR provider, DWORD encoding, HCRYPTPROV_LEGACY legacy, DWORD flags, const void* parameter) noexcept {
    return boundary<HCERTSTORE>(nullptr, [&] { return open_store(provider, encoding, legacy, flags, parameter); });
}
HCERTSTORE CertOpenSystemStoreW(HCRYPTPROV_LEGACY legacy, LPCWSTR name) noexcept {
    return CertOpenStore(CERT_STORE_PROV_SYSTEM_W, 0, legacy, CERT_SYSTEM_STORE_CURRENT_USER, name);
}
HCERTSTORE CertOpenSystemStoreA(HCRYPTPROV_LEGACY legacy, LPCSTR name) noexcept {
    return CertOpenStore(CERT_STORE_PROV_SYSTEM_A, 0, legacy, CERT_SYSTEM_STORE_CURRENT_USER, name);
}
HCERTSTORE CertDuplicateStore(HCERTSTORE store) noexcept {
    return boundary<HCERTSTORE>(nullptr, [&] { ++get_store(store)->references; return store; });
}
BOOL CertCloseStore(HCERTSTORE handle, DWORD flags) noexcept {
    return boundary<BOOL>(FALSE, [&] {
        auto store = get_store(handle);
        require((flags & ~CERT_CLOSE_STORE_CHECK_FLAG) == 0, ERROR_NOT_SUPPORTED, "Forced close is not supported");
        bool pending = store->contexts != 0;
        if (store->references == 1) {
            for (auto& [key, context] : contexts) {
                (void)key;
                if (context->store == store || context->view == store) refresh_properties(*context);
            }
        }
        if (--store->references == 0) stores.erase(handle);
        require(!(pending && (flags & CERT_CLOSE_STORE_CHECK_FLAG)), CRYPT_E_PENDING_CLOSE, "Store closed with outstanding contexts");
        return TRUE;
    });
}
PCCERT_CONTEXT CertCreateCertificateContext(DWORD encoding, const BYTE* encoded, DWORD size) noexcept {
    return boundary<PCCERT_CONTEXT>(nullptr, [&] {
        encoding_check(encoding);
        return publish(std::make_unique<Context>(bytes(encoded, size)));
    });
}
PCCERT_CONTEXT CertDuplicateCertificateContext(PCCERT_CONTEXT context) noexcept {
    return boundary<PCCERT_CONTEXT>(nullptr, [&] { ++get_context(context).references; return context; });
}
BOOL CertFreeCertificateContext(PCCERT_CONTEXT context) noexcept {
    return boundary<BOOL>(FALSE, [&] { release(context); return TRUE; });
}
PCCERT_CONTEXT CertEnumCertificatesInStore(HCERTSTORE store, PCCERT_CONTEXT previous) noexcept {
    return CertFindCertificateInStore(store, X509_ASN_ENCODING, 0, CERT_FIND_ANY, nullptr, previous);
}
PCCERT_CONTEXT CertFindCertificateInStore(HCERTSTORE store, DWORD encoding, DWORD flags,
    DWORD type, const void* parameter, PCCERT_CONTEXT previous) noexcept {
    return boundary<PCCERT_CONTEXT>(nullptr, [&] {
        Consume consume(previous);
        encoding_check(encoding);
        require(flags == 0, ERROR_NOT_SUPPORTED, "Find flags are unsupported");
        return find(store, type, parameter, previous);
    });
}
PCCERT_CONTEXT CertGetSubjectCertificateFromStore(HCERTSTORE store, DWORD encoding, PCERT_INFO id) noexcept {
    return CertFindCertificateInStore(store, encoding, 0, CERT_FIND_SUBJECT_CERT, id, nullptr);
}
PCCERT_CONTEXT CertGetIssuerCertificateFromStore(HCERTSTORE handle, PCCERT_CONTEXT subject,
    PCCERT_CONTEXT previous, DWORD* flags) noexcept {
    return boundary<PCCERT_CONTEXT>(nullptr, [&]() -> PCCERT_CONTEXT {
        Consume consume(previous);
        require(flags, E_INVALIDARG, "Missing issuer verification flags");
        require((*flags & ~(CERT_STORE_SIGNATURE_FLAG | CERT_STORE_TIME_VALIDITY_FLAG)) == 0,
            ERROR_NOT_SUPPORTED, "Only signature and validity issuer checks are supported");
        auto& source = get_context(subject);
        auto* x = source.certificate.get();
        auto* subject_key = X509_get0_pubkey(x);
        require(X509_NAME_cmp(X509_get_subject_name(x), X509_get_issuer_name(x)) != 0 ||
            !subject_key || X509_verify(x, subject_key) != 1, CRYPT_E_SELF_SIGNED, "Subject is self-signed");
        PCCERT_CONTEXT result = nullptr;
        try { result = find(handle, CERT_FIND_ISSUER_OF, subject, previous); }
        catch (const Error& error) {
            if (error.code == CRYPT_E_NOT_FOUND && (*flags & CERT_STORE_SIGNATURE_FLAG)) *flags |= CERT_STORE_NO_ISSUER_FLAG;
            throw;
        }
        auto* issuer = get_context(result).certificate.get();
        auto* issuer_key = X509_get0_pubkey(issuer);
        if ((*flags & CERT_STORE_SIGNATURE_FLAG) && issuer_key && X509_verify(x, issuer_key) == 1)
            *flags &= ~CERT_STORE_SIGNATURE_FLAG;
        if ((*flags & CERT_STORE_TIME_VALIDITY_FLAG) && X509_cmp_current_time(X509_get0_notBefore(x)) < 0 &&
            X509_cmp_current_time(X509_get0_notAfter(x)) > 0)
            *flags &= ~CERT_STORE_TIME_VALIDITY_FLAG;
        return result;
    });
}
BOOL CertAddCertificateContextToStore(HCERTSTORE handle, PCCERT_CONTEXT context, DWORD disposition, PCCERT_CONTEXT* result) noexcept {
    if (result) *result = nullptr;
    return boundary<BOOL>(FALSE, [&] {
        auto store = get_store(handle);
        auto added = add(*store, store, get_context(context), disposition, result != nullptr);
        if (result) *result = added;
        return TRUE;
    });
}
BOOL CertAddEncodedCertificateToStore(HCERTSTORE handle, DWORD encoding, const BYTE* encoded,
    DWORD size, DWORD disposition, PCCERT_CONTEXT* result) noexcept {
    if (result) *result = nullptr;
    return boundary<BOOL>(FALSE, [&] {
        encoding_check(encoding);
        Context source(bytes(encoded, size));
        auto store = get_store(handle);
        auto added = add(*store, store, source, disposition, result != nullptr);
        if (result) *result = added;
        return TRUE;
    });
}
BOOL CertDeleteCertificateFromStore(PCCERT_CONTEXT context) noexcept {
    return boundary<BOOL>(FALSE, [&] {
        Consume consume(context);
        auto& source = get_context(context);
        require(source.store != nullptr, E_INVALIDARG, "Certificate does not belong to a store");
        require(!source.view, ERROR_ACCESS_DENIED, "Inherited computer certificates must be modified through the computer store");
        require(source.store->references != 0, ERROR_INVALID_HANDLE, "Certificate store is closed");
        writable(*source.store);
        snapshot_row(source.store, source.row);
        if (source.store->native) remove_trusted_certificate(source.certificate.get(), source.store->layout);
        Transaction transaction(*source.store->db);
        retire_row(*source.store, source.row);
        transaction.commit();
        source.store->memory.erase(source.row);
        collect_garbage(*source.store);
        return TRUE;
    });
}
BOOL CertGetCertificateContextProperty(PCCERT_CONTEXT context, DWORD property, void* data, DWORD* size) noexcept {
    return boundary<BOOL>(FALSE, [&] { copy_out(property_value(get_context(context), property), data, size); return TRUE; });
}
BOOL CertSetCertificateContextProperty(PCCERT_CONTEXT context, DWORD property, DWORD flags, const void* data) noexcept {
    return boundary<BOOL>(FALSE, [&] {
        require(flags == 0, ERROR_NOT_SUPPORTED, "Property flags are unsupported");
        require(supported_property(property), ERROR_NOT_SUPPORTED, "Certificate property is unsupported");
        require(property != CERT_SHA1_HASH_PROP_ID && property != CERT_SHA256_HASH_PROP_ID && property != CERT_MD5_HASH_PROP_ID,
            ERROR_NOT_SUPPORTED, "Computed certificate hashes cannot be overridden");
        auto& target = get_context(context);
        require(!target.view, ERROR_ACCESS_DENIED, "Inherited computer certificate properties are read-only in a user view");
        refresh_properties(target);
        auto updated = target.properties;
        if (!data) updated.erase(property);
        else {
            const auto& blob = *static_cast<const CRYPT_DATA_BLOB*>(data);
            auto value = bytes(blob.pbData, blob.cbData);
            if (property == CERT_FRIENDLY_NAME_PROP_ID || property == CERT_DESCRIPTION_PROP_ID) {
                require(value.size() >= sizeof(WCHAR) && value.size() % sizeof(WCHAR) == 0,
                    E_INVALIDARG, "Text property must be a native-WCHAR string including its terminator");
                WCHAR terminator = 1;
                std::memcpy(&terminator, value.data() + value.size() - sizeof(WCHAR), sizeof(WCHAR));
                require(terminator == 0, E_INVALIDARG, "Text property is not null terminated");
            }
            updated[property] = std::move(value);
        }
        if (row_exists(target)) {
            writable(*target.store);
            require(!target.store->native, ERROR_NOT_SUPPORTED, "Native ROOT property persistence is not implemented");
            if (data) write_properties(*target.store, target.row, {{property, updated.at(property)}});
            else {
                Statement remove(target.store->db->value, "DELETE FROM properties WHERE cert=? AND property=?");
                remove.integer(1, target.row);
                remove.integer(2, property);
                remove.step();
            }
        }
        target.properties = std::move(updated);
        return TRUE;
    });
}
DWORD CertEnumCertificateContextProperties(PCCERT_CONTEXT context, DWORD previous) noexcept {
    return boundary<DWORD>(0, [&] {
        auto& target = get_context(context);
        refresh_properties(target);
        auto next = target.properties.upper_bound(previous);
        return next == target.properties.end() ? DWORD{0} : next->first;
    });
}
BOOL CertGetStoreProperty(HCERTSTORE handle, DWORD property, void* data, DWORD* size) noexcept {
    return boundary<BOOL>(FALSE, [&] {
        auto store = get_store(handle);
        materialize(*store);
        require(property == CERT_STORE_LOCALIZED_NAME_PROP_ID ||
            (property >= CERT_FIRST_USER_PROP_ID && property <= CERT_LAST_USER_PROP_ID),
            ERROR_NOT_SUPPORTED, "Unsupported store property");
        Statement query(store->db->value, "SELECT value FROM store_properties WHERE property=?");
        query.integer(1, property);
        require(query.step(), CRYPT_E_NOT_FOUND, "Store property is not set");
        copy_out(query.blob_column(0), data, size);
        return TRUE;
    });
}
BOOL CertSetStoreProperty(HCERTSTORE handle, DWORD property, DWORD flags, const void* data) noexcept {
    return boundary<BOOL>(FALSE, [&] {
        auto store = get_store(handle);
        writable(*store);
        require(!store->native, ERROR_NOT_SUPPORTED, "Native ROOT store-property persistence is not implemented");
        require(flags == 0, ERROR_NOT_SUPPORTED, "Store property flags are unsupported");
        require(property == CERT_STORE_LOCALIZED_NAME_PROP_ID ||
            (property >= CERT_FIRST_USER_PROP_ID && property <= CERT_LAST_USER_PROP_ID),
            ERROR_NOT_SUPPORTED, "Unsupported store property");
        if (data) {
            const auto& blob = *static_cast<const CRYPT_DATA_BLOB*>(data);
            Statement insert(store->db->value, "INSERT OR REPLACE INTO store_properties(property,value) VALUES(?,?)");
            insert.integer(1, property);
            insert.blob(2, bytes(blob.pbData, blob.cbData));
            insert.step();
        } else {
            Statement remove(store->db->value, "DELETE FROM store_properties WHERE property=?");
            remove.integer(1, property);
            remove.step();
        }
        return TRUE;
    });
}
BOOL CertControlStore(HCERTSTORE handle, DWORD flags, DWORD control, const void* parameter) noexcept {
    return boundary<BOOL>(FALSE, [&] {
        auto store = get_store(handle);
        require(flags == 0 && !parameter, ERROR_NOT_SUPPORTED, "Control flags and parameters are unsupported");
        if (control == CERT_STORE_CTRL_RESYNC) {
            if (store->native || !store->inherited.empty()) {
                require(store->contexts == 0, ERROR_BUSY, "Release native contexts before resynchronizing");
                if (store->native) load_native(*store);
                else {
                    auto replacement = machine_backing(store->name, CERT_STORE_READONLY_FLAG);
                    store->inherited = {std::move(replacement)};
                    materialize(*store);
                }
            } else {
                materialize(*store);
            }
        } else if (control == CERT_STORE_CTRL_COMMIT) {
            writable(*store);
            // Every SQLite mutation is committed before the API returns.
            db_check(store->db->value, sqlite3_db_cacheflush(store->db->value));
        } else throw Error(ERROR_NOT_SUPPORTED, "Store control operation is unsupported");
        return TRUE;
    });
}
BOOL CertSaveStore(HCERTSTORE handle, DWORD encoding, DWORD saveAs, DWORD saveTo, void* parameter, DWORD flags) noexcept {
    return boundary<BOOL>(FALSE, [&] {
        require(encoding == PKCS_7_ASN_ENCODING || encoding == (X509_ASN_ENCODING | PKCS_7_ASN_ENCODING),
            ERROR_NOT_SUPPORTED, "PKCS#7 save requires PKCS_7_ASN_ENCODING");
        require(saveAs == CERT_STORE_SAVE_AS_PKCS7 && saveTo == CERT_STORE_SAVE_TO_MEMORY && flags == 0,
            ERROR_NOT_SUPPORTED, "Only PKCS#7 export to memory is implemented");
        require(parameter, E_INVALIDARG, "Missing output blob");
        auto store = get_store(handle);
        std::unique_ptr<PKCS7, decltype(&PKCS7_free)> message(PKCS7_new(), PKCS7_free);
        require(message && PKCS7_set_type(message.get(), NID_pkcs7_signed) == 1 &&
            PKCS7_content_new(message.get(), NID_pkcs7_data) == 1, ERROR_GEN_FAILURE, "Cannot create PKCS#7 container");
        std::vector<std::shared_ptr<Store>> sources{store};
        sources.insert(sources.end(), store->inherited.begin(), store->inherited.end());
        for (const auto& source : sources) {
            materialize(*source);
            Statement query(source->db->value, "SELECT id FROM certificates ORDER BY id");
            while (query.step()) {
                auto certificate = load_context(*source, sqlite3_column_int64(query.value, 0));
                require(PKCS7_add_certificate(message.get(), certificate->certificate.get()) == 1,
                    ERROR_GEN_FAILURE, "Cannot add certificate to PKCS#7 container");
            }
        }
        int size = i2d_PKCS7(message.get(), nullptr);
        require(size > 0, ERROR_GEN_FAILURE, "PKCS#7 encoding failed");
        Bytes encoded(static_cast<std::size_t>(size));
        auto* cursor = encoded.data();
        require(i2d_PKCS7(message.get(), &cursor) == size, ERROR_GEN_FAILURE, "PKCS#7 encoding failed");
        auto& output = *static_cast<CRYPT_DATA_BLOB*>(parameter);
        copy_out(encoded, output.pbData, &output.cbData);
        return TRUE;
    });
}
BOOL CertGetCertificateChain(HCERTCHAINENGINE chainEngine, PCCERT_CONTEXT certificate,
    const FILETIME* time, HCERTSTORE additionalStore, const CERT_CHAIN_PARA* parameters,
    DWORD flags, void* reserved, PCCERT_CHAIN_CONTEXT* chainContext) noexcept {
    if (chainContext) *chainContext = nullptr;
    return boundary<BOOL>(FALSE, [&] {
        require(!chainEngine && !time && flags == 0 && !reserved && parameters && chainContext,
            ERROR_NOT_SUPPORTED, "Only default offline certificate-chain construction is supported");
        require(parameters->cbSize == sizeof(*parameters) &&
            parameters->RequestedUsage.Usage.cUsageIdentifier == 0 &&
            parameters->RequestedIssuancePolicy.Usage.cUsageIdentifier == 0 &&
            parameters->dwUrlRetrievalTimeout == 0 &&
            parameters->fCheckRevocationFreshnessTime == FALSE &&
            parameters->dwRevocationFreshnessTime == 0 &&
            !parameters->pftCacheResync && !parameters->pStrongSignPara &&
            parameters->dwStrongSignFlags == 0,
            ERROR_NOT_SUPPORTED, "Certificate-chain parameters are unsupported");

        auto& leaf = get_context(certificate);
        auto roots = system_chain_candidates("ROOT");
        std::set<Fingerprint> trusted_roots;
        for (const auto& root : roots)
            trusted_roots.insert(fingerprint(root.certificate.get()));
        std::map<Fingerprint, ChainCertificate> candidates;
        insert_chain_candidates(candidates, chain_candidates(additionalStore));
        insert_chain_candidates(candidates, system_chain_candidates("CA"));
        insert_chain_candidates(candidates, std::move(roots));

        std::vector<X509*> certificates{leaf.certificate.get()};
        std::set<Fingerprint> seen{fingerprint(leaf.certificate.get())};
        std::set<std::size_t> invalid_signatures;
        auto* current = leaf.certificate.get();
        bool partial = false;
        bool cyclic = false;
        while (!self_signed(current)) {
            std::map<Fingerprint, X509*> issuers;
            std::map<Fingerprint, X509*> name_matches;
            for (const auto& [hash, candidate] : candidates) {
                auto* value = candidate.certificate.get();
                if (!same_name(X509_get_subject_name(value), X509_get_issuer_name(current)))
                    continue;
                name_matches.emplace(hash, value);
                if (verifies(current, value)) issuers.emplace(hash, value);
            }
            bool signature_valid = !issuers.empty();
            if (!signature_valid) issuers = std::move(name_matches);
            if (issuers.empty()) {
                partial = true;
                break;
            }
            auto selected = std::find_if(issuers.begin(), issuers.end(),
                [&](const auto& item) { return trusted_roots.contains(item.first); });
            if (selected == issuers.end()) selected = issuers.begin();
            if (!signature_valid) invalid_signatures.insert(certificates.size() - 1);
            if (!seen.insert(selected->first).second) {
                cyclic = true;
                break;
            }
            current = selected->second;
            certificates.push_back(current);
        }
        auto [element_statuses, chain_status] =
            chain_statuses(certificates, trusted_roots, invalid_signatures, partial, cyclic);

        auto owned = std::make_unique<OwnedChain>();
        try {
            ++leaf.references;
            owned->contexts.push_back(certificate);
            for (std::size_t index = 1; index < certificates.size(); ++index)
                owned->contexts.push_back(publish(
                    std::make_unique<Context>(encode_x509(certificates[index]))));

            owned->elements.resize(owned->contexts.size());
            owned->element_pointers.reserve(owned->elements.size());
            for (std::size_t index = 0; index < owned->elements.size(); ++index) {
                owned->elements[index] = {
                    sizeof(CERT_CHAIN_ELEMENT), owned->contexts[index], element_statuses[index],
                    nullptr, nullptr, nullptr, nullptr};
                owned->element_pointers.push_back(&owned->elements[index]);
            }
            owned->simple = {
                sizeof(CERT_SIMPLE_CHAIN), chain_status, count(owned->element_pointers.size()),
                owned->element_pointers.data(), nullptr, FALSE, 0};
            owned->chain_pointers = {&owned->simple};
            owned->public_context = {
                sizeof(CERT_CHAIN_CONTEXT), chain_status, 1, owned->chain_pointers.data(),
                0, nullptr, FALSE, 0, 0, {}};
            auto* result = &owned->public_context;
            chains.emplace(result, std::move(owned));
            *chainContext = result;
        } catch (...) {
            if (owned)
                for (auto context : owned->contexts) release(context);
            throw;
        }
        return TRUE;
    });
}
void CertFreeCertificateChain(PCCERT_CHAIN_CONTEXT chainContext) noexcept {
    if (!chainContext) return;
    (void)boundary<int>(0, [&] {
        auto found = chains.find(chainContext);
        require(found != chains.end(), ERROR_INVALID_HANDLE, "Invalid or freed certificate chain");
        auto owned = std::move(found->second);
        chains.erase(found);
        for (auto context : owned->contexts) release(context);
        return 0;
    });
}
BOOL CertVerifyCertificateChainPolicy(LPCSTR policy, PCCERT_CHAIN_CONTEXT chainContext,
    const CERT_CHAIN_POLICY_PARA* parameters, CERT_CHAIN_POLICY_STATUS* status) noexcept {
    return boundary<BOOL>(FALSE, [&] {
        require(reinterpret_cast<std::uintptr_t>(policy) == 1 && chainContext && parameters && status,
            E_INVALIDARG, "Invalid certificate-chain policy arguments");
        require(chains.contains(chainContext), ERROR_INVALID_HANDLE, "Invalid or freed certificate chain");
        require(parameters->cbSize == sizeof(*parameters) && parameters->dwFlags == 0 &&
            !parameters->pvExtraPolicyPara && status->cbSize == sizeof(*status) &&
            !status->pvExtraPolicyStatus,
            ERROR_NOT_SUPPORTED, "Certificate-chain policy options are unsupported");
        const auto* simple = chainContext->rgpChain[0];
        auto find_element = [&](DWORD trust) {
            for (DWORD index = 0; index < simple->cElement; ++index)
                if (simple->rgpElement[index]->TrustStatus.dwErrorStatus & trust)
                    return static_cast<std::int32_t>(index);
            return std::int32_t{-1};
        };
        auto errors = chainContext->TrustStatus.dwErrorStatus;
        std::int32_t element = -1;
        if (errors & CERT_TRUST_IS_UNTRUSTED_ROOT) {
            status->dwError = CERT_E_UNTRUSTEDROOT;
            element = find_element(CERT_TRUST_IS_UNTRUSTED_ROOT);
        } else if (errors & (CERT_TRUST_IS_PARTIAL_CHAIN | CERT_TRUST_IS_CYCLIC)) {
            status->dwError = CERT_E_CHAINING;
        } else if (errors & CERT_TRUST_IS_NOT_TIME_VALID) {
            status->dwError = CERT_E_EXPIRED;
            element = find_element(CERT_TRUST_IS_NOT_TIME_VALID);
        } else if (errors & CERT_TRUST_IS_NOT_SIGNATURE_VALID) {
            status->dwError = TRUST_E_CERT_SIGNATURE;
            element = find_element(CERT_TRUST_IS_NOT_SIGNATURE_VALID);
        } else if (errors & CERT_TRUST_IS_NOT_VALID_FOR_USAGE) {
            status->dwError = CERT_E_WRONG_USAGE;
            element = find_element(CERT_TRUST_IS_NOT_VALID_FOR_USAGE);
        } else if (errors & CERT_TRUST_INVALID_BASIC_CONSTRAINTS) {
            status->dwError = TRUST_E_BASIC_CONSTRAINTS;
            element = find_element(CERT_TRUST_INVALID_BASIC_CONSTRAINTS);
        } else {
            status->dwError = ERROR_SUCCESS;
        }
        status->lChainIndex = status->dwError == ERROR_SUCCESS ? -1 : 0;
        status->lElementIndex = element;
        return TRUE;
    });
}
BOOL SysCertUpdateTrustAnchor(PCCERT_CONTEXT certificate, BOOL install, const SYS_CERT_NATIVE_OPTIONS* options, DWORD flags) noexcept {
    return boundary<BOOL>(FALSE, [&] {
        require(flags == SYS_CERT_TRUST_UPDATE_ALLOW, ERROR_ACCESS_DENIED, "Native trust update requires explicit SYS_CERT_TRUST_UPDATE_ALLOW");
        require(install == TRUE || install == FALSE, E_INVALIDARG, "Invalid install argument");
        if (install) update_anchor(get_context(certificate).certificate.get(), true, native_layout(options));
        else remove_trusted_certificate(get_context(certificate).certificate.get(), native_layout(options));
        return TRUE;
    });
}
BOOL SysCertImportPfxToStore(HCERTSTORE handle, const CRYPT_DATA_BLOB* pfx, LPCWSTR password, DWORD flags) noexcept {
    return boundary<BOOL>(FALSE, [&] {
        auto store = get_store(handle);
        require(!(flags & CRYPT_MACHINE_KEYSET) || store->location == CERT_SYSTEM_STORE_LOCAL_MACHINE,
            E_INVALIDARG, "Computer keyset requires a computer-scoped destination store");
        require(!(flags & CRYPT_USER_KEYSET) || store->location != CERT_SYSTEM_STORE_LOCAL_MACHINE,
            E_INVALIDARG, "User keyset cannot target a computer store");
        auto parsed = parse_pfx(pfx, password, flags);
        import_pfx(*store, parsed);
        return TRUE;
    });
}
HCERTSTORE PFXImportCertStore(CRYPT_DATA_BLOB* pfx, LPCWSTR password, DWORD flags) noexcept {
    return boundary<HCERTSTORE>(nullptr, [&] {
        auto parsed = parse_pfx(pfx, password, flags);
        bool machine = (flags & CRYPT_MACHINE_KEYSET) != 0;
        auto directory = machine ? system_paths.machine : user_data_directory();
        if (std::filesystem::create_directories(directory))
            std::filesystem::permissions(directory, machine ?
                std::filesystem::perms::owner_all | std::filesystem::perms::group_read |
                std::filesystem::perms::group_exec | std::filesystem::perms::others_read |
                std::filesystem::perms::others_exec : std::filesystem::perms::owner_all);
        auto store = std::make_shared<Store>();
        store->location = machine ? CERT_SYSTEM_STORE_LOCAL_MACHINE : CERT_SYSTEM_STORE_CURRENT_USER;
        store->name = store_name("IMPORT-" + object_id());
        store->public_material = machine;
        persistent_store(*store, directory / (store->name + ".db"), CERT_STORE_CREATE_NEW_FLAG);
        import_pfx(*store, parsed);
        return publish_store(std::move(store));
    });
}
BOOL PFXExportCertStoreEx(HCERTSTORE handle, CRYPT_DATA_BLOB* pfx, LPCWSTR password,
    void* parameter, DWORD flags) noexcept {
    return boundary<BOOL>(FALSE, [&] {
        require(pfx, E_INVALIDARG, "Missing PKCS#12 output blob");
        require(!parameter, ERROR_NOT_SUPPORTED, "PKCS#12 export parameter is unsupported");
        auto encoded = encode_pfx(*get_store(handle), password, flags);
        struct CleanseBytes {
            Bytes& value;
            ~CleanseBytes() { OPENSSL_cleanse(value.data(), value.size()); }
        } cleanse{encoded};
        copy_out(encoded, pfx->pbData, &pfx->cbData);
        return TRUE;
    });
}
BOOL SysCertGetCertificateFilePath(PCCERT_CONTEXT certificate, BOOL privateKey, char* path, DWORD* size) noexcept {
    return boundary<BOOL>(FALSE, [&] {
        require(privateKey == FALSE || privateKey == TRUE, E_INVALIDARG, "Invalid key-path selector");
        auto& context = get_context(certificate);
        require(!context.object_path.empty(), ERROR_NOT_SUPPORTED, "Context has no logical-store object path");
        require(!privateKey || !context.view, ERROR_ACCESS_DENIED, "Inherited views do not grant access to machine private keys");
        if (privateKey) load_private_key(context);
        require(!privateKey || context.private_key, CRYPT_E_NOT_FOUND, "Certificate has no private-key file");
        auto name = (privateKey ? context.key_path : context.object_path / "certificate.pem").string();
        name.push_back('\0');
        copy_out(Bytes(name.begin(), name.end()), path, size);
        return TRUE;
    });
}
}
