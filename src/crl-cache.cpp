#include "crypto.h"
#include "internal.h"
#include <openssl/err.h>
#include <openssl/http.h>
#include <openssl/pem.h>
#include <openssl/x509v3.h>
#include <algorithm>
#include <array>
#include <atomic>
#include <cerrno>
#include <cctype>
#include <cstdint>
#include <cstdlib>
#include <cstring>
#include <dirent.h>
#include <fcntl.h>
#include <fstream>
#include <iomanip>
#include <limits>
#include <map>
#include <pwd.h>
#include <set>
#include <sstream>
#include <string_view>
#include <sys/stat.h>
#include <unistd.h>

namespace scs {
namespace {
using CrlPtr = std::unique_ptr<X509_CRL, decltype(&X509_CRL_free)>;
using BioPtr = std::unique_ptr<BIO, decltype(&BIO_free)>;

struct Account {
    uid_t uid;
    gid_t gid;
    std::string name;
    std::filesystem::path home;
};

struct StoreHandle {
    HCERTSTORE value = nullptr;
    explicit StoreHandle(HCERTSTORE input) : value(input) {}
    ~StoreHandle() { if (value) CertCloseStore(value, 0); }
    StoreHandle(const StoreHandle&) = delete;
    StoreHandle& operator=(const StoreHandle&) = delete;
};

struct FileDescriptor {
    int value = -1;
    explicit FileDescriptor(int input = -1) : value(input) {}
    ~FileDescriptor() { if (value >= 0) close(value); }
    FileDescriptor(FileDescriptor&& other) noexcept : value(other.value) { other.value = -1; }
    FileDescriptor& operator=(FileDescriptor&& other) noexcept {
        if (this != &other) {
            if (value >= 0) close(value);
            value = other.value;
            other.value = -1;
        }
        return *this;
    }
    FileDescriptor(const FileDescriptor&) = delete;
    FileDescriptor& operator=(const FileDescriptor&) = delete;
};

struct FailureSummary {
    std::size_t count = 0;
    std::string first;
    void add(const std::string& message) {
        ++count;
        if (first.empty()) first = message;
    }
};

struct DirectoryCloser {
    void operator()(DIR* value) const noexcept { if (value) closedir(value); }
};

bool valid_utf8(std::string_view value) {
    for (std::size_t i = 0; i < value.size();) {
        auto byte = static_cast<unsigned char>(value[i]);
        std::size_t continuation = 0;
        if (byte <= 0x7f) continuation = 0;
        else if (byte >= 0xc2 && byte <= 0xdf) continuation = 1;
        else if (byte >= 0xe0 && byte <= 0xef) continuation = 2;
        else if (byte >= 0xf0 && byte <= 0xf4) continuation = 3;
        else return false;
        if (i + continuation >= value.size()) return false;
        for (std::size_t j = 1; j <= continuation; ++j)
            if ((static_cast<unsigned char>(value[i + j]) & 0xc0) != 0x80) return false;
        if (continuation == 2) {
            auto second = static_cast<unsigned char>(value[i + 1]);
            if ((byte == 0xe0 && second < 0xa0) || (byte == 0xed && second >= 0xa0)) return false;
        } else if (continuation == 3) {
            auto second = static_cast<unsigned char>(value[i + 1]);
            if ((byte == 0xf0 && second < 0x90) || (byte == 0xf4 && second >= 0x90)) return false;
        }
        i += continuation + 1;
    }
    return true;
}

template<class Lookup>
Account lookup_account(Lookup lookup, const char* description) {
    long suggested = sysconf(_SC_GETPW_R_SIZE_MAX);
    std::vector<char> buffer(static_cast<std::size_t>(suggested > 0 ? suggested : 16384));
    passwd entry{};
    passwd* result = nullptr;
    int error = 0;
    for (;;) {
        error = lookup(&entry, buffer.data(), buffer.size(), &result);
        if (error != ERANGE) break;
        require(buffer.size() <= (1U << 20), ERROR_NOT_ENOUGH_MEMORY,
            "The account database entry is too large");
        buffer.resize(buffer.size() * 2);
    }
    require(error == 0 && result, ERROR_INVALID_PARAMETER, description);
    require(entry.pw_name && entry.pw_dir && *entry.pw_dir, ERROR_INVALID_DATA,
        "The target account has no home directory");
    std::filesystem::path home(entry.pw_dir);
    require(home.is_absolute(), ERROR_INVALID_DATA, "The target account home directory is not absolute");
    return {entry.pw_uid, entry.pw_gid, entry.pw_name, home.lexically_normal()};
}

Account account_by_name(const char* name) {
    require(name && *name, E_INVALIDARG, "The user name must not be empty");
    require(valid_utf8(name), E_INVALIDARG, "The user name is not valid UTF-8");
    return lookup_account([&](passwd* entry, char* buffer, std::size_t size, passwd** result) {
        return getpwnam_r(name, entry, buffer, size, result);
    }, "The requested Linux account does not exist");
}

Account account_by_uid(uid_t uid) {
    return lookup_account([&](passwd* entry, char* buffer, std::size_t size, passwd** result) {
        return getpwuid_r(uid, entry, buffer, size, result);
    }, "A discovered process user does not have a Linux account");
}

X509Ptr decode_certificate(PCCERT_CONTEXT context) {
    const BYTE* cursor = context->pbCertEncoded;
    X509Ptr result(d2i_X509(nullptr, &cursor, context->cbCertEncoded), X509_free);
    require(result && cursor == context->pbCertEncoded + context->cbCertEncoded,
        ERROR_INVALID_DATA, "A certificate store entry is not valid DER");
    return result;
}

std::string certificate_key(X509* certificate) {
    std::array<unsigned char, EVP_MAX_MD_SIZE> digest{};
    unsigned length = 0;
    require(X509_digest(certificate, EVP_sha256(), digest.data(), &length) == 1,
        ERROR_GEN_FAILURE, "Cannot fingerprint a certificate");
    return std::string(reinterpret_cast<const char*>(digest.data()), length);
}

void append_store(std::vector<X509Ptr>& output, std::set<std::string>& seen, HCERTSTORE store) {
    PCCERT_CONTEXT current = nullptr;
    while ((current = CertEnumCertificatesInStore(store, current))) {
        try {
            auto certificate = decode_certificate(current);
            if (seen.insert(certificate_key(certificate.get())).second)
                output.push_back(std::move(certificate));
        } catch (...) {
            CertFreeCertificateContext(current);
            throw;
        }
    }
    require(GetLastError() == CRYPT_E_NOT_FOUND, GetLastError(),
        "Cannot enumerate a certificate source store");
}

void append_system_store(std::vector<X509Ptr>& output, std::set<std::string>& seen,
    DWORD location, LPCWSTR name) {
    StoreHandle store(CertOpenStore(CERT_STORE_PROV_SYSTEM_W, 0, 0,
        location | CERT_STORE_READONLY_FLAG | CERT_STORE_OPEN_EXISTING_FLAG, name));
    require(store.value != nullptr, GetLastError(), SysCertGetLastErrorMessage());
    append_store(output, seen, store.value);
}

void append_encoded_certificate(std::vector<X509Ptr>& output, std::set<std::string>& seen,
    const Bytes& encoded) {
    const BYTE* cursor = encoded.data();
    X509Ptr certificate(
        d2i_X509(nullptr, &cursor, static_cast<long>(encoded.size())), X509_free);
    require(certificate && cursor == encoded.data() + encoded.size(),
        ERROR_INVALID_DATA, "A user certificate store entry is not valid DER");
    if (seen.insert(certificate_key(certificate.get())).second)
        output.push_back(std::move(certificate));
}

std::vector<X509Ptr> source_certificates(bool computer,
    const std::filesystem::path& user_directory, uid_t user_owner) {
    std::vector<X509Ptr> result;
    std::set<std::string> seen;
    if (computer) {
        for (auto* name : {L"MY", L"CA", L"ROOT"})
            append_system_store(result, seen, CERT_SYSTEM_STORE_LOCAL_MACHINE, name);
    } else {
        for (const auto& encoded :
            read_user_store_certificates(user_directory, user_owner))
            append_encoded_certificate(result, seen, encoded);
        append_system_store(result, seen, CERT_SYSTEM_STORE_LOCAL_MACHINE, L"CA");
        append_system_store(result, seen, CERT_SYSTEM_STORE_LOCAL_MACHINE, L"ROOT");
    }
    return result;
}

std::vector<std::string> distribution_points(X509* certificate) {
    auto free_points = [](CRL_DIST_POINTS* value) { sk_DIST_POINT_pop_free(value, DIST_POINT_free); };
    int critical = -1;
    std::unique_ptr<CRL_DIST_POINTS, decltype(free_points)> points(
        static_cast<CRL_DIST_POINTS*>(X509_get_ext_d2i(
            certificate, NID_crl_distribution_points, &critical, nullptr)), free_points);
    std::vector<std::string> result;
    if (!points) {
        require(critical == -1, ERROR_INVALID_DATA,
            "A certificate has an invalid CRL distribution-points extension");
        ERR_clear_error();
        return result;
    }
    for (int i = 0; i < sk_DIST_POINT_num(points.get()); ++i) {
        auto* point = sk_DIST_POINT_value(points.get(), i);
        if (!point->distpoint || point->distpoint->type != 0) continue;
        auto* names = point->distpoint->name.fullname;
        for (int j = 0; j < sk_GENERAL_NAME_num(names); ++j) {
            auto* name = sk_GENERAL_NAME_value(names, j);
            if (name->type != GEN_URI) continue;
            auto* data = ASN1_STRING_get0_data(name->d.uniformResourceIdentifier);
            auto length = ASN1_STRING_length(name->d.uniformResourceIdentifier);
            if (!data || length <= 0 || std::memchr(data, '\0', static_cast<std::size_t>(length))) continue;
            std::string uri(reinterpret_cast<const char*>(data), static_cast<std::size_t>(length));
            constexpr std::string_view scheme = "http://";
            bool http = uri.size() >= scheme.size() &&
                std::equal(scheme.begin(), scheme.end(), uri.begin(),
                    [](unsigned char left, unsigned char right) {
                        return left == static_cast<unsigned char>(std::tolower(right));
                    });
            if (http) result.push_back(std::move(uri));
        }
    }
    return result;
}

X509* find_issuer(X509* certificate, const std::vector<X509Ptr>& certificates) {
    for (const auto& candidate : certificates) {
        if (X509_check_issued(candidate.get(), certificate) != X509_V_OK) continue;
        std::unique_ptr<EVP_PKEY, decltype(&EVP_PKEY_free)> key(
            X509_get_pubkey(candidate.get()), EVP_PKEY_free);
        if (key && X509_verify(certificate, key.get()) == 1) return candidate.get();
        ERR_clear_error();
    }
    return nullptr;
}

CrlPtr download_crl(const std::string& url) {
    const char* proxy = std::getenv("http_proxy");
    if (!proxy || !*proxy) proxy = std::getenv("HTTP_PROXY");
    const char* no_proxy = std::getenv("no_proxy");
    if (!no_proxy || !*no_proxy) no_proxy = std::getenv("NO_PROXY");
    BioPtr response(OSSL_HTTP_get(url.c_str(), proxy, no_proxy, nullptr, nullptr,
        nullptr, nullptr, 0, nullptr, nullptr, 0, 100 * 1024 * 1024, 10), BIO_free);
    require(response != nullptr, ERROR_GEN_FAILURE, ("Cannot download CRL from " + url).c_str());
    std::vector<unsigned char> bytes;
    std::array<unsigned char, 16384> buffer{};
    for (;;) {
        int count = BIO_read(response.get(), buffer.data(), static_cast<int>(buffer.size()));
        if (count > 0) {
            bytes.insert(bytes.end(), buffer.begin(), buffer.begin() + count);
            continue;
        }
        if (count == 0 || BIO_eof(response.get())) break;
        require(BIO_should_retry(response.get()), ERROR_GEN_FAILURE,
            ("Cannot read CRL response from " + url).c_str());
    }
    require(!bytes.empty(), ERROR_INVALID_DATA, ("The CRL response is empty: " + url).c_str());
    const unsigned char* cursor = bytes.data();
    CrlPtr result(d2i_X509_CRL(nullptr, &cursor, static_cast<long>(bytes.size())), X509_CRL_free);
    if (!result || cursor != bytes.data() + bytes.size()) {
        ERR_clear_error();
        BioPtr input(BIO_new_mem_buf(bytes.data(), static_cast<int>(bytes.size())), BIO_free);
        result.reset(input ? PEM_read_bio_X509_CRL(input.get(), nullptr, nullptr, nullptr) : nullptr);
    }
    require(result != nullptr, ERROR_INVALID_DATA, ("The downloaded object is not a CRL: " + url).c_str());
    return result;
}

void validate_crl(X509_CRL* crl, X509* issuer, const std::string& url) {
    require(X509_NAME_cmp(X509_CRL_get_issuer(crl), X509_get_subject_name(issuer)) == 0,
        ERROR_INVALID_DATA, ("The CRL issuer does not match its certificate: " + url).c_str());
    std::unique_ptr<EVP_PKEY, decltype(&EVP_PKEY_free)> key(X509_get_pubkey(issuer), EVP_PKEY_free);
    require(key && X509_CRL_verify(crl, key.get()) == 1, ERROR_INVALID_DATA,
        ("The CRL signature is invalid: " + url).c_str());
    auto* last = X509_CRL_get0_lastUpdate(crl);
    auto* next = X509_CRL_get0_nextUpdate(crl);
    require(last && X509_cmp_current_time(last) <= 0, ERROR_INVALID_DATA,
        ("The CRL lastUpdate is in the future: " + url).c_str());
    require(next && X509_cmp_current_time(next) > 0, ERROR_INVALID_DATA,
        ("The CRL is expired or has no nextUpdate: " + url).c_str());
}

std::string cache_name(X509* certificate, const std::string& url) {
    std::vector<unsigned char> utf16;
    utf16.reserve(url.size() * 2);
    for (auto byte : url) {
        utf16.push_back(static_cast<unsigned char>(byte));
        utf16.push_back(0);
    }
    std::array<unsigned char, EVP_MAX_MD_SIZE> digest{};
    unsigned length = 0;
    require(EVP_Digest(utf16.data(), utf16.size(), digest.data(), &length, EVP_sha256(), nullptr) == 1 &&
        length >= 4, ERROR_GEN_FAILURE, "Cannot hash a CRL distribution point");
    std::uint32_t url_hash = static_cast<std::uint32_t>(digest[0]) |
        (static_cast<std::uint32_t>(digest[1]) << 8) |
        (static_cast<std::uint32_t>(digest[2]) << 16) |
        (static_cast<std::uint32_t>(digest[3]) << 24);
    std::ostringstream result;
    result << std::hex << std::setfill('0') << std::nouppercase
        << std::setw(8) << (X509_issuer_name_hash(certificate) & 0xffffffffUL)
        << '.' << std::setw(8) << url_hash << ".crl";
    return result.str();
}

FileDescriptor open_directory(const std::filesystem::path& path, uid_t owner) {
    FileDescriptor result(open(path.c_str(), O_RDONLY | O_DIRECTORY | O_CLOEXEC | O_NOFOLLOW));
    require(result.value >= 0, errno == EACCES ? ERROR_ACCESS_DENIED : ERROR_FILE_NOT_FOUND,
        "Cannot open the target account home directory");
    struct stat status{};
    require(fstat(result.value, &status) == 0 && S_ISDIR(status.st_mode), ERROR_INVALID_DATA,
        "The target account home is not a directory");
    require(status.st_uid == owner, ERROR_ACCESS_DENIED,
        "The target account does not own its home directory");
    return result;
}

FileDescriptor ensure_directory(int parent, const char* name, const Account& account, bool cache_directory) {
    bool created = false;
    if (mkdirat(parent, name, 0700) == 0) created = true;
    else require(errno == EEXIST, errno == EACCES ? ERROR_ACCESS_DENIED : ERROR_GEN_FAILURE,
        "Cannot create the .NET CRL cache directory");
    FileDescriptor result(openat(parent, name, O_RDONLY | O_DIRECTORY | O_CLOEXEC | O_NOFOLLOW));
    require(result.value >= 0, errno == EACCES ? ERROR_ACCESS_DENIED : ERROR_INVALID_DATA,
        "A .NET CRL cache path component is not a safe directory");
    if (created && geteuid() == 0)
        require(fchown(result.value, account.uid, account.gid) == 0, ERROR_ACCESS_DENIED,
            "Cannot assign the .NET CRL cache directory to its user");
    struct stat status{};
    require(fstat(result.value, &status) == 0 && S_ISDIR(status.st_mode), ERROR_INVALID_DATA,
        "A .NET CRL cache path component is invalid");
    require(status.st_uid == account.uid, ERROR_ACCESS_DENIED,
        "The target user does not own a .NET CRL cache path component");
    require((status.st_mode & 0022) == 0, ERROR_ACCESS_DENIED,
        "A .NET CRL cache path component is writable by another user");
    if (cache_directory)
        require(fchmod(result.value, 0700) == 0, ERROR_ACCESS_DENIED,
            "Cannot secure the .NET CRL cache directory");
    return result;
}

FileDescriptor cache_directory(const Account& account, const std::filesystem::path& home) {
    auto current = open_directory(home, account.uid);
    for (const auto& component : std::array<const char*, 4>{".dotnet", "corefx", "cryptography", "crls"})
        current = ensure_directory(current.value, component, account, std::strcmp(component, "crls") == 0);
    return current;
}

void write_all(int file, const char* data, std::size_t size) {
    while (size) {
        auto written = write(file, data, size);
        if (written < 0 && errno == EINTR) continue;
        require(written > 0, ERROR_GEN_FAILURE, "Cannot write a .NET CRL cache file");
        data += written;
        size -= static_cast<std::size_t>(written);
    }
}

bool cached_crl_is_fresh(int directory, const Account& account,
    const std::string& name, X509* issuer, const std::string& url) {
    FileDescriptor file(openat(
        directory, name.c_str(), O_RDONLY | O_CLOEXEC | O_NOFOLLOW));
    if (file.value < 0) {
        require(errno == ENOENT, errno == EACCES ? ERROR_ACCESS_DENIED : ERROR_GEN_FAILURE,
            "Cannot inspect a .NET CRL cache file");
        return false;
    }
    struct stat status{};
    require(fstat(file.value, &status) == 0 && S_ISREG(status.st_mode) &&
        status.st_uid == account.uid && status.st_nlink == 1 &&
        (status.st_mode & 0077) == 0, ERROR_ACCESS_DENIED,
        "A .NET CRL cache file has unsafe ownership or permissions");
    BioPtr input(BIO_new_fd(file.value, BIO_NOCLOSE), BIO_free);
    require(input != nullptr, ERROR_GEN_FAILURE, "Cannot open a .NET CRL cache file");
    CrlPtr crl(PEM_read_bio_X509_CRL(input.get(), nullptr, nullptr, nullptr), X509_CRL_free);
    if (!crl) {
        ERR_clear_error();
        return false;
    }
    try {
        validate_crl(crl.get(), issuer, url);
        return true;
    } catch (const Error& error) {
        if (error.code != ERROR_INVALID_DATA) throw;
        ERR_clear_error();
        return false;
    }
}

void write_cache_file(int directory, const Account& account, const std::string& name, X509_CRL* crl) {
    BioPtr output(BIO_new(BIO_s_mem()), BIO_free);
    require(output && PEM_write_bio_X509_CRL(output.get(), crl) == 1,
        ERROR_GEN_FAILURE, "Cannot encode a CRL for the .NET cache");
    char* data = nullptr;
    auto size = BIO_get_mem_data(output.get(), &data);
    require(data && size > 0, ERROR_GEN_FAILURE, "Cannot encode a CRL for the .NET cache");
    static std::atomic<unsigned long> sequence{};
    auto temporary = "." + name + ".tmp-" + std::to_string(getpid()) + "-" +
        std::to_string(sequence.fetch_add(1, std::memory_order_relaxed));
    FileDescriptor file(openat(directory, temporary.c_str(),
        O_WRONLY | O_CREAT | O_EXCL | O_CLOEXEC | O_NOFOLLOW, 0600));
    require(file.value >= 0, errno == EACCES ? ERROR_ACCESS_DENIED : ERROR_GEN_FAILURE,
        "Cannot create a temporary .NET CRL cache file");
    bool renamed = false;
    try {
        require(fchmod(file.value, 0600) == 0, ERROR_ACCESS_DENIED,
            "Cannot secure a .NET CRL cache file");
        if (geteuid() == 0)
            require(fchown(file.value, account.uid, account.gid) == 0, ERROR_ACCESS_DENIED,
                "Cannot assign a .NET CRL cache file to its user");
        write_all(file.value, data, static_cast<std::size_t>(size));
        require(fsync(file.value) == 0, ERROR_GEN_FAILURE, "Cannot flush a .NET CRL cache file");
        require(renameat(directory, temporary.c_str(), directory, name.c_str()) == 0,
            ERROR_GEN_FAILURE, "Cannot install a .NET CRL cache file");
        renamed = true;
        require(fsync(directory) == 0, ERROR_GEN_FAILURE, "Cannot flush the .NET CRL cache directory");
    } catch (...) {
        if (!renamed) unlinkat(directory, temporary.c_str(), 0);
        throw;
    }
}

std::filesystem::path target_home(const Account& account, bool explicit_user) {
    if (explicit_user && account.uid == geteuid()) {
        const char* home = std::getenv("HOME");
        if (home && *home) {
            std::filesystem::path candidate(home);
            require(candidate.is_absolute(), E_INVALIDARG, "HOME must be absolute");
            return candidate.lexically_normal();
        }
    }
    return account.home;
}

uid_t process_uid(const std::filesystem::path& status_path) {
    std::ifstream status(status_path);
    require(status.good(), ERROR_ACCESS_DENIED, "Cannot inspect a process owner");
    std::string line;
    while (std::getline(status, line)) {
        if (!line.starts_with("Uid:")) continue;
        std::istringstream values(line.substr(4));
        unsigned long real = 0;
        unsigned long effective = 0;
        require(static_cast<bool>(values >> real >> effective), ERROR_INVALID_DATA,
            "A process has an invalid Uid status");
        (void)real;
        require(effective <= static_cast<unsigned long>(std::numeric_limits<uid_t>::max()),
            ERROR_INVALID_DATA, "A process UID is out of range");
        return static_cast<uid_t>(effective);
    }
    throw Error(ERROR_INVALID_DATA, "A process status has no Uid field");
}

std::vector<Account> dotnet_process_accounts(FailureSummary& failures) {
    std::unique_ptr<DIR, DirectoryCloser> directory(opendir("/proc"));
    require(directory != nullptr, ERROR_ACCESS_DENIED, "Cannot enumerate /proc");
    std::set<uid_t> users;
    while (auto* entry = readdir(directory.get())) {
        std::string_view name(entry->d_name);
        if (name.empty() || !std::all_of(name.begin(), name.end(),
            [](unsigned char value) { return value >= '0' && value <= '9'; })) continue;
        std::filesystem::path base = std::filesystem::path("/proc") / entry->d_name;
        std::ifstream maps(base / "maps");
        if (!maps) {
            struct stat status{};
            if (stat(base.c_str(), &status) == 0)
                failures.add("Cannot inspect " + base.string() + "/maps");
            continue;
        }
        bool coreclr = false;
        std::string line;
        while (std::getline(maps, line))
            if (line.find("libcoreclr.so") != std::string::npos) {
                coreclr = true;
                break;
            }
        if (!coreclr) continue;
        try {
            users.insert(process_uid(base / "status"));
        } catch (const std::exception& error) {
            failures.add(error.what());
        }
    }
    std::vector<Account> result;
    for (auto uid : users) {
        try {
            auto account = account_by_uid(uid);
            if (geteuid() != 0 && account.uid != geteuid()) {
                failures.add("Root privileges are required to populate another user's .NET CRL cache");
                continue;
            }
            result.push_back(std::move(account));
        } catch (const std::exception& error) {
            failures.add(error.what());
        }
    }
    return result;
}

BOOL populate(LPCSTR user_name) {
    FailureSummary failures;
    std::vector<Account> accounts;
    std::filesystem::path user_directory;
    bool explicit_user = user_name != nullptr;
    if (explicit_user) {
        auto account = account_by_name(user_name);
        require(geteuid() == 0 || account.uid == geteuid(), ERROR_ACCESS_DENIED,
            "Root privileges are required to populate another user's .NET CRL cache");
        user_directory = account.uid == geteuid()
            ? current_user_store_directory()
            : account.home / ".local/share/sys-cert-store";
        accounts.push_back(std::move(account));
    } else {
        accounts = dotnet_process_accounts(failures);
    }
    if (accounts.empty()) {
        if (!failures.count) return TRUE;
        throw Error(ERROR_GEN_FAILURE, "No .NET process account could be targeted. First failure: " +
            failures.first);
    }

    auto certificates = source_certificates(
        !explicit_user, user_directory, explicit_user ? accounts.front().uid : geteuid());
    struct Work {
        X509* certificate;
        X509* issuer;
        std::string url;
    };
    std::vector<Work> work;
    std::set<std::string> seen;
    for (const auto& certificate : certificates) {
        for (auto& url : distribution_points(certificate.get())) {
            auto* issuer = find_issuer(certificate.get(), certificates);
            if (!issuer) {
                failures.add("Cannot find the issuer for CRL distribution point " + url);
                continue;
            }
            auto key = certificate_key(issuer) + '\0' + url;
            if (seen.insert(key).second)
                work.push_back({certificate.get(), issuer, std::move(url)});
        }
    }

    std::map<uid_t, FileDescriptor> cache_directories;
    for (const auto& account : accounts) {
        try {
            cache_directories.emplace(account.uid,
                cache_directory(account, target_home(account, explicit_user)));
        } catch (const std::exception& error) {
            failures.add(account.name + ": " + error.what());
        }
    }
    if (cache_directories.empty()) {
        throw Error(ERROR_GEN_FAILURE, "No .NET CRL cache directory could be opened. First failure: " +
            failures.first);
    }

    std::size_t cached = 0;
    for (const auto& item : work) {
        try {
            auto name = cache_name(item.certificate, item.url);
            std::vector<const Account*> stale_accounts;
            for (const auto& account : accounts) {
                auto directory = cache_directories.find(account.uid);
                if (directory == cache_directories.end()) continue;
                if (cached_crl_is_fresh(
                    directory->second.value, account, name, item.issuer, item.url)) {
                    ++cached;
                } else {
                    stale_accounts.push_back(&account);
                }
            }
            if (stale_accounts.empty()) continue;

            auto crl = download_crl(item.url);
            validate_crl(crl.get(), item.issuer, item.url);
            for (const auto* account : stale_accounts) {
                auto directory = cache_directories.find(account->uid);
                if (directory == cache_directories.end()) continue;
                try {
                    write_cache_file(directory->second.value, *account, name, crl.get());
                    ++cached;
                } catch (const std::exception& error) {
                    failures.add(account->name + ": " + error.what());
                }
            }
        } catch (const std::exception& error) {
            failures.add(error.what());
        }
    }
    if (failures.count) {
        std::ostringstream message;
        message << "Cached " << cached << " CRL entr" << (cached == 1 ? "y" : "ies")
            << "; " << failures.count << " operation" << (failures.count == 1 ? "" : "s")
            << " failed. First failure: " << failures.first;
        throw Error(ERROR_GEN_FAILURE, message.str());
    }
    return TRUE;
}
} // namespace
} // namespace scs

extern "C" BOOL SysCertPopulateDotNetCrlCache(LPCSTR userName) noexcept {
    try {
        scs::initialize_api();
        return scs::populate(userName);
    } catch (const scs::Error& error) {
        scs::report_api_failure(error.code, error.what());
    } catch (const std::bad_alloc&) {
        scs::report_api_failure(ERROR_NOT_ENOUGH_MEMORY, "Memory allocation failed");
    } catch (const std::filesystem::filesystem_error& error) {
        scs::report_api_failure(error.code() == std::errc::permission_denied
            ? ERROR_ACCESS_DENIED : ERROR_GEN_FAILURE, error.what());
    } catch (const std::exception& error) {
        scs::report_api_failure(ERROR_GEN_FAILURE, error.what());
    } catch (...) {
        scs::report_api_failure(ERROR_GEN_FAILURE, "Unexpected exception at the C API boundary");
    }
    return FALSE;
}
