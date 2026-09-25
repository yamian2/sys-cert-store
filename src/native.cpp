#include "internal.h"
#include <openssl/evp.h>
#include <openssl/pem.h>
#include <openssl/x509v3.h>
#include <array>
#include <algorithm>
#include <cerrno>
#include <climits>
#include <cstring>
#include <fcntl.h>
#include <fstream>
#include <optional>
#include <set>
#include <spawn.h>
#include <sstream>
#include <sys/file.h>
#include <sys/stat.h>
#include <sys/wait.h>
#include <unistd.h>

namespace scs {
namespace {
class File {
public:
    int fd;
    explicit File(int value) : fd(value) {
        require(fd >= 0, errno == EACCES || errno == EPERM ? ERROR_ACCESS_DENIED : ERROR_GEN_FAILURE, std::strerror(errno));
    }
    ~File() { close(fd); }
    File(const File&) = delete;
    File& operator=(const File&) = delete;
};

std::string read_file(const std::filesystem::path& path) {
    std::ifstream input(path, std::ios::binary);
    require(input.is_open(), errno == EACCES ? ERROR_ACCESS_DENIED : ERROR_FILE_NOT_FOUND, "Cannot open native trust file");
    std::string result((std::istreambuf_iterator<char>(input)), {});
    require(!input.bad(), ERROR_GEN_FAILURE, "Cannot read native trust file");
    return result;
}

std::string os_value(std::string value) {
    if (value.size() >= 2 && (value.front() == '"' || value.front() == '\'') && value.back() == value.front())
        return value.substr(1, value.size() - 2);
    return value;
}

void run_updater(const NativeLayout& layout) {
    std::string executable = layout.updater.string();
    std::string extract = "extract";
    std::string fresh = "--fresh";
    std::array<char*, 3> argv{executable.data(), layout.debian ? fresh.data() : extract.data(), nullptr};
    // Do not pass caller-controlled PATH, loader settings, or OpenSSL configuration to a privileged child.
    char path[] = "PATH=/usr/sbin:/usr/bin:/sbin:/bin";
    char locale[] = "LC_ALL=C";
    std::array<char*, 3> environment{path, locale, nullptr};
    pid_t child = 0;
    int error = posix_spawn(&child, executable.c_str(), nullptr, nullptr, argv.data(), environment.data());
    require(error == 0, error == EACCES ? ERROR_ACCESS_DENIED : ERROR_GEN_FAILURE, "Cannot start distro trust updater");
    int status = 0;
    pid_t waited;
    do { waited = waitpid(child, &status, 0); } while (waited < 0 && errno == EINTR);
    require(waited == child && WIFEXITED(status) && WEXITSTATUS(status) == 0,
        ERROR_GEN_FAILURE, "Distro trust updater failed; inspect its stderr");
}

void write_all(int fd, const std::string& data) {
    std::size_t written = 0;
    while (written < data.size()) {
        auto amount = write(fd, data.data() + written, data.size() - written);
        if (amount < 0 && errno == EINTR) continue;
        require(amount > 0, ERROR_GEN_FAILURE, "Cannot write trust anchor");
        written += static_cast<std::size_t>(amount);
    }
    require(fsync(fd) == 0, ERROR_GEN_FAILURE, "Cannot flush trust anchor");
}

std::string pem(X509* certificate) {
    std::unique_ptr<BIO, decltype(&BIO_free)> output(BIO_new(BIO_s_mem()), BIO_free);
    require(output && PEM_write_bio_X509(output.get(), certificate) == 1, ERROR_GEN_FAILURE, "Cannot encode PEM certificate");
    char* data = nullptr;
    auto length = BIO_get_mem_data(output.get(), &data);
    require(length > 0, ERROR_GEN_FAILURE, "Empty PEM encoding");
    return std::string(data, static_cast<std::size_t>(length));
}

std::string anchor_name(X509* certificate) {
    std::array<BYTE, 32> hash{};
    unsigned int length = 0;
    require(X509_digest(certificate, EVP_sha256(), hash.data(), &length) == 1 && length == hash.size(),
        ERROR_GEN_FAILURE, "Cannot hash trust anchor");
    constexpr char digits[] = "0123456789abcdef";
    std::string name = "sys-cert-store-";
    for (BYTE ch : hash) { name += digits[ch >> 4]; name += digits[ch & 15]; }
    return name + ".crt";
}
std::filesystem::path blocklist_directory(const NativeLayout& layout) {
    auto source = layout.root / "etc/pki/ca-trust/source";
    if (!std::filesystem::exists(source / "blocklist") && std::filesystem::exists(source / "blacklist"))
        return source / "blacklist";
    return source / "blocklist";
}

struct Change {
    std::filesystem::path path;
    std::optional<std::string> before;
    std::optional<std::string> after;
    mode_t mode = 0644;
};
Change change(const std::filesystem::path& path, std::optional<std::string> after) {
    Change result{path, std::nullopt, std::move(after), 0644};
    struct stat status{};
    if (lstat(path.c_str(), &status) == 0) {
        require(S_ISREG(status.st_mode) && status.st_nlink == 1, ERROR_ACCESS_DENIED, "Trust source must be a regular non-symlink file");
        result.before = read_file(path);
        result.mode = status.st_mode & 0777;
    } else require(errno == ENOENT, ERROR_GEN_FAILURE, "Cannot inspect trust source");
    return result;
}
void sync_directory(const std::filesystem::path& path) {
    File directory(open(path.c_str(), O_RDONLY | O_DIRECTORY | O_CLOEXEC));
    require(fsync(directory.fd) == 0, ERROR_GEN_FAILURE, "Cannot flush trust directory");
}
void apply_changes(const NativeLayout& layout, std::vector<Change> changes, X509* certificate, bool installed) {
    require(!changes.empty(), CRYPT_E_NOT_FOUND, "No active root source to remove");
    if (mkdir(layout.staging.c_str(), 0700) != 0)
        require(errno == EEXIST, ERROR_ACCESS_DENIED, "Cannot create trust staging directory");
    File staging(open(layout.staging.c_str(), O_RDONLY | O_DIRECTORY | O_CLOEXEC | O_NOFOLLOW));
    struct stat status{};
    require(fstat(staging.fd, &status) == 0 && status.st_uid == geteuid() && (status.st_mode & 077) == 0,
        ERROR_ACCESS_DENIED, "Trust staging directory must be private and owned by the current user");
    File lock(openat(staging.fd, "lock", O_WRONLY | O_CREAT | O_CLOEXEC | O_NOFOLLOW, 0600));
    require(flock(lock.fd, LOCK_EX) == 0, ERROR_GEN_FAILURE, "Cannot lock native trust updates");
    File journal(openat(staging.fd, "pending-update", O_WRONLY | O_CREAT | O_EXCL | O_CLOEXEC | O_NOFOLLOW, 0600));
    std::string manifest;
    for (std::size_t i = 0; i < changes.size(); ++i)
        manifest += std::to_string(i) + ".rollback\t" + (changes[i].before ? "restore\t" : "remove\t") + changes[i].path.string() + "\n";
    write_all(journal.fd, manifest);
    require(fsync(staging.fd) == 0, ERROR_GEN_FAILURE, "Cannot persist trust update journal");
    std::size_t applied = 0;
    auto cleanup = [&] {
        for (std::size_t i = 0; i < changes.size(); ++i) {
            for (const char* suffix : {".rollback", ".new"}) {
                auto name = std::to_string(i) + suffix;
                require(unlinkat(staging.fd, name.c_str(), 0) == 0 || errno == ENOENT,
                    ERROR_GEN_FAILURE, "Cannot clean trust staging file");
            }
        }
        require(unlinkat(staging.fd, "pending-update", 0) == 0 && fsync(staging.fd) == 0,
            ERROR_GEN_FAILURE, "Cannot clear trust recovery journal");
    };
    try {
        for (std::size_t i = 0; i < changes.size(); ++i) {
            auto& item = changes[i];
            auto current = change(item.path, {});
            require(current.before == item.before, ERROR_BUSY, "Trust source changed concurrently; retry after resynchronizing");
            if (item.before) {
                File backup(openat(staging.fd, (std::to_string(i) + ".rollback").c_str(),
                    O_WRONLY | O_CREAT | O_EXCL | O_CLOEXEC | O_NOFOLLOW, item.mode));
                write_all(backup.fd, *item.before);
                require(fchmod(backup.fd, item.mode) == 0 && fsync(backup.fd) == 0,
                    ERROR_GEN_FAILURE, "Cannot preserve trust file permissions");
            }
            if (item.after) {
                auto name = std::to_string(i) + ".new";
                File replacement(openat(staging.fd, name.c_str(), O_WRONLY | O_CREAT | O_EXCL | O_CLOEXEC | O_NOFOLLOW, item.mode));
                write_all(replacement.fd, *item.after);
                require(fchmod(replacement.fd, item.mode) == 0 && fsync(replacement.fd) == 0 && fsync(staging.fd) == 0,
                    ERROR_GEN_FAILURE, "Cannot persist trust replacement");
                require(renameat(staging.fd, name.c_str(), AT_FDCWD, item.path.c_str()) == 0,
                    ERROR_GEN_FAILURE, "Cannot publish trust change; staging and target must share a filesystem");
            } else {
                require(fsync(staging.fd) == 0 && unlink(item.path.c_str()) == 0, ERROR_GEN_FAILURE, "Cannot remove root certificate file");
            }
            ++applied;
            sync_directory(item.path.parent_path());
        }
        run_updater(layout);
        auto expected = encode_x509(certificate);
        auto active = read_native(layout);
        bool present = std::find(active.begin(), active.end(), expected) != active.end();
        require(present == installed, ERROR_GEN_FAILURE,
            "Distro updater did not produce the requested active trust state; inspect other trust/distrust sources");
    } catch (const std::exception& original) {
        for (std::size_t i = applied; i > 0; --i) {
            auto& item = changes[i - 1];
            int result = item.before ? renameat(staging.fd, (std::to_string(i - 1) + ".rollback").c_str(), AT_FDCWD, item.path.c_str()) :
                unlink(item.path.c_str());
            require(result == 0, ERROR_GEN_FAILURE, "Trust update and rollback failed; inspect pending-update journal");
            sync_directory(item.path.parent_path());
        }
        if (applied) {
            try { run_updater(layout); }
            catch (const std::exception&) {
                cleanup();
                throw Error(ERROR_GEN_FAILURE, "Source changes rolled back, but trust bundle regeneration failed; run the distro updater manually");
            }
        }
        cleanup();
        throw Error(ERROR_GEN_FAILURE, std::string("Trust update rolled back: ") + original.what());
    }
    cleanup();
}

bool contains_certificate(const std::filesystem::path& path, const Bytes& expected) {
    auto text = read_file(path);
    if (text.find("-----BEGIN CERTIFICATE-----") == std::string::npos) return false;
    require(text.size() <= static_cast<std::size_t>(INT_MAX), ERROR_INVALID_DATA, "Oversized trust source");
    std::unique_ptr<BIO, decltype(&BIO_free)> input(BIO_new_mem_buf(text.data(), static_cast<int>(text.size())), BIO_free);
    require(input != nullptr, ERROR_NOT_ENOUGH_MEMORY, "Cannot allocate trust source reader");
    X509Ptr certificate(PEM_read_bio_X509(input.get(), nullptr, nullptr, nullptr), X509_free);
    if (!certificate || encode_x509(certificate.get()) != expected) return false;
    require(text.find("-----BEGIN CERTIFICATE-----", text.find("-----BEGIN CERTIFICATE-----") + 1) == std::string::npos,
        ERROR_NOT_SUPPORTED, "Cannot remove an individual certificate from a multi-certificate local source");
    return true;
}

void mutation_check(X509* certificate) {
    require(getuid() == geteuid() && getgid() == getegid(), ERROR_ACCESS_DENIED, "Trust updates are disabled in set-ID processes");
    require(X509_check_ca(certificate) > 0, E_INVALIDARG, "Only CA certificates can be installed as trust anchors");
}
} // namespace

NativeLayout native_layout(const SYS_CERT_NATIVE_OPTIONS* options) {
    require(!options || options->cbSize == sizeof(SYS_CERT_NATIVE_OPTIONS), E_INVALIDARG, "Invalid native options size");
    std::filesystem::path root = options && options->rootPath ? options->rootPath : "/";
    require(root.is_absolute(), E_INVALIDARG, "Native root must be absolute");
    root = std::filesystem::canonical(root);
    std::string id;
    std::string like;
    std::istringstream release(read_file(root / "etc/os-release"));
    for (std::string line; std::getline(release, line);) {
        if (line.starts_with("ID=")) id = os_value(line.substr(3));
        if (line.starts_with("ID_LIKE=")) like = os_value(line.substr(8));
    }
    std::set<std::string> family{id};
    std::istringstream words(like);
    for (std::string word; words >> word;) family.insert(word);
    bool debian = family.contains("ubuntu") || family.contains("debian");
    bool rpm = family.contains("rhel") || family.contains("fedora") || family.contains("centos") ||
        family.contains("rocky") || family.contains("almalinux") || family.contains("mariner") ||
        family.contains("azurelinux");
    require(debian || rpm, ERROR_NOT_SUPPORTED, "Unsupported distro; expected Ubuntu/Debian, Red Hat family, Mariner or Azure Linux");
    if (debian)
        return {root, root / "etc/ssl/certs/ca-certificates.crt",
            root / "usr/local/share/ca-certificates", root / "usr/local/share/.sys-cert-store-staging",
            root / "usr/sbin/update-ca-certificates", true};
    return {root, root / "etc/pki/ca-trust/extracted/pem/tls-ca-bundle.pem",
        root / "etc/pki/ca-trust/source/anchors", root / "etc/pki/.sys-cert-store-staging",
        root / "usr/bin/update-ca-trust", false};
}

std::vector<Bytes> read_native(const NativeLayout& layout) {
    auto text = read_file(layout.bundle);
    std::vector<Bytes> result;
    std::set<std::string> seen;
    constexpr std::string_view begin = "-----BEGIN CERTIFICATE-----";
    constexpr std::string_view end = "-----END CERTIFICATE-----";
    std::size_t offset = 0;
    while (offset < text.size()) {
        auto start = text.find(begin, offset);
        auto tail = start == std::string::npos ? text.substr(offset) : text.substr(offset, start - offset);
        std::istringstream lines(tail);
        for (std::string line; std::getline(lines, line);) {
            auto first = line.find_first_not_of(" \t\r");
            require(first == std::string::npos || line[first] == '#', ERROR_INVALID_DATA, "Unexpected data in native PEM trust bundle");
        }
        if (start == std::string::npos) break;
        auto stop = text.find(end, start + begin.size());
        require(stop != std::string::npos, ERROR_INVALID_DATA, "Truncated certificate in native trust bundle");
        auto size = stop + end.size() - start;
        require(size <= static_cast<std::size_t>(INT_MAX), ERROR_INVALID_DATA, "Oversized native certificate");
        std::unique_ptr<BIO, decltype(&BIO_free)> input(BIO_new_mem_buf(text.data() + start, static_cast<int>(size)), BIO_free);
        require(input != nullptr, ERROR_NOT_ENOUGH_MEMORY, "Cannot allocate PEM decoder");
        X509Ptr certificate(PEM_read_bio_X509(input.get(), nullptr, nullptr, nullptr), X509_free);
        require(certificate != nullptr, ERROR_INVALID_DATA, "Invalid certificate in native trust bundle");
        auto der = encode_x509(certificate.get());
        if (seen.emplace(reinterpret_cast<const char*>(der.data()), der.size()).second)
            result.push_back(std::move(der));
        offset = stop + end.size();
    }
    return result;
}

void update_anchor(X509* certificate, bool install, const NativeLayout& layout) {
    mutation_check(certificate);
    if (!install) { remove_trusted_certificate(certificate, layout); return; }
    auto addition = change(layout.anchors / anchor_name(certificate), pem(certificate));
    require(!addition.before, CRYPT_E_EXISTS, "Local trust anchor already exists");
    std::vector<Change> changes{std::move(addition)};
    if (!layout.debian) {
        auto blocked = change(blocklist_directory(layout) / anchor_name(certificate), {});
        if (blocked.before) changes.push_back(std::move(blocked));
    }
    apply_changes(layout, std::move(changes), certificate, true);
}

void remove_trusted_certificate(X509* certificate, const NativeLayout& layout) {
    mutation_check(certificate);
    auto expected = encode_x509(certificate);
    std::vector<Change> changes;
    for (const auto& file : std::filesystem::recursive_directory_iterator(layout.anchors)) {
        if (!file.is_regular_file() || file.is_symlink()) continue;
        if (layout.debian && file.path().extension() != ".crt") continue;
        if (contains_certificate(file.path(), expected)) changes.push_back(change(file.path(), {}));
    }
    if (layout.debian) {
        auto config_path = layout.root / "etc/ca-certificates.conf";
        if (std::filesystem::exists(config_path)) {
            auto config = read_file(config_path);
            std::istringstream input(config);
            std::string updated;
            bool modified = false;
            for (std::string line; std::getline(input, line);) {
                if (!line.empty() && line[0] != '#' && line[0] != '!') {
                    std::filesystem::path relative = line;
                    require(!relative.is_absolute() && line.find("..") == std::string::npos,
                        ERROR_INVALID_DATA, "Unsafe path in ca-certificates.conf");
                    auto source = layout.root / "usr/share/ca-certificates" / relative;
                    if (std::filesystem::exists(source) && contains_certificate(source, expected)) {
                        line.insert(line.begin(), '!');
                        modified = true;
                    }
                }
                updated += line + "\n";
            }
            if (modified) changes.push_back(change(config_path, updated));
        }
    } else {
        auto blocklist = blocklist_directory(layout);
        if (!std::filesystem::exists(blocklist))
            std::filesystem::create_directory(blocklist);
        auto blocked = change(blocklist / anchor_name(certificate), pem(certificate));
        if (!blocked.before) changes.push_back(std::move(blocked));
        else require(blocked.before == blocked.after, ERROR_ACCESS_DENIED, "Unexpected root blocklist contents");
    }
    apply_changes(layout, std::move(changes), certificate, false);
}
}
