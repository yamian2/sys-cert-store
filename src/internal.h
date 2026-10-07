#pragma once
#include <sys-cert-store/sys-cert-store.h>
#include <openssl/x509.h>
#include <filesystem>
#include <memory>
#include <mutex>
#include <stdexcept>
#include <string>
#include <sys/types.h>
#include <vector>

namespace scs {
using Bytes = std::vector<BYTE>;
using X509Ptr = std::unique_ptr<X509, decltype(&X509_free)>;
struct Error : std::runtime_error {
    DWORD code;
    Error(DWORD value, const std::string& message) : std::runtime_error(message), code(value) {}
};
inline void require(bool condition, DWORD code, const char* message) {
    if (!condition) throw Error(code, message);
}
struct NativeLayout {
    std::filesystem::path root;
    std::filesystem::path bundle;
    std::filesystem::path anchors;
    std::filesystem::path staging;
    std::filesystem::path updater;
    bool debian;
};
NativeLayout native_layout(const SYS_CERT_NATIVE_OPTIONS* options);
std::vector<Bytes> read_native(const NativeLayout& layout);
void update_anchor(X509* certificate, bool install, const NativeLayout& layout);
void remove_trusted_certificate(X509* certificate, const NativeLayout& layout);
Bytes encode_x509(X509* certificate);
std::recursive_mutex& api_gate() noexcept;
void report_api_failure(DWORD code, const char* message) noexcept;
std::filesystem::path current_user_store_directory();
std::vector<Bytes> read_user_store_certificates(
    const std::filesystem::path& directory, uid_t owner);
}
