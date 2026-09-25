#pragma once
#include "wincrypt.h"

inline constexpr LPCSTR SYS_CERT_STORE_PROV_SQLITE = "SysCertSQLite";
inline constexpr LPCSTR SYS_CERT_STORE_PROV_NATIVE = "SysCertNative";

// Native paths are resolved below rootPath. nullptr selects the real system root.
struct SYS_CERT_NATIVE_OPTIONS {
    DWORD cbSize;
    const char* rootPath;
};
inline constexpr DWORD SYS_CERT_TRUST_UPDATE_ALLOW = 1;
inline constexpr DWORD SYS_CERT_STORE_NATIVE_WRITE_FLAG = 0x10000000;

struct SYS_CERT_STORE_CONFIGURATION {
    DWORD cbSize;
    const char* userStoreDirectory;
    const char* machineStoreDirectory;
    const char* systemRoot;
};

extern "C" {
// Process-wide path relocation; pass nullptr to reset. All stores/contexts must be closed.
// This changes paths, not the process identity or filesystem permissions.
BOOL SysCertConfigureSystemStores(const SYS_CERT_STORE_CONFIGURATION* configuration) noexcept;
BOOL SysCertGetCertificateStoreLocation(PCCERT_CONTEXT certificate, DWORD* location) noexcept;
// Thread-local diagnostic, valid until the next failure or SetLastError on this thread.
const char* SysCertGetLastErrorMessage() noexcept;
// Explicit native mutation: removes local anchors and disables/distrusts matching vendor roots.
BOOL SysCertUpdateTrustAnchor(PCCERT_CONTEXT certificate, BOOL install,
    const SYS_CERT_NATIVE_OPTIONS* options, DWORD flags) noexcept;
// Import directly into an existing file-backed logical store, atomically for all certificates.
BOOL SysCertImportPfxToStore(HCERTSTORE store, const CRYPT_DATA_BLOB* pfx,
    LPCWSTR password, DWORD flags) noexcept;
// Returns a UTF-8 path (including the NUL terminator in the size query).
BOOL SysCertGetCertificateFilePath(PCCERT_CONTEXT certificate, BOOL privateKey,
    char* path, DWORD* size) noexcept;
}
