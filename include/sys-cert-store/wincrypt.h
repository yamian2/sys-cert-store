#pragma once

#include <cstddef>
#include <cstdint>

using BYTE = std::uint8_t;
using DWORD = std::uint32_t;
using BOOL = std::int32_t;
using WCHAR = wchar_t;
using LPCSTR = const char*;
using LPCWSTR = const WCHAR*;
using HCRYPTPROV_LEGACY = std::uintptr_t;
using HCERTSTORE = void*;
inline constexpr BOOL TRUE = 1;
inline constexpr BOOL FALSE = 0;

struct CRYPT_DATA_BLOB { DWORD cbData; BYTE* pbData; };
using CRYPT_INTEGER_BLOB = CRYPT_DATA_BLOB;
using CRYPT_HASH_BLOB = CRYPT_DATA_BLOB;
using CERT_NAME_BLOB = CRYPT_DATA_BLOB;
using CRYPT_OBJID_BLOB = CRYPT_DATA_BLOB;
struct CRYPT_BIT_BLOB { DWORD cbData; BYTE* pbData; DWORD cUnusedBits; };
struct FILETIME { DWORD dwLowDateTime; DWORD dwHighDateTime; };
struct CRYPT_ALGORITHM_IDENTIFIER { char* pszObjId; CRYPT_OBJID_BLOB Parameters; };
struct CERT_PUBLIC_KEY_INFO {
    CRYPT_ALGORITHM_IDENTIFIER Algorithm;
    CRYPT_BIT_BLOB PublicKey;
};
struct CERT_EXTENSION { char* pszObjId; BOOL fCritical; CRYPT_OBJID_BLOB Value; };
using PCERT_EXTENSION = CERT_EXTENSION*;
struct CERT_INFO {
    DWORD dwVersion;
    CRYPT_INTEGER_BLOB SerialNumber;
    CRYPT_ALGORITHM_IDENTIFIER SignatureAlgorithm;
    CERT_NAME_BLOB Issuer;
    FILETIME NotBefore;
    FILETIME NotAfter;
    CERT_NAME_BLOB Subject;
    CERT_PUBLIC_KEY_INFO SubjectPublicKeyInfo;
    CRYPT_BIT_BLOB IssuerUniqueId;
    CRYPT_BIT_BLOB SubjectUniqueId;
    DWORD cExtension;
    PCERT_EXTENSION rgExtension;
};
using PCERT_INFO = CERT_INFO*;
struct CERT_CONTEXT {
    DWORD dwCertEncodingType;
    BYTE* pbCertEncoded;
    DWORD cbCertEncoded;
    PCERT_INFO pCertInfo;
    HCERTSTORE hCertStore;
};
using PCERT_CONTEXT = CERT_CONTEXT*;
using PCCERT_CONTEXT = const CERT_CONTEXT*;
struct CERT_SYSTEM_STORE_INFO { DWORD cbSize; };
using PCERT_SYSTEM_STORE_INFO = CERT_SYSTEM_STORE_INFO*;
using PFN_CERT_ENUM_SYSTEM_STORE = BOOL (*)(const void*, DWORD, PCERT_SYSTEM_STORE_INFO, void*, void*);
using PFN_CERT_ENUM_SYSTEM_STORE_LOCATION = BOOL (*)(LPCWSTR, DWORD, void*, void*);

inline constexpr DWORD X509_ASN_ENCODING = 1;
inline constexpr DWORD PKCS_7_ASN_ENCODING = 0x10000;
#define CERT_STORE_PROV_MEMORY reinterpret_cast<LPCSTR>(2)
#define CERT_STORE_PROV_SYSTEM_A reinterpret_cast<LPCSTR>(9)
#define CERT_STORE_PROV_SYSTEM_W reinterpret_cast<LPCSTR>(10)
#define CERT_STORE_PROV_SYSTEM CERT_STORE_PROV_SYSTEM_W
inline constexpr DWORD CERT_SYSTEM_STORE_CURRENT_USER = 0x10000;
inline constexpr DWORD CERT_SYSTEM_STORE_LOCAL_MACHINE = 0x20000;
inline constexpr DWORD CERT_STORE_READONLY_FLAG = 0x8000;
inline constexpr DWORD CERT_STORE_OPEN_EXISTING_FLAG = 0x4000;
inline constexpr DWORD CERT_STORE_CREATE_NEW_FLAG = 0x2000;
inline constexpr DWORD CERT_STORE_ENUM_ARCHIVED_FLAG = 0x200;
inline constexpr DWORD CERT_CLOSE_STORE_CHECK_FLAG = 2;
inline constexpr DWORD CERT_CLOSE_STORE_FORCE_FLAG = 1;
inline constexpr DWORD CERT_STORE_ADD_NEW = 1;
inline constexpr DWORD CERT_STORE_ADD_USE_EXISTING = 2;
inline constexpr DWORD CERT_STORE_ADD_REPLACE_EXISTING = 3;
inline constexpr DWORD CERT_STORE_ADD_ALWAYS = 4;
inline constexpr DWORD CERT_STORE_ADD_REPLACE_EXISTING_INHERIT_PROPERTIES = 5;
inline constexpr DWORD CERT_STORE_ADD_NEWER = 6;
inline constexpr DWORD CERT_STORE_ADD_NEWER_INHERIT_PROPERTIES = 7;
inline constexpr DWORD CERT_SHA1_HASH_PROP_ID = 3;
inline constexpr DWORD CERT_MD5_HASH_PROP_ID = 4;
inline constexpr DWORD CERT_KEY_PROV_INFO_PROP_ID = 2;
inline constexpr DWORD CERT_KEY_CONTEXT_PROP_ID = 5;
inline constexpr DWORD CERT_FRIENDLY_NAME_PROP_ID = 11;
inline constexpr DWORD CERT_DESCRIPTION_PROP_ID = 13;
inline constexpr DWORD CERT_KEY_IDENTIFIER_PROP_ID = 20;
inline constexpr DWORD CERT_ARCHIVED_PROP_ID = 19;
inline constexpr DWORD CERT_NCRYPT_KEY_HANDLE_PROP_ID = 78;
inline constexpr DWORD CERT_SHA256_HASH_PROP_ID = 107;
inline constexpr DWORD CERT_FIRST_USER_PROP_ID = 0x8000;
inline constexpr DWORD CERT_LAST_USER_PROP_ID = 0xffff;
inline constexpr DWORD CERT_STORE_LOCALIZED_NAME_PROP_ID = 0x1000;
inline constexpr DWORD CERT_FIND_ANY = 0;
inline constexpr DWORD CERT_FIND_SHA1_HASH = 1 << 16;
inline constexpr DWORD CERT_FIND_HASH = CERT_FIND_SHA1_HASH;
inline constexpr DWORD CERT_FIND_MD5_HASH = 4 << 16;
inline constexpr DWORD CERT_FIND_SHA256_HASH = 22 << 16;
inline constexpr DWORD CERT_FIND_SUBJECT_NAME = (2 << 16) | 7;
inline constexpr DWORD CERT_FIND_ISSUER_NAME = (2 << 16) | 4;
inline constexpr DWORD CERT_FIND_SUBJECT_STR_A = (7 << 16) | 7;
inline constexpr DWORD CERT_FIND_SUBJECT_STR_W = (8 << 16) | 7;
inline constexpr DWORD CERT_FIND_ISSUER_STR_A = (7 << 16) | 4;
inline constexpr DWORD CERT_FIND_ISSUER_STR_W = (8 << 16) | 4;
inline constexpr DWORD CERT_FIND_SUBJECT_STR = CERT_FIND_SUBJECT_STR_W;
inline constexpr DWORD CERT_FIND_ISSUER_STR = CERT_FIND_ISSUER_STR_W;
inline constexpr DWORD CERT_FIND_PROPERTY = 5 << 16;
inline constexpr DWORD CERT_FIND_SUBJECT_CERT = 11 << 16;
inline constexpr DWORD CERT_FIND_ISSUER_OF = 12 << 16;
inline constexpr DWORD CERT_FIND_EXISTING = 13 << 16;
inline constexpr DWORD CERT_FIND_KEY_IDENTIFIER = 15 << 16;
inline constexpr DWORD CERT_STORE_SIGNATURE_FLAG = 1;
inline constexpr DWORD CERT_STORE_TIME_VALIDITY_FLAG = 2;
inline constexpr DWORD CERT_STORE_REVOCATION_FLAG = 4;
inline constexpr DWORD CERT_STORE_NO_CRL_FLAG = 0x10000;
inline constexpr DWORD CERT_STORE_NO_ISSUER_FLAG = 0x20000;
inline constexpr DWORD CERT_STORE_CTRL_RESYNC = 1;
inline constexpr DWORD CERT_STORE_CTRL_COMMIT = 3;
inline constexpr DWORD CERT_STORE_SAVE_AS_PKCS7 = 2;
inline constexpr DWORD CERT_STORE_SAVE_TO_MEMORY = 2;
inline constexpr DWORD CRYPT_EXPORTABLE = 1;
inline constexpr DWORD CRYPT_USER_KEYSET = 0x1000;
inline constexpr DWORD CRYPT_MACHINE_KEYSET = 0x20;
inline constexpr DWORD PKCS12_NO_PERSIST_KEY = 0x8000;

inline constexpr DWORD ERROR_SUCCESS = 0;
inline constexpr DWORD ERROR_FILE_NOT_FOUND = 2;
inline constexpr DWORD ERROR_ACCESS_DENIED = 5;
inline constexpr DWORD ERROR_INVALID_HANDLE = 6;
inline constexpr DWORD ERROR_NOT_ENOUGH_MEMORY = 8;
inline constexpr DWORD ERROR_INVALID_DATA = 13;
inline constexpr DWORD ERROR_NOT_SUPPORTED = 50;
inline constexpr DWORD ERROR_INVALID_PARAMETER = 87;
inline constexpr DWORD ERROR_BUSY = 170;
inline constexpr DWORD ERROR_MORE_DATA = 234;
inline constexpr DWORD ERROR_GEN_FAILURE = 31;
inline constexpr DWORD E_INVALIDARG = 0x80070057;
inline constexpr DWORD CRYPT_E_NOT_FOUND = 0x80092004;
inline constexpr DWORD CRYPT_E_EXISTS = 0x80092005;
inline constexpr DWORD CRYPT_E_NO_MATCH = 0x80092009;
inline constexpr DWORD CRYPT_E_PENDING_CLOSE = 0x8009200f;
inline constexpr DWORD CRYPT_E_SELF_SIGNED = 0x80092007;

extern "C" {
DWORD GetLastError() noexcept;
void SetLastError(DWORD error) noexcept;
HCERTSTORE CertOpenStore(LPCSTR provider, DWORD encoding, HCRYPTPROV_LEGACY legacy,
                        DWORD flags, const void* parameter) noexcept;
HCERTSTORE CertOpenSystemStoreW(HCRYPTPROV_LEGACY legacy, LPCWSTR name) noexcept;
HCERTSTORE CertOpenSystemStoreA(HCRYPTPROV_LEGACY legacy, LPCSTR name) noexcept;
BOOL CertEnumSystemStore(DWORD flags, void* locationParameter, void* argument,
    PFN_CERT_ENUM_SYSTEM_STORE callback) noexcept;
BOOL CertEnumSystemStoreLocation(DWORD flags, void* argument,
    PFN_CERT_ENUM_SYSTEM_STORE_LOCATION callback) noexcept;
HCERTSTORE CertDuplicateStore(HCERTSTORE store) noexcept;
BOOL CertCloseStore(HCERTSTORE store, DWORD flags) noexcept;
PCCERT_CONTEXT CertCreateCertificateContext(DWORD encoding, const BYTE* encoded, DWORD size) noexcept;
PCCERT_CONTEXT CertDuplicateCertificateContext(PCCERT_CONTEXT context) noexcept;
BOOL CertFreeCertificateContext(PCCERT_CONTEXT context) noexcept;
PCCERT_CONTEXT CertEnumCertificatesInStore(HCERTSTORE store, PCCERT_CONTEXT previous) noexcept;
PCCERT_CONTEXT CertFindCertificateInStore(HCERTSTORE store, DWORD encoding, DWORD flags,
    DWORD type, const void* parameter, PCCERT_CONTEXT previous) noexcept;
PCCERT_CONTEXT CertGetSubjectCertificateFromStore(HCERTSTORE store, DWORD encoding, PCERT_INFO id) noexcept;
PCCERT_CONTEXT CertGetIssuerCertificateFromStore(HCERTSTORE store, PCCERT_CONTEXT subject,
    PCCERT_CONTEXT previous, DWORD* flags) noexcept;
BOOL CertAddCertificateContextToStore(HCERTSTORE store, PCCERT_CONTEXT context, DWORD disposition,
    PCCERT_CONTEXT* result) noexcept;
BOOL CertAddEncodedCertificateToStore(HCERTSTORE store, DWORD encoding, const BYTE* encoded,
    DWORD size, DWORD disposition, PCCERT_CONTEXT* result) noexcept;
BOOL CertDeleteCertificateFromStore(PCCERT_CONTEXT context) noexcept;
BOOL CertGetCertificateContextProperty(PCCERT_CONTEXT context, DWORD property, void* data, DWORD* size) noexcept;
BOOL CertSetCertificateContextProperty(PCCERT_CONTEXT context, DWORD property, DWORD flags, const void* data) noexcept;
DWORD CertEnumCertificateContextProperties(PCCERT_CONTEXT context, DWORD previous) noexcept;
BOOL CertGetStoreProperty(HCERTSTORE store, DWORD property, void* data, DWORD* size) noexcept;
BOOL CertSetStoreProperty(HCERTSTORE store, DWORD property, DWORD flags, const void* data) noexcept;
BOOL CertControlStore(HCERTSTORE store, DWORD flags, DWORD control, const void* parameter) noexcept;
BOOL CertSaveStore(HCERTSTORE store, DWORD encoding, DWORD saveAs, DWORD saveTo,
    void* parameter, DWORD flags) noexcept;
HCERTSTORE PFXImportCertStore(CRYPT_DATA_BLOB* pfx, LPCWSTR password, DWORD flags) noexcept;
}

#ifdef UNICODE
#define CertOpenSystemStore CertOpenSystemStoreW
#else
#define CertOpenSystemStore CertOpenSystemStoreA
#endif
