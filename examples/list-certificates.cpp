#include <sys-cert-store/sys-cert-store.h>
#include <cstdio>

int main() {
    HCERTSTORE store = CertOpenSystemStoreW(0, L"ROOT");
    if (!store) {
        std::fprintf(stderr, "Open failed (0x%08x): %s\n", GetLastError(), SysCertGetLastErrorMessage());
        return 1;
    }
    unsigned count = 0;
    PCCERT_CONTEXT certificate = nullptr;
    while ((certificate = CertEnumCertificatesInStore(store, certificate))) {
        std::printf("Certificate %u: %u DER bytes, %u extensions\n",
            ++count, certificate->cbCertEncoded, certificate->pCertInfo->cExtension);
    }
    DWORD error = GetLastError();
    if (error != CRYPT_E_NOT_FOUND)
        std::fprintf(stderr, "Enumeration failed (0x%08x): %s\n", error, SysCertGetLastErrorMessage());
    CertCloseStore(store, 0);
    return error == CRYPT_E_NOT_FOUND ? 0 : 1;
}
