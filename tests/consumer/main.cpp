#include <sys-cert-store/sys-cert-store.h>

int main() {
    auto store = CertOpenStore(CERT_STORE_PROV_MEMORY, 0, 0, 0, nullptr);
    if (!store || !CertCloseStore(store, 0)) return 1;
    unsigned locations = 0;
    auto callback = [](LPCWSTR, DWORD, void*, void* argument) -> BOOL {
        ++*static_cast<unsigned*>(argument);
        return TRUE;
    };
    return CertEnumSystemStoreLocation(0, &locations, callback) && locations == 2 ? 0 : 1;
}
