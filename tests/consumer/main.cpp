#include <sys-cert-store/sys-cert-store.h>

int main() {
    auto store = CertOpenStore(CERT_STORE_PROV_MEMORY, 0, 0, 0, nullptr);
    return store && CertCloseStore(store, 0) ? 0 : 1;
}
