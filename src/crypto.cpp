#include "crypto.h"
#include <openssl/core.h>
#include <openssl/evp.h>
#include <openssl/provider.h>
#include <memory>
#include <stdexcept>

extern "C" int scs_symcrypt_provider_init(const OSSL_CORE_HANDLE*, const OSSL_DISPATCH*, const OSSL_DISPATCH**, void**);

namespace scs {
void initialize_crypto() {
    struct Providers {
        std::unique_ptr<OSSL_PROVIDER, decltype(&OSSL_PROVIDER_unload)> standard{nullptr, OSSL_PROVIDER_unload};
        std::unique_ptr<OSSL_PROVIDER, decltype(&OSSL_PROVIDER_unload)> symcrypt{nullptr, OSSL_PROVIDER_unload};
        Providers() {
            if (!OPENSSL_init_crypto(OPENSSL_INIT_NO_LOAD_CONFIG, nullptr))
                throw std::runtime_error("Cannot initialize statically linked OpenSSL");
            standard.reset(OSSL_PROVIDER_load(nullptr, "default"));
            if (!standard || !OSSL_PROVIDER_add_builtin(nullptr, "symcryptprovider", scs_symcrypt_provider_init))
                throw std::runtime_error("Cannot initialize statically linked crypto providers");
            symcrypt.reset(OSSL_PROVIDER_load(nullptr, "symcryptprovider"));
            if (!symcrypt || !EVP_set_default_properties(nullptr, "?provider=symcryptprovider"))
                throw std::runtime_error("Cannot initialize the statically linked SymCrypt provider");
        }
    };
    static const Providers providers;
}
}
