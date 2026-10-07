// Startup algorithm tests follow SymCrypt's POSIX module.c (MIT licensed).
// Copyright (c) Microsoft Corporation. Licensed under the MIT license.
// This is a static-library consumer, not the validated shared FIPS module.
#include "precomp.h"

SYMCRYPT_ENVIRONMENT_POSIX_USERMODE

static void __attribute__((constructor)) scs_symcrypt_start(void)
{
    SymCryptInit();
    SymCryptHmacSha256Selftest();
    SymCryptRngAesInstantiateSelftest();
    SymCryptRngAesReseedSelftest();
    SymCryptRngAesGenerateSelftest();
    SymCryptRngInit();

    SymCrypt3DesSelftest();
    SymCryptAesSelftest(SYMCRYPT_AES_SELFTEST_ALL);
    SymCryptAesCmacSelftest();
    SymCryptCcmSelftest();
    SymCryptGcmSelftest();
    SymCryptXtsAesSelftest();
    SymCryptHmacSha1Selftest();
    SymCryptHmacSha384Selftest();
    SymCryptHmacSha512Selftest();
    SymCryptParallelSha256Selftest();
    SymCryptParallelSha512Selftest();
    SymCryptTlsPrf1_1SelfTest();
    SymCryptTlsPrf1_2SelfTest();
    SymCryptHkdfSelfTest();
    SymCryptSp800_108_HmacSha1SelfTest();
    SymCryptSp800_108_HmacSha256SelfTest();
    SymCryptSp800_108_HmacSha384SelfTest();
    SymCryptSp800_108_HmacSha512SelfTest();
    SymCryptPbkdf2_HmacSha1SelfTest();
    SymCryptSrtpKdfSelfTest();
    SymCryptSshKdfSha256SelfTest();
    SymCryptSshKdfSha512SelfTest();
    SymCryptSskdfSelfTest();
    SymCryptHmacSha3_256Selftest();
    g_SymCryptFipsSelftestsPerformed |= SYMCRYPT_SELFTEST_ALGORITHM_STARTUP;
}

static void __attribute__((destructor)) scs_symcrypt_stop(void)
{
    // All provider users and keys must be gone before this image is unloaded.
    SymCryptEcurveCacheUninit();
    SymCryptRngUninit();
}

void SYMCRYPT_CALL scs_symcrypt_static_init(UINT32 api, UINT32 minor)
{
    if (api != SYMCRYPT_CODE_VERSION_API || minor > SYMCRYPT_CODE_VERSION_MINOR)
        SymCryptFatal('vers');
}
