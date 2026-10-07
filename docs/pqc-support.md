# Post-quantum certificates

The library and `certutil` embed OpenSSL **3.5.8**, Microsoft's
[SCOSSL provider](https://github.com/microsoft/SymCrypt-OpenSSL), and
[SymCrypt 103.13.0](https://github.com/microsoft/SymCrypt). All three are
statically linked from pinned public Git submodules. CompositeCrypto is no
longer a dependency. No external provider module, shared SymCrypt library, or
system OpenSSL development package is required. Updating embedded crypto
requires rebuilding and redeploying the library and tools.

The built-in `symcryptprovider` supplies both pure ML-DSA and composite
ML-DSA/ECDSA using SymCrypt. Composite signatures are not separate ML-DSA and
ECDSA certificates in a mixed chain. The embedded OpenSSL default provider
supplies formats and algorithms absent from SCOSSL; the default property query
`?provider=symcryptprovider` prefers SCOSSL wherever available.

## Covered algorithms

| Algorithm name | Public-key and signature OID |
| --- | --- |
| ML-DSA-44 | 2.16.840.1.101.3.4.3.17 |
| ML-DSA-65 | 2.16.840.1.101.3.4.3.18 |
| ML-DSA-87 | 2.16.840.1.101.3.4.3.19 |
| MLDSA44-ECDSA-P256-SHA256 | 1.3.6.1.5.5.7.6.40 |
| MLDSA65-ECDSA-P256-SHA512 | 1.3.6.1.5.5.7.6.45 |
| MLDSA65-ECDSA-P384-SHA512 | 1.3.6.1.5.5.7.6.46 |
| MLDSA87-ECDSA-P384-SHA512 | 1.3.6.1.5.5.7.6.49 |

**Compatibility change:** the previous Brainpool (`.47`, `.50`) and P-521
(`.54`) composites are not supported by the pinned SymCrypt API. Their keys
cannot be loaded or used and their signatures cannot be verified by this build.
Certificate-byte storage/display alone does not imply algorithm support.

Certificate import, enumeration, PEM/DER/PKCS#7 export, issuer-signature
checking, and private-key PFX import/export use these providers. Persistent
keys remain permission-protected PKCS#8 files. The CLI does not generate
certificates or keys.

`cmake/patches/scossl-composite-mldsa.patch` carries the four-variant key
management/signature/codec implementation, encoder-context cipher cleanup,
and an EC key-comparison fix (skip absent components rather than pass null
buffers to `memcmp`, and compare private components in constant time)
on public SCOSSL `d73b1e9ebf589f5c0098810e74e9556b2bef776a`.
`cmake/patches/symcrypt-curve-cache.patch` carries cache teardown on public
SymCrypt `286762b7730e2b780678f5ab11fef2b1bad639e0`.
CMake verifies the revisions, exports committed sources, and applies patches
to build-tree copies. The original submodules are unmodified and the composite
feature need not be published for a reproducible build.

`src/symcrypt-static.c` is platform/lifetime glue for SymCrypt's static
libraries. It runs the POSIX startup algorithm tests, retains on-demand
asymmetric tests and fatal-error behavior, and uses upstream AES DRBG,
kernel/jitter entropy and fork detection. The timing-sensitive jitter source
retains `-O0` and is not sanitizer-instrumented. SymCrypt uses its upstream
`Sanitize` configuration (which excludes alignment checks for intentional
unaligned accesses); the wrapper, SCOSSL and OpenSSL use ASan/UBSan.
This static consumer is **not
the validated shared FIPS module**: it does not claim that module's integrity
boundary or verification, and all SCOSSL registrations advertise `fips=no`.
Do not unload the library while any callers, contexts, or keys remain active.

## Validation

The regular CTest suite checks the listed OIDs, absent AlgorithmIdentifier
parameters, valid/invalid issuer signatures, corruption of both ends of
composite signatures, persistent key reload, and PFX round trips. CLI workflows
cover all three pure variants and all four composite variants. Provider checks
verify that key generation/reload, SHA-256, AES and the private DRBG use SCOSSL, that removed
variants fail to fetch, and that SCOSSL cannot satisfy a `fips=yes` query.
ELF checks reject dynamic OpenSSL/SCOSSL/SymCrypt/jitter dependencies and
exported or imported embedded crypto symbols.

An optional independent test exchanges fresh throwaway keys and signatures
with `Microsoft.Bcl.Cryptography` **11.0.0-preview.6.26359.118**, the package
used by QuahogCA. It checks `.40`, `.45`, `.46`, and `.49`: the C++ provider imports
.NET SPKI/PKCS#8, verifies .NET signatures, and signs certificates whose
signatures .NET verifies (including tampering rejection).
This is cryptographic wire interoperability, not a full QuahogCA service test.

After building `build-bundled` in Ubuntu WSL, run these commands from the
Windows repository directory with a .NET 10 SDK and supported crypto platform:

```powershell
dotnet run --project .\tests\interop\interop.csproj -- generate .\build-bundled\interop
wsl -d Ubuntu -- bash -lc './build-bundled/store-tests --interop ./build-bundled/interop'
dotnet run --project .\tests\interop\interop.csproj -- verify .\build-bundled\interop
```

Generated private keys are test material only. Use an access-restricted build
directory; do not commit fixtures. Successful verification deletes the private
DER files. Delete those files yourself if an earlier step fails.
The .NET harness is optional and is not a dependency of the Linux library.

## Limits

Passing these tests is not a security audit, formal standards certification,
or FIPS validation. Composite SCOSSL support is carried as a local development
patch, not an upstream release. RSA composites and composite KEMs are outside
this project's tested certificate support.

Static crypto does not make unrelated Linux programs understand composite
certificates, even if a certificate is installed in native trust. The native
trust updater and consuming application must also support the relevant
format/algorithm. Issuer-signature checking is not full chain-policy or
revocation validation.
