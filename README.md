# sys-cert-store

A C++20 certificate-store library for Linux, using Win32 `Cert*` names,
signatures and ownership conventions for source-level porting. This is an
**initial core implementation, not a complete Crypt32 replacement**. The full
scope and remaining APIs are tracked in [API compatibility](docs/api-compatibility.md).

Builds under Ubuntu, Red Hat-family distributions and Microsoft Azure Linux,
with Azure Linux the final deployment target. The initial development
environment is Ubuntu 24.04 under WSL. The build uses **pinned OpenSSL 3.5.8,
SCOSSL and SymCrypt
source**, SQLite 3.31 or newer, CMake 3.20, Perl, Python 3, GNU Make, and C/C++20
compilers. OpenSSL calls the built-in SCOSSL provider, which uses SymCrypt.
All three crypto dependencies are linked statically; system OpenSSL headers,
libraries and provider modules are not used.

## Storage

**Files are authoritative; SQLite is a metadata index.** Each logical-store
certificate is a PEM file in its own directory. If it has an associated private
key, that directory also contains an unencrypted PKCS#8 PEM file protected by
Linux ownership and permissions. SQLite contains only object references,
extended properties, store properties and pending-deletion metadata, never
certificate DER/PEM or private-key contents. Everything survives process restarts.

| Store | Backing storage |
| --- | --- |
| `CERT_STORE_PROV_MEMORY` | Temporary C++ certificate/key objects and in-memory metadata; no files |
| Current-user named stores (`ROOT`, `CA`, `MY`, or another logical name) | `<effective-user-home>/.local/share/sys-cert-store/<NAME>.db` plus `<NAME>.db.objects/` |
| Local-machine named stores other than `ROOT` | `/var/lib/sys-cert-store/<NAME>.db` plus `<NAME>.db.objects/` |
| Computer `ROOT` | Snapshot of native TLS trust; opt-in writes modify distro sources and regenerate trust |
| `SYS_CERT_STORE_PROV_SQLITE` | Caller-selected absolute metadata filename, plus adjacent `<filename>.objects/` |

For example, importing into current-user `MY` creates:

```text
MY.db                            # metadata only
MY.db.objects/
  <random-object-id>/
    certificate.pem
    private-key.pem              # only when the import contains a matching key
```

User/explicit-store object directories use mode `0700`; certificate, private-key
and new database files use `0600`. Computer stores expose certificate files and
metadata with `0644` and their directories with `0755`, while private keys remain
`0600` inside a separate `0700` `keys/` directory. Certificate enumeration never
opens private keys. Copying a key or requesting its path requires access to that
protected file. Do not place secrets in computer-store properties.
Certificate files are flushed before metadata commits.
Deletion removes the certificate **and its corresponding private-key file**.
A metadata garbage queue retries interrupted post-commit deletions when the
store is next opened writable. A crash before a new object's metadata commit
can leave an unreferenced object directory; automatic orphan sweeping is not
implemented. Back up both the metadata and object tree together while writers
are stopped. This is not a distributed transaction across arbitrary filesystems.

The effective user's home comes from the account database,
not environment variables. Store names are case-insensitive ASCII letters,
digits, `_` and `-`, up to 64 characters. `CA` stores intermediate CA files but
does **not** promote them to trusted roots. Linux has no universal native
equivalent of Windows `MY`/`CA`; their object hierarchy is library-managed.
The distro layout is used for native roots. Properties must not contain private-key material.

PKCS#12 imports preserve a matching private key and all certificates in the
bundle. `SysCertImportPfxToStore` imports directly into a chosen persistent
logical store. `PFXImportCertStore` returns a newly created persistent
`IMPORT-<id>.db` store in the user's library directory by default or the computer
directory with `CRYPT_MACHINE_KEYSET`, unlike Windows'
temporary returned certificate store. Closing it does not delete its files.
`SysCertGetCertificateFilePath` returns the certificate or key filename.
Multi-key PFX files and unsupported bag types fail rather than dropping material.
An import containing certificates alone cannot produce private keys.
`PFXExportCertStoreEx` exports all certificates using the two-call blob convention.
Flags `0`, `REPORT_NO_PRIVATE_KEY`, `REPORT_NOT_ABLE_TO_EXPORT_PRIVATE_KEY`, and
`EXPORT_PRIVATE_KEYS` are supported. Flag `0` never opens private-key files.
`EXPORT_PRIVATE_KEYS` requires exactly one matching key; multiple exportable keys
are rejected. Exported key and certificate safes use AES-256-CBC.

`SysCertPopulateDotNetCrlCache` preloads the private CRL cache used by .NET on
Linux. With a UTF-8 user name, it discovers HTTP CRL distribution points from
that user's `MY`, `CA`, and `ROOT` views and writes validated PEM CRLs below
`.dotnet/corefx/cryptography/crls`. The current user follows `HOME`, matching
.NET; another user follows that account's home-directory record. The caller
must be root or the selected user.

Passing `nullptr` scans `/proc/*/maps` for processes that have loaded
`libcoreclr.so`, deduplicates their effective UIDs, discovers CDPs from the
computer `MY`, `CA`, and `ROOT` stores, and populates each discovered account's
cache. Restricted `/proc` visibility is reported as a failure rather than
silently producing an incomplete result. Downloads use HTTP, require a matching
issuer and valid CRL signature, reject future/expired CRLs, and reproduce .NET's
`<issuer-hash>.<URL-hash>.crl` name. Cache directories are `0700`, files are
`0600`, writes are atomic, and root assigns ownership to the target account.
Processing is best effort: successful independent entries remain cached, but
the function returns `FALSE` and reports an aggregate diagnostic if any
discovered operation fails.

Computer `ROOT` exposes system TLS trust, not every certificate found somewhere below
`/etc`. Loading only the distro's generated bundle respects which anchors the
distro includes for TLS. This is not a full representation of p11-kit
purpose-specific trust or distrust metadata.

## User and computer stores

`ROOT`, `CA` (Windows' intermediate-certification-authorities store), and `MY`
(personal certificates) are predefined in both scopes, even before metadata
files exist. Read-only or existing-only opens of these empty standard stores
work without creating files. Metadata and object directories are created on the
first write. Custom store names are persisted separately.

| Logical view | Entries visible | Destination of adds/imports |
| --- | --- | --- |
| Current-user `ROOT` | User roots, then inherited computer roots | User root files and metadata only |
| Current-user `CA` | User intermediates, then inherited computer intermediates | User CA files and metadata only |
| Current-user `MY` | User personal certificates only | User MY files and metadata |
| Computer `ROOT` | Distro-native trusted roots | Native trust sources, with explicit write opt-in |
| Computer `CA` / `MY` | That computer store's certificates | Computer store files and metadata |

The current user is the effective Linux UID, not an environment-supplied name.
Different accounts have different user metadata directories. User changes never
modify computer trust: inherited entries are read-only through the user view.
To remove a machine root, explicitly open computer `ROOT` with native-write
permission. To remove a user root, delete its user-origin context normally.
Deleting a local duplicate does not remove an inherited copy. `CA` and `MY`
membership does not make a certificate a native trusted root.

Search, issuer lookup and PKCS#7 export see the same inherited view as
enumeration. `SysCertGetCertificateStoreLocation` reports an entry's origin;
an inherited context's `hCertStore` still identifies the user view for continued
enumeration. Inherited views do not expose computer private keys. User roots
are visible to library consumers, **not automatically to unrelated Linux TLS
applications**. There is no modification of the machine CA bundle for user trust.

`CertEnumSystemStoreLocation` enumerates the two locations;
`CertEnumSystemStore` enumerates standard and persisted custom store names for
the selected scope. The intermediate store's actual Win32 name is `CA`, not
`Intermediate`. `CertOpenSystemStoreA/W` selects current-user scope.

`SysCertConfigureSystemStores` can relocate user metadata, computer metadata and
the native system root for isolated fixtures or application deployments. All
stores and contexts must be closed before reconfiguration; null resets defaults.
Relocation does not impersonate a user, elevate privileges or sandbox native
update executables. Existing computer files created with earlier private-only
permissions retain those restrictions; the library does not silently loosen
permissions on existing stores.

## Certificate chains

`CertGetCertificateChain` constructs one offline chain from the leaf, an
optional additional store, and the current-user `CA` and `ROOT` views (including
their inherited computer certificates). Candidate certificates are
de-duplicated by SHA-256 fingerprint; signature-valid issuers are preferred,
and trusted-root candidates win deterministic ties. The returned context owns
references to every certificate element until `CertFreeCertificateChain`.

The implementation validates current-time validity, issuer signatures, CA
basic constraints, `keyCertSign`, path-length constraints, partial chains,
cycles, and root trust. `CertVerifyCertificateChainPolicy` supports
`CERT_CHAIN_POLICY_BASE` and reports the prioritized validation result in
`CERT_CHAIN_POLICY_STATUS`. Chain building does not perform AIA retrieval,
network access, or revocation checks, and custom engines, validation times,
usage constraints, and nonzero flags are rejected.

| Distro family | Authoritative TLS bundle | Local anchor directory | Update utility |
| --- | --- | --- | --- |
| Ubuntu / Debian | `/etc/ssl/certs/ca-certificates.crt` | `/usr/local/share/ca-certificates` | `/usr/sbin/update-ca-certificates --fresh` |
| Red Hat / Fedora / compatible | `/etc/pki/ca-trust/extracted/pem/tls-ca-bundle.pem` | `/etc/pki/ca-trust/source/anchors` | `/usr/bin/update-ca-trust extract` |
| CBL-Mariner / Azure Linux | `/etc/pki/ca-trust/extracted/pem/tls-ca-bundle.pem` | `/etc/pki/ca-trust/source/anchors` | `/usr/bin/update-ca-trust extract` |

Detection uses `/etc/os-release` (`ID` and `ID_LIKE`). Unknown distros fail
explicitly; missing or malformed bundles are not treated as empty successful
stores. Duplicate DER certificates in a native bundle are collapsed.

## Build

Initialize the pinned Git submodules before configuring:

```sh
git submodule update --init --recursive
```

The submodules pin OpenSSL 3.5.8, public SCOSSL at `d73b1e9`, and public
SymCrypt 103.13.0 at `286762b`, including SymCrypt's pinned jitterentropy source.
Build-tree patches carry the unpublished four-variant composite support,
SCOSSL encoder/EC-comparison cleanup, and SymCrypt curve-cache cleanup; dependency checkouts
are not modified. No unpublished remote commit or internal source is required.
OpenSSL uses Apache-2.0, SCOSSL and SymCrypt use MIT, and jitterentropy is used
under its BSD license. Installation includes the dependency license files.

CMake builds OpenSSL out of tree with `no-shared`, `no-module`, `no-dso` and PIC,
and registers SCOSSL's statically linked `symcryptprovider` in-process. SymCrypt
uses its PIC static libraries and a local POSIX runtime adapter, retaining the
upstream startup algorithm tests, AES DRBG, kernel and jitter entropy sources,
and fork detection. There is no system-OpenSSL fallback and no provider `.so`
deployment. The first build takes
longer. Static crypto symbols are hidden to avoid interposition with an
application's own OpenSSL. The library itself remains shared, and SQLite and
the platform runtime remain dynamic. This is not a fully static executable
or a FIPS-validated build. The static consumer is not SymCrypt's shared FIPS
module, does not perform that module's ELF integrity verification, and advertises
`fips=no`. SCOSSL is preferred for supported operations, including pure and
composite ML-DSA; OpenSSL's embedded default provider remains available for
formats and algorithms SCOSSL does not implement. Host OpenSSL configuration
is not loaded. Updating any embedded crypto requires rebuilding and redeploying
this project; OS package updates do not update its embedded copies.

Native Linux builds are supported; cross-compilation is explicitly rejected.
Under WSL, a build directory on the Linux filesystem avoids the substantial
compilation overhead of writing intermediate files under `/mnt/c`.
The full PQC coverage and current provider limits are described in
[PQC support](docs/pqc-support.md).

Ubuntu dependencies:

```sh
sudo apt-get install build-essential cmake perl python3 git libsqlite3-dev ca-certificates binutils
```

Red Hat 9 / compatible dependencies:

```sh
sudo dnf install gcc-c++ cmake make perl-core python3 git sqlite-devel ca-certificates binutils libatomic
```

Azure Linux 3 dependencies:

```sh
sudo rpm --import /etc/pki/rpm-gpg/MICROSOFT-RPM-GPG-KEY && sudo gpg --batch --import /etc/pki/rpm-gpg/MICROSOFT-RPM-GPG-KEY && sudo tdnf install build-essential cmake perl python3 git sqlite-devel ca-certificates findutils binutils libatomic
```

Azure Linux package signatures use RPM's keyring, while the `tdnf` repository
metadata plugin uses GPG's keyring under the current `HOME`. GitHub Actions
overrides the container's `HOME`, so initialize both keyrings with the shipped
distribution key before dependency installation. Do not disable package or
repository signature verification.

Build and exercise the isolated fixtures:

```sh
cmake -S . -B build -DCMAKE_BUILD_TYPE=Release && cmake --build build -j && ctest --test-dir build --output-on-failure
```

From Windows PowerShell, in the checkout:

```powershell
wsl -d Ubuntu --cd C:\src\sys-cert-store -- bash -lc 'cmake -S . -B build -DCMAKE_BUILD_TYPE=Debug && cmake --build build -j 4 && ctest --test-dir build --output-on-failure'
```

For production, place databases on a native Linux filesystem, not WSL's
Windows-mounted filesystem: SQLite relies on correct filesystem locking and
durability semantics.

Optional sanitizers:

```sh
cmake -S . -B build-asan -DCMAKE_BUILD_TYPE=Debug -DSYS_CERT_STORE_SANITIZERS=ON && cmake --build build-asan -j && ctest --test-dir build-asan --output-on-failure
```

`list-certificates` reads current-user ROOT, including inherited native roots,
without changing trust.
The test executable uses generated certificates and disposable directories
under `/tmp`. It exercises persistence in a separate executable process,
reference ownership, dispositions, properties, searches, PKCS#7 export, all
distro layouts, user/computer inheritance and isolation, private-key permissions,
explicit trust-write gating, and updater-failure rollback. When run as root, it
also drops privileges in a child process to verify public computer certificates
are readable without exposing their private keys.
Native write fixtures use disposable trees. On Ubuntu, the vendor-root test
also invokes the installed `update-ca-certificates` with **all** certificate,
configuration, output and hook directories redirected to its fixture tree.
No test changes the machine's active trust.

## Use

### Command-line tool

The build includes [`tools/certutil`](tools/certutil/README.md), a Windows-style
certificate-store CLI. Run `build/tools/certutil/certutil -?` for help. It supports
store enumeration, certificate display, PEM/DER/PKCS#7 import/export, deletion,
and password-protected PFX import/export. It defaults to **computer** scope;
`-user` selects the current user's stores.

```sh
build/tools/certutil/certutil -user -store MY
```

```sh
build/tools/certutil/certutil -user -addstore CA intermediate.pem
```

```sh
build/tools/certutil/certutil -user -importPFX MY identity.pfx
```

PFX commands prompt for a password without echoing it, or accept
`--password-file` for automation. Computer ROOT writes additionally require
`--allow-native-write`; the tool never elevates privileges. This is **not NSS
certutil**: use the full executable path when both are installed.

### Library

```cpp
#include <sys-cert-store/sys-cert-store.h>

HCERTSTORE store = CertOpenSystemStoreW(0, L"MY"); // Files with SQLite metadata.
if (!store) {
    // GetLastError() and SysCertGetLastErrorMessage() describe the failure.
    return;
}

PCCERT_CONTEXT certificate = nullptr;
while ((certificate = CertEnumCertificatesInStore(store, certificate))) {
    // certificate->pbCertEncoded, certificate->cbCertEncoded, certificate->pCertInfo
    // The next enumeration call consumes the previous context reference.
}
DWORD enumerationError = GetLastError(); // CRYPT_E_NOT_FOUND is normal end-of-store.
CertCloseStore(store, 0);
```

For an explicit persistent filename, create its parent directory first:

```cpp
HCERTSTORE store = CertOpenStore(SYS_CERT_STORE_PROV_SQLITE, 0, 0, 0, "/absolute/path/certificates.db");
```

Link against `sys-cert-store`. Installation supports
`find_package(sys-cert-store CONFIG REQUIRED)` and the imported target
`sys-cert-store::sys-cert-store`.

All public API functions have C linkage, with a C++ public header. `DWORD`,
`BOOL`, blobs, `CERT_INFO`, `CERT_CONTEXT`, and supported constants use Win32
names. `WCHAR` deliberately uses Linux's native `wchar_t`, so `L"..."` works
without conversion. This is **not Windows binary/layout compatibility**:
wide-character data is normally 32-bit on Linux, rather than Windows UTF-16.
The `_A` APIs accept UTF-8, not a Windows ANSI code page.

## Explicit native trust changes

Computer/native ROOT is read-only by default. Explicitly enable writes when opening it:

```cpp
HCERTSTORE roots = CertOpenStore(CERT_STORE_PROV_SYSTEM_W, 0, 0,
    CERT_SYSTEM_STORE_LOCAL_MACHINE | SYS_CERT_STORE_NATIVE_WRITE_FLAG, L"ROOT");
// Check every result and GetLastError().
CertAddCertificateContextToStore(roots, caContext, CERT_STORE_ADD_NEW, nullptr);
// Find a root context in roots, then:
CertDeleteCertificateFromStore(rootContext); // Consumes rootContext, even on failure.
```

These APIs now make filesystem changes, rather than just editing metadata.
The standalone `SysCertUpdateTrustAnchor` extension remains available with the
`SYS_CERT_TRUST_UPDATE_ALLOW` opt-in. Native operations:

1. Require explicit opt-in, filesystem permission, a CA certificate, and a
   non-set-ID process; it does not run `sudo` or elevate privilege.
2. Write a SHA-256-named `sys-cert-store-<hash>.crt` anchor and invoke the
   distro's absolute updater path, without a shell or inherited loader settings.
3. Physically remove matching single-certificate local anchor files. For
   distro-provided roots, Debian configuration is changed to `!<certificate>`
   in `/etc/ca-certificates.conf`; RPM-family systems receive a PEM distrust
   entry under `/etc/pki/ca-trust/source/blocklist` (or the existing legacy
   `blacklist` directory). The packaged original stays
   on disk but is removed from active trust and remains disabled on regeneration.
4. Stage changes, lock cooperating library writers, flush files/directories,
   verify the resulting active TLS bundle, and attempt rollback plus bundle
   regeneration if the updater fails or leaves the wrong trust state.

Native `ADD_ALWAYS` is rejected because system anchors are unique.
Re-adding a root clears this library's corresponding RPM blocklist entry;
it does not override unrelated administrator-defined distrust rules.
Root-property persistence, multi-certificate local-source surgery, and
replacing a native root with different bytes but the same identity are not
implemented. Remove the old root before adding a different replacement.

Trust updates affect the whole machine and are not an atomic transaction with
all distro-generated bundles. A process crash, filesystem failure, failing
updater, or independent administrator can require manual recovery. A leftover
`pending-update` journal blocks subsequent updates. It lists original paths and
numbered `.rollback` backups. Inspect it, restore the desired source state, run
the distro updater, and remove the recovered staging files before retrying.
Failures are reported,
including when rollback cannot regenerate the bundle. Adding a CA is a trust
decision made by the caller; this function does not establish that the CA is safe.

Staging is outside the distro's trust-source tree:
`/usr/local/share/.sys-cert-store-staging` on Debian-family systems and
`/etc/pki/.sys-cert-store-staging` on RPM-family systems. This prevents a
certificate staged for removal from still being imported by p11-kit. The staging
and changed source/configuration directories must be on the same filesystem for atomic rename;
otherwise the update fails explicitly without invoking the updater.

Reopen ROOT or call `CertControlStore(..., CERT_STORE_CTRL_RESYNC, nullptr)`
after external changes. Release native contexts before resynchronizing.
`SYS_CERT_NATIVE_OPTIONS::rootPath` supports fixture trees; it is **not a
chroot or security sandbox**. Do not copy a real distro updater into a fixture
tree: that program can still act on absolute host paths. Use only trusted,
purpose-built fixture executables there.

## Storage

**Files are authoritative; SQLite is a metadata index.** Each logical-store
certificate is a PEM file in its own directory. If it has an associated private
key, that directory also contains an unencrypted PKCS#8 PEM file protected by
Linux ownership and permissions. SQLite contains only object references,
extended properties, store properties and pending-deletion metadata, never
certificate DER/PEM or private-key contents. Everything survives process restarts.

| Store | Backing storage |
| --- | --- |
| `CERT_STORE_PROV_MEMORY` | Temporary C++ certificate/key objects and in-memory metadata; no files |
| Current-user named stores (`ROOT`, `CA`, `MY`, or another logical name) | `<effective-user-home>/.local/share/sys-cert-store/<NAME>.db` plus `<NAME>.db.objects/` |
| Local-machine named stores other than `ROOT` | `/var/lib/sys-cert-store/<NAME>.db` plus `<NAME>.db.objects/` |
| Computer `ROOT` | Snapshot of native TLS trust; opt-in writes modify distro sources and regenerate trust |
| `SYS_CERT_STORE_PROV_SQLITE` | Caller-selected absolute metadata filename, plus adjacent `<filename>.objects/` |

For example, importing into current-user `MY` creates:

```text
MY.db                            # metadata only
MY.db.objects/
  <random-object-id>/
    certificate.pem
    private-key.pem              # only when the import contains a matching key
```

User/explicit-store object directories use mode `0700`; certificate, private-key
and new database files use `0600`. Computer stores expose certificate files and
metadata with `0644` and their directories with `0755`, while private keys remain
`0600` inside a separate `0700` `keys/` directory. Certificate enumeration never
opens private keys. Copying a key or requesting its path requires access to that
protected file. Do not place secrets in computer-store properties.
Certificate files are flushed before metadata commits.
Deletion removes the certificate **and its corresponding private-key file**.
A metadata garbage queue retries interrupted post-commit deletions when the
store is next opened writable. A crash before a new object's metadata commit
can leave an unreferenced object directory; automatic orphan sweeping is not
implemented. Back up both the metadata and object tree together while writers
are stopped. This is not a distributed transaction across arbitrary filesystems.

The effective user's home comes from the account database,
not environment variables. Store names are case-insensitive ASCII letters,
digits, `_` and `-`, up to 64 characters. `CA` stores intermediate CA files but
does **not** promote them to trusted roots. Linux has no universal native
equivalent of Windows `MY`/`CA`; their object hierarchy is library-managed.
The distro layout is used for native roots. Properties must not contain private-key material.

PKCS#12 imports preserve a matching private key and all certificates in the
bundle. `SysCertImportPfxToStore` imports directly into a chosen persistent
logical store. `PFXImportCertStore` returns a newly created persistent
`IMPORT-<id>.db` store in the user's library directory by default or the computer
directory with `CRYPT_MACHINE_KEYSET`, unlike Windows'
temporary returned certificate store. Closing it does not delete its files.
`SysCertGetCertificateFilePath` returns the certificate or key filename.
Multi-key PFX files and unsupported bag types fail rather than dropping material.
`PFXExportCertStoreEx` supports certificate-only and single-private-key exports
with AES-256-CBC protection. Certificate-only export does not open private-key
files; key export requires exactly one matching key.


Computer `ROOT` exposes system TLS trust, not every certificate found somewhere below
`/etc`. Loading only the distro's generated bundle respects which anchors the
distro includes for TLS. This is not a full representation of p11-kit
purpose-specific trust or distrust metadata.


## Implementation boundaries

OpenSSL handles X.509/PKCS#12 parsing, PKCS#8 key files, digests, issuer signature
checks, and PKCS#7 encoding. SQLite indexes the file-backed logical stores.
C++ exceptions do not escape
the API; errors use thread-local `GetLastError()` and the diagnostic extension.
Calls are serialized within a process; SQLite coordinates independent database
connections/processes with a five-second busy timeout. Callers still own context
lifetimes and must not free a context concurrently with code using its fields.

Crypt32-compatible CRL stores/APIs, CTLs, general-purpose collections, link semantics, Windows serialization,
CNG/KSP bridging, registration callbacks and complete Win32 flag coverage
are planned, **not implemented or silently emulated**. Unsupported options in
implemented functions fail explicitly. Future functions are not declared as
misleading success-returning stubs.
