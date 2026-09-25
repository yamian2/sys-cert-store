# sys-cert-store

A C++20 certificate-store library for Linux, using Win32 `Cert*` names,
signatures and ownership conventions for source-level porting. This is an
**initial core implementation, not a complete Crypt32 replacement**. The full
scope and remaining APIs are tracked in [API compatibility](docs/api-compatibility.md).

The initial development environment is Ubuntu 24.04 under WSL. Red Hat-family
Linux and Microsoft Azure Linux are build targets, with Azure Linux the final
deployment target. The current dependency baseline is **OpenSSL 3**, SQLite
3.31 or newer, CMake 3.20, and a C++20 compiler. Older CBL-Mariner installations
with OpenSSL 1.1 require a future compatibility port.

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
| Current-user named stores (`MY`, `CA`, or another logical name) | `<effective-user-home>/.local/share/sys-cert-store/<NAME>.db` plus `<NAME>.db.objects/` |
| Local-machine named stores other than `ROOT` | `/var/lib/sys-cert-store/<NAME>.db` plus `<NAME>.db.objects/` |
| `ROOT`, at either supported location | Snapshot of native TLS trust; opt-in writes modify distro sources and regenerate trust |
| `SYS_CERT_STORE_PROV_SQLITE` | Caller-selected absolute metadata filename, plus adjacent `<filename>.objects/` |

For example, importing into `MY` creates:

```text
MY.db                            # metadata only
MY.db.objects/
  <random-object-id>/
    certificate.pem
    private-key.pem              # only when the import contains a matching key
```

Object directories use mode `0700`; certificate, private-key and new database
files use `0600`. Certificate files are flushed before metadata commits.
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
`IMPORT-<id>.db` store in the current user's library directory, unlike Windows'
temporary returned certificate store. Closing it does not delete its files.
`SysCertGetCertificateFilePath` returns the certificate or key filename.
Multi-key PFX files and unsupported bag types fail rather than dropping material.
An import containing certificates alone cannot produce private keys.

`ROOT` exposes system TLS trust, not every certificate found somewhere below
`/etc`. Loading only the distro's generated bundle respects which anchors the
distro includes for TLS. This is not a full representation of p11-kit
purpose-specific trust or distrust metadata. Current-user `ROOT` currently
exposes the same native snapshot as local-machine `ROOT`, without a per-user
overlay.

| Distro family | Authoritative TLS bundle | Local anchor directory | Update utility |
| --- | --- | --- | --- |
| Ubuntu / Debian | `/etc/ssl/certs/ca-certificates.crt` | `/usr/local/share/ca-certificates` | `/usr/sbin/update-ca-certificates --fresh` |
| Red Hat / Fedora / compatible | `/etc/pki/ca-trust/extracted/pem/tls-ca-bundle.pem` | `/etc/pki/ca-trust/source/anchors` | `/usr/bin/update-ca-trust extract` |
| CBL-Mariner / Azure Linux | `/etc/pki/ca-trust/extracted/pem/tls-ca-bundle.pem` | `/etc/pki/ca-trust/source/anchors` | `/usr/bin/update-ca-trust extract` |

Detection uses `/etc/os-release` (`ID` and `ID_LIKE`). Unknown distros fail
explicitly; missing or malformed bundles are not treated as empty successful
stores. Duplicate DER certificates in a native bundle are collapsed.

## Build

Ubuntu dependencies:

```sh
sudo apt-get install build-essential cmake libssl-dev libsqlite3-dev ca-certificates
```

Red Hat 9 / compatible dependencies:

```sh
sudo dnf install gcc-c++ cmake make openssl-devel sqlite-devel ca-certificates
```

Azure Linux 3 dependencies:

```sh
sudo tdnf install gcc-c++ cmake make openssl-devel sqlite-devel ca-certificates
```

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

`list-certificates` reads the actual native ROOT snapshot without changing it.
The test executable uses generated certificates and disposable directories
under `/tmp`. It exercises persistence in a separate executable process,
reference ownership, dispositions, properties, searches, PKCS#7 export, all
distro layouts, explicit trust-write gating, and updater-failure rollback.
Native write fixtures use disposable trees. On Ubuntu, the vendor-root test
also invokes the installed `update-ca-certificates` with **all** certificate,
configuration, output and hook directories redirected to its fixture tree.
No test changes the machine's active trust.

## Use

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

Native ROOT is read-only by default. Explicitly enable writes when opening it:

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

## Implementation boundaries

OpenSSL handles X.509/PKCS#12 parsing, PKCS#8 key files, digests, issuer signature
checks, and PKCS#7 encoding. SQLite indexes the file-backed logical stores.
C++ exceptions do not escape
the API; errors use thread-local `GetLastError()` and the diagnostic extension.
Calls are serialized within a process; SQLite coordinates independent database
connections/processes with a five-second busy timeout. Callers still own context
lifetimes and must not free a context concurrently with code using its fields.

CRLs, CTLs, collections, link semantics, Windows serialization,
CNG/KSP bridging, registration callbacks and complete Win32 flag coverage
are planned, **not implemented or silently emulated**. Unsupported options in
implemented functions fail explicitly. Future functions are not declared as
misleading success-returning stubs.
