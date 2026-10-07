# API compatibility and remaining scope

The requested scope comes from `Win32CertStoreAPI.md`. This matrix covers all
of its sections; a row marked planned is not an exported API in version 0.1.
Supported means the subset described here, not full Windows equivalence.

## Implemented entry points

| Reference section | APIs | Initial behavior |
| --- | --- | --- |
| 1 | `CertOpenStore`, `CertOpenSystemStoreW`, `CertOpenSystemStoreA` | Memory, system A/W, explicit SQLite and native providers. `Memory`/`System` provider strings are accepted. User and machine locations only. |
| 1 | `CertCloseStore`, `CertDuplicateStore` | Reference-counted store handles; default and check-close. Forced close is rejected. |
| 2 | `CertEnumCertificatesInStore` | Consumes previous context, including on failure. Skips archived certificates unless requested at open. |
| 3 | `CertFindCertificateInStore` | ANY; SHA-1, SHA-256, MD5; encoded subject/issuer names; subject/issuer strings A/W; issuer + serial; existing identity; issuer-of; key identifier; explicit property presence. Other types/flags fail. |
| 4 | `CertGetSubjectCertificateFromStore` | Issuer + little-endian serial identity. |
| 4 | `CertGetIssuerCertificateFromStore` | Issuer-name selection; optional subject signature and current-time checks; self-signed handling. No revocation checks or chain building. |
| 5 | `CertAddCertificateContextToStore`, `CertAddEncodedCertificateToStore` | All seven dispositions for logical stores; creates certificate/key files and indexes metadata. Native ROOT supports unique anchors with explicit write opt-in. |
| 6 | `CertDeleteCertificateFromStore` | Removes logical certificate/key files or removes/disables native roots; consumes context even on failure; other referenced contexts remain readable. |
| 7 | `CertCreateCertificateContext`, `CertDuplicateCertificateContext`, `CertFreeCertificateContext` | DER validation, populated `CERT_INFO`, reference counting. Duplicate returns the same pointer. |
| 8 | `CertGetCertificateContextProperty`, `CertSetCertificateContextProperty`, `CertEnumCertificateContextProperties` | Friendly name, description, archived, key identifier, application properties `0x8000..0xffff`; computed SHA-1/SHA-256/MD5. |
| 9 | `CertGetStoreProperty`, `CertSetStoreProperty` | Localized name and application properties `0x8000..0xffff`. |
| 11 | `CertSaveStore` | Unsigned certificate-only PKCS#7 export to memory; two-call size-query convention. Other output formats/targets fail. |
| 12 | `CertControlStore` | Immediate SQLite persistence and commit flush; native resync; unsupported controls fail. |
| 13 | `CertEnumSystemStore`, `CertEnumSystemStoreLocation` | User/computer locations, predefined ROOT/CA/MY and persisted custom-store names; callback early termination. |
| 16 | `PFXImportCertStore` | Single-key or certificate-only authenticated PKCS#12; creates a persistent import store with PEM certificates and filesystem-protected PKCS#8 key files. |

`GetLastError`, `SetLastError`, `SysCertGetLastErrorMessage` and
`SysCertUpdateTrustAnchor`, `SysCertImportPfxToStore`, and
`SysCertGetCertificateFilePath`, `SysCertGetCertificateStoreLocation`, and
`SysCertConfigureSystemStores` complete the error/native/file/scope integration
surface. `SysCertPopulateDotNetCrlCache` is a Linux-specific extension that
preloads .NET's private CRL cache from user or computer certificate-store CDPs;
it is not a Crypt32 API.

### Detailed compatibility limits

- Source-level Linux porting only. Native `wchar_t` is used, not 16-bit Windows
  `WCHAR`. Public structures have their documented fields, but there is no PE,
  DLL, Windows ABI, or serialized-structure interoperability promise.
- `CERT_INFO` includes version, little-endian serial, algorithm OIDs and DER
  parameters, encoded names, FILETIME validity, public key, unique IDs and
  extensions. Negative serials and pre-1601 dates fail explicitly.
- Add identity is issuer + serial, not DER bytes. `ADD_ALWAYS` permits duplicate
  rows. `ADD_NEWER` requires a strictly later `NotBefore`. The two inherit modes
  merge properties, with incoming values winning. Following the Microsoft
  reference for `ADD_REPLACE_EXISTING_INHERIT_PROPERTIES`, an existing encoded
  context is retained and receives the incoming properties. `ADD_USE_EXISTING`
  also retains it. `ADD_NEWER_INHERIT_PROPERTIES` replaces an older context.
- `CERT_FIND_EXISTING` matches issuer + serial identity. String matching uses
  UTF-8 distinguished-name attribute values, joined with `, `, and ASCII case
  folding. Full Windows locale/Punycode matching and exact `CertNameToStr`
  formatting are not implemented. Explicit searches can find archived rows.
- Subject key identifier uses the extension when present; otherwise it is
  derived with OpenSSL's SHA-1 public-key digest. Overrideable key identifier
  properties are persisted.
- Hashes are computed on demand and cannot be overridden in this release.
  They are not persisted as implicit properties; property enumeration and
  `CERT_FIND_PROPERTY` inspect explicitly stored properties only. Hash search
  and direct hash-property retrieval compute hashes independently.
- Friendly-name/description inputs are `CRYPT_DATA_BLOB` values containing a
  terminated native-WCHAR string, including the terminator. Application
  properties are opaque blobs. `nullptr` removes a property; a non-null empty
  blob sets an empty property, including the archived marker.
- Handles must originate from this library. Enumeration consumes its previous
  context on both success and failure, and deletion consumes its context even
  for access-denied failures. A normal close preserves outstanding contexts;
  check-close returns `CRYPT_E_PENDING_CLOSE` but still closes. Property changes
  after final close are context-local and do not persist.
- SQLite connections see committed changes from other connections; enumeration
  is ordered by row ID and is not a transaction-wide snapshot across calls.
  Deleted/replaced contexts retain their DER and last observed properties.
- SQLite contains object IDs, properties and a deletion queue, not certificate
  or key contents. Each object owns PEM certificate and optional PKCS#8 key
  files. Copying a certificate context to a persistent logical store also copies
  its associated key into a new protected object directory; this implementation
  does not emulate Windows non-exportable key policy.
- User/computer scopes have separate backing metadata. Standard `ROOT`, `CA`
  and `MY` exist logically before their first write. User ROOT/CA include
  read-only inherited machine entries; MY does not inherit. Adds target the
  selected scope's own backing store. Inherited deletion, property modification
  and key access are denied; modify the computer store explicitly instead.
  Searches, issuer lookups and PKCS#7 export include inherited entries. Local
  and inherited duplicate memberships are both enumerated, local first.
- Computer certificate files and metadata are readable independently of keys.
  New computer object directories use `0755`, certificate/metadata files `0644`,
  key directories `0700` and key files `0600`. Private-key files are opened
  lazily only for operations requiring them. Existing restrictive permissions
  are preserved. Linux filesystem permissions still control access.
- Native ROOT is a de-duplicated TLS-bundle snapshot, read-only unless explicitly
  opened with `SYS_CERT_STORE_NATIVE_WRITE_FLAG`. Add/delete then update native
  sources and regenerate trust. Local root files are physically deleted;
  vendor copies are disabled through Debian configuration or RPM distrust,
  not removed from package contents. Native property writes fail explicitly.
  SQLite logical
  stores do not implicitly become system trust. Read errors fail the whole
  load; failed resync leaves the previous snapshot unchanged.
- SQLite open supports read-only, existing-only, create-new, and archived
  enumeration. Explicit SQLite read-only opens require an existing file;
  standard system stores may be logically empty with no metadata file yet.
  Native/inherited-view resync rejects
  outstanding contexts rather than changing row identity underneath them.
- PFX import supports zero or one matching private key plus certificates.
  Integrity checks and password validation are required; unsupported bags and
  multiple keys are rejected. `0`, `CRYPT_EXPORTABLE`, and either
  `CRYPT_USER_KEYSET` or `CRYPT_MACHINE_KEYSET` are supported. Combining both
  keyset flags is an error. The explicit-destination import extension rejects
  a keyset flag contradicting the destination scope. No-persist flags are not
  implemented. Filesystem permission protection, not at-rest encryption,
  was selected for private keys. Private-key properties, CSP/KSP handles and
  private-key acquisition remain unimplemented.
- `PFXImportCertStore` deliberately creates a persistent user import store by
  default, or a computer import store for `CRYPT_MACHINE_KEYSET`,
  unlike the Windows returned memory store. Close preserves its certificate/key
  files. For predictable placement, use `SysCertImportPfxToStore` on an explicit
  file-backed store. It imports the entire supported PFX in one metadata
  transaction and creates separate object directories. Friendly-name bag
  attributes are not yet mapped to Windows properties.

## Planned entry points

| Reference section | APIs | Remaining implementation |
| --- | --- | --- |
| 5 | `CertAddCertificateLinkToStore` | Shared context/property lifetime across stores; not equivalent to copying DER. |
| 10 | `CertAddStoreToCollection`, `CertRemoveStoreFromCollection` | Priority traversal, write routing, sibling lifetime and collection provider. |
| 11 | Remaining `CertSaveStore` modes | File targets and Windows serialized stores/elements. |
| 12 | Remaining `CertControlStore` controls | Provider notifications and additional flag semantics. |
| 13 | `CertEnumPhysicalStore` and additional locations | Physical-store callbacks, service/remote/group-policy/enterprise locations. |
| 14 | `CertRegisterSystemStore`, `CertUnregisterSystemStore`, `CertRegisterPhysicalStore`, `CertUnregisterPhysicalStore` | Persistent registration and Windows-compatible callback structures. |
| 15 | `CertAddSerializedElementToStore`, `CertSerializeCertificateStoreElement` | Interoperable Windows element format, properties, context-type dispatch. |
| 16 | Remaining `PFXImportCertStore` behavior | Multiple keys, no-persist flags, bag-attribute mapping and Windows key-provider policies. |
| 17 | `CertAddCRLContextToStore`, `CertAddCRLLinkToStore`, `CertAddEncodedCRLToStore`, `CertDeleteCRLFromStore` | CRL context/storage/link ownership. |
| 17 | `CertEnumCRLsInStore`, `CertFindCRLInStore`, `CertGetCRLFromStore`, `CertSerializeCRLStoreElement` | CRL query, matching, issuer/revocation and serialization rules. |
| 17 | `CertGetCRLContextProperty`, `CertSetCRLContextProperty`, `CertEnumCRLContextProperties` | CRL property model. |
| 18 | `CertAddCTLContextToStore`, `CertAddCTLLinkToStore`, `CertAddEncodedCTLToStore`, `CertDeleteCTLFromStore` | CTL decoding, signed data, context/storage/link ownership. |
| 18 | `CertEnumCTLsInStore`, `CertFindCTLInStore`, `CertSerializeCTLStoreElement` | CTL usage matching, enumeration and serialization. |
| 18 | `CertGetCTLContextProperty`, `CertSetCTLContextProperty`, `CertEnumCTLContextProperties` | CTL property model. |
| 20 | `CryptAcquireCertificatePrivateKey`, CNG/KSP metadata | Linux key-provider abstraction; not part of certificate CRUD. |

CRL/CTL context creation, duplication and freeing will also be required even
though the supplied document lists only their store-manipulation functions.
The practical-core list in section 19 groups the above APIs; it is not a
separate set of exports.

## Portability status

The [certutil CLI](../tools/certutil/README.md) exposes the implemented store
operations and uses OpenSSL for public certificate formats and encrypted PFX
export. CLI export does not imply that the Windows `PFXExportCertStoreEx` library
API, Windows key providers, or full certutil command coverage is implemented.

Ubuntu 24.04 WSL is the initial exercised environment. The CI workflow also
targets Red Hat UBI 9 and Azure Linux 3 containers. These jobs establish
compiler/library compatibility; the isolated layout tests are not a substitute
for privileged native-update integration on those distros. Older CBL-Mariner
now uses the bundled OpenSSL rather than its OS crypto version, but older
CBL-Mariner toolchains have not been validated. Do not infer Windows behavioral
conformance from passing Linux tests alone. See [PQC support](pqc-support.md)
for standard-OID ML-DSA and composite coverage.

## References

- [Wincrypt.h function reference](https://learn.microsoft.com/en-us/windows/win32/api/wincrypt/)
- [Certificate-store function catalog](https://learn.microsoft.com/en-us/windows/win32/seccrypto/cryptography-functions)
- [Add dispositions](https://learn.microsoft.com/en-us/windows/win32/api/wincrypt/nf-wincrypt-certaddcertificatecontexttostore)
- [Find semantics](https://learn.microsoft.com/en-us/windows/win32/api/wincrypt/nf-wincrypt-certfindcertificateinstore)
- [Context property semantics](https://learn.microsoft.com/en-us/windows/win32/api/wincrypt/nf-wincrypt-certsetcertificatecontextproperty)
- [Close and context ownership](https://learn.microsoft.com/en-us/windows/win32/api/wincrypt/nf-wincrypt-certclosestore)
- [Windows system-store locations and physical siblings](https://learn.microsoft.com/en-us/windows/win32/seccrypto/system-store-locations)
- [Azure Linux CA package layout](https://github.com/microsoft/azurelinux/blob/3.0/SPECS/ca-certificates/ca-certificates.spec)
