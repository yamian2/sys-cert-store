# certutil for Linux

A store-focused command-line companion to sys-cert-store, using the relevant
[Windows certutil](https://learn.microsoft.com/en-us/windows-server/administration/windows-commands/certutil)
verb names. It is not a complete Windows certutil replacement and is unrelated
to Mozilla NSS's `certutil`. Commands and options are case-insensitive; file
paths and passwords are not.

Build with the repository's normal CMake commands. The executable is
`build/tools/certutil/certutil`; `cmake --install` installs it into the configured
binary directory alongside the library installation. Use the full path if NSS
certutil is also installed. Do not overwrite a distro-managed NSS executable.

## Commands

| Syntax | Behavior |
| --- | --- |
| `-?`, `--help` | Usage; no arguments also shows help |
| `-enumstore` | Enumerate ROOT, CA, MY and persisted custom stores in the selected scope |
| `-store [Store [CertId [OutFile]]]` | Display certificates; default store CA; optionally export matching public certificates |
| `-addstore Store InFile` | Import PEM certificates/bundles, DER certificates, or PEM/DER PKCS#7 |
| `-delstore Store CertId` | Delete exactly one certificate and its associated stored key |
| `-importPFX [Store] InFile` | Import all certificates and zero/one matching key into the chosen store; default MY |
| `-exportPFX [Store] CertId OutFile [NoChain\|NoRoot]` | Export one certificate/key with its offline issuer chain; default MY |
| `-dump InFile` | Display PEM/DER certificates or PKCS#7 without importing; a filename alone implies `-dump` |

Display includes subject, issuer, serial, validity, SHA-1/SHA-256 fingerprints,
and, for stored certificates, user/computer origin and inherited status.
`-v` adds full public certificate details and extensions to `-store`/`-dump`.
Display and public export do not read private keys. Dumping PFX, CRLs, CSRs and
CTLs is not implemented.

## Scope and selection

Computer scope is the default, matching Windows certutil. `-user` selects the
effective Linux user's stores; the Linux extension `-machine` explicitly selects
computer scope. `ROOT`, `CA` and `MY` mean roots, intermediate CAs and personal
certificates. Inherited computer ROOT/CA entries are visible but read-only in
user views; user MY never includes computer MY.

`CertId` matches a zero-based enumeration index, hexadecimal serial, SHA-1 or
SHA-256 fingerprint, or case-insensitive subject substring. Hashes can include
spaces or colon separators. Bare selectors may match more than one criterion.
Use `index:0`, `serial:01ab`, `sha1:...`, `sha256:...`, or `subject:Example` to
select a criterion explicitly. `*` selects every visible certificate; quote it
to prevent shell expansion. These index values are not stable identifiers.

Listing can show multiple matches. **Deletion and PFX export require exactly
one match**; use an explicit selector to resolve ambiguity. Inherited entries
cannot be deleted or used for private-key export through a user view.
`-f` never bypasses scope, native-write or key-permission checks.

```sh
build/tools/certutil/certutil -user -store MY
```

```sh
build/tools/certutil/certutil -store ROOT
```

```sh
build/tools/certutil/certutil -user -delstore MY serial:01ab
```

## Public imports and exports

`-addstore` rejects an existing issuer/serial identity. `-f` uses the library's
replace-existing disposition. Inputs are fully parsed and validated before
adding certificates; private-key PEM blocks, trailing garbage and CRL-bearing
PKCS#7 inputs are rejected rather than silently discarding material.
Multi-certificate `-addstore` is a sequence of individual library writes:
if a later write fails, earlier additions remain and are reported. It is not
an all-or-nothing transaction. PFX import uses the library's atomic metadata
transaction instead.

`-store` exports DER by default, requiring one match. `--format pem` produces a
PEM certificate or bundle; `--format pkcs7` produces DER-encoded, certificate-only
PKCS#7 and permits multiple matches. Extensions do not select the format.
Public exports never include private keys.

```sh
build/tools/certutil/certutil -user -addstore CA intermediate.pem
```

```sh
build/tools/certutil/certutil -user -store MY index:0 identity.cer
```

```sh
build/tools/certutil/certutil -user -store CA "*" intermediates.p7b --format pkcs7
```

## PFX and passwords

Import accepts authenticated, password-protected PFX with zero or one key and
preserves all certificates. It uses the library's filesystem-protected key
storage, not Windows CSP/KSP policy. Repeated PFX imports append memberships;
`-f` and Windows import modifiers are deliberately unsupported here.

Export requires an accessible matching private key and a **nonempty password**.
It produces encrypted PKCS#12 with AES-256-CBC and an integrity MAC, not a raw
private-key file. By default it resolves issuers from the selected store,
scoped CA and scoped ROOT, checking issuer linkage and signatures. A missing,
cyclic or ambiguous issuer path fails instead of silently emitting a partial
chain. `NoChain` exports only the selected certificate and key; `NoRoot` omits
the self-signed root from an otherwise complete chain. A selected self-signed
certificate itself is never omitted.

Chain construction is **not trust, validity, policy or revocation validation**.
There are no network/AIA fetches. Only one export modifier is accepted.
Extended properties, multiple private keys, CSP/KSP policies and alternative
PFX encryption modifiers are not supported.

Without a password option, a terminal prompt disables echo; export confirms
the password. In automation, use `--password-file` with a regular, non-symlink
UTF-8 file owned by the effective user, with no group/other permission bits
(typically `0600`). Its size is limited to 4096 bytes. A single final LF or
CRLF is removed; other bytes, including spaces, are preserved.
Noninteractive operation without a password option fails instead of hanging.
`-p Password` is accepted for Windows-style compatibility but warns because
the password is exposed in process arguments. An empty import password is
accepted; an empty export password is rejected.

```sh
build/tools/certutil/certutil -user -importPFX MY identity.pfx
```

```sh
build/tools/certutil/certutil -user -exportPFX MY serial:01ab identity.pfx
```

```sh
build/tools/certutil/certutil -user --password-file /secure/pfx-password -exportPFX MY serial:01ab leaf-only.pfx NoChain
```

## File and trust safety

Output files use owner-only permissions (`0600`, or more restrictive under the
process umask). Existing files require `-f`; symlink outputs are rejected.
Output is written and flushed to a private temporary file in the destination
directory, then atomically published. Failed encoding or an existing output
does not truncate the destination. A flush failure after publication is
reported even though the new file may already be present.

Computer ROOT changes require `--allow-native-write` plus ordinary Linux
permissions. Neither `-f` nor being root implicitly opts in. User ROOT changes
remain in the user's library store and do not modify the system TLS bundle.
Putting a certificate in CA or MY does not trust it as a native root.

```sh
sudo build/tools/certutil/certutil --allow-native-write -addstore ROOT trusted-root.pem
```

For fixtures or relocated deployments, the Linux extensions
`--user-store-dir`, `--machine-store-dir`, and `--system-root` accept absolute
paths and map to `SysCertConfigureSystemStores`. They change paths, not identity
or permissions. **`--system-root` is not a sandbox:** a real distro updater
copied there can still alter host trust. Tests use purpose-built fixture
updaters and never change host trust.

Use `--` after options/command to pass filenames beginning with a dash.
No operation starts a shell, elevates privileges or contacts a remote CA.
Unknown commands, options and unsupported modifiers fail explicitly.
Exit statuses are `0` for success, `1` for an operation/I/O/crypto failure,
and `2` for invalid or unsupported command-line usage.

Windows AD CS administration, issuance/enrollment, enterprise/service/group
policy stores, verification commands, key repair, CRL/CTL management,
conversion utilities and Windows-specific selector types remain outside
this tool's implemented scope.
