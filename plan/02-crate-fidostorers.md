# Crate 2: `fidostorers` — encryption product

Depends on `fido-token` as a library. This is the crate the end user actually reaches
for. It owns the "vault" concept, the archive/file/kv modes, and the CLI UX.

## Concepts

- **Vault**: one file on disk (extension `.fido`, settled in
  [07-open-decisions.md](07-open-decisions.md) #3; the magic bytes remain `FSTR`)
  holding a header (enrolled
  credentials + wrapped data key + mode metadata) and a ciphertext payload. Format
  detail in [03-vault-format-and-crypto.md](03-vault-format-and-crypto.md).
- **Enrollment**: a vault can have 1..N enrolled security keys. Any one of them can
  unlock it. This directly mirrors fidocrypt's multi-key support (e.g. a primary key
  you carry + a backup key in a safe).
- **Mode**: a vault is created in exactly one of three modes and keeps that mode for
  its lifetime:
  - `file` — payload is exactly one file's bytes.
  - `dir` — payload is a `tar` stream of a directory tree.
  - `kv` — payload is a serialized map of `name -> bytes`, with per-entry access
    (get/set/rm one entry re-encrypts the whole vault; see trade-off note below).

## CLI (`fidostorers`)

```
fidostorers init <vault> --mode file|dir|kv [--rp-id <id>] [--require-uv]
    Prompts to touch a security key, creates a new empty/seeded vault enrolled with
    that key.

fidostorers enroll <vault>
    Touch an *already-enrolled* key to unlock, then touch a *new* key to add it as an
    additional way to unlock this vault.

fidostorers revoke <vault> --credential <id>
    Touch an already-enrolled key to unlock, then remove another credential's wrapped
    key entry. Refuses to remove the last remaining credential.

fidostorers lock <vault> <input-path>
    (mode = file or dir) Encrypt input-path into the vault. For dir mode, input-path
    is a directory; for file mode, a single file.

fidostorers unlock <vault> <output-path>
    Touch an enrolled key, decrypt into output-path (file or directory, per mode).

fidostorers kv set <vault> <name> [--value <v> | --stdin | --file <path>]
fidostorers kv get <vault> <name>
fidostorers kv rm <vault> <name>
fidostorers kv ls <vault>
    (mode = kv only) Touch an enrolled key once per invocation; manage entries.
    `get` writes the raw value to stdout with no trailing newline, so binary values
    survive a pipe. `rm` errors on a name that is not there, so a typo cannot look
    like a successful deletion. The mode check happens before the touch: being told
    you used the wrong subcommand should not cost a key press.

fidostorers info <vault>
    Show mode, enrolled credential count/labels, format version — no touch required
    (header is not secret, only the wrapped keys within it, which reveal nothing
    without the security key). Output is UNAUTHENTICATED: header_mac can only be
    checked with the data key, which needs a touch. Marked as such in the output.
```

Every unlocking operation (`unlock`, `kv get/set/rm/ls`, `enroll`, `revoke`) needs a
live touch, by design — this is the whole point (see
[04-security-and-threat-model.md](04-security-and-threat-model.md)). There is no
"remember me" / cached-secret mode in v1.

### Exit codes

`fido-token` has its own richer table ([01-crate-fido-token.md](01-crate-fido-token.md));
this crate needs far less, because a failed touch is already reported there.

| Code | Meaning |
|---|---|
| 0 | success |
| 1 | error (the message says which) |
| 20 | **the vault was decrypted, but the extracted tree is incomplete** |

Code 20 exists because of [07-open-decisions.md](07-open-decisions.md) #8: on Windows
a symlink may be unreproducible, and "mostly extracted" must be distinguishable from
both success and failure so a script can detect a partial tree rather than trusting a
silent success. Every skipped entry is named on stderr with its reason before it.

## KV mode trade-off (documented, not hidden)

**Implemented in M4 exactly as described here.** Storing every KV entry inside one
AEAD-encrypted blob means any single `kv set` or `kv rm` re-encrypts and rewrites the
entire vault file. For the target use case (a
handful to a few hundred small secrets — API tokens, recovery codes, etc.) this is
fine and keeps the format simple (one ciphertext, one nonce, one AEAD tag — no
per-entry nonce management to get wrong). If usage ever demands large numbers of
entries or frequent writes, a per-entry-nonce design is the natural follow-up; not
needed for v1. Noted as a deliberate simplicity-over-scalability choice.

## Library surface

Crate 2 also exposes a thin library (`fidostorers::vault`) so the CLI is a thin
wrapper and so future GUI/other frontends aren't required to shell out. As
implemented in M2 — the original sketch differed in two ways, noted below:

```rust
/// Everything needed to give one security key the ability to unlock a vault.
pub struct Enrollment {
    pub credential: fido_token::Credential,
    pub label: String,
    pub salt: [u8; 32],
    pub kek: Zeroizing<[u8; 32]>,
}

/// HKDF the raw hmac-secret output into a KEK. The CLI calls this between
/// `fido_token::derive_secret` and `Vault`.
pub fn kek_from_secret(secret: &[u8; 32]) -> Zeroizing<[u8; 32]>;

pub struct Vault { /* opened header + the literal bytes header_mac covers + path */ }

impl Vault {
    pub fn create(path: &Path, mode: Mode, enrollment: &Enrollment) -> Result<Self, VaultError>;
    pub fn open(path: &Path) -> Result<Self, VaultError>; // header only, no touch, UNAUTHENTICATED
    pub fn credentials(&self) -> &[CredentialEntry];
    pub fn unlock_with(&self, credential_id: &[u8], kek: Zeroizing<[u8;32]>) -> Result<Zeroizing<[u8;32]>, VaultError>; // -> data key
    pub fn enroll(&mut self, data_key: &Zeroizing<[u8;32]>, enrollment: &Enrollment) -> Result<(), VaultError>;
    pub fn revoke(&mut self, data_key: &Zeroizing<[u8;32]>, credential_id: &[u8]) -> Result<(), VaultError>;

    pub fn seal_file(&mut self, data_key: &Zeroizing<[u8;32]>, input: &Path) -> Result<(), VaultError>;
    pub fn open_file(&self, data_key: &Zeroizing<[u8;32]>, output: &Path) -> Result<(), VaultError>;
    pub fn seal_dir(&mut self, data_key: &Zeroizing<[u8;32]>, input_dir: &Path) -> Result<(), VaultError>;
    pub fn open_dir(&self, data_key: &Zeroizing<[u8;32]>, output_dir: &Path) -> Result<(), VaultError>;

    pub fn kv_set(&mut self, data_key: &Zeroizing<[u8;32]>, name: &str, value: &[u8]) -> Result<(), VaultError>;
    pub fn kv_get(&self, data_key: &Zeroizing<[u8;32]>, name: &str) -> Result<Zeroizing<Vec<u8>>, VaultError>;
    pub fn kv_rm(&mut self, data_key: &Zeroizing<[u8;32]>, name: &str) -> Result<(), VaultError>;
    pub fn kv_ls(&self, data_key: &Zeroizing<[u8;32]>) -> Result<Vec<String>, VaultError>;
}
```

**`Enrollment` instead of a bare `(credential, kek)`.** The original sketch had no
salt parameter, which cannot work: the KEK *is* `HKDF(hmac-secret(credential, salt))`,
so the header must store the very salt it was derived from or the KEK can never be
re-derived. Passing the three as one struct makes them impossible to separate at a
call site.

**`seal_*` takes `&mut self`.** Sealing draws a fresh `payload_nonce` and sets
`payload_len` — both header fields — so under the sketched `&self` the in-memory
header would silently go stale against the file just written. A failed write rolls
both fields back, so an ignored error cannot leave the two disagreeing either.

`revoke` takes the data key because removing an entry changes the header, and the
header's `header_mac` must be recomputed under a key derived from the data key (see
[03-vault-format-and-crypto.md](03-vault-format-and-crypto.md)). The caller already
holds it: revoking requires unlocking with a surviving credential first.

Note the split: `unlock_with` takes an already-derived KEK (crate 2 never imports
`fido-token`'s HID internals into `Vault` itself — the CLI binary orchestrates "call
fido-token to get the KEK, then call Vault with it"). This keeps `Vault`'s unit tests
hardware-free by construction: tests just pass in an arbitrary 32-byte KEK, matching
what `fido-token::derive_secret` would have produced.

The HKDF step between the two lives in this crate as `kek_from_secret`, not in
`fido-token` and not in the binary: the domain separator `"fidostorers-kek-v1"` is
part of the *vault format*, so it belongs beside the format that defines it, while
the binary stays a pure orchestrator that never picks a crypto parameter of its own.

## Crash safety

Writes go to a temp file in the vault's directory then `rename()` into place
(atomic on both Linux and Windows NTFS for same-volume renames), so a crash or power
loss mid-write can't corrupt an existing vault. Old vault is only removed after the
new one is durably renamed in.
