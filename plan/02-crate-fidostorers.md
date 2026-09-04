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

fidostorers interactive [--idle-timeout <secs>] [--idle-warning <secs>]
    Open a session: unlock vaults once and work with them until you exit. Holds
    each open store's data key in memory, bounded by an idle timeout (default 15
    minutes). See [08-interactive-mode.md](08-interactive-mode.md).

fidostorers info <vault>
    Show mode, enrolled credential count/labels, format version — no touch required
    (header is not secret, only the wrapped keys within it, which reveal nothing
    without the security key). Output is UNAUTHENTICATED: header_mac can only be
    checked with the data key, which needs a touch. Marked as such in the output.
```

Every unlocking operation (`unlock`, `kv get/set/rm/ls`, `enroll`, `revoke`) needs a
live touch, by design — this is the whole point (see
[04-security-and-threat-model.md](04-security-and-threat-model.md)).

**As of M9 that describes the one-shot commands only.** `fidostorers interactive`
holds a store's data key from `open` to `close`, so one touch covers every command
against that vault ([08-interactive-mode.md](08-interactive-mode.md)). The window is
bounded by an idle timeout and the key is never written anywhere; what is given up
is stated in plan/04's "Interactive mode" section and at the session's own startup.

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

Crate 2 also exposes a library so the CLI is a thin wrapper and so future GUI/other
frontends aren't required to shell out. What follows is the surface **as it stands**;
the notes after it record where the original sketch did not survive contact.

```rust
/// How one enrolled entry produces its KEK.
pub enum Factor {
    Fido2(fido_token::Credential),
    Keyfile(KeyfileParams),
}

/// Everything needed to give one factor the ability to unlock a vault.
pub struct Enrollment {
    pub factor: Factor,
    pub rp_id: String,
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
    pub fn credentials(&self) -> &[FactorEntry];
    pub fn unlock_with(&self, entry_id: &[u8], kek: Zeroizing<[u8; 32]>) -> Result<Zeroizing<[u8; 32]>, VaultError>;
    pub fn enroll(&mut self, data_key: &[u8; 32], enrollment: &Enrollment) -> Result<(), VaultError>;
    pub fn revoke(&mut self, data_key: &[u8; 32], entry_id: &[u8]) -> Result<(), VaultError>;

    pub fn seal_file(&mut self, data_key: &[u8; 32], input: &Path) -> Result<(), VaultError>;
    pub fn open_file(&self, data_key: &[u8; 32], output: &Path) -> Result<(), VaultError>;
    pub fn seal_dir(&mut self, data_key: &[u8; 32], input_dir: &Path) -> Result<(), VaultError>;
    pub fn open_dir(&self, data_key: &[u8; 32], output_dir: &Path) -> Result<ExtractReport, VaultError>;

    pub fn kv_set(&mut self, data_key: &[u8; 32], name: &str, value: &[u8]) -> Result<(), VaultError>;
    pub fn kv_get(&self, data_key: &[u8; 32], name: &str) -> Result<Zeroizing<Vec<u8>>, VaultError>;
    pub fn kv_rm(&mut self, data_key: &[u8; 32], name: &str) -> Result<(), VaultError>;
    pub fn kv_ls(&self, data_key: &[u8; 32]) -> Result<Vec<String>, VaultError>;
}
```

Sessions build on that without changing it — see
[08-interactive-mode.md](08-interactive-mode.md):

```rust
/// One process, any number of open stores. Never talks to hardware: a `Store` is
/// handed an already-derived data key, exactly as `Vault` is handed a derived KEK.
pub struct Session { /* stores, injectable clock, idle timeout */ }
pub struct Store   { /* alias, vault, pinned data key, optional working directory */ }

/// 32 bytes in their own mlock'd page (M11).
pub struct SecretKey;
/// The advisory `<vault>.lock`: `acquire` for writers, `ensure_available` for readers.
pub struct VaultLock;
/// A store's extracted plaintext, and whether sealing it would change anything (M10).
pub struct WorkDir;
```

### Where the original sketch was wrong

**`Enrollment` instead of a bare `(credential, kek)`.** The M2 sketch had no salt
parameter, which cannot work: the KEK *is* `HKDF(hmac-secret(credential, salt))`, so
the header must store the very salt it was derived from or the KEK can never be
re-derived. Passing them as one struct makes them impossible to separate at a call
site. `rp_id` joined it in M8: a keyfile factor has no authenticator and therefore no
relying party of its own, so the value cannot be inferred from the factor.

**`seal_*` takes `&mut self`.** Sealing draws a fresh `payload_nonce` and sets
`payload_len` — both header fields — so under the sketched `&self` the in-memory
header would silently go stale against the file just written. A failed write rolls
both fields back, so an ignored error cannot leave the two disagreeing either.

**`open_dir` returns an `ExtractReport`, not `()`.** A partial extraction is a real
outcome on Windows and the caller must be able to tell it from a complete one
([07-open-decisions.md](07-open-decisions.md) #8).

**`Factor`, not `Credential`, and `entry_id`, not `credential_id`.** A keyfile factor
has no credential ID to be named by, so every entry gained a random 16-byte id in M8
([10-keyfile-password-auth.md](10-keyfile-password-auth.md)).

**The data key is a `&[u8; 32]`, not a wrapper.** A one-shot command holds it in a
`Zeroizing`; a session holds it in a page-locked `SecretKey` (M11). The vault has no
business caring which, the same way `unlock_with` does not care where its KEK came
from.

`revoke` takes the data key because removing an entry changes the header, and
`header_mac` must be recomputed under a key derived from it. The caller already holds
it: revoking requires unlocking with a surviving factor first.

Note the split: `unlock_with` takes an already-derived KEK, so crate 2 never imports
`fido-token`'s HID internals into `Vault` itself — the binary orchestrates "call
fido-token to get the KEK, then call Vault with it". This keeps `Vault`'s unit tests
hardware-free by construction, and it is what made a second factor type cheap in M8
and a session cheap in M9: both are just other ways to produce 32 bytes.

The HKDF step between the two lives in this crate as `kek_from_secret`, not in
`fido-token` and not in the binary: the domain separator `"fidostorers-kek-v1"` is
part of the *vault format*, so it belongs beside the format that defines it, while
the binary stays a pure orchestrator that never picks a crypto parameter of its own.

## Crash safety

Writes go to a temp file in the vault's directory then `rename()` into place
(atomic on both Linux and Windows NTFS for same-volume renames), so a crash or power
loss mid-write can't corrupt an existing vault. Old vault is only removed after the
new one is durably renamed in.
