# Keyfile + password authentication

A second way to unlock a vault, enrolled and revoked exactly like a security key: the
user supplies **both** an arbitrary file and a password, and the two together with a
per-entry salt derive that entry's KEK.

```
fidostorers init  vault.fido --mode kv --auth keyfile --keyfile ~/secrets/vault.key
fidostorers enroll vault.fido --auth keyfile --keyfile /media/usb/vault.key --label "usb backup"
fidostorers unlock vault.fido ./out --keyfile ~/secrets/vault.key
```

Both factors are required. A password alone is deliberately not offered — see
[Why both](#why-both-and-not-either).

## Why this fits the existing design

The architecture already anticipated this without meaning to.
[02-crate-fidostorers.md](02-crate-fidostorers.md) put the hardware seam at
`Vault::unlock_with(id, kek)`: the vault takes an **already-derived KEK** and does not
care where it came from. A keyfile+password factor is simply a different way to
produce those 32 bytes.

```
security key   ──(hmac-secret, salt)──► HKDF ──► KEK ──┐
keyfile+password ──(Argon2id, salt)──► HKDF ──► KEK ──┼──unwrap──► data key
                                                       ┘
```

Everything downstream — the wrapped data key per entry, `header_mac`, multi-factor
unlock, revocation — works unchanged. What has to change is the header, because an
entry is no longer always a FIDO2 credential.

## Header format: version 2

Today a header entry is a `CredentialEntry` holding a `fido_token::Credential`. It
becomes a **factor**, a tagged union:

```rust
#[derive(Serialize, Deserialize)]
pub enum Factor {
    Fido2(fido_token::Credential),
    Keyfile(KeyfileParams),
}

#[derive(Serialize, Deserialize)]
pub struct KeyfileParams {
    /// Argon2id cost parameters, stored so they can be raised later without
    /// invalidating existing entries. Bounds-checked at parse time.
    pub m_cost_kib: u32,
    pub t_cost: u32,
    pub parallelism: u32,
}

pub struct FactorEntry {
    /// Random at enrollment. Stable name for this entry, for `info` and `revoke`.
    pub id: [u8; 16],
    pub factor: Factor,
    pub label: String,
    pub salt: [u8; 32],
    pub wrap_nonce: [u8; 24],
    pub wrapped_data_key: Vec<u8>,
}
```

This is a breaking layout change, so `FORMAT_VERSION` goes to **2**.

### Entry IDs

`revoke --credential <hex>` identifies an entry by its FIDO2 credential ID, which a
keyfile factor does not have. Every entry therefore gains a random 16-byte `id`,
assigned at enrollment and shown by `info`. `revoke --id <hex>` becomes the spelling;
`--credential` stays as an alias that matches a `Fido2` factor's credential ID, so
anything already scripted keeps working.

`Vault::unlock_with(credential_id, kek)` becomes `unlock_with(entry_id, kek)` for the
same reason.

### Reading v1 vaults

`open` accepts v1 **and** v2; any write emits v2. A v1 entry loads as a `Fido2` factor
with an id derived deterministically from its credential ID, so the upgrade is
invisible and needs no migration command. `header_mac` is computed over the literal
bytes on disk and recomputed on write, so a v1-in / v2-out round trip is exactly a
normal write.

The alternative — reject v1 outright — would destroy the vaults created during
hardware testing for no benefit, since the compatibility branch is a few lines and can
be deleted once no v1 vault is worth keeping.

## Key derivation

```
keyfile_hash = SHA-256(keyfile bytes)                       // streamed, any file size
argon_out    = Argon2id(password  = password,
                        salt      = entry.salt,             // 32 bytes, already in the header
                        secret    = keyfile_hash,           // Argon2's "K" / pepper input
                        params    = entry.m_cost/t_cost/p,
                        out_len   = 32)
KEK          = HKDF-SHA256(ikm = argon_out, info = b"fidostorers-kek-keyfile-v1")
```

Three choices worth stating explicitly:

**Argon2id**, not PBKDF2 or a bare hash. A password has perhaps 30–60 bits of entropy
against the security key's 256, so this factor is the one that can actually be
attacked offline. A memory-hard KDF is what makes that attack expensive rather than
trivial. The `argon2` crate (RustCrypto, pure Rust) provides it, matching the existing
dependency policy.

**The keyfile is Argon2's `secret` parameter**, which is precisely what that input is
for: a value not stored alongside the hash. Hashing the file first means an arbitrary
file — 12 bytes or 12 GB — costs a constant 32 bytes in the KDF, and the file is
streamed so a huge one never lands in memory.

**A final HKDF**, mirroring the FIDO2 path, with a *different* `info` string. It costs
nothing, keeps "every KEK is the output of an HKDF" uniform across factor types, and
domain-separates the two so an `hmac-secret` output and an Argon2 output can never
collide into the same KEK.

### Parameters and their bounds

Default: `m_cost = 64 MiB`, `t_cost = 3`, `parallelism = 4` — RFC 9106's second
recommended profile, and a reasonable ~0.5s on a laptop. Settable at enroll time with
`--argon2-memory`, `--argon2-time`, `--argon2-parallelism`.

**Parse-time caps are mandatory, for the same reason the existing length prefixes have
them** ([07-open-decisions.md](07-open-decisions.md) #5): these fields are read from an
unauthenticated header and they drive an allocation. A hostile `m_cost` of 16 TiB must
fail cleanly, not attempt the allocation.

| | min | max |
|---|---|---|
| `m_cost_kib` | 8192 (8 MiB) | 1048576 (1 GiB) |
| `t_cost` | 1 | 16 |
| `parallelism` | 1 | 16 |

Maxima are enforced on read (an allocation guard) and minima on write (so a mistyped
flag cannot silently enroll a factor with negligible cost).

Note the caps fail *closed* in the interesting direction anyway: an attacker who edits
the parameters downward to make cracking cheaper simply gets a different KEK, and the
wrap tag fails. `header_mac` covers them regardless. The caps exist for resource
exhaustion, not for key security.

## The keyfile

Any file. Its bytes are read and hashed; nothing is interpreted, normalized, or
trimmed.

That last point is the operational hazard, and it deserves to be loud in the docs:
**the keyfile must stay byte-identical forever.** A text file that gains a trailing
newline, a document re-saved by its application, a file whose line endings are
translated by a Windows/Linux copy or by cloud sync, a photo run through an
optimizer — any of these silently makes the vault unopenable through that factor.

Mitigations, in order of preference:

1. **`fidostorers keyfile new <path>`** — generate a 32-byte random keyfile from
   `OsRng`. A binary file nothing will helpfully reformat, with a full 256 bits of
   entropy, which makes the password's weakness far less load-bearing. Refuses to
   overwrite an existing file.
2. If the user insists on an existing file, warn at enroll time when it looks fragile:
   plain text, very small, inside a git repo, or inside a known sync folder.
3. Document, in `enroll` output and the README, that the keyfile must be backed up as
   carefully as the vault — and **stored somewhere different from the vault**, since a
   thief who takes both is left with only the password.

Rejected at enroll: an empty file (contributes nothing and is almost certainly a
mistake) and a directory. A file over 64 MiB warns, since it will be re-read and
re-hashed on every unlock, but is not refused.

### No keyfile fingerprint is stored

It would be convenient to store a hash of the keyfile so the CLI could say "wrong
keyfile" rather than "authentication failed" — and it is deliberately not done. That
value would let anyone holding the vault file test candidate keyfiles offline without
knowing the password, turning a two-factor problem into two one-factor problems.

The cost is a real but acceptable UX loss: a wrong-but-readable keyfile and a wrong
password produce the same error. A *missing* or unreadable keyfile is still
distinguishable, because that fails as an I/O error before any derivation. The error
message should say plainly that either input may be at fault.

## Why both, and not either

A keyfile alone would be a bearer token: whoever copies the file opens the vault, with
no user interaction — strictly weaker than the FIDO2 path, where the secret cannot be
copied at all.

A password alone would be the classic offline-guessable secret this project was
explicitly built to avoid ([04-security-and-threat-model.md](04-security-and-threat-model.md)).

Together they are complementary: the keyfile supplies entropy that a human cannot
memorize, and the password supplies a secret that is not on the disk that was stolen.
Requiring both is the whole point of the factor, so neither is offered alone, and
`--keyfile` without a password (or the reverse) is an error rather than a silent
downgrade.

## Threat model consequences

This is the section to read twice. [04-security-and-threat-model.md](04-security-and-threat-model.md)
is amended by it.

**A vault is only as strong as its weakest enrolled factor.** Any single factor
unwraps the same data key. Enrolling a security key and a keyfile+password factor
means an attacker attacks whichever is easier — invariably the password. Adding this
factor to an existing vault *lowers* that vault's security, and the CLI should say so
at enroll time rather than leaving it as a footnote.

**"There is no password" stops being true.** plan/04 currently says offline brute
force is impossible because no password exists, and that a `hmac-secret` output has
256 bits of non-guessable entropy. For a vault with a keyfile factor, an attacker
holding the vault file *and* the keyfile can mount an offline attack on the password,
bounded only by Argon2's cost. That is a normal, well-understood position — it is what
every password manager lives with — but it is a genuine reduction from where this
project started, and the docs must not imply otherwise.

**The keyfile is what keeps it respectable.** With a 32-byte random keyfile kept apart
from the vault, an attacker with only the vault file has nothing to attack: they need
256 bits of keyfile they do not have. The password's strength only becomes the binding
constraint once the attacker has both. This is precisely why the keyfile should not
live beside the vault, and why generating a random one beats reusing a photo the
attacker may already have on the same stolen laptop.

**What does not change:** tamper detection. A new entry cannot be forged without the
data key; deleting or relabelling one is caught by `header_mac`; editing the Argon2
parameters or the salt yields the wrong KEK and fails the wrap tag. The field-by-field
table in [03-vault-format-and-crypto.md](03-vault-format-and-crypto.md) gains a row for
the KDF parameters and is otherwise unaffected.

## CLI

```
fidostorers keyfile new <path>
    Generate a 32-byte random keyfile. Refuses to overwrite.

fidostorers init <vault> --mode <m> --auth keyfile --keyfile <path> [--label <l>]
                         [--argon2-memory 64MiB] [--argon2-time 3] [--argon2-parallelism 4]
    Prompts for a password twice. Default --auth is fido2.

fidostorers enroll <vault> --auth keyfile --keyfile <path> [--label <l>]
    Unlock with any existing factor, then add a keyfile factor.

fidostorers <any unlocking command> --keyfile <path> [--id <hex>]
    Use a keyfile factor instead of a security key. Prompts for the password.

fidostorers revoke <vault> --id <hex>
    Remove any factor by id. `--credential <hex>` remains as an alias for FIDO2 entries.

fidostorers info <vault>
    Now shows each entry's id, factor type, and label.
```

**The password never appears in `argv`.** There is no `--password` flag: it is prompted
for with `rpassword`, or read from stdin with `--password-stdin` for scripting. A
command-line password would land in shell history and in every other process's view of
the process table — the same reasoning already applied to `kv set --value`.

`enroll` asks for the password twice and refuses a mismatch. It does not impose a
strength policy, but it does say what the password is protecting and that Argon2 is the
only thing standing between it and an offline attack.

### Choosing a factor at unlock time

`--keyfile <path>` selects a keyfile factor; its absence means a security key. If a
vault has several keyfile factors, each has its own salt and therefore needs its own
Argon2 run, so trying them in turn costs ~0.5s each. Acceptable for the two or three
entries a vault realistically has, and `--id` skips straight to one.

## Interaction with interactive mode

Complementary, and it makes the case for [08-interactive-mode.md](08-interactive-mode.md)
stronger: a session pays the Argon2 cost and the password prompt once per store rather
than once per command. Nothing in the session design changes — it caches a data key and
does not care which factor produced it.

One addition: `open`'s prompt must be able to ask for a password as well as a touch,
and the idle timeout applies identically.

## Testing

All hardware-free, since this factor involves no device at all — which also makes it
the first end-to-end test of the full unlock path that CI can run.

- KEK derivation is deterministic for fixed (keyfile, password, salt, params), and
  changes when **any** of the four changes.
- Round trip: enroll a keyfile factor, reopen, unlock, decrypt.
- Mixed vault: a FIDO2 factor (with a stubbed KEK) and a keyfile factor on one vault;
  either unlocks; revoking one leaves the other working.
- Wrong password, wrong keyfile, and empty keyfile each fail as
  `AuthenticationFailed` — and identically, per the no-fingerprint decision.
- Keyfile of many sizes, including 1 byte and several MB; a directory and an empty file
  are rejected at enroll.
- Argon2 parameters out of bounds are rejected at parse time **before allocating**,
  mirroring the existing hostile-header test.
- Parameters round-trip through the header and are honoured on unlock (an entry
  enrolled at t=1 must not be unlocked with t=3).
- A **v1 vault opens, unlocks, and is rewritten as v2**, with the same data key
  throughout.
- Property test over random (keyfile, password) pairs for derive/unlock.
- Fast test parameters: use a minimal Argon2 profile in tests via an injectable
  default, or the suite spends most of its time in the KDF on purpose.
