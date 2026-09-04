# Security & threat model

This is a planning-stage threat model to guide design decisions, not a completed
audit. Revisit before any real-world sensitive use.

## What this protects against

- **Theft of the vault file alone** (stolen laptop disk, leaked backup, cloud sync
  provider breach): the file contains no secret material; without physical access to
  an enrolled security key, the data key cannot be recovered. Equivalent guarantee to
  fidocrypt/age/GPG for "encrypted file at rest."
- **Offline brute force of a password**: there is no password. The `hmac-secret`
  output has 256 bits of entropy from the authenticator's `credRandom`, not derived
  from anything guessable. This is strictly stronger than a human-chosen passphrase.
- **Malware reading the vault file while the security key is unplugged**: safe, same
  as first bullet.

## What this does NOT protect against

- **Malware present at unlock time**: if malware is running with the same
  privileges as `fidostorers` *while the user touches the key*, it can ask the OS to
  read the decrypted output/payload just like the legitimate process can. This tool
  gates access behind physical presence, not behind "no local code execution."
- **Malicious/compromised authenticator firmware**: we trust the authenticator to
  actually keep `credRandom` secret and to correctly implement `hmac-secret`. Out of
  scope to defend against a backdoored key; user must trust their hardware.
- **Loss of all enrolled keys**: by design, there is no recovery path. This is a
  deliberate trade-off inherited from fidocrypt, not an oversight — it must be very
  clearly communicated in `init`/`enroll` CLI output and in top-level docs
  ("enroll at least two keys, or you will permanently lose this data if your one key
  is lost/destroyed").
- **Side-channel/physical attacks on the authenticator itself**: out of scope; that's
  the authenticator vendor's problem.

## Hostile vault contents (added in M3)

The threat model above considers an attacker who *obtains* a vault. It did not
consider one who *authors* it — but nothing stops someone handing you a vault file
along with a key that opens it, and "open this, it's the shared credentials" is an
entirely ordinary-sounding request.

Authentication does not help here. `header_mac` and the AEAD tags prove the vault has
not been altered since it was sealed; they say nothing about whether the person who
sealed it meant you well. So for directory mode, where the payload names paths on
your filesystem, entry paths are treated as untrusted input:

- Absolute paths, `..` components, and Windows path prefixes are rejected outright.
- Every entry's parent directory is canonicalized and checked to be inside the output
  directory *before* anything is written. This is what catches the two-step escape —
  an archive storing a symlink `escape -> /etc` and then an entry `escape/passwd`,
  where every individual path component is innocuous.
- Regular files are removed before being written, so an extraction never writes
  *through* a symlink left by an earlier entry or already present in the output tree.

What is still **not** defended against, deliberately: a vault whose contents are
merely enormous (a decompression-style bomb). Extraction is bounded by disk, not by a
policy limit. Anyone who can get you to unlock their vault can also just send you a
large file, so this is not the interesting attack.

## In-process secret hygiene

- All key material (`secret_i`, `KEK_i`, data key, decrypted KV values) is held in
  `Zeroizing<...>` wrappers (from the `zeroize` crate) so it's wiped on drop. This is
  best-effort defense in depth in a memory-safe language without mlock — it does not
  protect against swap-to-disk or a coredump taken mid-operation. `mlock`/`VirtualLock`
  pinning is a possible v2 hardening item, not required for v1 (tracked in
  [06-roadmap.md](06-roadmap.md)).
- PINs (if the authenticator requires one) are read via a no-echo prompt
  (`rpassword` crate) and never written to disk, logs, or shell history. They are
  passed straight to `fido-token`'s register/derive calls and dropped immediately
  after.
- Decrypted output written to disk (`unlock`) is, unavoidably, plaintext on disk
  from that point on — that's the user's explicit request (they asked to decrypt to a
  path) and outside this tool's control once written.
- `kv get` writes raw bytes to **stdout only**; the `--file` variant this section
  once described was deliberately not built (M4). Redirecting stdout to another
  process never puts the value on disk, and offering a `--file` shortcut would have
  made the less safe option the more convenient one. Callers who do want it on disk
  can redirect to a file themselves, which at least makes the choice explicit.

## Downgrade/tampering resistance

- Tampering with a field that feeds key derivation — a `salt` (including swapping two
  entries' salts), a `credential_id`, either nonce, or `payload_len` — is caught by
  the AEAD tag alone, because the wrong key or keystream is produced. No associated
  data is needed for this and none is used; see
  [03-vault-format-and-crypto.md](03-vault-format-and-crypto.md).
- The three things that would *not* be caught that way — silently deleting a
  credential's entry, relabelling one, and flipping `mode` — are covered by
  `header_mac`, an HMAC over the whole header under a key derived from the data key.
  It is verified on every unlock, immediately after the data key is unwrapped and
  before `mode` or any label is acted on.
- **`fidostorers info` output is unauthenticated.** Verifying `header_mac` requires
  the data key, which requires a touch; `info` deliberately requires no touch. Its
  output must be labelled as unverified, and nothing security-relevant should be
  decided from it. Every path that *acts* on header contents requires a touch and
  therefore verifies the MAC first.
- An attacker cannot add a working credential entry: forging a wrapped data key
  requires the data key itself.
- **Revocation is not re-keying** (M5). `revoke` removes a credential's wrapped entry
  from the current file. It does *not* change the data key, because doing so would
  mean re-wrapping for every surviving credential — which would require physically
  touching each of them, including the backup key in a safe, which is precisely the
  failure mode [07-open-decisions.md](07-open-decisions.md) #5b rejected.
  The consequence, verified experimentally: anyone holding **the revoked key plus any
  older copy of the vault file** (backup, cloud-sync history, filesystem snapshot,
  git) can recover the data key from that old copy — and the same data key still
  decrypts the *current* file. So `revoke` protects against "someone finds this file
  later and has the old key", not against "the old key's holder already copied the
  file". If a revoked key may be in someone else's hands, treat the contents as
  compromised: create a new vault and re-seal into it. The CLI says so when revoking.
  This is the same property as removing a recipient from an `age` or GPG file.
- `format_version` is checked on open; unknown versions are a hard error, not a
  best-effort parse, to avoid ever silently misinterpreting a header.
- Header length prefixes are read before `header_mac` can be verified, so they are
  bounds-checked at parse time. A hostile length field must fail cleanly rather than
  drive a huge allocation.

## Planned change: a second factor reintroduces the password

[10-keyfile-password-auth.md](10-keyfile-password-auth.md) plans a keyfile+password
factor, enrolled and revoked like a security key. It directly contradicts the second
bullet under "What this protects against" above, and the contradiction is the point of
this note:

- **"Offline brute force: there is no password"** stops being true for any vault with
  such a factor enrolled. An attacker holding both the vault file and the keyfile can
  attack the password offline, bounded only by Argon2id's cost. That is an ordinary,
  well-understood position — every password manager lives there — but it is a genuine
  reduction from where this project started.
- **A vault is only as strong as its weakest enrolled factor.** Every factor unwraps
  the same data key, so enrolling a security key *and* a keyfile+password factor means
  an attacker simply attacks whichever is cheaper. Adding this factor to a vault
  lowers that vault's security, and `enroll` is specified to say so at the point of
  use rather than leaving it in a document.
- **The keyfile is what keeps the trade acceptable.** With a 32-byte random keyfile
  stored somewhere other than the vault, an attacker holding only the vault file has
  no password attack to mount — they are missing 256 bits they cannot guess. The
  password becomes the binding constraint only once they have both, which is why the
  two must not live together.

Unchanged: tamper detection. Forging an entry still needs the data key, deleting or
relabelling one is still caught by `header_mac`, and editing a salt or the KDF
parameters still produces the wrong KEK and fails the wrap tag.

## Interactive mode: what a session weakens (M9)

`fidostorers interactive` ([08-interactive-mode.md](08-interactive-mode.md)) is
implemented, and it reverses one of this document's standing guarantees. This
section is written to describe what the tool does **today**, not what is planned.

**"Every unlocking operation needs a live touch" is no longer true inside a
session.** A session holds each open store's data key in memory from `open` until
`close`, so one touch covers every subsequent command against that vault. The same
follows for a keyfile factor: one password prompt and one Argon2 run per store, not
per command. [02-crate-fidostorers.md](02-crate-fidostorers.md)'s "there is no
remember-me / cached-secret mode" describes the one-shot commands only.

What bounds that window:

- **Only the data key is cached** — never the KEK, never the raw `hmac-secret`
  output, never the password or the keyfile hash. The data key is sufficient for
  every `Vault` operation and is the narrowest thing that is: it derives nothing for
  any other vault, and it says nothing about the security key that produced it.
- **An idle timeout closes stores automatically**, 15 minutes by default
  ([07-open-decisions.md](07-open-decisions.md) #18). Expiry is a full close — the
  key is dropped and the vault's lock released — not merely a flag flipped.
  `--idle-timeout 0` disables it, which is an explicit choice to leave vaults
  unlocked for the life of the process.
- **Every key is zeroized on close**, on every path out: `close`, `exit`, EOF,
  `SIGTERM`/`SIGHUP`, and idle expiry all drop the same `Zeroizing` data key.

**Plaintext on disk has *not* changed yet.** The working directories that would
extract a `file` or `dir` store to a plaintext path — decision #15, and the larger
of the two changes this section used to anticipate — are the next milestone. Today a
`file`/`dir` store can be opened, which caches its key so `info`, `enroll` and
`revoke` cost no further touches, but nothing is extracted and no plaintext reaches
the filesystem from a session. `kv` stores never need a working directory at all.

**A session is not yet hardened for the key lifetime it introduces.** `mlock`/
`VirtualLock` pinning and core-dump suppression are M11 and are not implemented, so
a session's data keys can be swapped to disk or captured in a crash dump. The CLI
says so at startup rather than leaving it here, and interactive mode should not be
described as safe until those land.

**What does not change:** a vault at rest, with no session running, is exactly as
protected as before. Tamper detection is untouched — a session verifies `header_mac`
when it opens a store, which makes its `info` output *authenticated*, unlike the
touchless one-shot `info`. Concurrent writers are excluded by an advisory
`<vault>.lock`, which the one-shot writing commands honour too; readers are
deliberately not excluded, since reading cannot corrupt a vault and a session holds
its lock for minutes at a time.

## Explicitly deferred (v2+ or "won't do")

- Resident/discoverable credentials (would let `fidostorers` enumerate "which vaults
  does this key open" without the caller supplying credential IDs — nice UX, extra
  attack surface, and burns limited on-device resident-credential slots). Deferred.
- The U2F deterministic-ECDSA fallback for non-CTAP2 tokens (see
  [00-overview.md](00-overview.md)) — deferred, and if built, must ship with loud
  documentation that it's a weaker guarantee (depends on the specific authenticator
  actually implementing RFC 6979 deterministic nonces, which is a firmware property
  we cannot verify from software).
- NFC/BLE authenticator transports — USB HID only for v1.
