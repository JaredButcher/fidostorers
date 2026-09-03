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
- Decrypted output written to disk (`unlock`, `kv get --file`) is, unavoidably,
  plaintext on disk from that point on — that's the user's explicit request (they
  asked to decrypt to a path) and outside this tool's control once written; `kv get`
  without `--file` writes to stdout instead, and callers wanting to avoid touching
  disk should redirect stdout to another process rather than using `--file`.

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
- `format_version` is checked on open; unknown versions are a hard error, not a
  best-effort parse, to avoid ever silently misinterpreting a header.
- Header length prefixes are read before `header_mac` can be verified, so they are
  bounds-checked at parse time. A hostile length field must fail cleanly rather than
  drive a huge allocation.

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
