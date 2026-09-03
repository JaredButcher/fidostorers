# Vault format & crypto pipeline

## Key hierarchy

```
security key #1 ──(hmac-secret, salt_1)──► secret_1 (32B) ──HKDF──► KEK_1 ──unwrap──┐
security key #2 ──(hmac-secret, salt_2)──► secret_2 (32B) ──HKDF──► KEK_2 ──unwrap──┼──► data key
security key #N ──(hmac-secret, salt_N)──► secret_N (32B) ──HKDF──► KEK_N ──unwrap──┘   (32B, random,
                                                                                         once at `init`)
                                    ┌────────────────────────────────────────────────────────┘
                                    │
              ┌─────────────────────┴─────────────────────┐
              ▼                                           ▼
   AEAD(data key) seals/opens             HKDF ──► mac key ──► header_mac
   the payload                                       authenticates the header
```

- **`data key`**: 32 random bytes, generated once with `OsRng` when the vault is
  `init`'d. Never derived from a security key — it's the only thing that actually
  encrypts the payload, which is what makes multi-key enrollment possible (each
  credential just needs its own copy of *this same* key, independently wrapped).
- **Per-credential salt**: 32 random bytes, generated at enrollment time, stored
  *unencrypted* in the header next to that credential's entry. Salt is not secret —
  its only job is domain separation (this vault vs. some other vault using the same
  physical key), matching how the `hmac-secret` extension is meant to be used.
- **`secret_i`**: the raw 32-byte `hmac-secret` extension output for
  `(credential_i, salt_i)`. Never stored anywhere.
- **`KEK_i`**: `HKDF-SHA256(ikm = secret_i, salt = None, info = b"fidostorers-kek-v1")`.
  The HKDF step exists so the AEAD key is clearly domain-separated from the raw
  `hmac-secret` output, in case that output is ever reused for anything else.
- **Wrapped data key**: `AEAD_Encrypt(key = KEK_i, nonce = wrap_nonce_i, plaintext = data key)`.
  No associated data — see "Header authentication" below for why AAD is not used
  anywhere in this format.
- **`mac key`**: `HKDF-SHA256(ikm = data key, salt = None, info = b"fidostorers-header-mac-v1")`.
  Domain-separated from the payload AEAD key so the data key is never used directly
  for two different primitives.
- **`header_mac`**: `HMAC-SHA256(mac key, all header bytes preceding this field)`.

## Header authentication

This format uses **no AAD**. Every AEAD call passes empty associated data, and header
integrity is provided by the single `header_mac` field instead.

The reason is that most of the header is already self-authenticating, because the
fields an attacker would want to tamper with are *inputs to the key derivation*:

| Tampered field | What catches it |
|---|---|
| `magic`, `format_version` | parser rejects before any crypto runs |
| `rp_id` | credential IDs are rp-bound blobs; the authenticator rejects the assertion |
| `credential_id` | device rejects it, or derives a different `credRandom` → wrong KEK |
| `salt` (including swapping two entries' salts) | wrong KEK → wrap tag fails |
| `wrap_nonce` | wrong keystream → wrap tag fails |
| `payload_nonce` | feeds the Poly1305 one-time key → payload tag fails |
| `payload_len` | truncates the ciphertext / reads past EOF → payload tag fails |
| payload ciphertext | payload tag fails |
| an entry the attacker *adds* | they cannot forge a wrap without the data key |

That leaves exactly three things an AEAD tag would not catch on its own: **deleting a
credential entry**, **relabelling one**, and **flipping `mode`**. `header_mac` covers
all three, in one place, for 32 bytes.

Using a MAC rather than AAD also keeps `enroll`/`revoke` cheap. Had the header been
the AAD for the per-credential wraps, changing the credential table would invalidate
*every* entry's wrap, and re-wrapping entry `B` requires `KEK_B` — which requires
physically touching key B. Revoking a lost key while holding the primary would
silently brick the backup key sitting in a safe, discovered only in the emergency
that backup exists for. A MAC under the data key has no such problem: `enroll` and
`revoke` both already hold the data key, so both can recompute `header_mac` without
touching any other credential's device.

**Verification order** on unlock: parse header (enforcing the size caps below) →
unwrap the data key with the chosen credential's KEK → derive the mac key → verify
`header_mac` → only then act on `mode`, labels, or the payload. Using the data key
solely to check a MAC before the header is trusted emits no plaintext and dispatches
on nothing, so the ordering is safe.

**Caveat**: `header_mac` cannot be checked without the data key, so `fidostorers info`
(which deliberately requires no touch) displays *unauthenticated* header data. Its
output must be labelled as such — see [04-security-and-threat-model.md](04-security-and-threat-model.md).

## On-disk layout

```
┌──────────────────────────────────────────────────────────┐
│ magic: b"FSTR" (4 bytes)                                  │
│ format_version: u16                                       │
│ header_len: u32   (byte length of the postcard body)       │
│ mode: u8   (0 = file, 1 = dir, 2 = kv)                     │
│ rp_id: length-prefixed UTF-8 string                        │
│ credential_count: u16                                      │
│ ── repeated credential_count times ──                      │
│   credential_id: length-prefixed bytes                     │
│   label: length-prefixed UTF-8 string (user-supplied)      │
│   salt: [u8; 32]                                            │
│   wrap_nonce: [u8; 24]        (XChaCha20-Poly1305 nonce)   │
│   wrapped_data_key: [u8; 32 + 16]  (ciphertext + AEAD tag) │
│ ── end repeated ──                                          │
│ payload_nonce: [u8; 24]                                     │
│ payload_len: u64                                            │
│ header_mac: [u8; 32]   (HMAC-SHA256 over all of the above)  │
│ payload_ciphertext: [payload_len + 16 bytes]                │
└──────────────────────────────────────────────────────────┘
```

Everything above `payload_ciphertext` is the "header". It is **not encrypted** (there
is nothing secret in it — credential IDs and salts are meaningless without the
physical authenticator, per the `hmac-secret` security model) but is authenticated by
`header_mac`.

`header_len` was **added during M2** and is not in the original sketch. It earns its
four bytes twice: it bounds the header allocation before a single unauthenticated
byte is parsed, and it locates `header_mac` without parsing the body first, so `open`
— and therefore `fidostorers info` — reads only the header of a multi-gigabyte vault
rather than the whole file. The fields between it and `header_mac` are one `postcard`
struct; `mode`, `rp_id`, `credential_count` and the per-credential fields are that
struct's members, so their exact widths are postcard's business, not the format's.

Note also that `rp_id` appears twice — once for the vault and once inside each
credential, since `fido_token::Credential` carries its own. `create` sources both from
the same value; the parser rejects a file where they disagree.

Serialization is `postcard` over `serde`-derived structs
([07-open-decisions.md](07-open-decisions.md) #5). Because `header_mac` is computed
over the literal bytes written to disk and verified over the literal byte range read
back, the header is never re-serialized for authentication purposes — so postcard's
cross-version encoding stability is an ordinary compatibility concern governed by
`format_version`, not a security property.

**Implemented in `FORMAT_VERSION` 2** (M8, [10-keyfile-password-auth.md](10-keyfile-password-auth.md)):
each credential entry becomes a *factor* entry — a tagged union of a FIDO2 credential
and a keyfile+password KDF parameter set — and gains a random 16-byte `id` so an entry
can be named by `info` and `revoke` regardless of type. The key hierarchy above is
otherwise untouched: a keyfile factor produces a KEK by a different route
(`Argon2id` rather than `hmac-secret`), and everything downstream of the KEK is
identical. The tamper table gains one row — editing the Argon2 parameters yields the
wrong KEK, so the wrap tag fails — and the parse-time caps below extend to cover them,
since those parameters drive an allocation.

**Parse-time size caps are mandatory.** Length prefixes are read from an
unauthenticated file and `header_mac` cannot be verified until after the data key is
recovered, so `credential_count`, `rp_id`'s length, and every length-prefixed byte
string must be bounds-checked *before* allocating. A corrupt or hostile 8-byte length
must not be able to drive a multi-gigabyte allocation.

## Payload size

The format puts **one** AEAD tag over the whole payload, so sealing and opening are
single-shot: the entire plaintext is in memory at once. That is a consequence of the
format, not an implementation shortcut — a streaming variant would need per-chunk
tags and a chunk framing, which is a different on-disk layout. Peak memory is
therefore the payload size, which is fine for `file` and `kv` but is the thing to
re-examine in M3, where a directory tree can be arbitrarily large.

## Payload encoding per mode

- **`file`**: `payload_ciphertext` decrypts straight to the file's raw bytes.
- **`dir`**: `payload_ciphertext` decrypts to a `tar` stream (via the `tar` crate) of
  the directory tree, built with deterministic entry order (sorted paths) so repeated
  `lock` of unchanged input is reproducible — useful for tests and for eyeballing
  diffs of re-encrypted vaults during development. Symlinks are stored as tar symlink
  entries (never followed) and Unix mode bits are stored as-is, on every OS, so the
  archive is always full-fidelity. Extraction is best-effort per platform: on Windows,
  a symlink that cannot be created (no Developer Mode, not elevated) warns with the
  link and target and continues, and mode bits are ignored with one warning. Any
  extraction that skipped an entry exits non-zero with a distinct code so callers can
  detect an incomplete tree. See [07-open-decisions.md](07-open-decisions.md) #8.
- **`kv`**: `payload_ciphertext` decrypts to a serialized `BTreeMap<String, Vec<u8>>`
  (`BTreeMap` for deterministic ordering, same rationale as `dir`'s sorted tar).

## AEAD nonce discipline

- `wrap_nonce_i` and `payload_nonce`: freshly random (`OsRng`, 24 bytes) on every
  write. XChaCha20-Poly1305's 192-bit nonce makes random generation safe against
  collision for the lifetime of any realistic vault (birthday bound ~2^96 encryptions
  under one key).
- **`payload_nonce` is load-bearing.** The data key is fixed for the vault's entire
  lifetime, and every `lock`, `kv set`, and `kv rm` re-encrypts the whole payload
  under it. A fixed or reused payload nonce would let anyone holding two versions of
  the vault file — from cloud-sync history, a filesystem snapshot, a backup set, or
  git — XOR them to recover the XOR of the two plaintexts, which for two consecutive
  states of a KV map is almost entirely zeros with a bright stripe at exactly the
  bytes that changed. Two tags under one Poly1305 one-time key additionally yield
  forgery. This is why a counter-based nonce is rejected: restoring an older vault
  from backup and writing again would walk the counter back over values it has
  already used.
- `wrap_nonce_i` is, by contrast, **defense in depth**. `KEK_i` is already unique per
  wrap because `salt_i` is drawn fresh at each enrollment, and a wrap cannot be
  produced without a device touch (which is also when a fresh salt is drawn), so a
  fixed nonce would in principle be safe here — the `age` recipient-stanza
  construction does exactly that. The random nonce costs 24 bytes per credential and
  keeps the wrap safe even if salt freshness is ever broken by an RNG failure or a
  restored VM snapshot. Keep it, but note in code that the salt is what actually
  carries the uniqueness argument.

## Why not derive the data key directly from the security key (skip the wrap step)?

Because then adding a second key would require *re-encrypting the entire payload*
under a new data key derived from the new device (there's no way to make two
different physical devices derive the *same* secret). Wrapping a single random data
key separately per credential is exactly how multi-recipient encryption normally
works (age, GPG, etc.) and is what makes `enroll`/`revoke` cheap (touch old key once,
touch new key once, rewrite the header, done — no re-encrypting a potentially large
`dir`/`file` payload).
