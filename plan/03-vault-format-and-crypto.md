# Vault format & crypto pipeline

## Key hierarchy

```
security key #1 ──(hmac-secret, salt_1)──► secret_1 (32B) ──HKDF──► KEK_1 ──unwrap──┐
security key #2 ──(hmac-secret, salt_2)──► secret_2 (32B) ──HKDF──► KEK_2 ──unwrap──┼──► data key (32B, random, generated once at `init`)
security key #N ──(hmac-secret, salt_N)──► secret_N (32B) ──HKDF──► KEK_N ──unwrap──┘
                                                                                       │
                                                                                       ▼
                                                                    AEAD(data key) seals/opens the payload
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
- **Wrapped data key**: `AEAD_Encrypt(key = KEK_i, nonce = wrap_nonce_i, plaintext = data key, aad = header-without-wrapped-keys)`.
  Binding the AAD to the rest of the header prevents mix-and-match tampering (e.g.
  swapping which mode a wrapped key claims to belong to).

## On-disk layout

```
┌──────────────────────────────────────────────────────────┐
│ magic: b"FSTR" (4 bytes)                                  │
│ format_version: u16                                       │
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
│ payload_ciphertext: [payload_len + 16 bytes]                │
└──────────────────────────────────────────────────────────┘
```

Everything above the payload is the "header"; it is **not encrypted** (there is
nothing secret in it — credential IDs and salts are meaningless without the physical
authenticator, per the `hmac-secret` security model) but *is* authenticated: it forms
the AAD for both the per-credential key-wrap AEAD calls and the payload AEAD call, so
no byte of it can be modified without every unlock failing loudly.

Exact byte-level framing (fixed-width vs. varint length prefixes, whether we use a
hand-rolled encoder or `postcard`/`bincode` over a `#[derive(Serialize)]` struct) is
an implementation detail to nail down in [07-open-decisions.md](07-open-decisions.md);
the field list and its authentication properties are the load-bearing part of this
doc.

## Payload encoding per mode

- **`file`**: `payload_ciphertext` decrypts straight to the file's raw bytes.
- **`dir`**: `payload_ciphertext` decrypts to a `tar` stream (via the `tar` crate) of
  the directory tree, built with deterministic entry order (sorted paths) so repeated
  `lock` of unchanged input is reproducible — useful for tests and for eyeballing
  diffs of re-encrypted vaults during development. Symlinks: stored as symlinks in the
  tar entry (not followed), consistent with GNU tar defaults; permissions preserved
  best-effort per-platform (Windows tar semantics differ — flagged in
  [07-open-decisions.md](07-open-decisions.md)).
- **`kv`**: `payload_ciphertext` decrypts to a serialized `BTreeMap<String, Vec<u8>>`
  (`BTreeMap` for deterministic ordering, same rationale as `dir`'s sorted tar).

## AEAD nonce discipline

- `wrap_nonce_i` and `payload_nonce`: freshly random (`OsRng`, 24 bytes) on every
  write. XChaCha20-Poly1305's 192-bit nonce makes random generation safe against
  collision for the lifetime of any realistic vault (birthday bound ~2^96 encryptions
  under one key).
- A given `KEK_i` only ever wraps one data key per credential-enrollment event, and a
  re-wrap (e.g. after `revoke` touches the header AAD) always draws a fresh nonce —
  so nonce reuse under a fixed key never happens by construction, not just by luck.

## Why not derive the data key directly from the security key (skip the wrap step)?

Because then adding a second key would require *re-encrypting the entire payload*
under a new data key derived from the new device (there's no way to make two
different physical devices derive the *same* secret). Wrapping a single random data
key separately per credential is exactly how multi-recipient encryption normally
works (age, GPG, etc.) and is what makes `enroll`/`revoke` cheap (touch old key once,
touch new key once, done — no re-encrypting a potentially large `dir`/`file`
payload).
