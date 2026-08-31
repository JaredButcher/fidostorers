# fidostorers — High-Level Project Plan

## What this is

A Rust reimplementation of the core idea behind [riastradh/fidocrypt](https://github.com/riastradh/fidocrypt):
use a FIDO2/U2F security key as the root of trust for a symmetric secret, and use that
secret to encrypt local data. Unlike fidocrypt (C, Linux/BSD-oriented, libfido2), this
project targets **Linux and Windows** from day one, and is split into two crates so the
FIDO device logic is independently reusable.

## Why this works (the fidocrypt trick)

A FIDO2 authenticator that supports the `hmac-secret` CTAP2 extension will, given a
credential and a 32-byte salt, return `HMAC-SHA256(credRandom, salt)` — a value derived
from a per-credential secret (`credRandom`) that never leaves the authenticator. The
computation is:

- **Deterministic**: same credential + same salt → same 32-byte output, every time.
- **Non-extractable**: the authenticator never reveals `credRandom` itself, only HMAC
  outputs, and even those are transported wrapped in an ECDH-derived channel.
- **Gated by physical possession** (+ optionally PIN/UV): you must touch the key (and
  optionally enter a PIN) to get the value.

That 32-byte output is usable directly as key material (after HKDF) for a KEK
(key-encryption-key), without the security key ever being a full HSM and without any
server component. This project is a local, offline password/keyfile replacement.

A `hmac-secret`-only design excludes plain U2F-only devices. Whether/when to add
fidocrypt's fallback (deterministic-ECDSA-signature-as-entropy for pure U2F tokens) is
tracked as a phase-2 stretch goal — see [06-roadmap.md](06-roadmap.md). It is not a
launch requirement.

## Non-goals

- Not a FIDO2/WebAuthn *server* or relying-party implementation for web login.
- Not a general password manager UI (CLI only, at least initially).
- Not trying to support every legacy authenticator quirk on day one — target modern
  CTAP2 authenticators with `hmac-secret` (YubiKey 5 series, SoloKeys, etc.).
- No network component. Everything is local-only.

## Two-crate architecture

```
fidostorers/                         workspace root
├── Cargo.toml                       [workspace]
├── crates/
│   ├── fido-token/                  crate 1: device I/O (lib + CLI)
│   │   ├── src/lib.rs
│   │   └── src/bin/fido-token.rs
│   └── fidostorers/                 crate 2: encryption product (lib + CLI)
│       ├── src/lib.rs
│       └── src/bin/fidostorers.rs
└── plan/, docs/                     this planning material
```

**Decision:** the currently-empty top-level `src/` is a leftover from repo scaffolding
and will be removed in favor of the `crates/` workspace layout above once we start
implementation. Flagged in [07-open-decisions.md](07-open-decisions.md).

### Crate 1: `fido-token` — FIDO device communication

A library (usable standalone by other Rust projects) *and* a CLI binary, covering:

- Enumerating connected FIDO2/U2F authenticators (USB HID; NFC/BLE out of scope for v1).
- Creating a non-resident (non-discoverable) credential with the `hmac-secret`
  extension requested, for a given local "relying party" identifier.
- Producing the `hmac-secret` output for a credential + salt (an "assertion").
- PIN/UV handling.
- A trait-based abstraction (`Authenticator`) so crate 2, and tests, never depend on
  physical hardware directly.

See [01-crate-fido-token.md](01-crate-fido-token.md).

### Crate 2: `fidostorers` — encryption product

A CLI (and thin library) that depends on `fido-token` and implements:

- **Vault**: a header format holding one-or-more wrapped copies of a random data key,
  one per enrolled security key, so *any* enrolled key can unlock the vault.
- **File mode**: encrypt/decrypt a single file.
- **Directory mode**: archive a directory tree, then encrypt/decrypt as one blob.
- **KV mode**: a small encrypted key/value store (one vault file, many named secrets).

See [02-crate-fidostorers.md](02-crate-fidostorers.md) and
[03-vault-format-and-crypto.md](03-vault-format-and-crypto.md).

## Key technology choices

| Concern | Choice | Rationale |
|---|---|---|
| CTAP transport | [`authenticator`](https://crates.io/crates/authenticator) crate (Mozilla, used in Firefox) | Only mature Rust crate with CTAP1+CTAP2 support *and* a Windows backend that goes through the OS WebAuthn API (`webauthn.dll`), which is required on Windows 10 1903+ since raw HID access to FIDO devices is blocked for non-admin processes. Also has a Linux/macOS raw-HID backend. Avoids hand-rolling CTAP2/PIN-protocol/HID framing. |
| AEAD | XChaCha20-Poly1305 (`chacha20poly1305` crate) | 192-bit nonce removes nonce-reuse foot-guns for randomly generated nonces (relevant since we may write many small KV entries over a vault's lifetime); pure-Rust, constant-time, no hardware AES dependency. |
| KDF (secret → key) | HKDF-SHA256 (`hkdf` crate) | Standard way to turn the 32-byte `hmac-secret` output into a properly domain-separated AEAD key. |
| Serialization | `serde` + a binary format (`postcard` or explicit hand-rolled encoding TBD) for vault headers | Deterministic, no-std-friendly options exist if ever needed. |
| Archiving | `tar` crate over the AEAD stream | Simple, well-understood, streams well; avoids reinventing an archive format. |
| Secret hygiene | `zeroize` crate on all key material structs | Best-effort defense in depth; see [04-security-and-threat-model.md](04-security-and-threat-model.md). |
| CLI parsing | `clap` (derive API) | De facto standard, good help/UX, works identically for both crates' binaries. |
| Errors | `thiserror` (library crates), `anyhow` (CLI binaries) | Standard split: typed errors in libraries, ergonomic bubbling in binaries. |

These are proposed defaults, not commitments — flagged where still open in
[07-open-decisions.md](07-open-decisions.md).

## Document index

1. [01-crate-fido-token.md](01-crate-fido-token.md) — device crate design & CLI
2. [02-crate-fidostorers.md](02-crate-fidostorers.md) — product crate design & CLI
3. [03-vault-format-and-crypto.md](03-vault-format-and-crypto.md) — on-disk format, crypto pipeline
4. [04-security-and-threat-model.md](04-security-and-threat-model.md) — what this protects against, and what it doesn't
5. [05-testing-strategy.md](05-testing-strategy.md) — unit tests, mock authenticator, hardware-in-the-loop tests
6. [06-roadmap.md](06-roadmap.md) — phased milestones
7. [07-open-decisions.md](07-open-decisions.md) — things to confirm before/while implementing
