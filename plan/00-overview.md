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
├── .github/workflows/ci.yml         Linux + Windows matrix, clippy/fmt gates
├── crates/
│   ├── fido-token/                  crate 1: device I/O (lib + CLI)
│   │   ├── Cargo.toml
│   │   └── src/
│   │       ├── lib.rs               public API + `Authenticator` trait
│   │       ├── hid.rs               real `HidAuthenticator` (feature `hardware`)
│   │       ├── enumerate/           passive device discovery (sysfs / SetupAPI)
│   │       ├── fake.rs              `FakeAuthenticator` for hardware-free tests
│   │       ├── error.rs             `TokenError`
│   │       └── bin/fido-token.rs
│   └── fidostorers/                 crate 2: encryption product (lib + CLI)
│       ├── Cargo.toml
│       ├── src/
│       │   ├── lib.rs
│       │   ├── vault.rs             header format + open/seal pipeline
│       │   ├── crypto.rs            HKDF, AEAD, header MAC
│       │   ├── keyfile.rs           Argon2id keyfile+password factor (M8)
│       │   ├── archive.rs           tar build/extract for dir mode (M3)
│       │   ├── kv.rs                the kv payload map (M4)
│       │   ├── session.rs           open stores, aliases, idle timeout (M9)
│       │   ├── lock.rs              advisory `<vault>.lock` (M9)
│       │   ├── workdir.rs           plaintext working directories (M10)
│       │   ├── orphan.rs            crash recovery for working dirs (M10)
│       │   ├── hardening.rs         mlock'd keys, core-dump suppression (M11)
│       │   ├── error.rs             `VaultError`
│       │   └── bin/fidostorers/
│       │       ├── main.rs          one-shot commands
│       │       ├── repl.rs          `fidostorers interactive` (M9/M10)
│       │       └── tokenize.rs      REPL line splitting
│       └── tests/
│           ├── cli.rs               one-shot CLI, end to end
│           ├── interactive.rs       whole sessions, end to end (M9-M11)
│           └── properties.rs        proptest round trips
├── docs/                            user- and developer-facing documentation
└── plan/                            this planning material
```

This layout is in place as of M0 ([06-roadmap.md](06-roadmap.md)); the placeholder
top-level `src/` from the original repo scaffolding has been removed
([07-open-decisions.md](07-open-decisions.md) #10).

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

- **Vault**: one `.fido` file holding a header with one-or-more wrapped copies of a
  random data key, one per enrolled security key, so *any* enrolled key can unlock the
  vault. The header is not encrypted (nothing in it is secret) but is authenticated by
  a single `header_mac` under a key derived from the data key; no AEAD call in the
  format uses associated data.
- **File mode**: encrypt/decrypt a single file.
- **Directory mode**: archive a directory tree, then encrypt/decrypt as one blob.
- **KV mode**: a small encrypted key/value store (one vault file, many named secrets).
- **Sessions**: `fidostorers interactive` holds an unlocked vault's data key so one
  touch covers many commands, extracting `file`/`dir` stores to a plaintext working
  directory for the life of the session. This is a deliberate reversal of the
  one-touch-per-command default; see
  [08-interactive-mode.md](08-interactive-mode.md) and
  [04-security-and-threat-model.md](04-security-and-threat-model.md).

See [02-crate-fidostorers.md](02-crate-fidostorers.md) and
[03-vault-format-and-crypto.md](03-vault-format-and-crypto.md).

## Key technology choices

| Concern | Choice | Rationale |
|---|---|---|
| CTAP transport | [`authenticator`](https://crates.io/crates/authenticator) crate (Mozilla, used in Firefox) | The mature Rust crate with CTAP1+CTAP2 and a working `hmac-secret` implementation, on Linux and Windows. Avoids hand-rolling CTAP2/PIN-protocol/HID framing. **Correction (M1):** contrary to the original assumption here, this crate has *no* `webauthn.dll` backend — its Windows path is raw USB HID via SetupAPI, the same as Linux. It does **not** work unprivileged on Windows 10 1903+: hardware testing confirmed every device interaction needs an elevated terminal. Accepted as a known limitation for now, with a direct `webauthn.dll` backend deferred to phase 2; see [07-open-decisions.md](07-open-decisions.md) #1, [06-roadmap.md](06-roadmap.md) and [../docs/M1-MANUAL-TESTING.md](../docs/M1-MANUAL-TESTING.md). |
| AEAD | XChaCha20-Poly1305 (`chacha20poly1305` crate) | 192-bit nonce removes nonce-reuse foot-guns for randomly generated nonces (relevant since we may write many small KV entries over a vault's lifetime); pure-Rust, constant-time, no hardware AES dependency. |
| KDF (secret → key) | HKDF-SHA256 (`hkdf` crate) | Standard way to turn the 32-byte `hmac-secret` output into a properly domain-separated AEAD key. |
| Serialization | `postcard` over `serde`-derived structs for vault headers | Compact and deterministic without hand-rolling an encoder. Encoder-version stability is an ordinary compatibility concern here rather than a security property, because `header_mac` is computed over the literal bytes written to disk and verified over the literal bytes read back. Requires parse-time bounds on every length prefix, since the header is read before it can be authenticated. |
| Archiving | `tar` crate over the AEAD stream | Simple, well-understood, streams well; avoids reinventing an archive format. |
| Secret hygiene | `zeroize` crate on all key material structs | Best-effort defense in depth; see [04-security-and-threat-model.md](04-security-and-threat-model.md). |
| PIN entry | `rpassword` (CLI); optional callback in the library API | No-echo prompt, never persisted. `Option<...>` so that `None` means "refuse rather than prompt", which is what `--no-pin` and non-interactive stdin need. **Correction (M1):** the original rationale here was that the callback never fires on Windows because the OS renders its own dialog. It does fire — that followed from the `webauthn.dll` assumption corrected above — and hardware test 6 confirms our own prompt is what appears. See [07-open-decisions.md](07-open-decisions.md) #9. |
| CLI parsing | `clap` (derive API) | De facto standard, good help/UX, works identically for both crates' binaries. |
| Errors | `thiserror` (library crates), `anyhow` (CLI binaries) | Standard split: typed errors in libraries, ergonomic bubbling in binaries. |
| Password KDF | Argon2id (`argon2` crate) | The keyfile+password factor is the only one an attacker can grind offline, so it needs a memory-hard KDF. RustCrypto, matching the rest. See [10-keyfile-password-auth.md](10-keyfile-password-auth.md). |
| REPL line editing | `rustyline`, **default features off** | For `fidostorers interactive`. Turning the default features off is load-bearing rather than a size choice: it drops `with-file-history`, which makes `DefaultHistory` an in-memory type with no way to reach disk, so `kv set --value <secret>` cannot be persisted. [07-open-decisions.md](07-open-decisions.md) #24. |
| Signals | `signal-hook` (unix only) | `SIGTERM`/`SIGHUP` must run the same graceful shutdown as `exit`, and `SIGINT` must cancel rather than kill a session. std exposes no way to catch them. Windows has no equivalent, so it has none of this. |
| Memory pinning, dumps | `libc` (unix), `winapi` (Windows) | `mlock`/`VirtualLock` for a session's data keys, plus `prctl(PR_SET_DUMPABLE)` and `setrlimit(RLIMIT_CORE)` on Linux. See M11 in [06-roadmap.md](06-roadmap.md). |
| Lock/session records | `serde_json` | Human-readable state a user may have to read or delete by hand — a `<vault>.lock` naming its holder, and the session records orphan recovery reads. Deliberately not `postcard`: nothing here is a hot path, and being able to `cat` the file is the point. |

The reasoning behind most of these is recorded in
[07-open-decisions.md](07-open-decisions.md) — #1-#10 for the original set, #21-#37
for the session-era additions. The CTAP transport (#1) was reopened by an
M1 finding — the Windows path is raw HID, not the OS WebAuthn API — and is now settled
with a known limitation: **on Windows the tool must run elevated.** That is accepted
for now, and the `webauthn.dll` backend that would lift it is tabled as phase-2 work.

## Document index

1. [01-crate-fido-token.md](01-crate-fido-token.md) — device crate design & CLI
2. [02-crate-fidostorers.md](02-crate-fidostorers.md) — product crate design & CLI
3. [03-vault-format-and-crypto.md](03-vault-format-and-crypto.md) — on-disk format, crypto pipeline
4. [04-security-and-threat-model.md](04-security-and-threat-model.md) — what this protects against, and what it doesn't
5. [05-testing-strategy.md](05-testing-strategy.md) — unit tests, mock authenticator, hardware-in-the-loop tests
6. [06-roadmap.md](06-roadmap.md) — phased milestones
7. [07-open-decisions.md](07-open-decisions.md) — decision record: what was settled, and why
8. [08-interactive-mode.md](08-interactive-mode.md) — long-lived sessions with cached keys (implemented, M9-M11)
9. [09-credential-encoding.md](09-credential-encoding.md) — hex credential IDs in CLI JSON (implemented, M7)
10. [10-keyfile-password-auth.md](10-keyfile-password-auth.md) — keyfile + password as a second factor (implemented, M8)

Documents 1-5 describe the design as it stands; 8-10 were written as proposals and
carry a status note at the top saying what shipped and what changed. The decision
record (7) is the place to look for *why* something is the way it is, and the roadmap
(6) for what each milestone actually did.
