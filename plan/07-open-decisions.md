# Open decisions

Things this plan made a reasonable default call on, now deliberately confirmed or
overridden rather than left to ossify by momentum.

## Decided

| # | Decision | Outcome | Notes |
|---|---|---|---|
| 1 | FIDO transport crate | [`authenticator`](https://crates.io/crates/authenticator) 0.5.0 (Mozilla) — **kept, with a known Windows limitation** | The premise of this row was wrong. This crate has **no `webauthn.dll` backend**; its Windows path is raw USB HID via SetupAPI, the same as Linux. Salt-based `hmac-secret` *is* fully plumbed through (`HMACGetSecretInput`/`HMACGetSecretOutput`, used identically on both OSes) and Windows hardware testing confirms it works. But Windows 10 1903+ denies non-elevated read/write opens of FIDO HID devices, and M1's test 3 confirmed that bites: **all device interaction requires an elevated terminal** (`list` works unprivileged; `register`/`derive`/`selftest` do not). **Accepted for now** rather than switching transports — the fallback (keep this crate on Linux, add direct `webauthn.dll` FFI on Windows) is deferred to phase 2, [06-roadmap.md](06-roadmap.md). Also note the crate does not compile for Windows as published; see the `winapi` shim in the workspace manifest. |
| 2 | Crate names | `fido-token` / `fidostorers` | Confirmed for the workspace. Revisit only if publishing: `fido-token` is generic enough that crates.io may want `fidostorers-token`. |
| 3 | Vault file extension | `.fido` | Confirmed. Chosen over `.fstr` (matches the `FSTR` magic) and `.vault` on the grounds that the extension's job is to tell a human browsing a directory how to open the file, and "use your security key" is the useful signal. The magic bytes stay `FSTR` regardless — extension and magic need not match. |
| 4 | AEAD cipher | XChaCha20-Poly1305 | Confirmed. The 192-bit nonce is what makes random-per-write nonces safe with no counter state, which matters because KV mode re-encrypts the whole payload on every `set`/`rm` under a data key fixed for the vault's lifetime. See the nonce discipline section of [03-vault-format-and-crypto.md](03-vault-format-and-crypto.md). |
| 5 | Header/vault serialization | `postcard` over `serde`-derived structs | Chosen over a hand-rolled encoder. The usual objection — that AAD bytes must stay reproducible across encoder versions — does not apply here, because there is no AAD (see below) and `header_mac` is computed over the literal bytes written to disk and verified over the literal byte range read back. The header is never re-serialized for authentication. **Still required**: explicit parse-time bounds on `credential_count`, `rp_id` length, and every length-prefixed byte string, checked before allocating, since length prefixes are read from an unauthenticated file. |
| 5b | Header authentication | **No AAD anywhere; single `header_mac`** | New decision, resolving a contradiction between docs 02 and 03. Every AEAD call passes empty associated data; header integrity comes from `HMAC-SHA256` over the header under a key HKDF'd from the data key. Rationale and the full field-by-field accounting are in [03-vault-format-and-crypto.md](03-vault-format-and-crypto.md) "Header authentication". The load-bearing reason: header-as-AAD would make each credential's wrap depend on every other entry, so revoking a lost key while holding the primary would silently brick a backup key in a safe. Consequence: `Vault::revoke` now takes the data key. |
| 6 | `rp_id` value | Configurable per-vault, default `"fidostorers.local"` | Upgraded from "fixed constant" — costs nothing, the field already exists on `Vault`, `Credential`, and `init --rp-id`. The default works against real hardware on Windows through the raw-HID backend (M1 tests 2 and 4). Whether `webauthn.dll` accepts a non-domain rp_id from a native (non-browser) caller is untested and moves to the deferred phase-2 backend work. |
| 7 | Resident vs. non-resident credentials | non-resident (v1) | Confirmed, no change. Deferred per [04-security-and-threat-model.md](04-security-and-threat-model.md). |
| 8 | Directory-mode symlinks & permissions | Preserve in the archive; best-effort on extract | The tar always stores symlinks as symlink entries and real Unix mode bits, on every OS, so a vault written on Linux round-trips back to Linux with full fidelity no matter where it was stored in between. Extraction applies what the platform allows. On Windows, symlink creation needs Developer Mode or elevation, so a failure warns per-entry (naming the link and its target, and how to enable it) and continues; Unix mode bits are ignored with a single warning. Rejected: dereferencing symlinks at seal time, which is lossy, duplicates bytes, needs cycle detection, and would drop executable bits on scripts. Also rejected: hard-failing extraction, which blocks Windows users entirely on any vault containing a symlink. **Extraction that skipped anything must exit non-zero** with a distinct code, so scripts can detect an incomplete tree rather than trusting a silent success. |
| 9 | PIN input mechanism | Library takes an optional callback (`PinProvider`); CLI uses `rpassword` | Confirmed, but **the stated Windows asymmetry does not exist**: it followed from the belief that Windows went through `webauthn.dll`, and it does not (#1). With a raw-HID backend on both OSes, our callback fires on Windows too and the OS renders no dialog of its own. Keeping it `Option<...>` remains right — `None` means "refuse rather than prompt", which is what `--no-pin` and non-interactive stdin need — but no code path should assume it *fails* to fire on Windows either. **Confirmed by hardware test 6 on Windows**: our own no-echo prompt is what appears, and `--no-pin` refuses cleanly. |
| 10 | Workspace layout | `crates/fido-token`, `crates/fidostorers` | Already implemented; top-level `src/` is gone. Nothing left to decide. |

## Still open

**Nothing is blocking.** #1's deciding test has been run: `fido-token selftest`
**fails** in a non-elevated Windows terminal and **passes** when elevated — the
`FAIL`/`PASS` row of test 3's table. Requiring Administrator on Windows is accepted as
a known limitation for now, so the transport stays as chosen and the `webauthn.dll`
backend is a **deferred phase-2 task**
([06-roadmap.md](06-roadmap.md)), not required work. It should be revisited before any
release aimed at non-developers.

#9's Windows asymmetry has been **withdrawn** as a consequence of the same finding,
and test 6 confirmed the withdrawal.

Unverified rather than open: **Linux hardware testing has not been run.** The same
procedure ([../docs/M1-MANUAL-TESTING.md](../docs/M1-MANUAL-TESTING.md)) must pass
there before M1 closes. Nothing in the Windows result predicts a Linux problem —
Linux gates the same access behind udev rules rather than a filter driver — but it is
currently untested, so no claim is made about it.

The decisions themselves are all settled. #8 governs M3 and #5/#5b govern M2, both
ahead of the milestones that need them.

## New decisions from M1

| # | Decision | Outcome | Notes |
|---|---|---|---|
| 11 | Hardware backend gating | Default-on `hardware` cargo feature | The `authenticator` dependency needs pkg-config + libudev headers on Linux. Putting it behind a feature keeps the hardware-free suite — which [05-testing-strategy.md](05-testing-strategy.md) promises runs everywhere — buildable on machines that cannot supply them, and lets crate 2 be tested without the platform HID stack. With the feature off, `HidAuthenticator` returns `TokenError::BackendUnavailable`. |
| 12 | Device enumeration | Implemented in-crate, not via `authenticator` | The crate exposes no public enumeration API, and its discovery is entangled with running a real operation (which needs a touch). Listing must be passive, so it is implemented against sysfs (Linux) and SetupAPI (Windows). Consequence: capabilities cannot be reported without a CTAP2 `getInfo`, which needs an I/O open, so `supports_hmac_secret`/`supports_client_pin` became `Option<bool>` and are `None` from enumeration. `selftest` is the authoritative capability answer. |
| 13 | Secret logging | Never the bytes; a truncated-hash `fingerprint` instead | Debugging a derivation mismatch requires knowing *whether two derivations agree*, which a fingerprint answers without putting key material in a log file. Salts are logged in full — they are not secret ([03-vault-format-and-crypto.md](03-vault-format-and-crypto.md)) and are the other half of what makes a mismatch diagnosable. PINs are never logged. |
| 14 | Client data hash | Fixed domain-separated constant | CTAP requires 32 bytes to sign over. There is no relying party and the signature is never checked — only the hmac-secret output, which does not depend on this value — so a constant keeps operations reproducible and removes a needless RNG dependency from the derive path. |
