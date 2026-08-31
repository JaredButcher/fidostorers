# Open decisions

Things this plan made a reasonable default call on, now deliberately confirmed or
overridden rather than left to ossify by momentum.

## Decided

| # | Decision | Outcome | Notes |
|---|---|---|---|
| 1 | FIDO transport crate | [`authenticator`](https://crates.io/crates/authenticator) (Mozilla) | Confirmed, but M1's spike must specifically verify that **hmac-secret salts are plumbed through the Windows backend**, not merely that registration works. Windows exposes salt-based hmac-secret only via a recent WebAuthn API version, and a wrapper can support CTAP2 broadly without surfacing that extension on that backend. Fallback if it fails: `ctap-hid-fido2` on Linux plus direct `webauthn.dll` FFI on Windows — much more work, so fail fast on it. See [06-roadmap.md](06-roadmap.md) M1. |
| 2 | Crate names | `fido-token` / `fidostorers` | Confirmed for the workspace. Revisit only if publishing: `fido-token` is generic enough that crates.io may want `fidostorers-token`. |
| 3 | Vault file extension | `.fido` | Confirmed. Chosen over `.fstr` (matches the `FSTR` magic) and `.vault` on the grounds that the extension's job is to tell a human browsing a directory how to open the file, and "use your security key" is the useful signal. The magic bytes stay `FSTR` regardless — extension and magic need not match. |
| 4 | AEAD cipher | XChaCha20-Poly1305 | Confirmed. The 192-bit nonce is what makes random-per-write nonces safe with no counter state, which matters because KV mode re-encrypts the whole payload on every `set`/`rm` under a data key fixed for the vault's lifetime. See the nonce discipline section of [03-vault-format-and-crypto.md](03-vault-format-and-crypto.md). |
| 5 | Header/vault serialization | `postcard` over `serde`-derived structs | Chosen over a hand-rolled encoder. The usual objection — that AAD bytes must stay reproducible across encoder versions — does not apply here, because there is no AAD (see below) and `header_mac` is computed over the literal bytes written to disk and verified over the literal byte range read back. The header is never re-serialized for authentication. **Still required**: explicit parse-time bounds on `credential_count`, `rp_id` length, and every length-prefixed byte string, checked before allocating, since length prefixes are read from an unauthenticated file. |
| 5b | Header authentication | **No AAD anywhere; single `header_mac`** | New decision, resolving a contradiction between docs 02 and 03. Every AEAD call passes empty associated data; header integrity comes from `HMAC-SHA256` over the header under a key HKDF'd from the data key. Rationale and the full field-by-field accounting are in [03-vault-format-and-crypto.md](03-vault-format-and-crypto.md) "Header authentication". The load-bearing reason: header-as-AAD would make each credential's wrap depend on every other entry, so revoking a lost key while holding the primary would silently brick a backup key in a safe. Consequence: `Vault::revoke` now takes the data key. |
| 6 | `rp_id` value | Configurable per-vault, default `"fidostorers.local"` | Upgraded from "fixed constant" — costs nothing, the field already exists on `Vault`, `Credential`, and `init --rp-id`. Add to M1's Windows checks that `webauthn.dll` accepts a non-domain rp_id from a native (non-browser) caller. |
| 7 | Resident vs. non-resident credentials | non-resident (v1) | Confirmed, no change. Deferred per [04-security-and-threat-model.md](04-security-and-threat-model.md). |
| 8 | Directory-mode symlinks & permissions | Preserve in the archive; best-effort on extract | The tar always stores symlinks as symlink entries and real Unix mode bits, on every OS, so a vault written on Linux round-trips back to Linux with full fidelity no matter where it was stored in between. Extraction applies what the platform allows. On Windows, symlink creation needs Developer Mode or elevation, so a failure warns per-entry (naming the link and its target, and how to enable it) and continues; Unix mode bits are ignored with a single warning. Rejected: dereferencing symlinks at seal time, which is lossy, duplicates bytes, needs cycle detection, and would drop executable bits on scripts. Also rejected: hard-failing extraction, which blocks Windows users entirely on any vault containing a symlink. **Extraction that skipped anything must exit non-zero** with a distinct code, so scripts can detect an incomplete tree rather than trusting a silent success. |
| 9 | PIN input mechanism | Library takes an optional callback; CLI uses `rpassword` | Confirmed, with one asymmetry to build in from the start: on Windows the OS renders its own PIN dialog, so **the callback is never invoked on that path**. Make it `Option<...>` and let no code path assume it fires. |
| 10 | Workspace layout | `crates/fido-token`, `crates/fidostorers` | Already implemented; top-level `src/` is gone. Nothing left to decide. |

## Still open

Nothing. All ten items are decided; see the table above.

#8 governs M3 and #5/#5b govern M2 — both are settled before the milestones that need
them. #1 remains the one decision that a real-hardware finding in M1 could reopen.
