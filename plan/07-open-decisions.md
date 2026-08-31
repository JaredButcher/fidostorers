# Open decisions

Things this plan makes a reasonable default call on, but that are worth a deliberate
confirm (or override) before/while implementing, rather than being locked in by
momentum.

| # | Decision | Default in this plan | Alternatives considered |
|---|---|---|---|
| 1 | FIDO transport crate | [`authenticator`](https://crates.io/crates/authenticator) (Mozilla) | Hand-rolled CTAP2 over `hidapi` (more control, much more work, no free Windows WebAuthn-API backend); `ctap-hid-fido2` (less actively maintained, Windows story less clear). Recommend validating in M1 before fully committing — see [06-roadmap.md](06-roadmap.md). |
| 2 | Crate names | `fido-token` / `fidostorers` | Repo is already named `fidostorers`; could instead name the device crate `fidostorers-token` to visually group them, or publish it under a fully independent name if it's meant to stand alone on crates.io. |
| 3 | Vault file extension | `.fido` | `.fstr`, `.vault` — cosmetic, easy to change later. |
| 4 | AEAD cipher | XChaCha20-Poly1305 | AES-256-GCM (hardware-accelerated on most modern CPUs, but 96-bit nonce needs a counter or careful random-nonce budget rather than "always safe to randomize"; also pulls in a dependency on AES-NI detection for best performance). |
| 5 | Header/vault serialization | TBD hand-rolled binary encoder vs. `postcard`/`bincode` over `serde` structs | Hand-rolled gives tightest control over the exact AAD bytes (important since the header doubles as AAD); a `serde`-based crate is less code but needs care that its output is canonical/stable across versions if it's ever used as AAD input directly rather than via an explicit canonicalization step. |
| 6 | `rp_id` value | fixed constant `"fidostorers.local"` | Configurable per-vault (lets one physical key be scoped differently per project/user) — low cost to make configurable now if wanted. |
| 7 | Resident vs. non-resident credentials | non-resident (v1) | Resident/discoverable, deferred per [04](04-security-and-threat-model.md) — revisit if "which vaults can this key open" discovery UX becomes a real ask. |
| 8 | Directory-mode symlink/permission handling on Windows | best-effort, documented gap | Could normalize (e.g. always dereference symlinks, drop Unix permission bits entirely) for cross-platform-produced-vault portability, at the cost of fidelity when staying on one OS. |
| 9 | PIN input mechanism | no-echo stdin prompt (`rpassword`) in the CLI; library takes a callback | GUI/agent integrations would want a callback or async channel instead of blocking stdin — the library API sketch in [01](01-crate-fido-token.md) already takes options rather than reading stdin itself, so this should already be flexible, but worth confirming once real usage patterns emerge. |
| 10 | Workspace layout | `crates/fido-token`, `crates/fidostorers`, remove top-level `src/` | Keep `fidostorers` as the root package (not under `crates/`) with only `fido-token` split out — slightly less nesting, slightly less symmetric. |

None of these block writing M0/M1 code — they're flagged so a deliberate "yes, that
default is fine" (or override) happens before each becomes expensive to change,
rather than silently ossifying.
