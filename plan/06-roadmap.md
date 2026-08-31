# Roadmap / milestones

Phased so that the riskiest unknown — real CTAP2 hardware behavior on both target
OSes — gets validated as early as possible, before much is built on top of it.

## M0 — Workspace scaffolding
- Convert repo to a Cargo workspace (`crates/fido-token`, `crates/fidostorers`),
  remove the placeholder top-level `src/`.
- CI skeleton (Linux + Windows matrix), `clippy`/`fmt` gates.
- Empty crates with the trait/struct shapes from
  [01](01-crate-fido-token.md)/[02](02-crate-fidostorers.md) stubbed out, compiling.

## M1 — `fido-token` talks to real hardware (spike, both OSes)
- Wire up the `authenticator` crate, implement `list_devices`, `register`,
  `derive_secret` for real, behind the `Authenticator` trait.
- Manually validate on Linux (raw HID) **and** Windows (WebAuthn API backend) with at
  least one physical key: register a credential, derive twice, confirm identical
  output. This is the single highest-risk item in the whole project — the rest of the
  plan assumes this works as documented; if the Windows backend behaves differently
  than expected, later milestones may need rework.
- `FakeAuthenticator` + hardware-free unit tests per
  [05-testing-strategy.md](05-testing-strategy.md).
- `fido-token` CLI (`list`, `register`, `derive`) usable standalone.

## M2 — Vault core + file mode
- Vault header format, HKDF/AEAD wrap-unwrap pipeline
  ([03-vault-format-and-crypto.md](03-vault-format-and-crypto.md)).
- `fidostorers init`, `lock`, `unlock`, `info` for `file` mode only.
- Full hardware-free unit test suite for this slice (round trip, tamper detection,
  wrong-KEK, format-version guard).
- End-to-end manual test against real hardware: `init` → `lock` → `unlock` a real file
  with a real key, both OSes.

## M3 — Directory mode
- `tar`-based archive/extract, `lock`/`unlock` extended to `dir` mode.
- Directory round-trip tests incl. nested dirs, symlinks, empty dirs.
- Implement the symlink/permission policy settled in
  [07-open-decisions.md](07-open-decisions.md) #8: full-fidelity archive everywhere,
  best-effort extraction, per-entry warnings on Windows, non-zero exit when anything
  was skipped.
- Manual check on Windows both with and without Developer Mode enabled, since that
  toggle is what decides whether symlink extraction works at all.

## M4 — KV mode
- `kv set/get/rm/ls`.
- Property tests for KV round trips.

## M5 — Multi-key enrollment & revocation
- `enroll`, `revoke` across all three modes.
- Enrollment/revocation unit tests, "can't revoke last key" guard.
- Manual test with two physical keys: enroll both, revoke one, confirm the other
  still works.

## M6 — Polish & docs
- User-facing README covering install (incl. Linux udev rules), quick start per mode,
  and the "you will lose your data if you lose all enrolled keys" warning front and
  center.
- CLI help text pass, error message pass (map `TokenError`/`VaultError` variants to
  actionable messages, not raw debug output).
- `cargo audit` / dependency review.

## Phase 2 (explicitly deferred, not committed)
- U2F-only deterministic-ECDSA fallback (see
  [04-security-and-threat-model.md](04-security-and-threat-model.md) for why this is
  lower-assurance and needs its own scrutiny before shipping).
- Resident/discoverable credential support.
- NFC/BLE transports.
- `mlock`/`VirtualLock` memory pinning hardening.
