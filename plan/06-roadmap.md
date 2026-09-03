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

**Code: done. Windows hardware validation: done — passed, but requires an elevated
terminal (see findings). Linux hardware validation: outstanding — this is what M1
still needs.**

- [x] Wire up the `authenticator` crate (0.5.0, `crypto_rust` backend), implement
  `register` and `derive_secret` for real behind the `Authenticator` trait, gated by
  the default-on `hardware` feature.
- [x] `list_devices` implemented directly against the platform (sysfs on Linux,
  SetupAPI on Windows) rather than via the `authenticator` crate, which exposes no
  public enumeration API. Passive: no touch, no I/O open, so capabilities report as
  unprobed.
- [x] `FakeAuthenticator` + hardware-free unit tests per
  [05-testing-strategy.md](05-testing-strategy.md).
- [x] `fido-token` CLI (`list`, `register`, `derive`, `selftest`) usable standalone,
  with `-v`/`-vv` logging and stable exit codes.
- [x] **Manually validate on Windows with a physical key.** Every test in
  [../docs/M1-MANUAL-TESTING.md](../docs/M1-MANUAL-TESTING.md) passed **except test
  3**: all device interaction requires elevation. `hmac-secret` itself behaves exactly
  as the design needs — deterministic, salt-bound, stable across a replug, wrong key
  rejected, PIN prompt and refusal path correct.
- [ ] **Manually validate on Linux with a physical key.** Not yet run — this is the
  remaining M1 item. Same procedure:
  [../docs/M1-MANUAL-TESTING.md](../docs/M1-MANUAL-TESTING.md). `fido-token selftest`
  runs the acceptance check (register → derive twice on one salt → derive on another
  → assert determinism and salt binding) in a single command.

### Findings so far

Two things turned up while wiring this that the plan had wrong:

1. **The `authenticator` crate has no `webauthn.dll` backend.** Its Windows path is
   raw USB HID via SetupAPI, exactly like Linux. The plan asserted the opposite in
   three places (now corrected). Since Windows 10 1903 denies non-elevated read/write
   opens of FIDO HID devices, this raised the question of whether the tool works
   without Administrator on Windows — test 3 of the manual guide. **Answered: it does
   not.** Hardware testing found that every device interaction (`register`, `derive`,
   `selftest`) needs an elevated terminal; only `list` works unprivileged, because it
   opens devices with zero desired access. This is **accepted as a known limitation
   for now**: the transport stays as chosen, and
   [07-open-decisions.md](07-open-decisions.md) #1's fallback (direct `webauthn.dll`
   FFI) becomes a deferred phase-2 task rather than blocking work. Windows development
   and manual testing from M2 on therefore run elevated.
2. **`authenticator` 0.5.0 does not compile for Windows as published** — a
   `libc::c_void` / `winapi::ctypes::c_void` mismatch. Worked around by declaring
   `winapi` with its `std` feature in the workspace manifest, which fixes it via
   feature unification.

Neither invalidates the `hmac-secret` design — Windows hardware testing confirms the
extension works as plan/03 requires. The first costs unprivileged operation on Windows
until the `webauthn.dll` backend is built.

## M2 — Vault core + file mode

**Code: done. Hardware validation: outstanding.**

- [x] Vault header format, HKDF/AEAD wrap-unwrap pipeline
  ([03-vault-format-and-crypto.md](03-vault-format-and-crypto.md)), including the
  `header_mac` and the parse-time bounds.
- [x] `fidostorers init`, `lock`, `unlock`, `info` for `file` mode only.
- [x] Full hardware-free unit test suite for this slice (round trip at four sizes,
  tamper detection on payload/label/mode/salt/wrapped key, wrong-KEK,
  format-version guard, malformed-header cases, crash safety).
- [ ] End-to-end manual test against real hardware: `init` → `lock` → `unlock` a real
  file with a real key, both OSes. On Windows this needs an elevated terminal (M1).

### Refinements to the plan made while implementing

Four places where the sketches in [02](02-crate-fidostorers.md)/[03](03-vault-format-and-crypto.md)
did not survive contact, all recorded there in full:

1. **`header_len` added to the on-disk layout.** Caps the header allocation before any
   unauthenticated byte is parsed, and locates `header_mac` without parsing the body
   first — so `info` reads only the header of a huge vault.
2. **`create`/`enroll` take an `Enrollment` struct, not a bare KEK.** The sketch's
   signature had no salt parameter, but the header must store the salt the KEK was
   derived from or the KEK can never be re-derived. Bundling them makes that
   unforgettable.
3. **`seal_*` takes `&mut self`.** Sealing draws a fresh `payload_nonce` and changes
   `payload_len`, both header fields, so a `&self` signature would leave the
   in-memory header stale against the file just written.
4. **The payload is processed in one shot, in memory.** The format has a single AEAD
   tag over the whole payload, so this follows from the format rather than being a
   shortcut — but it does mean peak memory is the payload size. Fine for M2/M4; worth
   revisiting for M3, where a directory tree could be large.

## M3 — Directory mode

**Code: done. Hardware and Windows validation: outstanding.**

- [x] `tar`-based archive/extract, `lock`/`unlock` extended to `dir` mode.
- [x] Directory round-trip tests incl. nested dirs, symlinks, empty dirs, a symlink
  cycle, and a read-only directory whose children still have to be written.
- [x] The symlink/permission policy settled in
  [07-open-decisions.md](07-open-decisions.md) #8: full-fidelity archive everywhere,
  best-effort extraction, per-entry warnings, and exit code 20 when anything was
  skipped.
- [ ] Manual check on Windows both with and without Developer Mode enabled, since
  that toggle is what decides whether symlink extraction works at all. This is the
  one part of #8 that unit tests on Linux structurally cannot cover — the skip path
  is exercised by a synthetic test, but not by a real Windows refusal.

### Refinements to the plan made while implementing

1. **`open_dir` returns an `ExtractReport`, not `()`.** #8 requires a distinct
   non-zero exit when extraction skipped anything, and `()` cannot carry that. The
   report names every skipped entry and its reason, and flags whether mode bits were
   discarded.
2. **Archive paths are treated as hostile.** The plan's threat model did not consider
   a vault *authored* by an attacker, which is a real case: someone can hand you a
   vault and a key that opens it. Extraction now rejects absolute paths, `..`
   traversal, and the symlink-then-write-through-it escape. See
   [04-security-and-threat-model.md](04-security-and-threat-model.md).

## M4 — KV mode

**Code: done. Hardware validation: outstanding.**

- [x] `kv set/get/rm/ls`, each rewriting the whole vault (the documented trade-off in
  [02-crate-fidostorers.md](02-crate-fidostorers.md)).
- [x] Property tests for KV round trips, and for directory round trips while there —
  arbitrary entry names and values, arbitrary small trees with colliding shapes.
- [ ] End-to-end manual test against real hardware, one touch per invocation.

### Refinement made while implementing

**A newly created vault now holds a payload that is valid for its mode**, rather than
zero bytes: an empty tar for `dir`, an encoded empty map for `kv`. Before this,
`kv ls` (or `unlock`) on a vault nothing had been sealed into yet would have tried to
parse an empty payload. The invariant is worth stating plainly: *a vault's payload is
always a well-formed encoding of its mode*, from `init` onward.

`kv get --file`, mentioned in passing in
[04-security-and-threat-model.md](04-security-and-threat-model.md), was **not** built.
`get` writes raw bytes to stdout with no trailing newline, which is both the CLI
spec in [02-crate-fidostorers.md](02-crate-fidostorers.md) and the option that doc
itself prefers — redirecting stdout to another process never puts the plaintext on
disk at all.

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
- **Direct `webauthn.dll` backend for Windows**, to remove the Administrator
  requirement M1 hardware testing confirmed (findings above,
  [07-open-decisions.md](07-open-decisions.md) #1). Substantial work: a second
  transport behind the `Authenticator` trait, with PIN/UV handled by the OS rather
  than our `PinProvider`, and a check that `webauthn.dll` accepts a non-domain
  `rp_id` from a native caller (#6). **Tabled deliberately** — running elevated is
  acceptable for development and for M2–M6, and doing this now would displace the
  vault itself. Revisit before any release aimed at non-developers: "run your
  encryption tool as Administrator" is bad UX and worse hygiene.
- U2F-only deterministic-ECDSA fallback (see
  [04-security-and-threat-model.md](04-security-and-threat-model.md) for why this is
  lower-assurance and needs its own scrutiny before shipping).
- Resident/discoverable credential support.
- NFC/BLE transports.
- `mlock`/`VirtualLock` memory pinning hardening.
