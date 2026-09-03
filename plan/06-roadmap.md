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

**Code: done. Hardware validation: outstanding.**

- [x] `enroll`, `revoke` across all three modes.
- [x] Enrollment/revocation unit tests, "can't revoke last key" guard, and the
  properties that matter: either key yields the *same* data key, enrolling leaves the
  payload ciphertext byte-identical, a revoked key stops working while the survivor
  keeps working.
- [ ] Manual test with two physical keys: enroll both, revoke one, confirm the other
  still works.

### Finding: revocation does not re-key the vault

Confirmed by experiment, not just by reading the design. The data key never changes,
so someone holding **both a revoked key and any older copy of the vault file** —
a backup, a synced folder, git history — can recover the data key from that old copy,
**and that same data key still decrypts the current file.** Revocation removes a key's
entry from this file; it does not retroactively protect the contents.

This is inherent to the wrap-a-shared-data-key design (age and GPG multi-recipient
files behave identically) and is the direct cost of the property that makes `revoke`
usable at all: not having to touch every remaining key. It is now documented in
[04-security-and-threat-model.md](04-security-and-threat-model.md) and warned about in
the `revoke` CLI output.

A true re-key — new data key, payload re-encrypted, every surviving credential
re-wrapped — would need every remaining key physically present. Worth offering as an
explicit `--rekey` in a later milestone; deliberately not silently substituted for
`revoke`, since a `revoke` that demands the backup key from the safe is exactly the
failure plan/07 #5b set out to avoid.

### Refinements made while implementing

1. **`enroll`/`revoke` stream the existing payload across rather than re-encrypting
   it.** They change only the header, so decrypting and resealing a possibly enormous
   `dir` payload would be pure waste. `write` now takes a payload *source*: fresh
   bytes, or a byte range copied from the current file.
2. **Both verify `header_mac` before touching anything**, including before the
   "unknown credential" and "last credential" guards, per plan/03's ordering rule.
3. **`enroll` rejects a duplicate credential and an `rp_id` mismatch**, neither of
   which the sketch mentioned. A credential made for a different `rp_id` could never
   derive a working KEK, so accepting it would enroll a key that silently never works.
4. **`init --label` and `enroll --label`** name each key, so `info` can show
   "backup in safe" rather than an opaque credential ID.

## M6 — Polish & docs

**Done.**

- [x] User-facing README: install (incl. Linux udev rules and the Windows elevation
  requirement), quick start per mode, multi-key workflow, what `revoke` does and does
  not do, a protects-against table, and the "lose every key and the data is gone"
  warning as the first thing after the title.
- [x] CLI help text pass on `fidostorers`: `long_about`, worked examples in
  `after_help`, and help on every argument (the positional ones had none).
  `fido-token`'s help was already written in M1 and needed no changes.
- [x] Error message pass. `fidostorers` now prints an actionable `hint:` line after
  the error itself, mapped exhaustively from `TokenError`/`VaultError` — "run from an
  elevated terminal", "enroll another key first, then revoke this one", "check
  `fidostorers kv ls`". The match is deliberately exhaustive rather than defaulted, so
  a new variant fails the build until someone decides what to advise; that caught a
  missed variant while writing it.
- [x] `cargo audit` in CI as its own job, plus a dependency review (below).

### Dependency review

`cargo audit`, 156 crates: **no vulnerabilities**, one unmaintained-crate warning.

`serde_cbor` 0.11.2 is unmaintained (RUSTSEC-2021-0127). It is reached only via
`authenticator` → `serde_cbor`, so it is not a dependency this project chose and
cannot be swapped without replacing the CTAP transport. Worth weighing: it is the code
that parses CBOR coming *off the device*, which is the one place in the stack where a
malicious USB device supplies the input. Unmaintained is not the same as vulnerable,
and no advisory affects it beyond "nobody is looking after it" — but it belongs on the
list of reasons to revisit [07-open-decisions.md](07-open-decisions.md) #1, alongside
the Windows elevation limitation, rather than being tracked separately.

Everything else in the direct dependency set is current and actively maintained:
`chacha20poly1305`, `hkdf`, `hmac`, `sha2` (RustCrypto), `postcard`, `tar`, `tempfile`,
`zeroize`, `clap`, `anyhow`, `thiserror`, `rand`, `serde`, and `proptest` (dev-only).

## M7 — Credential JSON hex encoding

**Done.**

- [x] `CredentialJson` DTO in the `fido-token` CLI; `credential_id` emitted as a hex
  string, with the byte-array form still accepted on read.
- [x] Shared hex helpers in `fido-token`'s library, replacing the copies that were
  duplicated in both binaries.
- [x] A test asserting the vault header still stores credential IDs as raw bytes, not
  hex — the regression that would have mattered most.
- [x] Sample output added to [../docs/M1-MANUAL-TESTING.md](../docs/M1-MANUAL-TESTING.md).

Full detail: [09-credential-encoding.md](09-credential-encoding.md).

## M8 — Keyfile + password authentication

**Done.** Sequenced before interactive mode on purpose: it changes the header layout
to `FORMAT_VERSION` 2 and changes `Vault::unlock_with` from a credential ID to an entry
ID, and doing that underneath a finished session implementation would have meant
revising it twice.

- [x] `Factor` enum in the header (`Fido2` | `Keyfile`), per-entry random 16-byte `id`,
  `FORMAT_VERSION` 2, with v1 vaults still readable and silently rewritten as v2.
- [x] `Argon2id(password, salt = entry salt, secret = SHA-256(keyfile))` -> HKDF -> KEK,
  with cost parameters stored per entry and **bounds-checked at parse time**.
- [x] `fidostorers keyfile new`; enroll-time warnings for a keyfile that looks fragile
  (plain text, inside a git repo or a sync folder, very large).
- [x] `--auth keyfile --keyfile <path>` on `init`/`enroll`, `--keyfile` on every
  unlocking command, `revoke --id <hex>` with `--credential` kept as an alias.
- [x] Password prompted with no echo, never in `argv`; `--password-stdin` for scripting.
- [x] An end-to-end unlock path CI can run, since this factor needs no hardware.
- [ ] Manual check that a **mixed** vault (one security key, one keyfile factor) opens
  by either route — the one part still needing hardware.

### Refinements made while implementing

1. **`Enrollment` carries an explicit `rp_id`.** A keyfile factor has no authenticator
   and therefore no relying party of its own, so the value cannot be inferred from the
   factor the way it could when every entry was a FIDO2 credential. A FIDO2 credential
   that disagrees with the vault is still rejected.
2. **`enroll` and `revoke` use `--unlock-*` flags** for the factor doing the unlocking.
   Both commands have to name two different things — the factor being added or removed,
   and the one authorising it — and a single `--keyfile`/`--id` cannot mean both.
3. **`enroll --password-stdin` reads the new factor's password**, with
   `--unlock-password-stdin` reading the unlocking one first, so a two-factor enroll is
   scriptable.
4. **Duplicate detection only applies to FIDO2 factors.** Two keyfile factors over the
   same file and password are legitimate (different salts, different labels) and are
   indistinguishable from the header without the password, so there is nothing to check.

Full detail, including why both factors are required and what this costs the threat
model: [10-keyfile-password-auth.md](10-keyfile-password-auth.md).

## M9 — Interactive session core

The session, without working directories — so `kv` stores work end to end and no
plaintext reaches disk in this milestone. That ordering keeps the riskiest part (M9)
out of the first working version.

- `fidostorers interactive`: REPL over the existing `clap` command definitions,
  `rustyline` for line editing, **memory-only history** (a persisted history file
  would capture `kv set --value <secret>`).
- Any number of open stores, each holding only its data key; aliases from file stems.
- `open`, `close`, `stores`, `seal`, `info`, `kv *`, `enroll`, `revoke`, `exit`.
- Idle timeout with an injectable clock, default 15 minutes.
- Graceful shutdown on `exit`, EOF, Ctrl+C, `SIGTERM`, `SIGHUP`, with signals during a
  write deferred rather than aborting it.
- Advisory `<vault>.lock`, honoured by the one-shot commands too.
- Ctrl+D (or `exit`) shuts down gracefully; Ctrl+C cancels the current line or
  operation, and interrupts a shutdown that is taking too long
  ([07-open-decisions.md](07-open-decisions.md) #19).

## M10 — Working directories for `file` and `dir` stores

The part that puts plaintext on disk, and the reason it is its own milestone.

- Extraction on `open` to `$XDG_RUNTIME_DIR`/temp, mode `0700`, never beside the vault
  by default; `--work-dir` with a warning when the destination looks like a git repo
  or a sync folder.
- Manifest-based dirty tracking, so an unchanged store is not rewritten on exit.
- Idle-timeout expiry performs a full close, and counts working-directory
  modifications as activity.
- Orphan recovery: a session file, dead-pid detection at startup, and a per-store
  seal/discard/leave prompt.
- Honest documentation that cleanup is unlinking, not secure erasure.

## M11 — Hardening to match the longer key lifetime

Promoted out of phase 2 by M9/M10: a data key held for a single command is unlikely to
be swapped out, but one held for an hour is a different proposition.

- `mlock`/`VirtualLock` pinning for data keys.
- Core-dump suppression, so a crash dump of a session process cannot contain every
  open store's data key.

Interactive mode should not be recommended for real use, and the docs should not
describe a session as safe, until these land.

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
- `mlock`/`VirtualLock` memory pinning hardening. **Promoted to M11** if interactive
  mode is built, since that is what makes it load-bearing rather than nice to have.
- A true `--rekey` for `revoke` (new data key, payload re-encrypted, every surviving
  credential re-wrapped), which needs every remaining key physically present. See M5's
  finding above.
