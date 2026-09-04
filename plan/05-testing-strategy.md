# Testing strategy

Physical FIDO hardware cannot run in CI. The whole crate boundary
(`Authenticator` trait, `Vault` taking an already-derived KEK — see
[01](01-crate-fido-token.md)/[02](02-crate-fidostorers.md)) exists specifically so
that "requires a physical key" is isolated to a thin layer, and everything else is
unit-testable on every commit.

## `fido-token` unit tests (hardware-free)

- **Fake authenticator**: an in-memory `Authenticator` impl (`FakeAuthenticator`,
  test-only, likely gated behind `#[cfg(test)]` or a `test-util` feature so crate 2
  can reuse it too) that:
  - simulates `register()` by generating a random credential id and remembering a
    fake `credRandom` for it,
  - simulates `derive_secret()` by computing `HMAC-SHA256(fake_credRandom, salt)`
    locally (same construction as real hmac-secret, just without any device),
  - can be configured to return `NotAllowed`/`Timeout`/`UnknownCredential` to test
    error paths,
  - can simulate "two different physical keys" as two independent
    `FakeAuthenticator` instances with different `credRandom` pools, to test that
    deriving with the wrong credential id fails.
- Tests against the fake:
  - deriving twice with the same credential+salt gives identical output
    (determinism, the property everything else relies on).
  - different salts, same credential → different outputs.
  - same salt, different credentials → different outputs.
  - unknown credential id → `TokenError::UnknownCredential`.
  - CLI arg parsing (`clap`'s derive gives this almost for free via
    `Command::debug_assert()` / `try_parse_from` in tests).
- **CTAP2 wire-format encoding tests** (extension request/response CBOR shapes) can be
  unit-tested against fixed byte vectors without hardware, if we end up hand-rolling
  any of that — likely unnecessary given we lean on the `authenticator` crate for
  wire format, but worth a placeholder if we ever need to debug interop issues.

## `fidostorers` unit tests (hardware-free)

All of these construct a `Vault` directly with an arbitrary 32-byte KEK (standing in
for whatever `fido-token::derive_secret` would have returned) — no fake authenticator
needed at this layer, just raw bytes:

- **Round trip, file mode**: `create` → `seal_file` → `open_file` → bytes match
  input, for empty file, small file, and a multi-MB file (buffered I/O correctness).
- **Round trip, dir mode**: build a temp directory tree (nested dirs, empty dirs, a
  symlink) with `tempfile`/`assert_fs`, `seal_dir` → `open_dir` → tree matches
  (byte-for-byte file contents + structure; permissions compared loosely per platform).
- **Round trip, kv mode**: `kv_set` several entries, `kv_get` each back, `kv_ls`
  matches, `kv_rm` then `kv_get` errors as not-found.
- **Multi-key enrollment**: `create` with credential A's KEK, `enroll` credential B's
  KEK, then confirm `unlock_with` succeeds using *either* A's or B's KEK
  independently and both yield the same data key.
- **Revoke**: after `revoke(A)`, `unlock_with` using A's KEK fails, B's KEK still
  works; revoking the last remaining credential is rejected with a clear error.
- **Tamper detection**: flip a byte in the header (a credential's salt, the mode
  field) or in the payload ciphertext post-write, confirm `unlock_with`/`open_file`
  etc. return an authentication-failure error, never a silent garbage decrypt.
- **Wrong KEK**: `unlock_with` with a KEK that doesn't match any wrapped entry fails
  cleanly (this is the local stand-in for "touched the wrong security key").
- **Format version guard**: a header claiming a future/unknown `format_version` is
  rejected on `open`, not partially parsed.
- **Crash-safety**: the original vault survives a failed write. Implemented by
  pointing `seal_*` at input that cannot be read and asserting the file on disk is
  byte-identical afterwards, plus a check that no temp file is left behind — the
  "exact mechanism TBD" this line used to carry.
- **Keyfile factors** (M8): derivation is deterministic and changes when any of
  keyfile, password, salt or Argon2 parameters changes; a mixed vault opens by
  either route; wrong keyfile and wrong password fail *identically*, per the
  no-fingerprint decision; out-of-range KDF parameters are rejected at parse time
  before allocating; a v1 vault opens and is rewritten as v2 with the same data key.
- **Property tests** (`proptest`) for the KV and dir round trips over randomized
  small inputs (random byte strings, random small directory trees) to catch edge
  cases fixed example tests miss (empty values, names with unusual characters,
  duplicate/near-duplicate paths).

## Session tests (hardware-free)

M9-M11 added state that outlives a single command, and the seam that keeps it
testable is the same one `Vault` uses: a `Store` is handed an **already-derived data
key**, so nothing below the REPL needs a security key.

- **Session state** (`session.rs`): aliases from file stems with `-2` on collision,
  resolution by alias or path, close and close-all ordering, and re-opening the same
  vault reporting "already open" rather than a lock conflict with itself.
- **Idle timeout** against an **injectable clock**, so expiry is asserted rather than
  slept through: an idle store expires and a busy one does not, the warning fires
  before the expiry and does not itself close anything, `--idle-timeout 0` never
  expires, and expiry seals before dropping the key.
- **Working directories** (`workdir.rs`): an untouched tree is not pending; edits,
  additions, deletions and permission changes each are; a `--work-dir` the user
  supplied is emptied but not removed; a failed seal keeps its plaintext.
- **Locking** (`lock.rs`): acquire/release, a held lock excludes writers *and*
  readers, a process never excludes itself, an unparseable lock file still excludes,
  a provably dead holder is cleared automatically, and a holder on another host never
  is.
- **Orphan recovery** (`orphan.rs`): a dead session's working directory is offered, a
  live one's is not, one on another host is not, resolving one store leaves the
  others, and "leave it" is repeatable.
- **Hardening** (`hardening.rs`): each key gets its own page, `Debug` never prints
  key bytes, locks are released on drop so `RLIMIT_MEMLOCK` is not exhausted, and —
  on Linux — the kernel is asked to confirm it, via `VmLck` in `/proc/self/status`.
  Plus the interaction that could quietly destroy data: a process that has suppressed
  its core dumps must still look *alive* to the liveness check that vault locks and
  orphan records depend on.

### End-to-end session tests (`tests/interactive.rs`)

The keyfile factor from M8 is what makes these possible in CI: a whole session can be
driven with no security key at all. They spawn the real binary with a scripted stdin
and their own `XDG_RUNTIME_DIR`, and cover what unit tests structurally cannot — that
a typed line becomes the right `Vault` call:

- one unlock serving many commands, with no second password prompt;
- a session's writes readable afterwards by a separate one-shot process;
- a file and a dir store extracted, edited on disk, and sealed back, with an
  unchanged store leaving the vault byte-identical;
- a one-shot writer *and* reader both refused while a vault is held, and both working
  once it is released;
- a session killed outright, then its orphan offered and discarded by the next one;
- `--work-dir` refusing a non-empty directory without touching what is in it;
- a typo not ending the session;
- on Linux, the kernel reporting locked memory in a running session.

`tests/cli.rs` does the same for the one-shot commands that need no key — `info`
being the only touch-free command, and `init` refusing to overwrite.

## Hardware-in-the-loop tests (manual, not CI)

A small `#[ignore]`-gated test module (or a separate `tests/hardware/` integration
test target) that talks to a real connected authenticator, run manually by a
developer with a key plugged in:

```
cargo test --test hardware -- --ignored --test-threads=1
```

Covers: `list_devices` finds the plugged-in key, a full `register` → `derive_secret`
round trip against real hardware confirms determinism holds outside the fake, and a
basic Windows-vs-Linux parity check (same test binary, run manually on both OSes
during development — see [06-roadmap.md](06-roadmap.md) M1 which calls out validating
the Windows backend early precisely because it's the one thing unit tests
structurally cannot cover; that validation is what turned up the elevation
requirement). The Windows run is done; the Linux run is outstanding.

## What CI actually runs

- `cargo test --workspace` (everything above except the `--ignored` hardware tests)
  on Linux and Windows runners (GitHub Actions matrix), on every push — the whole
  point of the hardware-free split is that this matrix needs no physical keys.
  Linux runners install `pkg-config` and `libudev-dev` first, which the
  `authenticator` crate's HID backend links against.
- The same suite again with `--no-default-features`, which drops the `hardware`
  feature and with it the platform HID stack. This guards the promise that the
  hardware-free tests really are hardware-free: they must build and pass on a machine
  that cannot compile the real backend at all.
- `cargo clippy --workspace --all-targets -- -D warnings` and `cargo fmt --check`.
- `cargo audit` as its own job. It fails on a vulnerability; unmaintained-crate
  warnings do not fail the build (there is one, `serde_cbor`, reached only via
  `authenticator` — see [06-roadmap.md](06-roadmap.md) M6).
- Hardware-in-the-loop tests are a manual pre-release checklist item, not a CI gate.
  The M1 procedure is written up in
  [../docs/M1-MANUAL-TESTING.md](../docs/M1-MANUAL-TESTING.md); `fido-token selftest`
  packages its acceptance check as one command.

Worth doing locally before pushing anything with platform code in it:
`cargo clippy --all-targets --target x86_64-pc-windows-msvc -- -D warnings`. The
Windows half of the matrix is otherwise the first thing to find out that a
`#[cfg]`-gated helper is now dead code there, or that a platform call does not
compile — which is exactly what it caught for M11's `VirtualLock` work.

## What still needs a physical key

Every milestone from M1 on carries unchecked manual-validation boxes in
[06-roadmap.md](06-roadmap.md); that is the list, kept per milestone rather than
duplicated here so the two cannot drift. The shape of it: **Linux hardware validation
has never been run at all** (M1's remaining item), the Windows run passed except for
needing elevation, and everything from M2 on — vault round trips, directory symlink
handling with and without Developer Mode, two-key enroll/revoke, a mixed
security-key-and-keyfile vault, one touch per session `open`, and `VirtualLock` on
Windows — is still outstanding.
