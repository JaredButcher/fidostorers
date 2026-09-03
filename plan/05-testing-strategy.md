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
- **Crash-safety**: simulate an interrupted write (e.g. by asserting the temp file
  exists pre-rename in a controlled test hook, or simply asserting the original vault
  file is untouched if `seal_*` is made to fail partway via an injected I/O error) —
  exact mechanism TBD once the write path is implemented, but "original vault survives
  a failed write" is a required test, not optional.
- **Property tests** (`proptest`) for the KV and dir round trips over randomized
  small inputs (random byte strings, random small directory trees) to catch edge
  cases fixed example tests miss (empty values, names with unusual characters,
  duplicate/near-duplicate paths).

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
- `cargo clippy --workspace -- -D warnings` and `cargo fmt --check`.
- Hardware-in-the-loop tests are a manual pre-release checklist item, not a CI gate.
  The M1 procedure is written up in
  [../docs/M1-MANUAL-TESTING.md](../docs/M1-MANUAL-TESTING.md); `fido-token selftest`
  packages its acceptance check as one command.
