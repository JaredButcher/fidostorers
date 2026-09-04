# `fido-token` — the device layer

Everything that talks to a physical security key lives in the `fido-token` crate, and
nowhere else. It ships as a library *and* a standalone CLI, and knows nothing about
vaults — it is useful on its own, and published separately for that reason.

- [Why it exists](#why-it-exists)
- [CLI](#cli)
- [Exit codes](#exit-codes)
- [Platform setup](#platform-setup)
- [Library use](#library-use)

## Why it exists

A CTAP2 authenticator supporting the `hmac-secret` extension will, given a credential
and a 32-byte salt, return `HMAC-SHA256(credRandom, salt)`. That output is:

- **deterministic** — same credential, same salt, same 32 bytes, every time;
- **non-extractable** — the authenticator never reveals `credRandom` itself;
- **gated by physical possession** — you must touch the key, and optionally enter a
  PIN.

That is the whole trick `fidostorers` is built on. This crate asks for those bytes
and does nothing else.

Credentials are **non-resident**: the caller stores the credential and passes it back
on every assertion, so many vaults can share one physical key without exhausting its
limited on-device credential slots.

## CLI

```
fido-token list
    Enumerate connected authenticators. Passive: no touch, and no device is opened
    for I/O, so hmac-secret and clientPIN support report as "unprobed" rather than
    being queried.

fido-token register [--rp-id <id>] [--name <label>] [--require-uv]
                    [--timeout 30] [--no-pin]
    Create a credential and print it as JSON for the caller to store.

fido-token derive --credential <path.json> --salt <hex>
                  [--require-uv] [--timeout 30] [--no-pin]
    Prompt for a touch, print the 32-byte secret as hex.

fido-token selftest [--credential <path>] [--require-uv] [--timeout 30] [--no-pin]
    Register, derive twice with one salt, derive once with another, and assert
    determinism and salt binding. --credential reuses a saved credential, to
    re-test after a replug or reboot.
```

Global flags: `-v`/`-vv` raise log verbosity (`-vv` includes the full CTAP2
exchange), `-q` silences all but errors, and `RUST_LOG` overrides both. Key material
is never logged — derived secrets appear only as a non-invertible fingerprint, which
is enough to check that two derivations agree without putting the secret in a log
file.

**`fido-token selftest` is the fastest way to find out whether a given key works with
this tool at all.** It is the acceptance check described in
[M1-MANUAL-TESTING.md](M1-MANUAL-TESTING.md).

`register` and `selftest` print credentials as JSON with `credential_id` as a
lowercase hex string. The older array-of-bytes form is still accepted on read.

## Exit codes

Finer-grained than `fidostorers`' own, so that a caller can distinguish failures
without re-deriving the logic.

| Code | Meaning |
|---|---|
| 0 | success |
| 1 | generic error |
| 2 | usage error — bad arguments |
| 3 | no device found |
| 4 | timed out waiting for user presence |
| 5 | user declined, or the PIN was wrong |
| 6 | credential not recognised by any connected key — the wrong key was touched |
| 7 | no `hmac-secret` support (a U2F-only key) |
| 8 | PIN required, or the key is locked out |
| 9 | device present but unopenable — the Windows elevation case |
| 10 | transport error |
| 11 | `selftest` ran but its assertions failed |

## Platform setup

Both platforms use raw USB HID. There is **no `webauthn.dll` path**, on either.

### Linux

The backend links libudev:

```sh
sudo apt-get install -y pkg-config libudev-dev        # Debian/Ubuntu
sudo dnf install -y pkgconf-pkg-config systemd-devel  # Fedora
```

`/dev/hidraw*` is root-only by default. Rather than running as root, grant your user
access with a udev rule:

```sh
sudo tee /etc/udev/rules.d/70-fido.rules >/dev/null <<'RULE'
KERNEL=="hidraw*", SUBSYSTEM=="hidraw", ATTRS{idVendor}=="1050", TAG+="uaccess"
RULE
sudo udevadm control --reload-rules && sudo udevadm trigger
```

`1050` is Yubico — use your key's vendor ID from `fido-token list`. Replug the key
afterwards.

### Windows

> **An elevated terminal is required.**
>
> Since Windows 10 1903 a filter driver reserves read/write access to FIDO HID
> devices for elevated processes. Start PowerShell with **Run as Administrator**.
>
> This is a known limitation, not a design choice. Lifting it needs a `webauthn.dll`
> backend, which is [tracked as future work](../plan/06-roadmap.md). Everything
> except `fido-token list` fails without elevation — `list` works because it opens
> devices with zero desired access, which the filter permits.

## Library use

The real CTAP2 calls sit behind the `Authenticator` trait, so consumers — including
this crate's own tests — never depend on a physical device.

```rust,no_run
use std::time::Duration;

let credential = fido_token::register(&fido_token::RegisterOptions {
    rp_id: "example.local".to_string(),
    user_name: "example".to_string(),
    require_uv: false,
    timeout: Duration::from_secs(30),
    pin_provider: fido_token::terminal_pin_provider(),
})?;

let secret = fido_token::derive_secret(
    &credential,
    &[0u8; 32],
    &fido_token::DeriveOptions {
        require_uv: false,
        timeout: Duration::from_secs(30),
        pin_provider: fido_token::terminal_pin_provider(),
    },
)?;
# Ok::<(), fido_token::TokenError>(())
```

Two feature flags matter:

- **`hardware`** (default on) gates the real backend and the `authenticator`
  dependency. With it off, device calls return `TokenError::BackendUnavailable` and
  everything else still builds — which is what lets dependent crates be tested on a
  machine that cannot satisfy the platform HID build dependencies.
- **`test-util`** exposes `FakeAuthenticator`, a pure-software stand-in that
  reproduces the real `hmac-secret` construction locally and can be told to fail in
  specific ways.

Run `cargo doc --open -p fido-token` for the full API.

Design notes: [`plan/01-crate-fido-token.md`](../plan/01-crate-fido-token.md).
