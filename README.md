# fidostorers

Encrypt files, directories, and small secrets with a FIDO2 security key instead of a
password. Based on [riastradh/fidocrypt](https://github.com/riastradh/fidocrypt), but
written in Rust and targeting Linux **and** Windows.

There is no password to forget, phish, or brute-force. To open a vault you touch a
security key you physically have.

> ### ⚠️ Lose every enrolled key and the data is gone. Permanently.
>
> There is no recovery code, no backup password, no support address. This is the
> whole point of the design, not an oversight: the key material never leaves the
> security key, so nobody — including you — can recover a vault without one.
>
> **Enroll a second key and keep it somewhere safe.** Do it when you create the
> vault, not when you need it.
>
> ```sh
> fidostorers enroll my.fido --label "backup in safe"
> ```

## How it works

A FIDO2 authenticator supporting the CTAP2 `hmac-secret` extension will, given a
credential and a 32-byte salt, return `HMAC-SHA256(credRandom, salt)`. That output is
deterministic, gated behind a physical touch, and derived from a secret that never
leaves the key.

fidostorers uses it as a key-encryption key. A vault holds one random data key,
wrapped separately for each enrolled factor, so any one of them opens the vault and
adding a factor never re-encrypts your data.

```
security key ──(touch)──► hmac-secret ──HKDF──► KEK ──┐
keyfile + password ──────►  Argon2id  ──HKDF──► KEK ──┼──unwraps──► data key ──► your data
```

A **keyfile plus a password** is the alternative for when you have no hardware. Both
are required, always. It is weaker — see [Two ways to
unlock](docs/fidostorers.md#factors-how-a-vault-is-unlocked).

## Install

```sh
cargo build --release
# binaries: target/release/fidostorers and target/release/fido-token
```

Linux needs `pkg-config` and `libudev-dev`, plus a udev rule for non-root access to
your key. **Windows currently requires an elevated terminal.** Both are covered in
[docs/fido-token.md](docs/fido-token.md#platform-setup).

`fido-token selftest` is the fastest way to find out whether a given key works with
this tool at all.

## Quick start

Vaults come in three modes, fixed when the vault is created.

```sh
# A single file
fidostorers init secrets.fido --mode file    # touch twice
fidostorers lock secrets.fido ./private.txt  # touch once
fidostorers unlock secrets.fido ./private.txt

# A directory tree — symlinks and Unix permissions preserved
fidostorers init backup.fido --mode dir
fidostorers lock backup.fido ./my-folder
fidostorers unlock backup.fido ./restored

# Many named secrets
fidostorers init tokens.fido --mode kv
fidostorers kv set tokens.fido github --stdin < token.txt
fidostorers kv get tokens.fido github
fidostorers kv ls  tokens.fido
```

Then add a second key, and check what a vault holds:

```sh
fidostorers enroll my.fido --label "backup in safe"
fidostorers info my.fido
```

Full command reference: **[docs/fidostorers.md](docs/fidostorers.md)**.

## Sessions

Every command above needs its own touch. `fidostorers interactive` unlocks a vault
once and keeps its key until you close it — and for `file` and `dir` vaults, extracts
them to a working directory you can edit with ordinary tools.

```
fidostorers> open tokens.fido
opened "tokens" (kv)

fidostorers> kv get tokens github
ghp_...
```

A session is weaker than the default on purpose: keys live in memory, and working
directories put plaintext on disk, both until you close the store. Stores close
themselves after 15 minutes idle, keys are pinned out of swap, and core dumps are
suppressed. Read **[docs/sessions.md](docs/sessions.md)** before relying on it.

## What this protects against

| | |
|---|---|
| Stolen laptop, leaked backup, cloud-sync breach | ✅ The file holds no secret material. |
| Offline password guessing | ✅ with security keys only — there is no password. ⚠️ A keyfile+password factor reintroduces it: someone with both the vault *and* the keyfile can attack the password offline, bounded by Argon2id. |
| Malware reading the vault while the key is unplugged | ✅ |
| Malware running *while you touch the key* | ❌ It can read what you just decrypted. |
| Backdoored security-key firmware | ❌ Out of scope; trust your hardware. |
| Losing every enrolled key | ❌ By design, unrecoverable. |

Two things worth knowing before you rely on this:

- **`revoke` is not re-keying.** It removes a factor from *this file*; anyone with
  the revoked key and an older copy can still read it.
  [Details](docs/fidostorers.md#what-revoke-does-and-does-not-do).
- **A vault is only as strong as its weakest factor.** Adding a keyfile+password
  factor to a vault that has a security key lowers that vault's security.

The full threat model, including what tampering is and is not detected, is
[`plan/04-security-and-threat-model.md`](plan/04-security-and-threat-model.md).

**This has not been security-audited.** It is a personal project implementing a
well-understood construction; read the design notes before trusting it with anything
you cannot afford to lose.

## Documentation

| | |
|---|---|
| [docs/fidostorers.md](docs/fidostorers.md) | vault command reference: modes, factors, enrolling, revoking, exit codes |
| [docs/sessions.md](docs/sessions.md) | `fidostorers interactive`: working directories, idle timeout, locking, recovery |
| [docs/fido-token.md](docs/fido-token.md) | the device layer, its CLI, and platform setup |
| [docs/M1-MANUAL-TESTING.md](docs/M1-MANUAL-TESTING.md) | the hardware acceptance procedure |
| [`plan/`](plan/) | design notes: the [on-disk format](plan/03-vault-format-and-crypto.md), the [threat model](plan/04-security-and-threat-model.md), and a [decision record](plan/07-open-decisions.md) of what was chosen and why |

API docs for both crates: `cargo doc --workspace --open`.

## Development

```sh
cargo test --workspace --features fido-token/test-util     # needs libudev on Linux
cargo test --workspace --no-default-features --features fido-token/test-util
cargo clippy --workspace --all-targets --features fido-token/test-util -- -D warnings
cargo fmt --all -- --check
cargo audit
```

The second command drops the `hardware` feature and the whole platform HID stack, so
the test suite builds and passes on a machine that cannot compile the real backend.

**No test needs a physical key.** `Vault` takes an already-derived key-encryption
key, a session takes an already-derived data key, and `fido-token` has an in-memory
fake authenticator. `crates/fidostorers/tests/interactive.rs` drives whole sessions
end to end through a keyfile factor, which involves no hardware at all.

If you touch anything platform-specific, cross-check the other half of the CI matrix
before pushing — it is otherwise the first thing to discover that a `#[cfg]`-gated
helper is now dead code there:

```sh
rustup target add x86_64-pc-windows-msvc
cargo clippy --workspace --all-targets --features fido-token/test-util \
      --target x86_64-pc-windows-msvc -- -D warnings
```

Hardware behaviour is verified manually — see
[docs/M1-MANUAL-TESTING.md](docs/M1-MANUAL-TESTING.md) for the procedure, and the
unchecked boxes in [`plan/06-roadmap.md`](plan/06-roadmap.md) for what is still
outstanding.

## License

MIT. See [LICENSE](LICENSE).
