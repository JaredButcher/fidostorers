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
wrapped separately for each enrolled security key, so any one of them opens the vault
and adding a key never re-encrypts your data.

```
security key ──(touch)──► hmac-secret ──HKDF──► KEK ──unwraps──► data key ──► your data
```

Full design notes are in [`plan/`](plan/); the on-disk format is
[`plan/03-vault-format-and-crypto.md`](plan/03-vault-format-and-crypto.md).

## Two ways to unlock

**A security key** is the stronger option and the reason this project exists: the
secret cannot be copied off the device, and every unlock needs a physical touch.
Requires a CTAP2 key implementing `hmac-secret` — YubiKey 5 series, SoloKey,
Nitrokey 3, Token2 and similar. **U2F-only keys cannot work** and are rejected with a
clear error.

**A keyfile plus a password** needs no hardware. Both are required, always: a keyfile
alone would be a copyable bearer token, and a password alone is exactly the
offline-guessable secret this tool exists to avoid. The two are combined with Argon2id.

```sh
fidostorers keyfile new ~/secrets/vault.key
fidostorers init vault.fido --mode kv --auth keyfile --keyfile ~/secrets/vault.key
```

> **A vault is only as strong as its weakest enrolled factor.** Any one factor opens
> it, so adding a keyfile+password factor to a vault that has a security key *lowers*
> that vault's security — an attacker will go after the password. For the strongest
> setup, enroll only hardware keys.
>
> What keeps the keyfile factor respectable is the keyfile itself. With 32 random
> bytes stored somewhere the vault is not, an attacker holding only the vault file has
> nothing to attack. Store them together and you are back to guessing a password.
>
> The keyfile must stay **byte-identical forever**. An editor adding a trailing
> newline, a Windows/Linux copy translating line endings, or a sync service
> "optimising" an image will silently make the vault unopenable. This is why
> `keyfile new` writes random binary rather than letting you point at a photo.

## Install

```sh
cargo build --release
# binaries: target/release/fidostorers and target/release/fido-token
```

### Linux

The FIDO backend links libudev:

```sh
sudo apt-get install -y pkg-config libudev-dev        # Debian/Ubuntu
sudo dnf install -y pkgconf-pkg-config systemd-devel  # Fedora
```

`/dev/hidraw*` is root-only by default. Rather than running as root, grant your user
access to FIDO devices with a udev rule:

```sh
sudo tee /etc/udev/rules.d/70-fido.rules >/dev/null <<'RULE'
KERNEL=="hidraw*", SUBSYSTEM=="hidraw", ATTRS{idVendor}=="1050", TAG+="uaccess"
RULE
sudo udevadm control --reload-rules && sudo udevadm trigger
```

`1050` is Yubico — use your key's vendor ID from `fido-token list`. Replug the key
afterwards.

### Windows

> **fidostorers currently requires an elevated terminal on Windows.**
>
> Windows 10 1903 and later reserve direct access to FIDO HID devices for elevated
> processes, and the CTAP stack this project uses talks to the device directly rather
> than through the OS WebAuthn API. Start PowerShell with **Run as Administrator**.
>
> This is a known limitation, not a design choice; lifting it needs a `webauthn.dll`
> backend, which is [tracked as future work](plan/06-roadmap.md). Everything except
> `fido-token list` fails without elevation.

Directory mode also needs **Developer Mode** (Settings → Privacy & security → For
developers) or elevation to recreate symlinks. Without it, symlinks are skipped with a
warning and `unlock` exits 20.

## Quick start

Vaults come in three modes, fixed when the vault is created.

### A single file

```sh
fidostorers init secrets.fido --mode file   # touch twice
fidostorers lock secrets.fido ./private.txt # touch once
fidostorers unlock secrets.fido ./private.txt
```

### A directory tree

```sh
fidostorers init backup.fido --mode dir
fidostorers lock backup.fido ./my-folder
fidostorers unlock backup.fido ./restored
```

Symlinks are stored as symlinks and never followed; Unix permissions are preserved.

### Many named secrets

```sh
fidostorers init tokens.fido --mode kv
fidostorers kv set tokens.fido github --stdin < token.txt
fidostorers kv get tokens.fido github          # raw bytes to stdout, no newline
fidostorers kv ls  tokens.fido
fidostorers kv rm  tokens.fido github
```

Add `--keyfile <path>` to any of these to unlock with a keyfile factor instead of a
security key; the password is prompted for, or read from stdin with
`--password-stdin`. There is deliberately no `--password` flag — a password in the
command line lands in shell history and is visible to every other process.

Prefer `--stdin` or `--file` over `--value`: a value on the command line is visible in
your shell history and to other processes on the machine.

Each `kv set`/`kv rm` re-encrypts and rewrites the whole vault. That keeps the format
simple and is fine for hundreds of small secrets; it is not built for hundreds of
thousands.

## Sessions: unlock once, not once per command

Every command above needs its own touch. That is the default and the safest thing,
but it gets tiring when you are working through a handful of secrets in a row.
`fidostorers interactive` unlocks a vault once and keeps its key until you close it:

```sh
fidostorers interactive
```

```
fidostorers 0.1.0 — `help` lists commands, `exit` closes every store and quits
Stores close automatically after 15m idle.

fidostorers> open tokens.fido
touch your security key...
opened "tokens" (kv)

fidostorers> kv get tokens github
ghp_...

fidostorers> kv set tokens gitlab --file ./token.txt
set "gitlab"

fidostorers> stores
  tokens       kv    -        idle 0s    tokens.fido

fidostorers> exit
closing tokens
```

Any number of vaults can be open at once, each with an alias taken from its file
name (`--as` renames one). `open`, `close`, `stores`, `seal`, `info`, `init`,
`kv *`, `enroll`, `revoke`, `help` and `exit` all work; `help <command>` explains
any of them. Ctrl+D or `exit` closes everything and quits; Ctrl+C clears the line
you are typing without ending the session.

> **A session is weaker than the default, on purpose.** Each open vault's data key
> lives in memory until you close it. Stores therefore close themselves after 15
> minutes idle (`--idle-timeout <secs>`, or `0` to disable), and closing — whether
> by `close`, `exit`, a timeout, or `SIGTERM` — drops the key.
>
> To match that longer lifetime, a session pins each data key in its own locked page
> so it cannot be written to swap, and the process suppresses its own core dumps —
> which on Linux also stops another program running as you from reading its memory
> or attaching a debugger. The startup banner reports whether each is *actually* in
> force:
>
> ```
>   data keys pinned in memory (never swapped): enabled
>   core dumps suppressed:                      enabled
> ```
>
> If either line says otherwise, believe it rather than this page. On Windows, crash
> dumps are configured by the system and a process cannot refuse them, so that line
> will say so; memory pinning does work there.

### Editing files and directories

Opening a `file` or `dir` vault extracts it to a **working directory**, so you can
use an editor, a file manager, `grep` — anything. Closing seals your changes back
and removes it:

```
fidostorers> open backup.fido
opened "backup" (dir) at /run/user/1000/fidostorers/work-4213-9f3a/backup

  ...edit files there with whatever tools you like...

fidostorers> stores
  backup       dir   changed  idle 0s    backup.fido
       work: /run/user/1000/fidostorers/work-4213-9f3a/backup

fidostorers> exit
sealed "backup"
```

`seal <alias|all>` writes without closing, if you want a checkpoint. A store nobody
changed is not rewritten at all, so the vault file stays byte-identical.

> **This is plaintext on disk, for as long as the store is open.** It goes in
> `$XDG_RUNTIME_DIR` (usually a tmpfs, so it lives in RAM and is cleared at logout),
> mode `0700`, and **never beside the vault** — a vault often sits in a synced
> folder or a git repo, and extracting next to it would push your decrypted files
> straight into cloud sync or version history. `--work-dir <path>` overrides it, and
> warns if the destination looks like a repo or a sync folder.
>
> **Deleting a working directory is `unlink`, not secure erasure, and making it so
> is not something this tool tries to do.** On an SSD or a copy-on-write filesystem,
> overwriting a file does not reliably destroy what was there. If plaintext must
> never reach stable storage, keep the working directory on a tmpfs or a ramdisk —
> which is what the default already is on Linux — or use a `kv` vault, which never
> needs one.
>
> On Windows there is no `0700`; the directory inherits your user profile's
> permissions and is only as private as that profile.

If a seal fails, the working directory is **kept** rather than deleted — it is the
only copy of your changes at that point — and the session says where it is.

### If a session is killed

A session that is killed outright (or loses power) leaves its working directory
behind, unsealed. The next session finds it and offers it back:

```
Found an unsealed working directory from a session that did not exit cleanly:
  vault:   /home/u/backup.fido
  work:    /run/user/1000/fidostorers/work-4213-9f3a/backup
  holds:   12 entries, last modified since that session started
  [s]eal it into the vault  [d]iscard it  [l]eave it for now:
```

Sealing costs an unlock, since the data key died with the old process. "Leave it"
writes nothing, and you will be asked again next time.

### One vault, one process

While a session has a vault open it holds a `<vault>.lock` beside it, and **no other
`fidostorers` command may open or write that vault** — including to read it, since
the session's working directory can hold changes the vault file does not have yet.
Close the store, or exit the session, and everything works again.

If a session is killed, the stale lock is cleared automatically the next time you
open that vault on the same machine. On Windows, or for a lock recorded by another
machine, liveness cannot be checked, so use `open <vault> --force` — which tells you
whose lock you are taking.

## Multiple factors

Any enrolled factor opens the vault. Enroll at least two.

```sh
fidostorers enroll my.fido --label "backup in safe"

# ...or add a keyfile factor, unlocking with a key you already have enrolled
fidostorers enroll my.fido --auth keyfile --keyfile /media/usb/vault.key \
                           --label "usb backup"

fidostorers info my.fido
fidostorers revoke my.fido --id <hex-id-from-info>
```

`info` lists each factor's id, kind, and label:

```
enrolled factors:
  a346e8d266fc8aabf81dd91835b407e1  keyfile  primary
  b142a0eb29a19ceedc320d9f30779ca4  fido2    backup in safe
```

Commands that both name a factor *and* unlock the vault (`enroll`, `revoke`) use
`--unlock-keyfile` / `--unlock-id` for the factor doing the unlocking, since a single
`--keyfile` cannot mean both.

`info` needs no touch, so its output is **unauthenticated** — it is labelled as such,
and nothing security-relevant should be decided from it.

### What `revoke` does and does not do

`revoke` removes a key's entry from **this file**. It does not change the data key.
So anyone holding both the revoked key and an older copy of the vault — a backup, a
synced folder, git history — can still recover the data key from that old copy, and
that key still decrypts the current file.

Revoking protects against *"someone finds this vault later and has the old key"*. It
does **not** protect against *"the old key's holder already copied the vault"*. If a
revoked key may be in someone else's hands, treat the contents as compromised: create
a new vault and re-seal your data into it. (Removing a recipient from an `age` or GPG
file behaves the same way.)

## What this protects against

| | |
|---|---|
| Stolen laptop, leaked backup, cloud-sync breach | ✅ The file holds no secret material. |
| Offline password guessing | ✅ with security keys only — there is no password. ⚠️ A keyfile+password factor reintroduces it: someone with both the vault *and* the keyfile can attack the password offline, bounded by Argon2id. |
| Malware reading the vault while the key is unplugged | ✅ |
| Malware running *while you touch the key* | ❌ It can read what you just decrypted. |
| Backdoored security-key firmware | ❌ Out of scope; trust your hardware. |
| Losing every enrolled key | ❌ By design, unrecoverable. |

The full threat model, including what tampering is and is not detected, is
[`plan/04-security-and-threat-model.md`](plan/04-security-and-threat-model.md).

**This has not been security-audited.** It is a personal project implementing a
well-understood construction; read the design notes before trusting it with anything
you cannot afford to lose.

## Exit codes

| Code | Meaning |
|---|---|
| 0 | success |
| 1 | error — the message says which, usually with a hint |
| 20 | the vault decrypted, but the extracted tree is **incomplete** |

`fido-token` has its own finer-grained table; see
[`plan/01-crate-fido-token.md`](plan/01-crate-fido-token.md).

## `fido-token`

The device layer ships as a standalone crate and CLI, useful for debugging and usable
independently of the vault format:

```sh
fido-token list        # enumerate keys (no touch)
fido-token selftest    # register, derive, check determinism and salt binding
```

`fido-token selftest` is the fastest way to find out whether a given key works with
this tool at all. The manual test procedure is in
[`docs/M1-MANUAL-TESTING.md`](docs/M1-MANUAL-TESTING.md).

## Development

```sh
cargo test --workspace --features fido-token/test-util     # needs libudev on Linux
cargo test --workspace --no-default-features --features fido-token/test-util
cargo clippy --workspace --all-targets --features fido-token/test-util -- -D warnings
cargo fmt --all -- --check
cargo audit
```

`crates/fidostorers/tests/interactive.rs` drives a real session end to end using a
keyfile factor, which is why it needs no security key.

The second form drops the `hardware` feature and the whole platform HID stack, so the
test suite builds and passes on a machine that cannot compile the real backend. Tests
never require a physical key: `Vault` takes an already-derived key-encryption key, and
`fido-token` has an in-memory fake authenticator.

Hardware behaviour is verified manually — see
[`docs/M1-MANUAL-TESTING.md`](docs/M1-MANUAL-TESTING.md).

## License

MIT. See [LICENSE](LICENSE).
