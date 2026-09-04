# `fidostorers` — command reference

The vault tool. For sessions (`fidostorers interactive`) see
[sessions.md](sessions.md); for the device layer see [fido-token.md](fido-token.md).

- [Vault modes](#vault-modes)
- [Factors: how a vault is unlocked](#factors-how-a-vault-is-unlocked)
- [Creating a vault](#creating-a-vault)
- [File and directory vaults](#file-and-directory-vaults)
- [Key/value vaults](#keyvalue-vaults)
- [Enrolling and revoking factors](#enrolling-and-revoking-factors)
- [Inspecting a vault](#inspecting-a-vault)
- [Keyfiles](#keyfiles)
- [Exit codes](#exit-codes)

## Vault modes

A vault is created in one mode and keeps it for life. `fidostorers info` tells you
which one a file is.

| Mode | Holds | Managed with |
|---|---|---|
| `file` | one file's bytes | `lock` / `unlock` |
| `dir` | a directory tree | `lock` / `unlock` |
| `kv` | many named secrets | `fidostorers kv …` |

Directory vaults store symlinks as symlinks and never follow them, and preserve Unix
mode bits on every platform. Extraction is best-effort: on Windows a symlink that
cannot be created is reported and skipped, and the command exits 20 so a script can
tell a partial tree from a complete one.

Every write re-encrypts the whole payload and replaces the file through a temp file
and a rename, so an interrupted write cannot corrupt an existing vault. The payload
is processed in one piece in memory, so a `dir` vault is practically limited to a
tree that fits in RAM.

## Factors: how a vault is unlocked

A vault has one or more enrolled **factors**, and any one of them opens it. There
are two kinds.

**A security key** is the stronger option and the reason this project exists: the
secret cannot be copied off the device, and every unlock needs a physical touch.
Requires a CTAP2 key implementing `hmac-secret` — YubiKey 5 series, SoloKey,
Nitrokey 3, Token2 and similar. U2F-only keys cannot work and are rejected with a
clear error.

**A keyfile plus a password** needs no hardware. Both are required, always: a
keyfile alone would be a copyable bearer token, and a password alone is exactly the
offline-guessable secret this tool exists to avoid. They are combined with Argon2id.

> **A vault is only as strong as its weakest enrolled factor.** Any one factor opens
> it, so adding a keyfile+password factor to a vault that has a security key *lowers*
> that vault's security — an attacker will go after the password. For the strongest
> setup, enroll only hardware keys.
>
> What keeps the keyfile factor respectable is the keyfile itself. With 32 random
> bytes stored somewhere the vault is not, an attacker holding only the vault file
> has nothing to attack. Store them together and you are back to guessing a password.

Add `--keyfile <path>` to any unlocking command to use a keyfile factor instead of a
security key. The password is prompted for without echo, or read from stdin with
`--password-stdin`. There is deliberately no `--password` flag: a password in the
command line lands in shell history and is visible to every other process.

`--id <hex>` picks one specific factor, from `fidostorers info`. Without it, every
enrolled factor of the chosen kind is tried in turn.

## Creating a vault

```sh
fidostorers init secrets.fido --mode file          # touch twice
fidostorers init tokens.fido  --mode kv --auth keyfile --keyfile ~/secrets/vault.key
```

| Option | Meaning |
|---|---|
| `--mode file\|dir\|kv` | required; fixed for the vault's life |
| `--auth fido2\|keyfile` | which kind of factor to enroll first (default `fido2`) |
| `--keyfile <path>` | required with `--auth keyfile` |
| `--label <name>` | shown by `info` (default `primary`) |
| `--rp-id <id>` | relying-party id bound into the credential; the default is fine |
| `--require-uv` | require PIN or biometric, not just a touch |
| `--argon2-memory/-time/-parallelism` | Argon2id cost for a keyfile factor |

`init` refuses to overwrite an existing file, and warns that a vault with one factor
is a vault you can lose permanently.

## File and directory vaults

```sh
fidostorers lock   secrets.fido ./private.txt
fidostorers unlock secrets.fido ./private.txt

fidostorers lock   backup.fido ./my-folder
fidostorers unlock backup.fido ./restored
```

`lock` replaces whatever the vault held. `unlock` writes it back out, and exits 20 if
the extracted tree is incomplete.

Directory vaults treat archive contents as **untrusted**: absolute paths, `..`
traversal, and the symlink-then-write-through-it escape are all rejected. This
matters because someone can hand you a vault *and* a key that opens it, and
authentication proves only that the contents have not changed since they were
sealed — not that whoever sealed them meant you well.

## Key/value vaults

```sh
fidostorers kv set tokens.fido github --stdin < token.txt
fidostorers kv get tokens.fido github     # raw bytes to stdout, no trailing newline
fidostorers kv ls  tokens.fido
fidostorers kv rm  tokens.fido github
```

`get` writes raw bytes with no trailing newline, so binary values survive a pipe.
`rm` errors on a name that is not there, so a typo cannot look like a successful
deletion.

Prefer `--stdin` or `--file` over `--value`: a value on the command line is visible
in your shell history and to every other process on the machine.

Each `set`/`rm` re-encrypts and rewrites the whole vault. That keeps the format
simple and is fine for hundreds of small secrets; it is not built for hundreds of
thousands.

## Enrolling and revoking factors

Any enrolled factor opens the vault. **Enroll at least two.**

```sh
fidostorers enroll my.fido --label "backup in safe"

# ...or add a keyfile factor, unlocking with a key you already have enrolled
fidostorers enroll my.fido --auth keyfile --keyfile /media/usb/vault.key \
                           --label "usb backup"

fidostorers revoke my.fido --id <hex-id-from-info>
```

`enroll` and `revoke` both name *two* things — the factor being added or removed, and
the factor authorising the change — so the unlocking half is spelled `--unlock-keyfile`,
`--unlock-id`, `--unlock-password-stdin`, `--unlock-require-uv`.

Enrolling never re-encrypts the payload, and never needs any other enrolled key to be
present. That is deliberate: a `revoke` that demanded the backup key from your safe
would be useless in the emergency that backup exists for.

### What `revoke` does and does not do

`revoke` removes a factor's entry from **this file**. It does not change the data key.
So anyone holding both the revoked key and an older copy of the vault — a backup, a
synced folder, git history — can still recover the data key from that old copy, and
that key still decrypts the current file.

Revoking protects against *"someone finds this vault later and has the old key"*. It
does **not** protect against *"the old key's holder already copied the vault"*. If a
revoked key may be in someone else's hands, treat the contents as compromised: create
a new vault and re-seal your data into it. Removing a recipient from an `age` or GPG
file behaves the same way.

## Inspecting a vault

```sh
fidostorers info tokens.fido
```

```
enrolled factors:
  a346e8d266fc8aabf81dd91835b407e1  keyfile  primary
  b142a0eb29a19ceedc320d9f30779ca4  fido2    backup in safe
```

`info` is the only command needing no touch — which is exactly why its output is
**unauthenticated**. Verifying the header's MAC requires the data key, which requires
a touch. It is labelled as such, and nothing security-relevant should be decided from
it. (Inside a session the same output *is* authenticated, because opening the store
already verified the header.)

## Keyfiles

```sh
fidostorers keyfile new ~/secrets/vault.key
```

Writes 32 random bytes. Refuses to overwrite.

The keyfile must stay **byte-identical forever**. An editor adding a trailing
newline, a Windows/Linux copy translating line endings, or a sync service
"optimising" an image will silently make the vault unopenable through that factor.
That is why `keyfile new` writes random binary rather than letting you point at a
photo, and why `enroll` warns when a keyfile looks like text, lives in a git repo, or
sits in a sync folder.

Back it up as carefully as the vault, and **store it somewhere the vault is not** — a
thief who takes both is left with only your password to guess.

There is deliberately no stored keyfile fingerprint, so a wrong keyfile and a wrong
password produce the same error. A fingerprint would let anyone holding the vault
test candidate keyfiles offline without knowing the password, turning one two-factor
problem into two one-factor problems.

## Exit codes

| Code | Meaning |
|---|---|
| 0 | success |
| 1 | error — the message says which, usually with a `hint:` line |
| 20 | the vault decrypted, but the extracted tree is **incomplete** |

`fido-token` has its own finer-grained table; see [fido-token.md](fido-token.md).
