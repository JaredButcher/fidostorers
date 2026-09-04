# Sessions — `fidostorers interactive`

Every one-shot command needs its own touch. That is the default and the safest
thing, but it gets tiring when you are working through a handful of secrets in a
row. A session unlocks a vault once and keeps its key until you close it.

```
$ fidostorers interactive
fidostorers 0.1.0 — `help` lists commands, `exit` closes every store and quits
Stores close automatically after 15m idle.

  data keys pinned in memory (never swapped): enabled
  core dumps suppressed:                      enabled

fidostorers> open tokens.fido
touch your security key...
opened "tokens" (kv)

fidostorers> kv get tokens github
ghp_...

fidostorers> exit
"tokens" unchanged, nothing to write
```

- [What a session costs you](#what-a-session-costs-you)
- [Commands](#commands)
- [Working directories](#working-directories)
- [The idle timeout](#the-idle-timeout)
- [One vault, one process](#one-vault-one-process)
- [If a session is killed](#if-a-session-is-killed)
- [Hardening](#hardening)

## What a session costs you

This is a deliberate reversal of one of the project's guarantees, so it is worth
being plain about the trade.

**What you give up.** Each open vault's data key lives in process memory until you
close it, instead of for the length of one command. For `file` and `dir` stores,
**plaintext lives on disk** in a working directory for the same window.

**What you keep.** A vault at rest, with no session running, is exactly as protected
as before. Nothing about the file format changes.

**What bounds the window.** Stores close themselves after 15 minutes idle. Only the
data key is cached — never the KEK, the raw `hmac-secret` output, the password, or
the keyfile. Keys are pinned in memory and the process suppresses its own core
dumps. Closing, by any route, drops the key and removes the plaintext.

The full accounting is in
[`plan/04-security-and-threat-model.md`](../plan/04-security-and-threat-model.md).

## Commands

`help` lists them; `help <command>` explains one.

| Command | Does |
|---|---|
| `open <vault> [--as <alias>] [--work-dir <path>] [--force]` | unlock, keep the key |
| `close <alias\|all>` | seal, remove the working directory, drop the key |
| `stores` | aliases, modes, whether anything changed, idle time, working paths |
| `seal <alias\|all>` | write pending changes without closing |
| `info [<alias>]` | as the one-shot command, but **authenticated** |
| `kv set\|get\|rm\|ls <alias> …` | as the one-shot commands |
| `init <vault> --mode …` | create a vault and open it |
| `enroll <alias> [--label …]` | add a factor — no unlocking flags, it is already open |
| `revoke <alias> --id <hex>` | remove a factor |
| `exit` / `quit` | close everything and leave |

Stores are named by an alias taken from the vault's file name (`tokens.fido` →
`tokens`), or by their path. `--as` renames one; a collision appends a counter.

`lock`/`unlock` are deliberately **not** session commands: extraction happens at
`open` and sealing at `close`/`seal`, and reusing those verbs for something different
would mislead.

Unlocking flags work as they do one-shot — `--keyfile`, `--id`, `--require-uv`. Two
things are refused inside a session, because stdin is the prompt you are typing at:
`kv set --stdin` (use `--file`), and `--password-stdin` when stdin is a terminal
(omit it and you are prompted without echo). Piped input still works, which is the
scripting case the flag exists for.

Ctrl+D or `exit` closes everything and quits. Ctrl+C clears the line you are typing
without ending the session. History is kept in memory only and never written to disk,
so a `kv set --value <secret>` cannot end up in a history file.

## Working directories

Opening a `file` or `dir` vault extracts it to a working directory, so you can use an
editor, a file manager, `grep` — anything. Closing seals your changes back and
removes it.

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

A store nobody changed is not rewritten at all — the vault file stays byte-identical.
`seal` writes without closing, if you want a checkpoint.

> **This is plaintext on disk for as long as the store is open.** It goes in
> `$XDG_RUNTIME_DIR` (usually a tmpfs, so it lives in RAM and is cleared at logout),
> mode `0700`, and **never beside the vault** — a vault often sits in a synced folder
> or a git repo, and extracting next to it would push your decrypted files straight
> into cloud sync or version history.
>
> `--work-dir <path>` overrides the location. It refuses a directory that already
> contains anything, and warns if the destination looks like a repo or a sync folder.
>
> On Windows there is no `0700`; the directory inherits your user profile's
> permissions and is only as private as that profile.

**Deleting a working directory is `unlink`, not secure erasure, and making it so is
explicitly not something this tool tries to do.** On an SSD or a copy-on-write
filesystem, overwriting a file does not reliably destroy what was there, and nothing
done from userspace changes that. If plaintext must never reach stable storage, keep
the working directory on a tmpfs or a ramdisk — which is what the default already is
on Linux — or use a `kv` vault, which never needs one.

If a seal fails, the working directory is **kept** rather than deleted: at that point
it is the only copy of your changes. The session says where it is and exits non-zero.

## The idle timeout

On by default at 15 minutes. `--idle-timeout <secs>`, or `0` to disable — which
leaves vaults unlocked for as long as the process runs, and is an explicit choice.

Expiry is a full close: seal, remove the working directory, drop the key, release the
lock. It never merely forgets the key while leaving plaintext readable on disk.

Editing files inside a working directory counts as activity, not just typing at the
prompt — otherwise a session would seal the tree out from under your editor while you
worked. A warning fires 60 seconds before expiry (`--idle-warning <secs>`).

## One vault, one process

While a session has a vault open it holds a `<vault>.lock` beside it, and **no other
`fidostorers` command may open or write that vault** — including to read it, since
the session's working directory can hold changes the vault file does not have yet.
Close the store, or exit the session, and everything works again.

The lock is advisory: it stops this tool's own commands colliding, which is the
collision that actually happens. It does not stop unrelated programs.

If a session is killed, the stale lock is cleared automatically the next time you
open that vault on the same machine. Where liveness cannot be checked — a lock
recorded by another machine, or a process this one is not allowed to query — use
`open <vault> --force`, which tells you whose lock you are taking.

## If a session is killed

A session that is killed outright, or loses power, leaves its working directory
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

Only directories left by a process that is *provably* gone are offered. A session
still running is never touched.

## Hardening

Because a session holds keys far longer than a single command does:

- **Data keys are pinned in memory**, each in its own `mlock`ed (`VirtualLock`ed)
  page, so the 32 bytes that open a vault cannot be written to swap.
- **Core dumps are suppressed** for every command. On Linux this also makes
  `/proc/<pid>/mem` root-owned, so another program running as you cannot read the
  session's memory or attach a debugger.

Both are attempted and then **measured**, and the startup banner prints what is
actually in force. If a line says otherwise, believe it:

```
  data keys pinned in memory (never swapped): enabled
  core dumps suppressed:                      enabled
```

Memory locking can fail on a low `RLIMIT_MEMLOCK` (`ulimit -l`). On Windows, crash
dumps are configured by the system and a process cannot refuse them, so that line
will say so; memory pinning does work there.

Not protected, deliberately: decrypted payloads, which can exceed any
`RLIMIT_MEMLOCK` and are on disk by design anyway, and keys held by one-shot
commands, which are short-lived enough to be unlikely to page out.
