# Interactive mode

A long-lived session that keeps a vault's data key in memory, so a user working with
one or more vaults touches their security key once per vault rather than once per
command.

> **Status: the session core is implemented (M9). Working directories are not.**
>
> What works today: `open`/`close`/`stores`/`seal`/`info`/`init`/`kv *`/`enroll`/
> `revoke`/`help`/`exit`, aliases, the idle timeout and its warning, the advisory
> lock, and graceful shutdown. `kv` stores work end to end.
>
> What is deferred to M10, and is described below as though it existed: the
> **working directories** that extract a `file` or `dir` store to a plaintext path,
> and everything that depends on them — dirty tracking and the `stores` dirty
> column, a `seal` that actually writes, orphan recovery and its session file, and
> interrupting a shutdown that is taking too long. Opening a `file`/`dir` store
> today caches its key (so `info`, `enroll` and `revoke` need no further touches)
> but extracts nothing.
>
> Deviations from the design below that were deliberate rather than deferred are
> recorded in [06-roadmap.md](06-roadmap.md) M9, "Refinements made while
> implementing".

```
$ fidostorers interactive
fidostorers 0.1.0 - type `help`, `exit` to seal everything and quit

> open tokens.fido
touch your security key...
opened `tokens` (kv, 12 entries)

> open backup.fido
touch your security key...
opened `backup` (dir) at /run/user/1000/fidostorers-a1b2/backup

> kv get tokens github
ghp_...

> stores
  tokens   kv    clean    idle 0m
  backup   dir   dirty    idle 2m   /run/user/1000/fidostorers-a1b2/backup

> exit
sealing `backup` (2 files changed)... done
`tokens` unchanged, nothing to write
removed 1 working directory
```

## Why this is a deliberate reversal

[04-security-and-threat-model.md](04-security-and-threat-model.md) and
[02-crate-fidostorers.md](02-crate-fidostorers.md) both state that every unlocking
operation requires a live touch and that there is *no* "remember me" or cached-secret
mode. Interactive mode is exactly that mode. It is being added knowingly, and the
cost is real:

- A data key lives in process memory for as long as the store is open.
- For `file` and `dir` stores, **plaintext lives on disk** for as long as the store is
  open (see [Working directories](#working-directories)).

The guarantee that survives is the one that matters most: the vault file at rest,
with no session running, is exactly as protected as before. What weakens is the
window while a session is open — which is now minutes or hours rather than the
duration of a single command.

Everything below is shaped by trying to keep that window honest: bounded by an idle
timeout, visible in `stores`, and never larger than the user asked for.

## Session model

One process, any number of open stores. Each open store holds:

| | |
|---|---|
| `Vault` | the parsed header, as today |
| data key | `Zeroizing<[u8; 32]>`, from one `unlock_with` at open time |
| alias | short handle for commands, default = the vault file's stem |
| working directory | `file`/`dir` modes only; `None` for `kv` |
| dirty flag | whether anything needs re-sealing |
| last activity | for the idle timeout |

**Only the data key is cached, never the KEK or the `hmac-secret` output.** The data
key is sufficient for every `Vault` operation, and it is the narrowest thing that
works: it cannot be used to derive anything for another vault, and it says nothing
about the security key that produced it.

Aliases default to the file stem (`tokens.fido` -> `tokens`); a collision appends a
counter (`tokens-2`). Commands accept either the alias or the path.

## Working directories

Settled in [07-open-decisions.md](07-open-decisions.md) #15: opening a `file` or `dir`
store decrypts it to a plaintext working path, so ordinary tools (an editor, a file
manager, `grep`) work on it. Closing re-seals and removes it.

This is the single biggest security change in this document. It is not a cache or an
implementation detail: it is unencrypted user data sitting in the filesystem for the
lifetime of the session, and the plan must treat it that way.

### Where it goes

Default location, in order of preference:

1. `$XDG_RUNTIME_DIR/fidostorers-<random>/<alias>` on Linux — usually `tmpfs`, so the
   contents live in RAM, are mode `0700` already, and are cleared on logout.
2. The system temp directory otherwise, in a `0700` subdirectory.
3. `--work-dir <path>` to override.

**Never next to the vault by default.** A vault commonly sits in a synced folder, a
git repo, or a backed-up home directory; extracting plaintext beside it would push
the decrypted contents straight into cloud sync or version history. `--work-dir` must
warn if the destination looks like a git repo or a known sync folder.

On Unix the directory is created `0700`. On Windows there is no equivalent one-liner;
the plan is to create it under the user's local app data with inherited ACLs and to
**document that Windows working directories are only as private as the user profile**,
rather than claim a protection that was not implemented.

### Cleanup

On close, the tree is removed with ordinary deletion. It is worth being blunt in the
docs: **this is unlinking, not secure erasure.** On an SSD, a CoW filesystem, or any
journalling filesystem, overwriting a file does not reliably destroy the prior
contents, and pretending otherwise would be worse than saying so. Users who need
plaintext never to hit stable storage should use a `kv` store (which has no working
directory) or point `--work-dir` at a `tmpfs` mount.

### Dirty tracking

Re-sealing on exit is the write most likely to be interrupted, so the cheapest way to
make it safe is to do it less often. At open time the session records a manifest of
the extracted tree (relative path, size, mtime, and for `file` mode a hash). At close
time it re-scans; if nothing changed, **nothing is written at all** and the vault file
is not touched.

`stores` shows the dirty flag, so a user can see before exiting whether an exit will
write.

## Idle timeout

Settled in [07-open-decisions.md](07-open-decisions.md) #18: on by default, 15
minutes, `--idle-timeout 0` disables it.

An expiry does a full `close` of every open store — re-seal, remove the working
directory, drop the key. It deliberately does **not** merely drop the key while
leaving plaintext extracted, which would report "locked" while the data sat readable
on disk.

**Activity means either a REPL command or a modification inside an open working
directory.** This matters: a user editing files in another terminal for twenty
minutes is working, not idle, and a timeout that only watched the prompt would seal
the tree out from under their editor. The timeout tick re-scans working directory
mtimes before deciding anything has expired.

Even so, an expiry can arrive while an editor holds an unsaved buffer. The session
prints a warning `--idle-warning` seconds beforehand (default 60), and a user who
wants no interruption sets `--idle-timeout 0` and accepts the consequence.

## Shutdown

Graceful exit triggers on `exit`, `quit`, **Ctrl+D** (EOF), `SIGTERM`, and `SIGHUP`.
Each performs the same sequence:

1. Stop accepting new commands.
2. For each open store, in open order: re-seal if dirty, then remove the working
   directory.
3. Zeroize every data key.
4. Remove the session file (see [Orphan recovery](#orphan-recovery)).
5. Report what was written, and exit non-zero if any store failed to seal.

### Ctrl+C and Ctrl+D

Settled in [07-open-decisions.md](07-open-decisions.md) #19, following the convention
every other REPL uses:

| Gesture | At an empty prompt | While typing | During a long operation |
|---|---|---|---|
| **Ctrl+C** | clears the line, session continues | clears the line | cancels that operation, session continues |
| **Ctrl+D** | graceful shutdown | nothing (EOF only applies to an empty line) | — |

So a reflexive Ctrl+C to clear a half-typed command does what the user expects, and
ending the session is a distinct, deliberate gesture. It also leaves Ctrl+C free for
the job it is best at: interrupting a shutdown that is taking too long, below.

### Signals during a write

A signal arriving mid-seal must not abort the write. The handler only sets an atomic
flag; the main loop checks it between operations, and any seal already in progress
runs to completion.

Ctrl+C *during* shutdown prints what is still being sealed and how to force it; a
second aborts immediately. Aborting is safe for the vault — `Vault::write` writes a
temp file and renames it into place, so an interrupted seal leaves the previous vault
wholly intact ([07-open-decisions.md](07-open-decisions.md) #16) — but it discards
that store's unsaved changes, which the message must say plainly.

## Orphan recovery

A `SIGKILL`, a panic, or a power loss skips shutdown entirely and leaves a plaintext
working directory behind. Silently ignoring that would be the worst outcome: the data
is both exposed and, from the user's point of view, lost.

The session writes a session file (in the same runtime directory) listing each open
store's vault path, working directory, and the pid that owns it. On startup,
`fidostorers interactive` looks for session files whose pid is no longer alive and
offers, per orphaned store:

```
Found an unsealed working directory from a session that did not exit cleanly:
  vault:   /home/u/backup.fido
  work:    /run/user/1000/fidostorers-9f3a/backup
  changed: 3 files, last modified 2026-09-03 14:02

  [s]eal it into the vault   [d]iscard it   [l]eave it for now
```

Sealing requires a touch, since the data key died with the old process. "Leave it"
must be repeatable — the prompt returns next session rather than being dismissed.

## Concurrency

Two sessions with the same vault open would silently lose one side's changes: both
hold the same data key, both re-seal on exit, last writer wins.

`open` therefore takes an advisory lock, a `<vault>.lock` file holding pid, hostname,
and start time. A second open reports who holds it and refuses. `--force` steals the
lock after confirmation, for the case where the recorded pid is dead on another
machine — which the session cannot verify itself.

This is advisory: it does not stop the non-interactive CLI from writing the same
vault. Making the one-shot commands respect the same lock is a small addition and
should be done at the same time.

## Command surface

The REPL reuses the existing `clap` definitions wherever the command already exists,
so the interactive and one-shot spellings cannot drift.

```
open <vault> [--work-dir <path>] [--require-uv]   unlock, keep the key, return an alias
close <alias|all>                                 re-seal, remove work dir, drop key
init <vault> --mode file|dir|kv [...]             create, then open it
stores                                            aliases, modes, dirty flags, idle, work dirs
info <alias>                                      as the one-shot command
seal <alias|all>                                  re-seal now without closing
kv set|get|rm|ls <alias> ...                      as the one-shot commands
enroll <alias> [--label ...] / revoke <alias> --credential <hex>
help [command]
exit | quit
```

`lock`/`unlock` are deliberately **not** REPL commands: in a session, extraction
happens at `open` and sealing at `close`/`seal`, and reusing those verbs for something
different would be confusing. `seal` is the explicit "write my changes now" escape
hatch for a user who wants a checkpoint without closing.

### History and echo

`rustyline` provides line editing and history. **History is memory-only and never
written to disk**, because `kv set <alias> <name> --value <secret>` would otherwise
persist a secret to `~/.fidostorers_history` in cleartext. For the same reason, the
interactive `kv set` should prefer `--stdin`/`--file` and warn on `--value`.

Values printed by `kv get` go to stdout as raw bytes, as in the one-shot CLI. When
stdout is a terminal and the value is not valid UTF-8, print a short summary rather
than spraying control bytes at the terminal.

## Secret hygiene consequences

Long-lived keys make two deferred items materially more important:

- **`mlock`/`VirtualLock` memory pinning**, currently phase 2 in
  [06-roadmap.md](06-roadmap.md). A data key held for a single command is unlikely to
  be swapped out; one held for an hour is a different proposition. This should be
  promoted to ship alongside interactive mode.
- **Core dump suppression** (`prctl(PR_SET_DUMPABLE, 0)` on Linux, equivalent on
  Windows). A crash dump of a session process contains every open store's data key.

Neither is required for a first working version, but both should land before
interactive mode is recommended for real use, and the docs must not describe the
session as safe until they do.

## Testing

The session must be testable without hardware, the same way `Vault` is: the session
type takes an *already-derived* data key per store, and only the REPL's `open`
command calls `fido-token`. That keeps every test below hardware-free.

- Open/close/re-open round trips per mode, asserting the vault is byte-identical when
  nothing changed and correctly updated when something did.
- Dirty tracking: no write when the working directory is untouched; a write when a
  file's contents, mode, or symlink target changed.
- Idle timeout with an **injectable clock**, including the "activity in the working
  directory counts" rule.
- Shutdown sequencing: all stores sealed, in order, with one store's seal failing and
  the others still completing and the exit code reflecting it.
- Orphan detection against a hand-written session file with a dead pid.
- Lock contention: a second session refuses, and `--force` takes over.
- Command parsing, via the shared `clap` definitions.
- A property test that a random sequence of `open`/edit/`seal`/`close` operations
  leaves the vault decrypting to exactly the last sealed state.

Hardware-in-the-loop, manual: one touch per `open` and no more; a session left idle
past the timeout re-prompts; Ctrl+C with a dirty store seals it.
