# M1 manual testing guide

Milestone M1 ([plan/06-roadmap.md](../plan/06-roadmap.md)) exists to answer one
question with real hardware, before anything is built on top of it:

> Does a physical security key produce a **stable, salt-bound 32-byte secret** via
> the CTAP2 `hmac-secret` extension, on **both Linux and Windows**?

Everything in [plan/03-vault-format-and-crypto.md](../plan/03-vault-format-and-crypto.md)
assumes yes. This document is how you check. **Windows: answered yes, but only from an
elevated terminal. Linux: not yet run.** See [Results so far](#results-so-far).

Unit tests cannot answer it — that is structural, not laziness. The whole point of
the `Authenticator` trait seam is that everything *except* this question is testable
without hardware, so the part that needs a human with a key in hand is as small as
possible.

---

## Read this first: a finding that changes the plan

The plan says the `authenticator` crate reaches FIDO devices on Windows through the
OS WebAuthn API (`webauthn.dll`). **It does not.** Version 0.5.0 has no `webauthn.dll`
code path at all; its Windows backend is raw USB HID via SetupAPI and `hid.dll`, the
same approach it uses on Linux.

This matters because Windows 10 1903+ ships a filter driver that denies **read/write**
opens of FIDO HID devices to non-elevated processes. So the open question M1 had to
settle was no longer only "does hmac-secret work" but also:

> **Does `register`/`derive` work in a normal, non-elevated terminal, or does it
> require Administrator?**

Test 3 below was written specifically to answer that, and it now has: **it requires
Administrator.** That outcome is recorded below and has been accepted as a known
limitation for now, rather than blocking on the `webauthn.dll` backend
(plan/07-open-decisions.md #1's fallback) — which is a substantial piece of work, now
tabled as phase-2 (plan/06-roadmap.md).

Note that *enumeration* (`fido-token list`) is unaffected: it opens devices with zero
desired access, which only permits metadata queries and is not blocked by that filter.
That is why `list` may work fine while `derive` fails.

A second, smaller finding: `authenticator` 0.5.0 **does not compile for Windows** as
published — it passes a `std::os::windows::io::RawHandle` where `winapi` expects its
own `c_void`, which are distinct types unless `winapi`'s `std` feature is on, and the
crate does not enable it. The workspace `Cargo.toml` declares `winapi` with that
feature to fix it graph-wide via feature unification. If a future `authenticator`
release enables it upstream, that declaration can be deleted.

---

## Results so far

| Platform | Outcome |
|---|---|
| **Windows** | **Tests 1, 2, 4, 5, 6, 7 pass. Test 3 fails.** `hmac-secret` behaves exactly as [plan/03](../plan/03-vault-format-and-crypto.md) requires: deterministic, salt-bound, stable across a replug, wrong key correctly rejected, PIN prompt and `--no-pin` refusal both correct. **But all device interaction requires an elevated terminal** — only `list` (test 1) works unprivileged. |
| **Linux** | **Not yet run.** This is the one outstanding M1 item. |

Test 3's result is the `FAIL` (non-elevated) / `PASS` (elevated) row of its table: the
Windows 10 1903 filter driver does bite, exactly as the finding above predicted.

**This has been accepted as a known limitation for now** rather than treated as
stop-the-line. The transport stays as chosen
([plan/07-open-decisions.md](../plan/07-open-decisions.md) #1) and the direct
`webauthn.dll` backend that would remove the requirement is **tabled as phase-2 work**
([plan/06-roadmap.md](../plan/06-roadmap.md)). It should be revisited before any
release aimed at non-developers. Until it exists, **run `fido-token` and `fidostorers`
from an elevated terminal on Windows** — including for the manual hardware checks in
M2 and later.

So when re-running anything below on Windows, start the shell with **Run as
Administrator**. The exceptions are test 1, which is expected to work either way, and
test 3, whose entire point is to observe what unprivileged access does.

---

## Prerequisites

A CTAP2 authenticator that implements `hmac-secret` — a YubiKey 5 series, SoloKey,
Nitrokey 3, or Token2 will do. A U2F-only key will *not*: that is a known limitation,
not a bug (see [plan/00-overview.md](../plan/00-overview.md)).

Two keys are better than one: it lets you check that a credential from key A is
correctly rejected by key B (test 5).

### Windows

Nothing to install beyond a Rust toolchain (MSVC or GNU). Build with:

```powershell
cargo build -p fido-token
```

### Linux

The `authenticator` crate links libudev, so its headers must be present:

```bash
sudo apt-get install -y pkg-config libudev-dev     # Debian/Ubuntu
sudo dnf install -y pkgconf-pkg-config systemd-devel  # Fedora
```

`/dev/hidraw*` is root-only by default. Rather than running as root, install a udev
rule granting your user access to FIDO devices:

```bash
sudo tee /etc/udev/rules.d/70-fido.rules >/dev/null <<'RULE'
KERNEL=="hidraw*", SUBSYSTEM=="hidraw", ATTRS{idVendor}=="1050", TAG+="uaccess"
RULE
sudo udevadm control --reload-rules && sudo udevadm trigger
```

`1050` is Yubico; use your key's vendor ID from `fido-token list`. Replug the key
after reloading the rules.

> **No hardware, or a machine that cannot install libudev?** Everything except the
> real backend still builds and tests:
> ```bash
> cargo test --workspace --no-default-features --features fido-token/test-util
> ```

---

## Logging

Debug builds default to `debug`-level logging, so `cargo run` already prints a useful
trace with no flags. Release builds stay at `warn`.

| What you want | How |
|---|---|
| Default debug-build trace | `cargo run -p fido-token -- list` |
| More detail | `-v` (debug) or `-vv` (trace, includes the full CTAP2 exchange) |
| Silence | `-q` |
| Fine-grained control | `RUST_LOG=fido_token=debug,authenticator=trace` (always wins over `-v`) |

`-vv` turns on the `authenticator` crate's own logging, which prints the CTAP2
commands and responses as they go over the wire. That is the level to use when
something fails and you need to know *where*.

**Secrets are never logged.** Derived secrets appear only as a `fingerprint` — a
truncated hash — which is enough to confirm two derivations agree without putting key
material in a log file. Salts *are* logged in full, deliberately: they are not secret
(see plan/03) and knowing which salt produced which output is the single most useful
fact when debugging a mismatch. PINs are never logged, echoed, or persisted.

To capture a session for a bug report:

```powershell
cargo run -p fido-token -- -vv selftest 2> selftest.log
```

```bash
cargo run -p fido-token -- -vv selftest 2> selftest.log
```

Stdout carries results, stderr carries logs, so this keeps them separate.

---

## Test 1 — enumeration (no touch required)

```
cargo run -p fido-token -- list
```

**Expect** one line per connected FIDO key, with a path, manufacturer, product, and
`vid:pid`.

`hmac-secret=unprobed` and `clientPIN=unprobed` are **correct output, not a failure**.
Enumeration is deliberately passive: answering those needs a CTAP2 `getInfo`, which
needs the device opened for I/O — exactly what a non-elevated Windows process cannot
do. The authoritative answer comes from test 2.

- **Nothing listed on Linux** → udev rules, or the key is in a hub that hides it.
  Enumeration reads sysfs, so this usually means the key genuinely is not enumerated;
  check `ls /sys/class/hidraw`.
- **Nothing listed on Windows** → run with `-vv`; a "could not be queried" warning
  names how many interfaces failed to open.

## Test 2 — the acceptance test

This is the M1 gate, packaged as one command. It needs **four touches**.

```
cargo run -p fido-token -- selftest
```

It registers a credential, derives twice with salt A, derives once with salt B, and
checks the two properties the whole project depends on:

```
determinism  (salt A twice -> same secret):      PASS
salt binding (salt A vs B  -> different secret): PASS

PASS — hmac-secret works as required on this platform.
```

**A `FAIL` here, or a `HmacSecretUnsupported` error, is a stop-the-line result** —
it invalidates the design in plan/03 for that platform. Capture `-vv` output.

Run it on **both** Linux and Windows. Save the credential JSON it prints at the end.

## Test 3 — Windows elevation (answered: elevation is required)

**Result: `FAIL` non-elevated, `PASS` elevated** — the second row below. Kept here as
the procedure to re-run after a Windows update, a driver change, or once a
`webauthn.dll` backend exists.

Run test 2 twice on Windows:

1. In a **normal** PowerShell window.
2. In one started with **Run as Administrator**.

Record which succeed. Four outcomes, and what each means:

| Non-elevated | Elevated | Meaning |
|---|---|---|
| PASS | PASS | Best case. The plan's `webauthn.dll` concern was unfounded for this path; correct plan/00 and plan/01 and move on to M2. |
| FAIL | PASS | **← this is what happened.** The 1903 restriction bites; `fidostorers` requires Administrator on Windows. Unacceptable for a shipped user tool long-term → build the `webauthn.dll` backend (plan/07 #1 fallback), **deferred to phase 2** and acceptable in the meantime. |
| FAIL | FAIL | Something else is wrong; treat as a bug, not an elevation issue. Capture `-vv`. |
| PASS | FAIL | Unexpected; capture `-vv`. |

A denial shows up as `error: cannot access authenticator (on Windows this usually
means the process is not elevated)` — exit code 9. That error variant exists to make
this specific outcome unmistakable, and it is the message a non-elevated Windows run
actually produces.

## Test 4 — persistence across a replug

The secret must survive the key leaving and re-entering the machine, or it is useless
for encrypting anything.

```
cargo run -p fido-token -- selftest > first.txt
```

Save the credential JSON from the last line of that output as `cred.json`. It looks
like this — `credential_id` is lowercase hex (it was a byte array before M7; old files
saved in that form still load):

```json
{
  "rp_id": "fidostorers.local",
  "credential_id": "a1b2c3d46016084f...",
  "device_hint": "YubiKey 5 NFC"
}
```

Then
**unplug the key, plug it back in** (a full reboot is a stronger version of this
test), and:

```
cargo run -p fido-token -- selftest --credential cred.json
```

**Expect** the same fingerprints as the first run. Different fingerprints for the same
credential and salt would mean the secret is not stable, which breaks everything.

## Test 5 — wrong key is rejected

With a *second*, different key plugged in (and the first unplugged):

```
cargo run -p fido-token -- derive --credential cred.json --salt 1111111111111111111111111111111111111111111111111111111111111111
```

**Expect** failure with `credential not recognized by any connected authenticator`,
exit code 6 — **not** a different secret, and not a hang.

## Test 6 — PIN handling

On a key with a PIN set:

```
cargo run -p fido-token -- selftest --require-uv
```

**Expect** a no-echo PIN prompt, then success. Then check the refusal path:

```
cargo run -p fido-token -- selftest --require-uv --no-pin
```

**Expect** a clean `PIN required` error (exit code 8), not a hang.

Note: because the Windows backend is raw HID rather than `webauthn.dll`, **this
prompt is ours on Windows too** — Windows does not render its own PIN dialog here.
That contradicts plan/07 #9, which assumed the callback would never fire on Windows.
Confirm which you actually see.

## Test 7 — timeout and decline

```
cargo run -p fido-token -- register --timeout 5
```

Do not touch the key. **Expect** it to give up after ~5s with a timeout (exit code 4),
not to hang forever.

---

## Exit codes

Useful for scripting the above, and for crate 2 to map errors without re-deriving the
logic.

| Code | Meaning |
|---|---|
| 0 | success |
| 2 | usage error (bad arguments, unreadable file) |
| 3 | no device found |
| 4 | timed out waiting for user presence |
| 5 | user declined |
| 6 | credential not recognized by the connected key |
| 7 | authenticator does not support `hmac-secret` |
| 8 | PIN required, or the key is locked out |
| 9 | device present but could not be opened (Windows elevation) |
| 10 | transport/backend error |
| 11 | self-test ran but the key failed a required property |

---

## Reporting results

For each platform, record: OS version, key model, which tests passed, and for any
failure the `-vv` log. Add the outcome to [Results so far](#results-so-far).

Test 3's outcome was the one that determined whether plan/07 decision #1 stayed
settled; it is now recorded, and #1 stands with a documented Windows limitation. What
still closes M1 is a **Linux** run of tests 1, 2, 4, 5, 6 and 7.
