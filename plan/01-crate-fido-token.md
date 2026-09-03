# Crate 1: `fido-token` — FIDO device communication

Purpose: everything that talks to a physical FIDO2/U2F authenticator lives here, and
nowhere else. Crate 2 never touches CTAP/HID directly.

## Public library API (sketch)

```rust
/// One discovered authenticator, not yet opened for exclusive use.
pub struct DeviceInfo {
    pub path: String,           // platform HID path / handle id
    pub product: Option<String>,
    pub manufacturer: Option<String>,
    pub vendor_id: Option<u16>,
    pub product_id: Option<u16>,
    // `None` = not determined. Answering these needs a CTAP2 getInfo, which needs
    // the device opened for I/O — which a non-elevated Windows process cannot do.
    // Enumeration stays passive, so these are unprobed there. (M1 change.)
    pub supports_hmac_secret: Option<bool>,
    pub supports_client_pin: Option<bool>,
}

pub fn list_devices() -> Result<Vec<DeviceInfo>, TokenError>;

/// An enrolled credential, persisted by the caller (crate 2 stores this in the vault
/// header). Contains nothing secret — the credential ID does not reveal credRandom.
#[derive(Serialize, Deserialize, Clone)]
pub struct Credential {
    pub rp_id: String,          // e.g. "fidostorers.local"
    pub credential_id: Vec<u8>,
    pub device_hint: Option<String>, // last-seen product name, for UX only
}

pub struct RegisterOptions {
    pub rp_id: String,
    pub user_name: String,      // shown on some authenticator displays; not sensitive
    pub require_uv: bool,       // require PIN/biometric, not just touch
    pub timeout: Duration,
    pub pin_provider: Option<PinProvider>,  // None = never prompt (07 #9)
}

/// Create a new non-resident credential with the hmac-secret extension requested.
/// Blocks until the user touches (and if required, verifies on) a key, or times out.
pub fn register(opts: &RegisterOptions) -> Result<Credential, TokenError>;

pub struct DeriveOptions {
    pub require_uv: bool,
    pub timeout: Duration,
    pub pin_provider: Option<PinProvider>,
}

/// Supplies a PIN on demand; returning None means the user cancelled.
pub type PinProvider = Arc<dyn Fn(PinPrompt) -> Option<Zeroizing<String>> + Send + Sync>;

/// Ask whichever authenticator holds `credential` to compute
/// HMAC-SHA256(credRandom, salt) and return the 32-byte result.
/// `salt` is caller-provided (crate 2 derives it from the vault); output changes iff
/// salt or credential changes.
pub fn derive_secret(
    credential: &Credential,
    salt: &[u8; 32],
    opts: &DeriveOptions,
) -> Result<Zeroizing<[u8; 32]>, TokenError>;
```

### Why non-resident credentials

fidocrypt-style usage doesn't need the authenticator to remember/list the credential
(discoverable/resident credentials use up limited on-device storage slots on many
keys). We store the `credential_id` ourselves (in the vault header, see crate 2) and
pass it in the CTAP2 `allowList` on every assertion. This also means multiple vaults
can each have their own credential on the same physical key without exhausting its
resident-credential slots.

### `Authenticator` trait — the hardware seam

To keep crate 2 (and crate 1's own tests) free of physical-device dependencies, the
real CTAP2 calls sit behind a trait:

```rust
pub trait Authenticator {
    fn register(&self, opts: &RegisterOptions) -> Result<Credential, TokenError>;
    fn derive_secret(
        &self,
        credential: &Credential,
        salt: &[u8; 32],
        opts: &DeriveOptions,
    ) -> Result<Zeroizing<[u8; 32]>, TokenError>;
}

pub struct HidAuthenticator { /* wraps the `authenticator` crate's manager */ }
impl Authenticator for HidAuthenticator { ... }
```

`HidAuthenticator`'s CTAP2 methods are compiled behind the default-on `hardware`
feature, which gates the `authenticator` dependency. With the feature off they
return `TokenError::BackendUnavailable` and everything else — the fake, the vault,
the CLI parsing — still builds and tests. That keeps the hardware-free suite runnable
on a machine that cannot satisfy the platform build dependencies (Linux needs
pkg-config and libudev headers), which is what
[05-testing-strategy.md](05-testing-strategy.md) promises. Enumeration is *not* gated:
it is this crate's own code, not the dependency's.

`register`/`derive_secret` free functions are thin wrappers that construct a default
`HidAuthenticator`. Tests (in this crate and crate 2) use an in-memory fake
implementing the same trait — see [05-testing-strategy.md](05-testing-strategy.md).

## CTAP2 flow details

**Registration (`makeCredential`)**
- `rp.id` = a fixed local string (e.g. `"fidostorers.local"`), not a real domain —
  this is offline/local use, there is no relying party server.
- `user.id` = random bytes generated per credential (CTAP2 requires *some* user id).
- `pubKeyCredParams`: ES256 (algorithm -7) is sufficient; we never use the credential's
  actual public key/signature, only its `hmac-secret` capability.
- extensions: `{"hmac-secret": true}`.
- `residentKey`: discouraged/false (non-resident, see above).
- `userVerification`: `"preferred"` by default, `"required"` if `require_uv`.

**Derivation (`getAssertion`)**
- `allowList`: `[{"id": credential_id, "type": "public-key"}]`.
- extensions: `hmac-secret` with a fresh ephemeral ECDH key pair, `saltEnc` (the
  32-byte salt encrypted under the ECDH-derived shared key), `saltAuth` (HMAC over
  `saltEnc`). This full key-agreement dance is handled internally by the
  `authenticator` crate — we just supply the salt.
- Response's decrypted `hmac-secret` output is the 32-byte derived value.

**PIN handling**: if the authenticator has a PIN set and `require_uv` (or the
authenticator mandates UV for `hmac-secret`, which some do), prompt on stdin for the
CLI, or accept a callback in the library API (`PinProvider`). Never log or persist a
PIN. Because the Windows backend is raw HID rather than `webauthn.dll`, the callback
fires on Windows too — the OS renders no PIN dialog of its own here, which reverses
the asymmetry assumed in [07-open-decisions.md](07-open-decisions.md) #9. Confirmed
against hardware (M1 test 6).

## CLI (`fido-token`)

Standalone binary, useful on its own for debugging/inspecting keys, and dogfoods the
library API.

```
fido-token list
    Enumerate connected authenticators. Passive: no touch, no device open for I/O,
    so hmac-secret/clientPIN report as "unprobed" rather than being queried.

fido-token register [--rp-id <id>] [--name <label>] [--require-uv] [--timeout 30] [--no-pin]
    Creates a credential, prints it as JSON to stdout (for the caller to store).

fido-token derive --credential <path-to-json> --salt <hex> [--require-uv] [--timeout 30] [--no-pin]
    Prompts for touch, prints the 32-byte secret as hex to stdout.
    (Primarily a debugging/scripting tool; crate 2 calls the library directly.)

fido-token selftest [--credential <path>] [--require-uv] [--timeout 30] [--no-pin]
    The M1 acceptance check as one command: register, derive twice with one salt,
    derive once with another, and assert determinism and salt binding.
    `--credential` reuses a saved credential, to re-test after a replug or reboot.

Global: -v/-vv raise log verbosity (-vv includes the full CTAP2 exchange),
        -q silences all but errors, RUST_LOG overrides both.
```

Exit codes distinguish "no device found" (3), "timed out" (4), "user declined" (5),
"wrong key touched" (6), "no hmac-secret support" (7), "PIN required or locked
out" (8), "device present but unopenable — the Windows elevation case" (9), and
generic transport errors (10), so crate 2's CLI can give good error messages without
re-deriving that logic. The full table is in
[../docs/M1-MANUAL-TESTING.md](../docs/M1-MANUAL-TESTING.md).

## Error type (sketch)

```rust
#[derive(thiserror::Error, Debug)]
pub enum TokenError {
    #[error("no FIDO authenticator found")]
    NoDevice,
    #[error("authenticator does not support the hmac-secret extension")]
    HmacSecretUnsupported,
    #[error("operation timed out waiting for user presence")]
    Timeout,
    #[error("user declined or wrong PIN")]
    NotAllowed,
    #[error("credential not recognized by any connected authenticator")]
    UnknownCredential,
    #[error("transport error: {0}")]
    Transport(String),
}
```

## Platform notes

- **Linux**: raw USB HID via the `authenticator` crate's hidapi backend; typically
  needs udev rules for non-root access (documented in crate 2's user-facing docs, not
  a code concern).
- **Windows**: **raw USB HID via SetupAPI + `hid.dll`** — *not* `webauthn.dll`. The
  original plan assumed the `authenticator` crate had an OS-WebAuthn-API backend; M1
  established that it does not (version 0.5.0 contains no `webauthn.dll` code path).
  Since Windows 10 1903 a filter driver denies read/write opens of FIDO HID devices to
  non-elevated processes, and M1 hardware testing confirmed that this bites:
  **`register` and `derive_secret` require an elevated process on Windows.** Accepted
  as a known limitation for now; the direct `webauthn.dll` backend that would lift it
  is tabled as phase-2 work — see [06-roadmap.md](06-roadmap.md) M1 and phase 2,
  [07-open-decisions.md](07-open-decisions.md) #1, and
  [../docs/M1-MANUAL-TESTING.md](../docs/M1-MANUAL-TESTING.md) test 3.
  Device *enumeration* is unaffected: this crate implements it itself, opening devices
  with zero desired access (metadata queries only), which that filter permits — `list`
  is the one command that works unprivileged there.
- macOS is a bonus, not a target; if the dependency's macOS backend works, we don't
  block it, but we don't test or support it in v1.
