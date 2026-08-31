# Crate 1: `fido-token` — FIDO device communication

Purpose: everything that talks to a physical FIDO2/U2F authenticator lives here, and
nowhere else. Crate 2 never touches CTAP/HID directly.

## Public library API (sketch)

```rust
/// One discovered authenticator, not yet opened for exclusive use.
pub struct DeviceInfo {
    pub path: String,           // platform HID path / handle id
    pub product: Option<String>,
    pub supports_hmac_secret: bool,
    pub supports_client_pin: bool,
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
}

/// Create a new non-resident credential with the hmac-secret extension requested.
/// Blocks until the user touches (and if required, verifies on) a key, or times out.
pub fn register(opts: &RegisterOptions) -> Result<Credential, TokenError>;

pub struct DeriveOptions {
    pub require_uv: bool,
    pub timeout: Duration,
}

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
CLI, or accept a callback/prefetched PIN in the library API. Never log or persist a PIN.

## CLI (`fido-token`)

Standalone binary, useful on its own for debugging/inspecting keys, and dogfoods the
library API.

```
fido-token list
    Enumerate connected authenticators and their capabilities.

fido-token register --rp-id <id> --name <label> [--require-uv] [--timeout 30s]
    Creates a credential, prints it as JSON to stdout (for the caller to store).

fido-token derive --credential <path-to-json-or-inline> --salt <hex-or-file> [--require-uv]
    Prompts for touch, prints the 32-byte secret as hex to stdout.
    (Primarily a debugging/scripting tool; crate 2 calls the library directly.)
```

Exit codes distinguish "no device found", "user declined/timed out", "wrong key
touched" (credential not recognized by the device that responded), and generic I/O
errors, so crate 2's CLI can give good error messages without re-deriving that logic.

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
- **Windows**: goes through `webauthn.dll` (Windows Hello / Windows WebAuthn API) via
  the `authenticator` crate's Windows backend, required for non-elevated processes
  since Windows 10 1903. This is a different code path inside the dependency, not
  something we implement ourselves, but it does mean **Windows behavior should be
  validated against real hardware early** — see [06-roadmap.md](06-roadmap.md) M1.
- macOS is a bonus, not a target; if the dependency's macOS backend works, we don't
  block it, but we don't test or support it in v1.
