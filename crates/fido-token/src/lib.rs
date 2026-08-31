//! FIDO2/U2F device communication.
//!
//! This crate isolates every bit of CTAP2/HID hardware interaction behind the
//! [`Authenticator`] trait, so that consumers (including this crate's own tests)
//! never have to depend on physical hardware directly. See
//! `plan/01-crate-fido-token.md` for the full design rationale.
//!
//! The real hardware backend ([`hid::HidAuthenticator`]) is scaffolded but not yet
//! implemented — that's tracked as milestone M1 in `plan/06-roadmap.md`. Until then
//! its methods return [`TokenError::NotImplemented`].

mod error;
mod hid;

#[cfg(any(test, feature = "test-util"))]
pub mod fake;

use std::time::Duration;

pub use error::TokenError;
pub use hid::HidAuthenticator;

use serde::{Deserialize, Serialize};
use zeroize::Zeroizing;

/// A discovered authenticator, not yet opened for exclusive use.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DeviceInfo {
    /// Platform-specific HID path / handle identifying this device.
    pub path: String,
    pub product: Option<String>,
    pub supports_hmac_secret: bool,
    pub supports_client_pin: bool,
}

/// An enrolled credential. Contains nothing secret: the credential ID does not
/// reveal `credRandom`, so this is safe to persist (e.g. in a vault header) and
/// serialize as plain JSON.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Credential {
    pub rp_id: String,
    pub credential_id: Vec<u8>,
    /// Last-seen product name, for UX only (e.g. "which key is this?" prompts).
    pub device_hint: Option<String>,
}

#[derive(Debug, Clone)]
pub struct RegisterOptions {
    pub rp_id: String,
    /// Shown on some authenticator displays; not sensitive.
    pub user_name: String,
    /// Require PIN/biometric verification, not just a touch.
    pub require_uv: bool,
    pub timeout: Duration,
}

#[derive(Debug, Clone)]
pub struct DeriveOptions {
    pub require_uv: bool,
    pub timeout: Duration,
}

/// The hardware seam. Real CTAP2 calls live in [`HidAuthenticator`]; tests (in this
/// crate and downstream) use [`fake::FakeAuthenticator`] instead.
pub trait Authenticator {
    fn list_devices(&self) -> Result<Vec<DeviceInfo>, TokenError>;

    /// Create a new non-resident credential with the hmac-secret extension
    /// requested. Blocks until the user touches (and if required, verifies on) a
    /// key, or `opts.timeout` elapses.
    fn register(&self, opts: &RegisterOptions) -> Result<Credential, TokenError>;

    /// Ask whichever authenticator holds `credential` to compute
    /// `HMAC-SHA256(credRandom, salt)` and return the 32-byte result. Deterministic:
    /// the output only changes if `credential` or `salt` changes.
    fn derive_secret(
        &self,
        credential: &Credential,
        salt: &[u8; 32],
        opts: &DeriveOptions,
    ) -> Result<Zeroizing<[u8; 32]>, TokenError>;
}

/// Enumerate connected authenticators using the default (real hardware) backend.
pub fn list_devices() -> Result<Vec<DeviceInfo>, TokenError> {
    HidAuthenticator::default().list_devices()
}

/// Register a new credential using the default (real hardware) backend.
pub fn register(opts: &RegisterOptions) -> Result<Credential, TokenError> {
    HidAuthenticator::default().register(opts)
}

/// Derive the hmac-secret output for a credential + salt using the default (real
/// hardware) backend.
pub fn derive_secret(
    credential: &Credential,
    salt: &[u8; 32],
    opts: &DeriveOptions,
) -> Result<Zeroizing<[u8; 32]>, TokenError> {
    HidAuthenticator::default().derive_secret(credential, salt, opts)
}
