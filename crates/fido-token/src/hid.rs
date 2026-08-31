//! Real hardware backend.
//!
//! Wiring this up to actual CTAP2/HID transport (via the `authenticator` crate —
//! see plan/01-crate-fido-token.md and plan/07-open-decisions.md #1) is milestone M1
//! in plan/06-roadmap.md. Until then every method returns
//! [`TokenError::NotImplemented`] so the rest of the workspace can be built and
//! tested against the [`Authenticator`](crate::Authenticator) trait today.

use crate::{Authenticator, Credential, DeriveOptions, DeviceInfo, RegisterOptions, TokenError};
use zeroize::Zeroizing;

/// Talks to physical FIDO2/U2F authenticators over USB HID (Linux) or the Windows
/// WebAuthn API (Windows). See plan/01-crate-fido-token.md "Platform notes".
#[derive(Debug, Default)]
pub struct HidAuthenticator {
    _private: (),
}

impl Authenticator for HidAuthenticator {
    fn list_devices(&self) -> Result<Vec<DeviceInfo>, TokenError> {
        Err(TokenError::NotImplemented(
            "hardware device enumeration lands in M1, see plan/06-roadmap.md",
        ))
    }

    fn register(&self, _opts: &RegisterOptions) -> Result<Credential, TokenError> {
        Err(TokenError::NotImplemented(
            "hardware registration lands in M1, see plan/06-roadmap.md",
        ))
    }

    fn derive_secret(
        &self,
        _credential: &Credential,
        _salt: &[u8; 32],
        _opts: &DeriveOptions,
    ) -> Result<Zeroizing<[u8; 32]>, TokenError> {
        Err(TokenError::NotImplemented(
            "hardware secret derivation lands in M1, see plan/06-roadmap.md",
        ))
    }
}
