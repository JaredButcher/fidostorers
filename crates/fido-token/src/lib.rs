//! FIDO2/U2F device communication.
//!
//! This crate isolates every bit of CTAP2/HID hardware interaction behind the
//! [`Authenticator`] trait, so that consumers (including this crate's own tests)
//! never have to depend on physical hardware directly. See
//! `plan/01-crate-fido-token.md` for the full design rationale.
//!
//! # Backends
//!
//! - [`HidAuthenticator`] is the real one, built on Mozilla's `authenticator`
//!   crate. It is compiled only when the `hardware` feature is on (the default).
//! - [`fake::FakeAuthenticator`] is a pure-software stand-in for tests, behind the
//!   `test-util` feature.
//!
//! # Logging
//!
//! Every hardware operation logs its progress through the [`log`] facade, as does
//! the `authenticator` crate underneath, so `RUST_LOG=trace` yields a full trace of
//! the CTAP2 exchange. Key material is never logged: derived secrets appear only as
//! a non-invertible [`fingerprint`], which is enough to check that two derivations
//! agree without putting the secret itself in a log file.

mod error;
mod hid;

pub mod enumerate;

#[cfg(any(test, feature = "test-util"))]
pub mod fake;

use std::fmt;
use std::sync::Arc;
use std::time::Duration;

pub use error::TokenError;
pub use hid::HidAuthenticator;

use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use zeroize::Zeroizing;

/// The `rp.id` used when the caller does not pick one. Not a real domain: this is
/// offline, local-only use with no relying-party server. See
/// plan/07-open-decisions.md #6.
pub const DEFAULT_RP_ID: &str = "fidostorers.local";

/// A discovered authenticator, not yet opened for exclusive use.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DeviceInfo {
    /// Platform-specific HID path / handle identifying this device.
    pub path: String,
    pub product: Option<String>,
    pub manufacturer: Option<String>,
    pub vendor_id: Option<u16>,
    pub product_id: Option<u16>,
    /// `None` means "not determined". Answering this needs a CTAP2 `getInfo`, which
    /// needs the device opened for I/O — which a non-elevated Windows process cannot
    /// do. Enumeration deliberately stays passive (no touch, no exclusive open), so
    /// on some platforms capabilities are simply unknown until an operation is
    /// actually attempted. See docs/M1-MANUAL-TESTING.md.
    pub supports_hmac_secret: Option<bool>,
    pub supports_client_pin: Option<bool>,
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

/// Why the authenticator is asking for a PIN.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PinPrompt {
    /// First request: the authenticator has a PIN set and needs it to proceed.
    Required,
    /// A previous attempt was rejected. `attempts_left` is what the device
    /// reported, when it reported anything.
    Invalid { attempts_left: Option<u8> },
}

/// Supplies a PIN on demand. Returning `None` means "the user cancelled", which
/// surfaces as [`TokenError::NotAllowed`].
///
/// The PIN is never logged, never persisted, and is dropped as soon as it has been
/// handed to the authenticator.
pub type PinProvider = Arc<dyn Fn(PinPrompt) -> Option<Zeroizing<String>> + Send + Sync>;

#[derive(Clone)]
pub struct RegisterOptions {
    pub rp_id: String,
    /// Shown on some authenticator displays; not sensitive.
    pub user_name: String,
    /// Require PIN/biometric verification, not just a touch.
    pub require_uv: bool,
    pub timeout: Duration,
    /// How to obtain a PIN if the authenticator asks for one. `None` means "don't
    /// ask" — a PIN-protected device will then fail with
    /// [`TokenError::PinRequired`] rather than blocking on input.
    pub pin_provider: Option<PinProvider>,
}

#[derive(Clone)]
pub struct DeriveOptions {
    pub require_uv: bool,
    pub timeout: Duration,
    /// See [`RegisterOptions::pin_provider`].
    pub pin_provider: Option<PinProvider>,
}

impl Default for RegisterOptions {
    fn default() -> Self {
        Self {
            rp_id: DEFAULT_RP_ID.to_string(),
            user_name: "fidostorers".to_string(),
            require_uv: false,
            timeout: Duration::from_secs(30),
            pin_provider: None,
        }
    }
}

impl Default for DeriveOptions {
    fn default() -> Self {
        Self {
            require_uv: false,
            timeout: Duration::from_secs(30),
            pin_provider: None,
        }
    }
}

// Hand-written so a `PinProvider` (a boxed closure, which cannot derive `Debug`)
// doesn't stop these from being logged.
impl fmt::Debug for RegisterOptions {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("RegisterOptions")
            .field("rp_id", &self.rp_id)
            .field("user_name", &self.user_name)
            .field("require_uv", &self.require_uv)
            .field("timeout", &self.timeout)
            .field("pin_provider", &self.pin_provider.is_some())
            .finish()
    }
}

impl fmt::Debug for DeriveOptions {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("DeriveOptions")
            .field("require_uv", &self.require_uv)
            .field("timeout", &self.timeout)
            .field("pin_provider", &self.pin_provider.is_some())
            .finish()
    }
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

/// A [`PinProvider`] that prompts on the terminal with echo disabled.
///
/// Returns `None` when stdin is not a terminal: prompting a non-interactive caller
/// would block until the operation times out, which is a worse failure than a clear
/// [`TokenError::PinRequired`]. Callers that want to refuse PIN entry outright
/// should just pass `None` rather than calling this.
///
/// The prompt is written to the TTY rather than stdout, so a value being printed to
/// stdout stays pipeable.
pub fn terminal_pin_provider() -> Option<PinProvider> {
    use std::io::IsTerminal;

    if !std::io::stdin().is_terminal() {
        log::warn!("stdin is not a terminal; PIN prompting is disabled");
        return None;
    }

    Some(Arc::new(|prompt: PinPrompt| {
        let message = match prompt {
            PinPrompt::Required => "Enter the security key's PIN: ".to_string(),
            PinPrompt::Invalid {
                attempts_left: Some(left),
            } => format!("Wrong PIN, {left} attempt(s) left. Try again: "),
            PinPrompt::Invalid {
                attempts_left: None,
            } => "Wrong PIN. Try again: ".to_string(),
        };
        match rpassword::prompt_password(&message) {
            Ok(pin) => Some(Zeroizing::new(pin)),
            Err(err) => {
                log::error!("could not read PIN: {err}");
                None
            }
        }
    }))
}

/// A short, non-invertible tag for a secret, so logs and CLI output can show that
/// two derivations produced the same 32 bytes without showing the bytes.
///
/// This is `SHA-256("fido-token-fingerprint-v1" || secret)` truncated to 8 bytes.
/// Truncated-hash-of-a-256-bit-secret is not a practical route back to the secret,
/// but it *is* a value that confirms a guess, so it stays out of anything but
/// debug-level output.
pub fn fingerprint(secret: &[u8]) -> String {
    let mut hasher = Sha256::new();
    hasher.update(b"fido-token-fingerprint-v1");
    hasher.update(secret);
    hasher
        .finalize()
        .iter()
        .take(8)
        .map(|b| format!("{b:02x}"))
        .collect()
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn fingerprint_is_stable_and_distinguishing() {
        let a = fingerprint(&[0u8; 32]);
        assert_eq!(a, fingerprint(&[0u8; 32]));
        assert_ne!(a, fingerprint(&[1u8; 32]));
        assert_eq!(a.len(), 16, "8 bytes rendered as hex");
    }

    #[test]
    fn fingerprint_does_not_contain_the_secret() {
        // Guards against the tag ever being reduced to a prefix of the input.
        let secret = [0xABu8; 32];
        let tag = fingerprint(&secret);
        assert!(!tag.starts_with("abab"));
    }
}
