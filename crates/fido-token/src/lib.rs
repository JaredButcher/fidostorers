//! FIDO2/U2F device communication.
//!
//! Given a credential and a 32-byte salt, a CTAP2 authenticator supporting the
//! `hmac-secret` extension returns `HMAC-SHA256(credRandom, salt)`: 32 bytes that
//! are deterministic, gated behind a physical touch, and derived from a secret that
//! never leaves the device. This crate is the thin layer that asks for them.
//!
//! It is useful on its own — nothing here knows about vaults — and is published as
//! a separate crate for that reason.
//!
//! # The hardware seam
//!
//! Every CTAP2/HID interaction sits behind the [`Authenticator`] trait, so
//! consumers (including this crate's own tests) never depend on a physical device.
//!
//! ```no_run
//! use std::time::Duration;
//!
//! # fn main() -> Result<(), fido_token::TokenError> {
//! // Create a credential. Blocks until someone touches the key.
//! let credential = fido_token::register(&fido_token::RegisterOptions {
//!     rp_id: "example.local".to_string(),
//!     user_name: "example".to_string(),
//!     require_uv: false,
//!     timeout: Duration::from_secs(30),
//!     pin_provider: fido_token::terminal_pin_provider(),
//! })?;
//!
//! // Ask that credential for 32 bytes. Same credential and salt, same bytes,
//! // every time -- which is the property everything else relies on.
//! let salt = [0u8; 32];
//! let secret = fido_token::derive_secret(
//!     &credential,
//!     &salt,
//!     &fido_token::DeriveOptions {
//!         require_uv: false,
//!         timeout: Duration::from_secs(30),
//!         pin_provider: fido_token::terminal_pin_provider(),
//!     },
//! )?;
//! assert_eq!(secret.len(), 32);
//! # Ok(())
//! # }
//! ```
//!
//! Credentials are **non-resident**: the caller stores the [`Credential`] and passes
//! it back on every assertion, so many vaults can share one physical key without
//! exhausting its limited on-device credential slots. A `Credential` contains
//! nothing secret.
//!
//! # Backends
//!
//! - [`HidAuthenticator`] is the real one, built on Mozilla's `authenticator`
//!   crate. It is compiled only when the `hardware` feature is on (the default),
//!   which is what lets dependent crates build and test on a machine that cannot
//!   satisfy the platform HID build dependencies. With it off, every device call
//!   returns [`TokenError::BackendUnavailable`].
//! - `fake::FakeAuthenticator` is a pure-software stand-in for tests, behind the
//!   `test-util` feature. It reproduces the real `hmac-secret` construction locally,
//!   and can be told to fail in specific ways to exercise error paths.
//!
//! [`enumerate::list_devices`] is *not* gated: it is this crate's own code and is
//! deliberately passive — no touch, no device opened for I/O — so it works where
//! device interaction does not, which on Windows means unprivileged.
//!
//! # Platform notes
//!
//! Both platforms use raw USB HID; there is no `webauthn.dll` path. Since Windows 10
//! 1903 a filter driver denies non-elevated processes read/write access to FIDO HID
//! devices, so **on Windows everything except `list_devices` needs an elevated
//! process**. On Linux, `/dev/hidraw*` is root-only by default and normally wants a
//! udev rule. See `docs/fido-token.md`.
//!
//! # Logging
//!
//! Every hardware operation logs its progress through the [`log`] facade, as does
//! the `authenticator` crate underneath, so `RUST_LOG=trace` yields a full trace of
//! the CTAP2 exchange. Key material is never logged: derived secrets appear only as
//! a non-invertible [`fingerprint`], which is enough to check that two derivations
//! agree without putting the secret itself in a log file.
//!
//! # Design notes
//!
//! `plan/01-crate-fido-token.md`.

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
/// crate and downstream) use `fake::FakeAuthenticator` instead.
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

/// Render bytes as lowercase hex, no separators and no prefix.
///
/// Lives here, beside [`Credential`], because both binaries and the vault header's
/// human-facing output all speak hex about the same values and should agree on the
/// spelling.
pub fn to_hex(bytes: &[u8]) -> String {
    use fmt::Write as _;
    bytes
        .iter()
        .fold(String::with_capacity(bytes.len() * 2), |mut out, byte| {
            // Writing to a String is infallible.
            let _ = write!(out, "{byte:02x}");
            out
        })
}

/// Parse lowercase or uppercase hex with no separators.
///
/// Errors name the offending character and its offset: this parses user-supplied
/// files and command-line arguments, so "invalid hex" alone would not be enough to
/// find the typo.
pub fn from_hex(input: &str) -> Result<Vec<u8>, HexError> {
    if input.is_empty() {
        return Err(HexError::Empty);
    }
    if input.len() % 2 != 0 {
        return Err(HexError::OddLength(input.len()));
    }
    input
        .as_bytes()
        .chunks(2)
        .enumerate()
        .map(|(i, pair)| {
            let text = std::str::from_utf8(pair).map_err(|_| HexError::InvalidChar {
                offset: i * 2,
                found: '?',
            })?;
            u8::from_str_radix(text, 16).map_err(|_| HexError::InvalidChar {
                offset: i * 2,
                found: text.chars().next().unwrap_or('?'),
            })
        })
        .collect()
}

#[derive(thiserror::Error, Debug, PartialEq, Eq)]
pub enum HexError {
    #[error("expected hex digits, found nothing")]
    Empty,
    #[error("hex must have an even number of digits, found {0}")]
    OddLength(usize),
    #[error("invalid hex digit {found:?} at offset {offset}")]
    InvalidChar { offset: usize, found: char },
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
    fn hex_round_trips() {
        for bytes in [vec![], vec![0u8], vec![0u8, 0x0F, 0xA5, 0xFF]] {
            let text = to_hex(&bytes);
            assert_eq!(text.len(), bytes.len() * 2);
            if bytes.is_empty() {
                assert_eq!(from_hex(&text), Err(HexError::Empty));
            } else {
                assert_eq!(from_hex(&text).unwrap(), bytes);
            }
        }
        assert_eq!(to_hex(&[0xAB, 0xCD]), "abcd");
        // Uppercase is accepted on the way in, even though we never emit it.
        assert_eq!(from_hex("ABCD").unwrap(), vec![0xAB, 0xCD]);
    }

    #[test]
    fn hex_errors_locate_the_problem() {
        assert_eq!(from_hex(""), Err(HexError::Empty));
        assert_eq!(from_hex("abc"), Err(HexError::OddLength(3)));
        assert_eq!(
            from_hex("abzz"),
            Err(HexError::InvalidChar {
                offset: 2,
                found: 'z'
            })
        );
    }

    #[test]
    fn fingerprint_does_not_contain_the_secret() {
        // Guards against the tag ever being reduced to a prefix of the input.
        let secret = [0xABu8; 32];
        let tag = fingerprint(&secret);
        assert!(!tag.starts_with("abab"));
    }
}
