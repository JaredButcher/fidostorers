//! Encrypt files, directories, and key/value secrets using a FIDO2 security key.
//!
//! Depends on `fido-token` for device I/O but never talks to hardware itself: every
//! [`vault::Vault`] method that needs key material takes an already-derived KEK or
//! data key as a plain byte array. That split is what keeps this crate's tests
//! hardware-free — see plan/02-crate-fidostorers.md and plan/05-testing-strategy.md.

mod error;
mod vault;

pub use error::VaultError;
pub use vault::{CredentialEntry, Mode, Vault, FORMAT_VERSION};
