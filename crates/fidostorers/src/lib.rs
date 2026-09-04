//! Encrypt files, directories, and key/value secrets using a FIDO2 security key.
//!
//! Depends on `fido-token` for device I/O but never talks to hardware itself: every
//! [`vault::Vault`] method that needs key material takes an already-derived KEK or
//! data key as a plain byte array. That split is what keeps this crate's tests
//! hardware-free — see plan/02-crate-fidostorers.md and plan/05-testing-strategy.md.

mod archive;
mod crypto;
mod error;
pub mod keyfile;
mod kv;
pub mod lock;
pub mod session;
mod vault;

pub use archive::{ExtractReport, SkippedEntry};
pub use crypto::kek_from_secret;
pub use error::VaultError;
pub use keyfile::KeyfileParams;
pub use lock::VaultLock;
pub use session::{Session, SessionError, Store};
pub use vault::{Enrollment, Factor, FactorEntry, Mode, Vault, FORMAT_VERSION};
