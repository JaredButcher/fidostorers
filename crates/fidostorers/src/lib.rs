//! Encrypt files, directories, and key/value secrets with a FIDO2 security key.
//!
//! A vault is one file holding a random **data key**, wrapped separately for each
//! enrolled factor, plus a payload encrypted under that data key. Any one factor
//! opens the vault, and adding a factor never re-encrypts the payload.
//!
//! ```text
//! security key ──(touch)──► hmac-secret ──HKDF──► KEK ──┐
//! keyfile + password ──────►  Argon2id  ──HKDF──► KEK ──┼──unwrap──► data key ──► payload
//! ```
//!
//! # This crate never talks to hardware
//!
//! That is the central design decision, and everything else follows from it.
//! [`Vault::unlock_with`] takes an **already-derived** key-encryption key; where
//! those 32 bytes came from is the caller's business. The `fidostorers` binary is
//! the only place that asks a security key for them.
//!
//! Two things fall out. Every test here runs without a security key, by passing an
//! arbitrary KEK. And adding a second kind of factor — [`keyfile`], a keyfile plus
//! a password run through Argon2id — changed nothing below the KEK.
//!
//! ```
//! use fidostorers::{Enrollment, Factor, Mode, Vault};
//! use zeroize::Zeroizing;
//!
//! # fn main() -> Result<(), Box<dyn std::error::Error>> {
//! let dir = tempfile::tempdir()?;
//! let path = dir.path().join("tokens.fido");
//!
//! // In the real CLI these 32 bytes come from a touch. Here they are just bytes,
//! // which is the whole point of the seam.
//! let kek = Zeroizing::new([0x42u8; 32]);
//! let enrollment = Enrollment {
//!     factor: Factor::Fido2(fido_token::Credential {
//!         rp_id: "fidostorers.local".into(),
//!         credential_id: vec![1, 2, 3],
//!         device_hint: None,
//!     }),
//!     rp_id: "fidostorers.local".into(),
//!     label: "primary".into(),
//!     salt: [7u8; 32],
//!     kek: kek.clone(),
//! };
//!
//! let mut vault = Vault::create(&path, Mode::Kv, &enrollment)?;
//! let entry_id = vault.credentials()[0].id;
//! let data_key = vault.unlock_with(&entry_id, kek)?;
//!
//! vault.kv_set(&data_key, "github", b"ghp_example")?;
//! assert_eq!(&vault.kv_get(&data_key, "github")?[..], b"ghp_example");
//! # Ok(())
//! # }
//! ```
//!
//! # Modes
//!
//! A vault is created in one [`Mode`] and keeps it for life:
//!
//! | Mode | Payload | Use |
//! |---|---|---|
//! | [`Mode::File`] | one file's bytes | [`Vault::seal_file`] / [`Vault::open_file`] |
//! | [`Mode::Dir`] | a `tar` stream of a tree | [`Vault::seal_dir`] / [`Vault::open_dir`] |
//! | [`Mode::Kv`] | a `name -> bytes` map | [`Vault::kv_set`] and friends |
//!
//! Every write re-encrypts the whole payload and rewrites the file through a temp
//! file and a rename, so an interrupted write cannot corrupt an existing vault.
//! One consequence worth knowing: the payload is held in memory in one piece,
//! because the format puts a single AEAD tag over all of it.
//!
//! # Module map
//!
//! The vault itself is the core; the rest exists to support long-lived sessions.
//!
//! - [`keyfile`] — the keyfile + password factor (Argon2id), for unlocking without
//!   hardware.
//! - [`session`] — [`Session`] and [`Store`]: vaults held open with their data keys
//!   cached, so one touch covers many operations. Takes an already-derived data key
//!   for the same reason [`Vault`] takes an already-derived KEK, and so is equally
//!   testable without hardware. Bounded by an idle timeout on an injectable clock.
//! - [`workdir`] — the plaintext working directory a `file`/`dir` store is edited
//!   through while open, and the digest that decides whether sealing would change
//!   anything. **This is the part that puts unencrypted data on disk**; read its
//!   module docs before relying on it.
//! - [`lock`] — the advisory `<vault>.lock`. While a session holds a vault, no other
//!   process of this tool may open or write it.
//! - [`orphan`] — recovering working directories left by a session that was killed.
//! - [`hardening`] — [`SecretKey`], 32 bytes in their own `mlock`ed page, and
//!   process-wide core-dump suppression.
//!
//! # Errors
//!
//! Almost everything returns [`VaultError`]. The one distinction worth handling
//! explicitly is [`VaultError::AuthenticationFailed`], which means *either* the
//! wrong factor was supplied *or* the vault was tampered with — the two are
//! deliberately indistinguishable. [`Vault::open_dir`] additionally returns an
//! [`ExtractReport`], because a partial extraction is a real outcome on Windows and
//! callers must be able to tell it from a complete one.
//!
//! # Design notes
//!
//! `plan/02-crate-fidostorers.md` for this crate, `plan/03-vault-format-and-crypto.md`
//! for the on-disk format, `plan/04-security-and-threat-model.md` for what this does
//! and does not protect against.

mod archive;
mod crypto;
mod error;
pub mod hardening;
pub mod keyfile;
mod kv;
pub mod lock;
pub mod orphan;
pub mod session;
mod vault;
pub mod workdir;

pub use archive::{ExtractReport, SkippedEntry};
pub use crypto::kek_from_secret;
pub use error::VaultError;
pub use hardening::{Hardening, SecretKey, Support};
pub use keyfile::KeyfileParams;
pub use lock::VaultLock;
pub use session::{ClosedStore, Session, SessionError, Store};
pub use vault::{Enrollment, Factor, FactorEntry, Mode, Vault, FORMAT_VERSION};
pub use workdir::WorkDir;
