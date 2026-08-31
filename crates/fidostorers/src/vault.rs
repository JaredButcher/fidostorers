//! Vault: header + credential enrollment + payload, per
//! plan/03-vault-format-and-crypto.md.
//!
//! The AEAD wrap/unwrap and on-disk (de)serialization are milestone M2
//! (`create`/`open`/`unlock_with`/`seal_file`/`open_file`), directory support is M3,
//! KV support is M4, and enrollment/revocation are M5 — see plan/06-roadmap.md. The
//! struct shapes and the hardware-independent guard logic (e.g. "can't revoke the
//! last credential") are real and tested today; the crypto/I/O bodies return
//! [`VaultError::NotImplemented`] until their milestone lands.

use std::fmt;
use std::path::{Path, PathBuf};
use std::str::FromStr;

use serde::{Deserialize, Serialize};
use zeroize::Zeroizing;

use crate::VaultError;

/// Format version written by this build. Bumped whenever the on-disk layout in
/// plan/03-vault-format-and-crypto.md changes in an incompatible way.
pub const FORMAT_VERSION: u16 = 1;

/// The payload shape a vault was created with; fixed for the vault's lifetime.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum Mode {
    /// Payload is exactly one file's bytes.
    File,
    /// Payload is a `tar` stream of a directory tree.
    Dir,
    /// Payload is a serialized `name -> bytes` map.
    Kv,
}

impl fmt::Display for Mode {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Mode::File => "file",
            Mode::Dir => "dir",
            Mode::Kv => "kv",
        })
    }
}

impl FromStr for Mode {
    type Err = String;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s {
            "file" => Ok(Mode::File),
            "dir" => Ok(Mode::Dir),
            "kv" => Ok(Mode::Kv),
            other => Err(format!("unknown mode {other:?}, expected file, dir, or kv")),
        }
    }
}

/// One enrolled credential's entry in the vault header: everything needed to
/// re-derive its `KEK` and unwrap the data key, none of it secret on its own. See
/// plan/03-vault-format-and-crypto.md.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CredentialEntry {
    pub credential: fido_token::Credential,
    /// User-supplied label (e.g. "primary", "backup in safe"), for UX only.
    pub label: String,
    pub salt: [u8; 32],
    pub wrap_nonce: [u8; 24],
    /// XChaCha20-Poly1305 ciphertext + tag of the data key, under this entry's KEK.
    pub wrapped_data_key: Vec<u8>,
}

/// An opened vault: header metadata plus (once M2 lands) the encrypted payload.
#[derive(Debug, Clone)]
pub struct Vault {
    path: PathBuf,
    format_version: u16,
    mode: Mode,
    rp_id: String,
    credentials: Vec<CredentialEntry>,
}

impl Vault {
    /// Create a new vault at `path`, enrolled with a single credential. `kek` is the
    /// already-derived key-encryption-key for that credential (see
    /// `fido_token::derive_secret` + HKDF, plan/03-vault-format-and-crypto.md) —
    /// this type never talks to hardware directly.
    pub fn create(
        path: &Path,
        mode: Mode,
        credential: &fido_token::Credential,
        label: impl Into<String>,
        kek: Zeroizing<[u8; 32]>,
    ) -> Result<Self, VaultError> {
        let _ = (path, mode, credential, label.into(), kek);
        Err(VaultError::NotImplemented(
            "vault creation (data key generation + initial wrap) lands in M2, see plan/06-roadmap.md",
        ))
    }

    /// Load a vault's header from `path`. Reading the header requires no touch — it
    /// contains nothing secret on its own.
    pub fn open(path: &Path) -> Result<Self, VaultError> {
        let _ = path;
        Err(VaultError::NotImplemented(
            "vault header loading lands in M2, see plan/06-roadmap.md",
        ))
    }

    pub fn path(&self) -> &Path {
        &self.path
    }

    pub fn mode(&self) -> Mode {
        self.mode
    }

    pub fn rp_id(&self) -> &str {
        &self.rp_id
    }

    pub fn format_version(&self) -> u16 {
        self.format_version
    }

    pub fn credentials(&self) -> &[CredentialEntry] {
        &self.credentials
    }

    fn find_credential(&self, credential_id: &[u8]) -> Result<&CredentialEntry, VaultError> {
        self.credentials
            .iter()
            .find(|entry| entry.credential.credential_id == credential_id)
            .ok_or(VaultError::UnknownCredential)
    }

    /// Unwrap the data key using `credential_id`'s already-derived KEK. Returns
    /// [`VaultError::UnknownCredential`] if that credential isn't enrolled in this
    /// vault, and (once M2 lands) [`VaultError::AuthenticationFailed`] if `kek` is
    /// wrong or the vault has been tampered with.
    pub fn unlock_with(
        &self,
        credential_id: &[u8],
        kek: Zeroizing<[u8; 32]>,
    ) -> Result<Zeroizing<[u8; 32]>, VaultError> {
        self.find_credential(credential_id)?;
        let _ = kek;
        Err(VaultError::NotImplemented(
            "vault unlocking (AEAD unwrap) lands in M2, see plan/06-roadmap.md",
        ))
    }

    /// Enroll an additional credential, so it can independently unlock this vault.
    /// Requires the already-unwrapped `data_key` (from a prior `unlock_with`).
    pub fn enroll(
        &mut self,
        data_key: &Zeroizing<[u8; 32]>,
        new_credential: &fido_token::Credential,
        label: impl Into<String>,
        new_kek: Zeroizing<[u8; 32]>,
    ) -> Result<(), VaultError> {
        let _ = (data_key, new_credential, label.into(), new_kek);
        Err(VaultError::NotImplemented(
            "enrollment lands in M5, see plan/06-roadmap.md",
        ))
    }

    /// Remove a credential's ability to unlock this vault. Refuses to remove the
    /// last remaining credential, so a vault can never be left unopenable.
    pub fn revoke(&mut self, credential_id: &[u8]) -> Result<(), VaultError> {
        self.find_credential(credential_id)?;
        if self.credentials.len() <= 1 {
            return Err(VaultError::LastCredential);
        }
        Err(VaultError::NotImplemented(
            "revocation lands in M5, see plan/06-roadmap.md",
        ))
    }

    /// (mode = File) Encrypt `input`'s bytes into this vault.
    pub fn seal_file(
        &self,
        data_key: &Zeroizing<[u8; 32]>,
        input: &Path,
    ) -> Result<(), VaultError> {
        let _ = (data_key, input);
        Err(VaultError::NotImplemented(
            "file sealing lands in M2, see plan/06-roadmap.md",
        ))
    }

    /// (mode = File) Decrypt this vault's payload to `output`.
    pub fn open_file(
        &self,
        data_key: &Zeroizing<[u8; 32]>,
        output: &Path,
    ) -> Result<(), VaultError> {
        let _ = (data_key, output);
        Err(VaultError::NotImplemented(
            "file opening lands in M2, see plan/06-roadmap.md",
        ))
    }

    /// (mode = Dir) Archive `input_dir` and encrypt it into this vault.
    pub fn seal_dir(
        &self,
        data_key: &Zeroizing<[u8; 32]>,
        input_dir: &Path,
    ) -> Result<(), VaultError> {
        let _ = (data_key, input_dir);
        Err(VaultError::NotImplemented(
            "directory sealing lands in M3, see plan/06-roadmap.md",
        ))
    }

    /// (mode = Dir) Decrypt and extract this vault's payload into `output_dir`.
    pub fn open_dir(
        &self,
        data_key: &Zeroizing<[u8; 32]>,
        output_dir: &Path,
    ) -> Result<(), VaultError> {
        let _ = (data_key, output_dir);
        Err(VaultError::NotImplemented(
            "directory opening lands in M3, see plan/06-roadmap.md",
        ))
    }

    /// (mode = Kv) Set (inserting or overwriting) one entry.
    pub fn kv_set(
        &self,
        data_key: &Zeroizing<[u8; 32]>,
        name: &str,
        value: &[u8],
    ) -> Result<(), VaultError> {
        let _ = (data_key, name, value);
        Err(VaultError::NotImplemented(
            "kv support lands in M4, see plan/06-roadmap.md",
        ))
    }

    /// (mode = Kv) Get one entry's value.
    pub fn kv_get(
        &self,
        data_key: &Zeroizing<[u8; 32]>,
        name: &str,
    ) -> Result<Zeroizing<Vec<u8>>, VaultError> {
        let _ = (data_key, name);
        Err(VaultError::NotImplemented(
            "kv support lands in M4, see plan/06-roadmap.md",
        ))
    }

    /// (mode = Kv) Remove one entry.
    pub fn kv_rm(&self, data_key: &Zeroizing<[u8; 32]>, name: &str) -> Result<(), VaultError> {
        let _ = (data_key, name);
        Err(VaultError::NotImplemented(
            "kv support lands in M4, see plan/06-roadmap.md",
        ))
    }

    /// (mode = Kv) List entry names.
    pub fn kv_ls(&self, data_key: &Zeroizing<[u8; 32]>) -> Result<Vec<String>, VaultError> {
        let _ = data_key;
        Err(VaultError::NotImplemented(
            "kv support lands in M4, see plan/06-roadmap.md",
        ))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn dummy_credential(id: u8) -> fido_token::Credential {
        fido_token::Credential {
            rp_id: "fidostorers.local".to_string(),
            credential_id: vec![id],
            device_hint: None,
        }
    }

    fn dummy_entry(id: u8) -> CredentialEntry {
        CredentialEntry {
            credential: dummy_credential(id),
            label: format!("key-{id}"),
            salt: [id; 32],
            wrap_nonce: [id; 24],
            wrapped_data_key: vec![0u8; 48],
        }
    }

    fn dummy_vault(credentials: Vec<CredentialEntry>) -> Vault {
        Vault {
            path: PathBuf::from("/tmp/test.fido"),
            format_version: FORMAT_VERSION,
            mode: Mode::File,
            rp_id: "fidostorers.local".to_string(),
            credentials,
        }
    }

    #[test]
    fn mode_display_and_from_str_round_trip() {
        for mode in [Mode::File, Mode::Dir, Mode::Kv] {
            let s = mode.to_string();
            assert_eq!(s.parse::<Mode>().unwrap(), mode);
        }
    }

    #[test]
    fn mode_from_str_rejects_unknown() {
        assert!("bogus".parse::<Mode>().is_err());
    }

    #[test]
    fn revoke_rejects_last_credential() {
        let mut vault = dummy_vault(vec![dummy_entry(1)]);
        let err = vault.revoke(&[1]).unwrap_err();
        assert!(matches!(err, VaultError::LastCredential));
    }

    #[test]
    fn revoke_rejects_unknown_credential() {
        let mut vault = dummy_vault(vec![dummy_entry(1), dummy_entry(2)]);
        let err = vault.revoke(&[99]).unwrap_err();
        assert!(matches!(err, VaultError::UnknownCredential));
    }

    #[test]
    fn revoke_of_known_non_last_credential_is_not_yet_implemented() {
        // Guard clauses are real; the actual header rewrite is M5. Confirms we get
        // past both guards and hit the intended stub, not an early wrong error.
        let mut vault = dummy_vault(vec![dummy_entry(1), dummy_entry(2)]);
        let err = vault.revoke(&[1]).unwrap_err();
        assert!(matches!(err, VaultError::NotImplemented(_)));
    }

    #[test]
    fn unlock_with_rejects_unknown_credential() {
        let vault = dummy_vault(vec![dummy_entry(1)]);
        let err = vault
            .unlock_with(&[99], Zeroizing::new([0u8; 32]))
            .unwrap_err();
        assert!(matches!(err, VaultError::UnknownCredential));
    }

    #[test]
    fn unlock_with_known_credential_is_not_yet_implemented() {
        let vault = dummy_vault(vec![dummy_entry(1)]);
        let err = vault
            .unlock_with(&[1], Zeroizing::new([0u8; 32]))
            .unwrap_err();
        assert!(matches!(err, VaultError::NotImplemented(_)));
    }

    #[test]
    fn credentials_accessor_reflects_construction() {
        let vault = dummy_vault(vec![dummy_entry(1), dummy_entry(2)]);
        assert_eq!(vault.credentials().len(), 2);
        assert_eq!(vault.mode(), Mode::File);
        assert_eq!(vault.rp_id(), "fidostorers.local");
        assert_eq!(vault.format_version(), FORMAT_VERSION);
    }
}
