//! Keyfile + password authentication: the second way to produce a KEK.
//!
//! See plan/10-keyfile-password-auth.md. Both inputs are required, always. A keyfile
//! alone would be a copyable bearer token, strictly weaker than a security key whose
//! secret cannot be copied; a password alone is exactly the offline-guessable secret
//! this project set out to avoid.
//!
//! ```text
//! keyfile_hash = SHA-256(keyfile bytes)              streamed, any file size
//! argon_out    = Argon2id(password, salt, secret = keyfile_hash, params)
//! KEK          = HKDF-SHA256(argon_out, info = "fidostorers-kek-keyfile-v1")
//! ```
//!
//! The keyfile goes in Argon2's `secret` ("pepper") input, which is precisely what
//! that parameter is for: a value that is not stored next to the hash. Hashing it
//! first means an arbitrary file costs a constant 32 bytes in the KDF.

use std::fs::File;
use std::io::{self, Read};
use std::path::Path;

use argon2::{Algorithm, Argon2, Params, Version};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use zeroize::Zeroizing;

use crate::crypto;
use crate::VaultError;

/// RFC 9106's second recommended profile: ~64 MiB and a few passes, which lands
/// around half a second on a laptop.
pub const DEFAULT_M_COST_KIB: u32 = 64 * 1024;
pub const DEFAULT_T_COST: u32 = 3;
pub const DEFAULT_PARALLELISM: u32 = 4;

// Bounds. The maxima are enforced when *reading* a header, because these fields are
// read before `header_mac` can be verified and they drive an allocation — the same
// reasoning as the header's length prefixes (plan/07 #5). A hostile 16 TiB m_cost
// must fail on the bound rather than be attempted.
//
// The minima are enforced when *writing*, so a mistyped flag cannot silently enroll a
// factor whose cost is negligible.
pub const MIN_M_COST_KIB: u32 = 8 * 1024;
pub const MAX_M_COST_KIB: u32 = 1024 * 1024;
pub const MIN_T_COST: u32 = 1;
pub const MAX_T_COST: u32 = 16;
pub const MIN_PARALLELISM: u32 = 1;
pub const MAX_PARALLELISM: u32 = 16;

/// A keyfile over this size warns: it is re-read and re-hashed on every unlock.
pub const LARGE_KEYFILE_WARN_BYTES: u64 = 64 * 1024 * 1024;

/// Argon2id cost parameters for one enrolled keyfile factor.
///
/// Stored per entry so the cost can be raised later without invalidating factors
/// enrolled under the old settings.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct KeyfileParams {
    pub m_cost_kib: u32,
    pub t_cost: u32,
    pub parallelism: u32,
}

impl Default for KeyfileParams {
    fn default() -> Self {
        Self {
            m_cost_kib: DEFAULT_M_COST_KIB,
            t_cost: DEFAULT_T_COST,
            parallelism: DEFAULT_PARALLELISM,
        }
    }
}

impl KeyfileParams {
    /// Checked when reading a header, before any allocation is made from them.
    pub(crate) fn validate_for_read(&self) -> Result<(), VaultError> {
        let bad = |what: &str| {
            Err(VaultError::MalformedHeader(format!(
                "keyfile factor has an out-of-range Argon2 {what}"
            )))
        };
        if !(MIN_M_COST_KIB..=MAX_M_COST_KIB).contains(&self.m_cost_kib) {
            return bad(&format!(
                "memory cost {} KiB (allowed {MIN_M_COST_KIB}..={MAX_M_COST_KIB})",
                self.m_cost_kib
            ));
        }
        if !(MIN_T_COST..=MAX_T_COST).contains(&self.t_cost) {
            return bad(&format!("time cost {}", self.t_cost));
        }
        if !(MIN_PARALLELISM..=MAX_PARALLELISM).contains(&self.parallelism) {
            return bad(&format!("parallelism {}", self.parallelism));
        }
        Ok(())
    }

    /// Checked before enrolling, so a mistyped flag cannot weaken a new factor.
    pub fn validate_for_write(&self) -> Result<(), VaultError> {
        self.validate_for_read().map_err(|_| {
            VaultError::InvalidKdfParams(format!(
                "Argon2 parameters out of range: memory {}..={MAX_M_COST_KIB} KiB, \
                 time {MIN_T_COST}..={MAX_T_COST}, parallelism {MIN_PARALLELISM}..={MAX_PARALLELISM}",
                MIN_M_COST_KIB
            ))
        })
    }
}

/// Hash a keyfile's contents, streaming so an arbitrarily large file never lands in
/// memory.
///
/// Rejects an empty file (it contributes nothing and is almost certainly a mistake)
/// and anything that is not a regular file.
pub fn hash_keyfile(path: &Path) -> Result<Zeroizing<[u8; 32]>, VaultError> {
    let metadata = std::fs::metadata(path)?;
    if metadata.is_dir() {
        return Err(VaultError::UnusableKeyfile(format!(
            "{} is a directory",
            path.display()
        )));
    }
    if metadata.len() == 0 {
        return Err(VaultError::UnusableKeyfile(format!(
            "{} is empty, so it would contribute nothing",
            path.display()
        )));
    }

    let mut file = File::open(path)?;
    let mut hasher = Sha256::new();
    let mut buffer = Zeroizing::new(vec![0u8; 64 * 1024]);
    loop {
        let read = match file.read(&mut buffer) {
            Ok(0) => break,
            Ok(n) => n,
            Err(err) if err.kind() == io::ErrorKind::Interrupted => continue,
            Err(err) => return Err(VaultError::Io(err)),
        };
        hasher.update(&buffer[..read]);
    }
    Ok(Zeroizing::new(hasher.finalize().into()))
}

/// Derive a KEK from a keyfile hash, a password, and this entry's salt.
///
/// Deliberately takes the keyfile *hash* rather than a path, so callers hash once and
/// can try several entries (each with its own salt) without re-reading the file.
pub fn derive_kek(
    keyfile_hash: &[u8; 32],
    password: &[u8],
    salt: &[u8; 32],
    params: &KeyfileParams,
) -> Result<Zeroizing<[u8; 32]>, VaultError> {
    params.validate_for_read()?;

    let argon_params = Params::new(
        params.m_cost_kib,
        params.t_cost,
        params.parallelism,
        Some(32),
    )
    .map_err(|err| VaultError::InvalidKdfParams(err.to_string()))?;

    let argon = Argon2::new_with_secret(
        keyfile_hash,
        Algorithm::Argon2id,
        Version::V0x13,
        argon_params,
    )
    .map_err(|err| VaultError::InvalidKdfParams(err.to_string()))?;

    let mut out = Zeroizing::new([0u8; 32]);
    argon
        .hash_password_into(password, salt, &mut out[..])
        .map_err(|err| VaultError::Internal(format!("Argon2 failed: {err}")))?;

    // Same final step as the FIDO2 path, with its own domain string, so the two kinds
    // of KEK can never collide and "every KEK is an HKDF output" stays uniform.
    Ok(crypto::kek_from_keyfile_secret(&out))
}

/// Generate a 32-byte random keyfile. Refuses to overwrite an existing file.
///
/// A binary file of full-entropy random bytes is the keyfile users should want:
/// nothing will helpfully reformat it, and it carries 256 bits, which is what keeps
/// the password from being the only thing between an attacker and the vault.
pub fn generate_keyfile(path: &Path) -> Result<(), VaultError> {
    use std::io::Write as _;

    if path.exists() {
        return Err(VaultError::UnusableKeyfile(format!(
            "{} already exists; refusing to overwrite it",
            path.display()
        )));
    }
    let bytes = crypto::random_key();
    let mut file = File::create(path)?;
    file.write_all(&bytes[..])?;
    file.sync_all()?;
    restrict_permissions(&file)?;
    Ok(())
}

#[cfg(unix)]
fn restrict_permissions(file: &File) -> Result<(), VaultError> {
    use std::os::unix::fs::PermissionsExt;
    file.set_permissions(std::fs::Permissions::from_mode(0o600))?;
    Ok(())
}

#[cfg(not(unix))]
fn restrict_permissions(_file: &File) -> Result<(), VaultError> {
    // Windows has no direct equivalent; the file inherits the directory's ACL.
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::TempDir;

    /// Argon2 at real cost makes a test suite crawl; these are deliberately the
    /// weakest parameters the validator accepts.
    fn fast() -> KeyfileParams {
        KeyfileParams {
            m_cost_kib: MIN_M_COST_KIB,
            t_cost: MIN_T_COST,
            parallelism: MIN_PARALLELISM,
        }
    }

    fn keyfile(dir: &TempDir, name: &str, contents: &[u8]) -> std::path::PathBuf {
        let path = dir.path().join(name);
        std::fs::write(&path, contents).unwrap();
        path
    }

    #[test]
    fn derivation_is_deterministic() {
        let hash = [1u8; 32];
        let a = derive_kek(&hash, b"password", &[2u8; 32], &fast()).unwrap();
        let b = derive_kek(&hash, b"password", &[2u8; 32], &fast()).unwrap();
        assert_eq!(*a, *b);
    }

    #[test]
    fn every_input_changes_the_result() {
        let base = derive_kek(&[1u8; 32], b"password", &[2u8; 32], &fast()).unwrap();

        // different keyfile
        assert_ne!(
            *base,
            *derive_kek(&[9u8; 32], b"password", &[2u8; 32], &fast()).unwrap()
        );
        // different password
        assert_ne!(
            *base,
            *derive_kek(&[1u8; 32], b"other", &[2u8; 32], &fast()).unwrap()
        );
        // different salt
        assert_ne!(
            *base,
            *derive_kek(&[1u8; 32], b"password", &[9u8; 32], &fast()).unwrap()
        );
        // different cost
        let mut slower = fast();
        slower.t_cost += 1;
        assert_ne!(
            *base,
            *derive_kek(&[1u8; 32], b"password", &[2u8; 32], &slower).unwrap()
        );
    }

    #[test]
    fn the_kek_is_not_the_raw_argon2_output() {
        // Guards the final HKDF step: without it the KEK would be Argon2's output
        // directly, losing the domain separation from the FIDO2 path.
        let params = fast();
        let argon_params = Params::new(
            params.m_cost_kib,
            params.t_cost,
            params.parallelism,
            Some(32),
        )
        .unwrap();
        let argon = Argon2::new_with_secret(
            &[1u8; 32],
            Algorithm::Argon2id,
            Version::V0x13,
            argon_params,
        )
        .unwrap();
        let mut raw = [0u8; 32];
        argon
            .hash_password_into(b"password", &[2u8; 32], &mut raw)
            .unwrap();

        let kek = derive_kek(&[1u8; 32], b"password", &[2u8; 32], &params).unwrap();
        assert_ne!(*kek, raw);
    }

    #[test]
    fn keyfile_hashing_handles_any_size() {
        let dir = TempDir::new().unwrap();
        let one = hash_keyfile(&keyfile(&dir, "one", b"x")).unwrap();
        let big = hash_keyfile(&keyfile(&dir, "big", &vec![0xABu8; 3 * 1024 * 1024])).unwrap();
        assert_ne!(*one, *big);

        // Streaming must agree with hashing in one go.
        let expected: [u8; 32] = Sha256::digest(b"x").into();
        assert_eq!(*one, expected);
    }

    #[test]
    fn an_empty_or_missing_keyfile_is_rejected() {
        let dir = TempDir::new().unwrap();
        assert!(matches!(
            hash_keyfile(&keyfile(&dir, "empty", b"")),
            Err(VaultError::UnusableKeyfile(_))
        ));
        assert!(matches!(
            hash_keyfile(dir.path()),
            Err(VaultError::UnusableKeyfile(_))
        ));
        assert!(matches!(
            hash_keyfile(&dir.path().join("nope")),
            Err(VaultError::Io(_))
        ));
    }

    #[test]
    fn hostile_parameters_are_rejected_before_use() {
        let hostile = KeyfileParams {
            m_cost_kib: u32::MAX,
            t_cost: 1,
            parallelism: 1,
        };
        assert!(hostile.validate_for_read().is_err());
        // ...and the derive path refuses rather than attempting the allocation.
        assert!(derive_kek(&[1u8; 32], b"p", &[2u8; 32], &hostile).is_err());

        for bad in [
            KeyfileParams {
                m_cost_kib: 1024,
                ..fast()
            },
            KeyfileParams {
                t_cost: 0,
                ..fast()
            },
            KeyfileParams {
                t_cost: 999,
                ..fast()
            },
            KeyfileParams {
                parallelism: 0,
                ..fast()
            },
            KeyfileParams {
                parallelism: 999,
                ..fast()
            },
        ] {
            assert!(
                bad.validate_for_read().is_err(),
                "{bad:?} should be rejected"
            );
        }
        assert!(fast().validate_for_read().is_ok());
        assert!(KeyfileParams::default().validate_for_read().is_ok());
    }

    #[test]
    fn generated_keyfiles_are_random_and_never_overwrite() {
        let dir = TempDir::new().unwrap();
        let a = dir.path().join("a.key");
        let b = dir.path().join("b.key");
        generate_keyfile(&a).unwrap();
        generate_keyfile(&b).unwrap();

        assert_eq!(std::fs::metadata(&a).unwrap().len(), 32);
        assert_ne!(std::fs::read(&a).unwrap(), std::fs::read(&b).unwrap());
        assert!(matches!(
            generate_keyfile(&a),
            Err(VaultError::UnusableKeyfile(_))
        ));
    }
}
