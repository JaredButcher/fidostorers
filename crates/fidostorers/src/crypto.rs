//! Key derivation, AEAD, and header authentication.
//!
//! Every primitive the vault format uses lives here, so the domain-separation
//! strings and the "no associated data anywhere" rule are stated in exactly one
//! place. See plan/03-vault-format-and-crypto.md.

use chacha20poly1305::aead::Aead;
use chacha20poly1305::{Key, KeyInit, XChaCha20Poly1305, XNonce};
use hkdf::Hkdf;
use hmac::{Hmac, Mac};
use rand::rngs::OsRng;
use rand::RngCore;
use sha2::Sha256;
use zeroize::Zeroizing;

use crate::VaultError;

type HmacSha256 = Hmac<Sha256>;

/// Domain separator turning a raw `hmac-secret` output into a key-encryption key.
/// Exists so the AEAD key is distinct from the authenticator's output in case that
/// output is ever reused for anything else.
const KEK_INFO: &[u8] = b"fidostorers-kek-v1";

/// Domain separator for the header MAC key, so the data key is never used directly
/// for two different primitives (it encrypts the payload; its derivative MACs the
/// header).
const HEADER_MAC_INFO: &[u8] = b"fidostorers-header-mac-v1";

/// Turn the 32-byte `hmac-secret` output for a (credential, salt) pair into that
/// credential's KEK.
///
/// This is the seam described in plan/02-crate-fidostorers.md: callers derive the
/// secret via `fido_token::derive_secret`, run it through here, and hand the result
/// to [`crate::Vault`], which never touches hardware itself.
pub fn kek_from_secret(secret: &[u8; 32]) -> Zeroizing<[u8; 32]> {
    hkdf_32(secret, KEK_INFO)
}

pub(crate) fn mac_key_from_data_key(data_key: &[u8; 32]) -> Zeroizing<[u8; 32]> {
    hkdf_32(data_key, HEADER_MAC_INFO)
}

fn hkdf_32(ikm: &[u8; 32], info: &[u8]) -> Zeroizing<[u8; 32]> {
    let mut okm = Zeroizing::new([0u8; 32]);
    Hkdf::<Sha256>::new(None, ikm)
        .expand(info, &mut okm[..])
        .expect("32 bytes is a valid HKDF-SHA256 output length");
    okm
}

pub(crate) fn random_key() -> Zeroizing<[u8; 32]> {
    let mut key = Zeroizing::new([0u8; 32]);
    OsRng.fill_bytes(&mut key[..]);
    key
}

/// A fresh 192-bit nonce. Random rather than counter-based on purpose: restoring an
/// older vault from a backup and writing again would walk a counter back over
/// values it had already used. See plan/03's "AEAD nonce discipline".
pub(crate) fn random_nonce() -> [u8; 24] {
    let mut nonce = [0u8; 24];
    OsRng.fill_bytes(&mut nonce);
    nonce
}

/// XChaCha20-Poly1305, empty associated data. The format uses no AAD anywhere;
/// header integrity comes from [`header_mac`] instead (plan/07 #5b).
pub(crate) fn seal(
    key: &[u8; 32],
    nonce: &[u8; 24],
    plaintext: &[u8],
) -> Result<Vec<u8>, VaultError> {
    XChaCha20Poly1305::new(Key::from_slice(key))
        .encrypt(XNonce::from_slice(nonce), plaintext)
        .map_err(|_| VaultError::Internal("AEAD encryption failed".to_string()))
}

pub(crate) fn unseal(
    key: &[u8; 32],
    nonce: &[u8; 24],
    ciphertext: &[u8],
) -> Result<Zeroizing<Vec<u8>>, VaultError> {
    XChaCha20Poly1305::new(Key::from_slice(key))
        .decrypt(XNonce::from_slice(nonce), ciphertext)
        .map(Zeroizing::new)
        .map_err(|_| VaultError::AuthenticationFailed)
}

pub(crate) fn header_mac(mac_key: &[u8; 32], bytes: &[u8]) -> [u8; 32] {
    let mut mac =
        <HmacSha256 as Mac>::new_from_slice(mac_key).expect("HMAC accepts any key length");
    mac.update(bytes);
    mac.finalize().into_bytes().into()
}

/// Constant-time comparison, via `hmac`'s own verifier.
pub(crate) fn verify_header_mac(
    mac_key: &[u8; 32],
    bytes: &[u8],
    expected: &[u8; 32],
) -> Result<(), VaultError> {
    let mut mac =
        <HmacSha256 as Mac>::new_from_slice(mac_key).expect("HMAC accepts any key length");
    mac.update(bytes);
    mac.verify_slice(expected)
        .map_err(|_| VaultError::AuthenticationFailed)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn kek_derivation_is_deterministic_and_domain_separated() {
        let secret = [7u8; 32];
        assert_eq!(*kek_from_secret(&secret), *kek_from_secret(&secret));
        assert_ne!(*kek_from_secret(&secret), *kek_from_secret(&[8u8; 32]));
        // The KEK must not be the raw authenticator output.
        assert_ne!(*kek_from_secret(&secret), secret);
        // And the two derivations off one input must differ from each other.
        assert_ne!(*kek_from_secret(&secret), *mac_key_from_data_key(&secret));
    }

    #[test]
    fn aead_round_trips_and_rejects_tampering() {
        let key = [1u8; 32];
        let nonce = [2u8; 24];
        let mut ct = seal(&key, &nonce, b"hello").unwrap();
        assert_eq!(&unseal(&key, &nonce, &ct).unwrap()[..], b"hello");

        ct[0] ^= 1;
        assert!(matches!(
            unseal(&key, &nonce, &ct),
            Err(VaultError::AuthenticationFailed)
        ));
    }

    #[test]
    fn aead_rejects_wrong_key_and_wrong_nonce() {
        let ct = seal(&[1u8; 32], &[2u8; 24], b"hello").unwrap();
        assert!(unseal(&[9u8; 32], &[2u8; 24], &ct).is_err());
        assert!(unseal(&[1u8; 32], &[9u8; 24], &ct).is_err());
    }

    #[test]
    fn header_mac_detects_any_change() {
        let key = [3u8; 32];
        let tag = header_mac(&key, b"header bytes");
        assert!(verify_header_mac(&key, b"header bytes", &tag).is_ok());
        assert!(verify_header_mac(&key, b"header bytee", &tag).is_err());
        assert!(verify_header_mac(&[4u8; 32], b"header bytes", &tag).is_err());
    }

    #[test]
    fn nonces_are_not_repeated() {
        // Not a randomness test, just a guard against a stubbed-out generator.
        let a = random_nonce();
        assert_ne!(a, random_nonce());
        assert_ne!(a, [0u8; 24]);
    }
}
