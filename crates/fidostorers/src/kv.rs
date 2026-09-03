//! The key/value payload for `kv`-mode vaults.
//!
//! The whole store is one `BTreeMap<String, Vec<u8>>` serialized into the single
//! AEAD-sealed payload — `BTreeMap` for deterministic ordering, same rationale as
//! the sorted tar in [`crate::archive`]. Every `set`/`rm` therefore re-encrypts and
//! rewrites the entire vault. That is the deliberate simplicity-over-scalability
//! trade-off recorded in plan/02-crate-fidostorers.md: one ciphertext, one nonce,
//! one tag, and no per-entry nonce management to get wrong.
//!
//! # Why this parses with fewer bounds than the header
//!
//! The header is parsed *before* it can be authenticated, so every length prefix in
//! it is a hostile input and is capped (plan/07 #5). This payload is parsed only
//! *after* the AEAD tag has verified, which proves it is exactly what was sealed —
//! and its total size is already bounded by the payload we just decrypted. So the
//! caps here are input validation on the way *in* (what names may be stored), not
//! allocation guards on the way out.

use std::collections::BTreeMap;

use zeroize::Zeroize;

use crate::VaultError;

/// Longest entry name accepted by `kv_set`. Generous for "API token", "recovery
/// codes for X"; short enough that `kv ls` output stays readable.
const MAX_NAME_LEN: usize = 255;

/// A decrypted key/value store.
///
/// Values are wiped on drop. This is the same best-effort hygiene the rest of the
/// crate applies (plan/04): it does not defend against swap or a coredump taken
/// mid-operation, but it keeps decrypted secrets from lingering in freed memory.
#[derive(Debug, Default)]
pub(crate) struct KvMap(BTreeMap<String, Vec<u8>>);

impl Drop for KvMap {
    fn drop(&mut self) {
        for value in self.0.values_mut() {
            value.zeroize();
        }
    }
}

impl KvMap {
    pub(crate) fn get(&self, name: &str) -> Option<&[u8]> {
        self.0.get(name).map(|v| v.as_slice())
    }

    pub(crate) fn insert(&mut self, name: &str, value: &[u8]) -> Result<(), VaultError> {
        validate_name(name)?;
        // Overwriting drops the old value without zeroizing it, so wipe it first.
        if let Some(previous) = self.0.get_mut(name) {
            previous.zeroize();
        }
        self.0.insert(name.to_string(), value.to_vec());
        Ok(())
    }

    /// Returns whether anything was removed.
    pub(crate) fn remove(&mut self, name: &str) -> bool {
        match self.0.remove(name) {
            Some(mut value) => {
                value.zeroize();
                true
            }
            None => false,
        }
    }

    pub(crate) fn names(&self) -> Vec<String> {
        self.0.keys().cloned().collect()
    }

    pub(crate) fn encode(&self) -> Result<Vec<u8>, VaultError> {
        postcard::to_stdvec(&self.0)
            .map_err(|err| VaultError::Internal(format!("cannot serialize kv store: {err}")))
    }

    pub(crate) fn decode(bytes: &[u8]) -> Result<Self, VaultError> {
        if bytes.is_empty() {
            return Ok(Self::default());
        }
        postcard::from_bytes(bytes)
            .map(Self)
            .map_err(|err| VaultError::MalformedPayload(format!("cannot parse kv store: {err}")))
    }
}

fn validate_name(name: &str) -> Result<(), VaultError> {
    if name.is_empty() {
        return Err(VaultError::InvalidEntryName(
            "entry name must not be empty".to_string(),
        ));
    }
    if name.len() > MAX_NAME_LEN {
        return Err(VaultError::InvalidEntryName(format!(
            "entry name is {} bytes, over the {MAX_NAME_LEN}-byte limit",
            name.len()
        )));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn round_trips_through_postcard() {
        let mut map = KvMap::default();
        map.insert("token", b"secret-value").unwrap();
        map.insert("empty", b"").unwrap();
        map.insert("binary", &[0u8, 255, 128]).unwrap();

        let decoded = KvMap::decode(&map.encode().unwrap()).unwrap();
        assert_eq!(decoded.get("token"), Some(&b"secret-value"[..]));
        assert_eq!(decoded.get("empty"), Some(&b""[..]));
        assert_eq!(decoded.get("binary"), Some(&[0u8, 255, 128][..]));
        assert_eq!(decoded.get("absent"), None);
    }

    #[test]
    fn encoding_is_deterministic_regardless_of_insertion_order() {
        let mut forward = KvMap::default();
        for name in ["a", "b", "c"] {
            forward.insert(name, name.as_bytes()).unwrap();
        }
        let mut backward = KvMap::default();
        for name in ["c", "b", "a"] {
            backward.insert(name, name.as_bytes()).unwrap();
        }
        assert_eq!(forward.encode().unwrap(), backward.encode().unwrap());
    }

    #[test]
    fn an_empty_payload_decodes_as_an_empty_store() {
        assert!(KvMap::decode(&[]).unwrap().names().is_empty());
    }

    #[test]
    fn names_come_back_sorted() {
        let mut map = KvMap::default();
        for name in ["zeta", "alpha", "Mu", "beta"] {
            map.insert(name, b"x").unwrap();
        }
        assert_eq!(map.names(), vec!["Mu", "alpha", "beta", "zeta"]);
    }

    #[test]
    fn remove_reports_whether_it_removed_anything() {
        let mut map = KvMap::default();
        map.insert("here", b"x").unwrap();
        assert!(map.remove("here"));
        assert!(!map.remove("here"));
        assert_eq!(map.get("here"), None);
    }

    #[test]
    fn insert_overwrites() {
        let mut map = KvMap::default();
        map.insert("k", b"first").unwrap();
        map.insert("k", b"second").unwrap();
        assert_eq!(map.get("k"), Some(&b"second"[..]));
        assert_eq!(map.names().len(), 1);
    }

    #[test]
    fn rejects_unusable_names() {
        let mut map = KvMap::default();
        assert!(matches!(
            map.insert("", b"x"),
            Err(VaultError::InvalidEntryName(_))
        ));
        assert!(matches!(
            map.insert(&"x".repeat(MAX_NAME_LEN + 1), b"y"),
            Err(VaultError::InvalidEntryName(_))
        ));
        assert!(map.insert(&"x".repeat(MAX_NAME_LEN), b"y").is_ok());
    }

    #[test]
    fn names_with_awkward_characters_survive() {
        let mut map = KvMap::default();
        for name in ["with space", "with/slash", "with\nnewline", "ünïcødé", "🔑"] {
            map.insert(name, name.as_bytes()).unwrap();
        }
        let decoded = KvMap::decode(&map.encode().unwrap()).unwrap();
        for name in ["with space", "with/slash", "with\nnewline", "ünïcødé", "🔑"] {
            assert_eq!(decoded.get(name), Some(name.as_bytes()), "{name:?}");
        }
    }

    #[test]
    fn rejects_a_corrupt_payload() {
        // Not reachable through a vault (the AEAD tag catches corruption first), but
        // the decoder must still fail cleanly rather than panic.
        assert!(matches!(
            KvMap::decode(&[0xFF; 4]),
            Err(VaultError::MalformedPayload(_))
        ));
    }
}
