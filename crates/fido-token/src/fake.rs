//! Pure-software [`Authenticator`] implementation for tests.
//!
//! Simulates the `hmac-secret` extension with the exact same construction a real
//! authenticator uses — `HMAC-SHA256(credRandom, salt)` — just without any hardware
//! in the loop, so callers can verify the properties they actually depend on
//! (determinism, salt/credential separation) on every `cargo test`. See
//! plan/05-testing-strategy.md.

use std::collections::HashMap;
use std::sync::Mutex;

use hmac::{Hmac, Mac};
use rand::RngCore;
use sha2::Sha256;
use zeroize::Zeroizing;

use crate::{Authenticator, Credential, DeriveOptions, DeviceInfo, RegisterOptions, TokenError};

type HmacSha256 = Hmac<Sha256>;

/// A canned failure to inject on the *next* `register`/`derive_secret` call, to
/// exercise error-handling paths without real hardware.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Failure {
    NotAllowed,
    Timeout,
}

/// An in-memory stand-in for one physical authenticator. Two independent
/// `FakeAuthenticator` instances behave like two different physical keys: a
/// credential registered on one is unrecognized ([`TokenError::UnknownCredential`])
/// on the other.
#[derive(Default)]
pub struct FakeAuthenticator {
    credentials: Mutex<HashMap<Vec<u8>, [u8; 32]>>,
    fail_next: Mutex<Option<Failure>>,
}

impl FakeAuthenticator {
    pub fn new() -> Self {
        Self::default()
    }

    /// Make the next `register` or `derive_secret` call return `failure` instead of
    /// succeeding.
    pub fn fail_next(&self, failure: Failure) {
        *self.fail_next.lock().expect("lock poisoned") = Some(failure);
    }

    fn take_failure(&self) -> Option<Failure> {
        self.fail_next.lock().expect("lock poisoned").take()
    }
}

impl Authenticator for FakeAuthenticator {
    fn list_devices(&self) -> Result<Vec<DeviceInfo>, TokenError> {
        Ok(vec![DeviceInfo {
            path: "fake-0".to_string(),
            product: Some("FakeAuthenticator".to_string()),
            supports_hmac_secret: true,
            supports_client_pin: true,
        }])
    }

    fn register(&self, opts: &RegisterOptions) -> Result<Credential, TokenError> {
        if let Some(failure) = self.take_failure() {
            return Err(failure.into());
        }

        let mut credential_id = vec![0u8; 16];
        rand::thread_rng().fill_bytes(&mut credential_id);
        let mut cred_random = [0u8; 32];
        rand::thread_rng().fill_bytes(&mut cred_random);

        self.credentials
            .lock()
            .expect("lock poisoned")
            .insert(credential_id.clone(), cred_random);

        Ok(Credential {
            rp_id: opts.rp_id.clone(),
            credential_id,
            device_hint: Some("FakeAuthenticator".to_string()),
        })
    }

    fn derive_secret(
        &self,
        credential: &Credential,
        salt: &[u8; 32],
        _opts: &DeriveOptions,
    ) -> Result<Zeroizing<[u8; 32]>, TokenError> {
        if let Some(failure) = self.take_failure() {
            return Err(failure.into());
        }

        let credentials = self.credentials.lock().expect("lock poisoned");
        let cred_random = credentials
            .get(&credential.credential_id)
            .ok_or(TokenError::UnknownCredential)?;

        let mut mac = HmacSha256::new_from_slice(cred_random).expect("HMAC accepts any key length");
        mac.update(salt);
        let mut out = [0u8; 32];
        out.copy_from_slice(&mac.finalize().into_bytes());
        Ok(Zeroizing::new(out))
    }
}

impl From<Failure> for TokenError {
    fn from(failure: Failure) -> Self {
        match failure {
            Failure::NotAllowed => TokenError::NotAllowed,
            Failure::Timeout => TokenError::Timeout,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::Duration;

    fn register_opts() -> RegisterOptions {
        RegisterOptions {
            rp_id: "fidostorers.local".to_string(),
            user_name: "test".to_string(),
            require_uv: false,
            timeout: Duration::from_secs(1),
        }
    }

    fn derive_opts() -> DeriveOptions {
        DeriveOptions {
            require_uv: false,
            timeout: Duration::from_secs(1),
        }
    }

    #[test]
    fn same_credential_and_salt_derives_identical_secret() {
        let auth = FakeAuthenticator::new();
        let cred = auth.register(&register_opts()).unwrap();
        let salt = [7u8; 32];

        let first = auth.derive_secret(&cred, &salt, &derive_opts()).unwrap();
        let second = auth.derive_secret(&cred, &salt, &derive_opts()).unwrap();

        assert_eq!(*first, *second);
    }

    #[test]
    fn different_salts_derive_different_secrets() {
        let auth = FakeAuthenticator::new();
        let cred = auth.register(&register_opts()).unwrap();

        let a = auth
            .derive_secret(&cred, &[1u8; 32], &derive_opts())
            .unwrap();
        let b = auth
            .derive_secret(&cred, &[2u8; 32], &derive_opts())
            .unwrap();

        assert_ne!(*a, *b);
    }

    #[test]
    fn different_credentials_derive_different_secrets_for_same_salt() {
        let auth = FakeAuthenticator::new();
        let cred_a = auth.register(&register_opts()).unwrap();
        let cred_b = auth.register(&register_opts()).unwrap();
        let salt = [9u8; 32];

        let a = auth.derive_secret(&cred_a, &salt, &derive_opts()).unwrap();
        let b = auth.derive_secret(&cred_b, &salt, &derive_opts()).unwrap();

        assert_ne!(*a, *b);
    }

    #[test]
    fn unknown_credential_is_rejected() {
        let registered_on = FakeAuthenticator::new();
        let queried_on = FakeAuthenticator::new();
        let cred = registered_on.register(&register_opts()).unwrap();

        let err = queried_on
            .derive_secret(&cred, &[0u8; 32], &derive_opts())
            .unwrap_err();

        assert!(matches!(err, TokenError::UnknownCredential));
    }

    #[test]
    fn injected_failures_surface_as_errors() {
        let auth = FakeAuthenticator::new();
        auth.fail_next(Failure::Timeout);
        let err = auth.register(&register_opts()).unwrap_err();
        assert!(matches!(err, TokenError::Timeout));

        // Failure is consumed; the next call succeeds normally.
        let cred = auth.register(&register_opts()).unwrap();
        auth.fail_next(Failure::NotAllowed);
        let err = auth
            .derive_secret(&cred, &[0u8; 32], &derive_opts())
            .unwrap_err();
        assert!(matches!(err, TokenError::NotAllowed));
    }
}
