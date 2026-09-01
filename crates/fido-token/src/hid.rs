//! Real hardware backend, built on Mozilla's `authenticator` crate (the CTAP stack
//! Firefox ships). See plan/01-crate-fido-token.md and plan/07-open-decisions.md #1.
//!
//! Compiled only with the `hardware` feature (on by default). Without it, the
//! methods below return [`TokenError::BackendUnavailable`] so the rest of the
//! workspace still builds and tests on machines that cannot satisfy the platform
//! build dependencies.

use crate::{Authenticator, Credential, DeriveOptions, DeviceInfo, RegisterOptions, TokenError};
use zeroize::Zeroizing;

/// Talks to physical FIDO2/U2F authenticators over USB HID.
///
/// On both Linux and Windows this is raw HID access — the `authenticator` crate has
/// no `webauthn.dll` backend, which has consequences for running unprivileged on
/// Windows. See docs/M1-MANUAL-TESTING.md.
#[derive(Debug, Default)]
pub struct HidAuthenticator {
    _private: (),
}

impl HidAuthenticator {
    pub fn new() -> Self {
        Self::default()
    }
}

impl Authenticator for HidAuthenticator {
    fn list_devices(&self) -> Result<Vec<DeviceInfo>, TokenError> {
        // Enumeration is ours, not the `authenticator` crate's, and so is available
        // regardless of the `hardware` feature.
        crate::enumerate::list_devices()
    }

    fn register(&self, opts: &RegisterOptions) -> Result<Credential, TokenError> {
        #[cfg(feature = "hardware")]
        {
            imp::register(opts)
        }
        #[cfg(not(feature = "hardware"))]
        {
            let _ = opts;
            Err(TokenError::BackendUnavailable)
        }
    }

    fn derive_secret(
        &self,
        credential: &Credential,
        salt: &[u8; 32],
        opts: &DeriveOptions,
    ) -> Result<Zeroizing<[u8; 32]>, TokenError> {
        #[cfg(feature = "hardware")]
        {
            imp::derive_secret(credential, salt, opts)
        }
        #[cfg(not(feature = "hardware"))]
        {
            let _ = (credential, salt, opts);
            Err(TokenError::BackendUnavailable)
        }
    }
}

#[cfg(feature = "hardware")]
mod imp {
    use std::sync::mpsc::{channel, Receiver, RecvTimeoutError, Sender};
    use std::time::{Duration, Instant};

    use authenticator::authenticatorservice::{AuthenticatorService, RegisterArgs, SignArgs};
    use authenticator::crypto::COSEAlgorithm;
    use authenticator::ctap2::commands::StatusCode;
    use authenticator::ctap2::server::{
        AuthenticationExtensionsClientInputs, HMACGetSecretInput, PublicKeyCredentialDescriptor,
        PublicKeyCredentialParameters, PublicKeyCredentialUserEntity, RelyingParty,
        ResidentKeyRequirement, Transport, UserVerificationRequirement,
    };
    use authenticator::errors::{AuthenticatorError, CommandError, HIDError, PinError};
    use authenticator::statecallback::StateCallback;
    use authenticator::{Pin, StatusPinUv, StatusUpdate};
    use rand::RngCore;
    use zeroize::Zeroizing;

    use crate::{Credential, DeriveOptions, PinPrompt, PinProvider, RegisterOptions, TokenError};

    /// CTAP requires a 32-byte client data hash to sign over. There is no relying
    /// party here and we never look at the resulting signature — only at the
    /// hmac-secret extension output, which does not depend on this value — so a
    /// fixed domain-separated constant is used rather than a random challenge. That
    /// keeps operations reproducible and removes a needless RNG dependency from the
    /// derive path.
    const CLIENT_DATA_HASH: [u8; 32] = *b"fidostorers/fido-token client-da";

    /// Grace period added to the caller's timeout before we give up waiting on the
    /// backend, so that its own timeout fires first and we can report the more
    /// specific error it produces.
    const TIMEOUT_GRACE: Duration = Duration::from_secs(5);

    pub(super) fn register(opts: &RegisterOptions) -> Result<Credential, TokenError> {
        log::info!("register: {opts:?}");

        let mut service = service()?;
        let (status_tx, status_rx) = channel::<StatusUpdate>();
        let status_thread = spawn_status_thread(status_rx, opts.pin_provider.clone());

        // CTAP2 requires *a* user id; nothing reads it back, so random bytes are
        // both sufficient and the least informative choice.
        let mut user_id = [0u8; 16];
        rand::thread_rng().fill_bytes(&mut user_id);

        let args = RegisterArgs {
            client_data_hash: CLIENT_DATA_HASH,
            relying_party: RelyingParty {
                id: opts.rp_id.clone(),
                name: None,
            },
            origin: format!("https://{}", opts.rp_id),
            user: PublicKeyCredentialUserEntity {
                id: user_id.to_vec(),
                name: Some(opts.user_name.clone()),
                display_name: None,
            },
            // We never use the credential's public key or signature, only its
            // hmac-secret capability, so one widely supported algorithm is enough.
            pub_cred_params: vec![PublicKeyCredentialParameters {
                alg: COSEAlgorithm::ES256,
            }],
            exclude_list: vec![],
            user_verification_req: uv_requirement(opts.require_uv),
            // Non-resident: we store the credential id ourselves rather than
            // consuming one of the device's limited resident slots. See
            // plan/01-crate-fido-token.md "Why non-resident credentials".
            resident_key_req: ResidentKeyRequirement::Discouraged,
            extensions: AuthenticationExtensionsClientInputs {
                hmac_create_secret: Some(true),
                ..Default::default()
            },
            pin: None,
            // hmac-secret is CTAP2-only; silently dropping to CTAP1 would produce a
            // credential that can never derive a secret.
            use_ctap1_fallback: false,
        };
        log::debug!(
            "makeCredential rp_id={:?} uv={:?} rk=discouraged hmac_create_secret=true timeout={:?}",
            args.relying_party.id,
            args.user_verification_req,
            opts.timeout
        );

        let (result_tx, result_rx) = channel();
        let callback = StateCallback::new(Box::new(move |rv| {
            // The receiver is dropped only after a result arrives, so a send error
            // here means the caller already gave up; nothing to do but note it.
            if result_tx.send(rv).is_err() {
                log::debug!("register result arrived after the caller stopped waiting");
            }
        }));

        let started = Instant::now();
        service
            .register(timeout_ms(opts.timeout), args, status_tx, callback)
            .map_err(|err| map_error(err, started, opts.timeout))?;

        let outcome = wait(result_rx, opts.timeout);
        drop(service);
        let _ = status_thread.join();

        let result = outcome?.map_err(|err| map_error(err, started, opts.timeout))?;

        let credential_data = result.att_obj.auth_data.credential_data.ok_or_else(|| {
            TokenError::Transport("authenticator returned no attested credential data".to_string())
        })?;

        // The device reports whether it actually enabled hmac-secret. Catching a
        // "no" here turns a confusing failure at first derive into a clear failure
        // at enrollment, while the user still has the key in hand.
        match result.extensions.hmac_create_secret {
            Some(true) => log::debug!("authenticator confirmed hmac-secret is enabled"),
            Some(false) => {
                log::error!("authenticator declined to enable hmac-secret for this credential");
                return Err(TokenError::HmacSecretUnsupported);
            }
            None => log::warn!(
                "authenticator returned no hmac-secret confirmation; \
                 the credential may not support derivation"
            ),
        }

        let credential = Credential {
            rp_id: opts.rp_id.clone(),
            credential_id: credential_data.credential_id,
            device_hint: None,
        };
        log::info!(
            "registered credential ({} byte id) for rp_id={:?}",
            credential.credential_id.len(),
            credential.rp_id
        );
        Ok(credential)
    }

    pub(super) fn derive_secret(
        credential: &Credential,
        salt: &[u8; 32],
        opts: &DeriveOptions,
    ) -> Result<Zeroizing<[u8; 32]>, TokenError> {
        log::info!(
            "derive_secret: rp_id={:?} credential_id={} bytes, {opts:?}",
            credential.rp_id,
            credential.credential_id.len()
        );
        // The salt is not secret (see plan/03-vault-format-and-crypto.md) so it is
        // safe to log in full, and knowing which salt produced which output is the
        // single most useful thing when debugging a derivation mismatch.
        log::debug!("salt = {}", hex(salt));

        let mut service = service()?;
        let (status_tx, status_rx) = channel::<StatusUpdate>();
        let status_thread = spawn_status_thread(status_rx, opts.pin_provider.clone());

        let args = SignArgs {
            client_data_hash: CLIENT_DATA_HASH,
            origin: format!("https://{}", credential.rp_id),
            relying_party_id: credential.rp_id.clone(),
            allow_list: vec![PublicKeyCredentialDescriptor {
                id: credential.credential_id.clone(),
                transports: vec![Transport::USB],
            }],
            user_verification_req: uv_requirement(opts.require_uv),
            user_presence_req: true,
            extensions: AuthenticationExtensionsClientInputs {
                hmac_get_secret: Some(HMACGetSecretInput {
                    salt1: *salt,
                    // One salt per call. The extension's second slot exists to
                    // rotate two secrets in a single touch; we have no use for it,
                    // and leaving it unset keeps the request minimal.
                    salt2: None,
                }),
                ..Default::default()
            },
            pin: None,
            use_ctap1_fallback: false,
        };
        log::debug!(
            "getAssertion rp_id={:?} uv={:?} hmac_get_secret=1 salt timeout={:?}",
            args.relying_party_id,
            args.user_verification_req,
            opts.timeout
        );

        let (result_tx, result_rx) = channel();
        let callback = StateCallback::new(Box::new(move |rv| {
            if result_tx.send(rv).is_err() {
                log::debug!("assertion result arrived after the caller stopped waiting");
            }
        }));

        let started = Instant::now();
        service
            .sign(timeout_ms(opts.timeout), args, status_tx, callback)
            .map_err(|err| map_error(err, started, opts.timeout))?;

        let outcome = wait(result_rx, opts.timeout);
        drop(service);
        let _ = status_thread.join();

        let result = outcome?.map_err(|err| map_error(err, started, opts.timeout))?;

        let output = result
            .extensions
            .hmac_get_secret
            .ok_or_else(|| {
                log::error!(
                    "assertion succeeded but carried no hmac-secret output; \
                     the authenticator ignored the extension"
                );
                TokenError::HmacSecretUnsupported
            })?
            .output1;

        let secret = Zeroizing::new(output);
        log::info!(
            "derived 32-byte secret, fingerprint={}",
            crate::fingerprint(&*secret)
        );
        Ok(secret)
    }

    fn service() -> Result<AuthenticatorService, TokenError> {
        let mut service = AuthenticatorService::new().map_err(|err| {
            TokenError::Transport(format!("initializing authenticator service: {err}"))
        })?;
        service.add_u2f_usb_hid_platform_transports();
        log::debug!("USB HID transport registered");
        Ok(service)
    }

    fn uv_requirement(require_uv: bool) -> UserVerificationRequirement {
        if require_uv {
            UserVerificationRequirement::Required
        } else {
            // "Preferred" lets a device that mandates UV for hmac-secret ask for it,
            // while not forcing a PIN prompt on a device that does not.
            UserVerificationRequirement::Preferred
        }
    }

    fn timeout_ms(timeout: Duration) -> u64 {
        timeout.as_millis().try_into().unwrap_or(u64::MAX)
    }

    /// Wait for the backend's callback, with our own outer deadline as a backstop in
    /// case it never fires at all.
    fn wait<T>(
        result_rx: Receiver<Result<T, AuthenticatorError>>,
        timeout: Duration,
    ) -> Result<Result<T, AuthenticatorError>, TokenError> {
        match result_rx.recv_timeout(timeout + TIMEOUT_GRACE) {
            Ok(result) => Ok(result),
            Err(RecvTimeoutError::Timeout) => {
                log::error!("backend did not report a result within {timeout:?} (+grace)");
                Err(TokenError::Timeout)
            }
            Err(RecvTimeoutError::Disconnected) => Err(TokenError::Transport(
                "authenticator backend dropped the result channel without answering".to_string(),
            )),
        }
    }

    /// Relay status updates to the log, and answer PIN requests from the provider.
    ///
    /// Runs on its own thread because the backend publishes updates while the
    /// calling thread is blocked waiting for the final result.
    fn spawn_status_thread(
        status_rx: Receiver<StatusUpdate>,
        pin_provider: Option<PinProvider>,
    ) -> std::thread::JoinHandle<()> {
        std::thread::spawn(move || {
            while let Ok(update) = status_rx.recv() {
                match update {
                    StatusUpdate::PresenceRequired => {
                        log::info!("touch your security key now");
                    }
                    StatusUpdate::SelectDeviceNotice => {
                        log::info!(
                            "multiple authenticators connected; touch the one you want to use"
                        );
                    }
                    StatusUpdate::PinUvError(StatusPinUv::PinRequired(sender)) => {
                        supply_pin(&pin_provider, PinPrompt::Required, &sender);
                    }
                    StatusUpdate::PinUvError(StatusPinUv::InvalidPin(sender, attempts_left)) => {
                        log::warn!("PIN rejected; attempts left: {attempts_left:?}");
                        supply_pin(&pin_provider, PinPrompt::Invalid { attempts_left }, &sender);
                    }
                    StatusUpdate::PinUvError(StatusPinUv::InvalidUv(attempts_left)) => {
                        log::warn!("user verification failed; attempts left: {attempts_left:?}");
                    }
                    StatusUpdate::PinUvError(other) => {
                        log::error!("PIN/UV error: {other:?}");
                    }
                    StatusUpdate::SelectResultNotice(_, _) => {
                        log::warn!(
                            "authenticator returned multiple assertions; \
                             unexpected for a single-credential allow list"
                        );
                    }
                    StatusUpdate::InteractiveManagement(_) => {
                        log::warn!("unexpected interactive-management update");
                    }
                }
            }
            log::trace!("status channel closed");
        })
    }

    /// Ask the provider for a PIN and hand it to the backend. The PIN is moved
    /// straight into the channel and never logged.
    fn supply_pin(pin_provider: &Option<PinProvider>, prompt: PinPrompt, sender: &Sender<Pin>) {
        let Some(provider) = pin_provider else {
            // Dropping the sender without answering tells the backend to give up,
            // which surfaces as a PIN-related error the caller can map.
            log::error!("authenticator requires a PIN but no PIN provider was configured");
            return;
        };
        match provider(prompt) {
            Some(pin) => {
                log::debug!("supplying PIN to authenticator");
                if sender.send(Pin::new(&pin)).is_err() {
                    log::warn!("authenticator stopped waiting for the PIN");
                }
            }
            None => log::info!("PIN entry cancelled by the user"),
        }
    }

    /// Map a backend error onto this crate's coarse-grained error type.
    ///
    /// `started`/`timeout` are used to tell a genuine timeout from a decline: the
    /// backend reports both as a generic "not allowed", so the only signal
    /// distinguishing them is whether the clock ran out.
    fn map_error(err: AuthenticatorError, started: Instant, timeout: Duration) -> TokenError {
        log::debug!("backend error: {err:?}");
        let elapsed = started.elapsed();

        match err {
            AuthenticatorError::NoConfiguredTransports => TokenError::NoDevice,

            AuthenticatorError::CancelledByUser => {
                if elapsed >= timeout {
                    TokenError::Timeout
                } else {
                    TokenError::NotAllowed
                }
            }

            AuthenticatorError::U2FToken(_) => {
                if elapsed >= timeout {
                    TokenError::Timeout
                } else {
                    TokenError::NotAllowed
                }
            }

            AuthenticatorError::PinError(pin_error) => match pin_error {
                PinError::PinRequired => TokenError::PinRequired(
                    "the authenticator has a PIN set and it was not supplied",
                ),
                PinError::PinNotSet => TokenError::PinRequired(
                    "this operation requires user verification but the authenticator has no PIN set",
                ),
                PinError::PinAuthBlocked => TokenError::PinBlocked(
                    "too many PIN attempts in a row; unplug the key and plug it back in",
                ),
                PinError::PinBlocked => TokenError::PinBlocked(
                    "too many PIN attempts; the key must be factory reset to be usable again",
                ),
                PinError::UvBlocked => TokenError::PinBlocked(
                    "too many failed user-verification attempts; use the PIN instead",
                ),
                other => {
                    log::debug!("PIN error: {other:?}");
                    TokenError::NotAllowed
                }
            },

            AuthenticatorError::UnsupportedOption(option) => {
                log::error!("authenticator does not support a required option: {option:?}");
                TokenError::HmacSecretUnsupported
            }

            AuthenticatorError::HIDError(hid_error) => map_hid_error(hid_error),

            AuthenticatorError::Io(io_error) => {
                // On Windows a non-elevated process is denied read/write access to
                // FIDO HID devices, which arrives here as a permission error.
                if io_error.kind() == std::io::ErrorKind::PermissionDenied {
                    TokenError::DeviceAccess(io_error.to_string())
                } else {
                    TokenError::Transport(io_error.to_string())
                }
            }

            other => TokenError::Transport(format!("{other:?}")),
        }
    }

    fn map_hid_error(err: HIDError) -> TokenError {
        match err {
            HIDError::Command(CommandError::StatusCode(StatusCode::NoCredentials, _)) => {
                TokenError::UnknownCredential
            }
            HIDError::Command(CommandError::StatusCode(StatusCode::UnsupportedExtension, _)) => {
                TokenError::HmacSecretUnsupported
            }
            HIDError::Command(CommandError::StatusCode(StatusCode::OperationDenied, _)) => {
                TokenError::NotAllowed
            }
            HIDError::Command(CommandError::StatusCode(StatusCode::ActionTimeout, _)) => {
                TokenError::Timeout
            }
            HIDError::DeviceNotSupported => TokenError::HmacSecretUnsupported,
            HIDError::IO(path, io_error) => {
                if io_error.kind() == std::io::ErrorKind::PermissionDenied {
                    TokenError::DeviceAccess(format!("{path:?}: {io_error}"))
                } else {
                    TokenError::Transport(format!("{path:?}: {io_error}"))
                }
            }
            other => TokenError::Transport(format!("{other:?}")),
        }
    }

    fn hex(bytes: &[u8]) -> String {
        bytes.iter().map(|b| format!("{b:02x}")).collect()
    }

    #[cfg(test)]
    mod tests {
        use super::*;

        #[test]
        fn client_data_hash_is_32_bytes() {
            assert_eq!(CLIENT_DATA_HASH.len(), 32);
        }

        #[test]
        fn timeout_converts_without_overflow() {
            assert_eq!(timeout_ms(Duration::from_secs(30)), 30_000);
            assert_eq!(timeout_ms(Duration::MAX), u64::MAX);
        }

        #[test]
        fn uv_requirement_maps_both_ways() {
            assert_eq!(uv_requirement(true), UserVerificationRequirement::Required);
            assert_eq!(
                uv_requirement(false),
                UserVerificationRequirement::Preferred
            );
        }

        #[test]
        fn no_transports_means_no_device() {
            let err = map_error(
                AuthenticatorError::NoConfiguredTransports,
                Instant::now(),
                Duration::from_secs(30),
            );
            assert!(matches!(err, TokenError::NoDevice));
        }

        #[test]
        fn cancellation_within_the_deadline_is_a_decline_not_a_timeout() {
            let err = map_error(
                AuthenticatorError::CancelledByUser,
                Instant::now(),
                Duration::from_secs(30),
            );
            assert!(matches!(err, TokenError::NotAllowed));
        }

        #[test]
        fn cancellation_after_the_deadline_is_a_timeout() {
            let err = map_error(
                AuthenticatorError::CancelledByUser,
                Instant::now() - Duration::from_secs(31),
                Duration::from_secs(30),
            );
            assert!(matches!(err, TokenError::Timeout));
        }

        #[test]
        fn blocked_pins_are_reported_as_lockouts() {
            let now = Instant::now();
            let timeout = Duration::from_secs(30);
            assert!(matches!(
                map_error(
                    AuthenticatorError::PinError(PinError::PinBlocked),
                    now,
                    timeout
                ),
                TokenError::PinBlocked(_)
            ));
            assert!(matches!(
                map_error(
                    AuthenticatorError::PinError(PinError::PinAuthBlocked),
                    now,
                    timeout
                ),
                TokenError::PinBlocked(_)
            ));
        }

        #[test]
        fn a_missing_pin_is_distinct_from_a_decline() {
            let err = map_error(
                AuthenticatorError::PinError(PinError::PinRequired),
                Instant::now(),
                Duration::from_secs(30),
            );
            assert!(matches!(err, TokenError::PinRequired(_)));
        }

        #[test]
        fn permission_denied_is_reported_as_a_device_access_problem() {
            let err = map_error(
                AuthenticatorError::Io(std::io::Error::from(std::io::ErrorKind::PermissionDenied)),
                Instant::now(),
                Duration::from_secs(30),
            );
            assert!(matches!(err, TokenError::DeviceAccess(_)));
        }

        #[test]
        fn unknown_credential_is_recognized() {
            let err = map_hid_error(HIDError::Command(CommandError::StatusCode(
                StatusCode::NoCredentials,
                None,
            )));
            assert!(matches!(err, TokenError::UnknownCredential));
        }

        #[test]
        fn hex_renders_lowercase_fixed_width() {
            assert_eq!(hex(&[0x00, 0x0f, 0xff]), "000fff");
        }
    }
}
