/// Everything that can go wrong talking to a FIDO2/U2F authenticator.
///
/// Variants are deliberately coarse-grained (mirroring what a CLI/UI actually needs
/// to tell a user apart) rather than a 1:1 mirror of every CTAP2 status code — see
/// plan/01-crate-fido-token.md.
#[derive(thiserror::Error, Debug)]
pub enum TokenError {
    #[error("no FIDO authenticator found")]
    NoDevice,

    #[error("authenticator does not support the hmac-secret extension")]
    HmacSecretUnsupported,

    #[error("operation timed out waiting for user presence")]
    Timeout,

    #[error("user declined the request or provided an incorrect PIN")]
    NotAllowed,

    #[error("credential not recognized by any connected authenticator")]
    UnknownCredential,

    /// A PIN is required but no way to obtain one was supplied, or the user
    /// cancelled the prompt. Distinct from [`TokenError::NotAllowed`] so a CLI can
    /// say "this key has a PIN set, re-run without --no-pin" rather than "declined".
    #[error("PIN required but not supplied: {0}")]
    PinRequired(&'static str),

    /// The authenticator is locked out after too many bad PIN attempts. Recovering
    /// needs a replug (`PinAuthBlocked`) or a factory reset (`PinBlocked`), so this
    /// is worth telling the user about specifically.
    #[error("authenticator is locked out: {0}")]
    PinBlocked(&'static str),

    /// The device was found but could not be opened. On Windows this is the
    /// expected error for a non-elevated process, because Windows 10 1903+ reserves
    /// direct HID access to FIDO devices — see docs/M1-MANUAL-TESTING.md.
    #[error("cannot access authenticator (on Windows this usually means the process is not elevated): {0}")]
    DeviceAccess(String),

    #[error("transport error: {0}")]
    Transport(String),

    /// The crate was built without the `hardware` feature, so there is no real
    /// CTAP2 backend compiled in.
    #[error("built without the `hardware` feature; no real authenticator backend is available")]
    BackendUnavailable,

    #[error("not yet implemented: {0}")]
    NotImplemented(&'static str),
}
