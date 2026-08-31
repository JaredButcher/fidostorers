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

    #[error("transport error: {0}")]
    Transport(String),

    #[error("not yet implemented: {0}")]
    NotImplemented(&'static str),
}
