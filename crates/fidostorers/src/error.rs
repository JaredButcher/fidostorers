use crate::Mode;

#[derive(thiserror::Error, Debug)]
pub enum VaultError {
    #[error("I/O error: {0}")]
    Io(#[from] std::io::Error),

    #[error("not a fidostorers vault (bad magic bytes)")]
    NotAVault,

    #[error("malformed vault header: {0}")]
    MalformedHeader(String),

    #[error("credential not enrolled in this vault")]
    UnknownCredential,

    #[error("refusing to revoke the last remaining credential")]
    LastCredential,

    #[error("authentication failed: wrong key, or the vault is corrupted or tampered with")]
    AuthenticationFailed,

    #[error("unsupported vault format version {found} (this build supports {supported})")]
    FormatVersionMismatch { found: u16, supported: u16 },

    #[error("this is a {found} vault; that operation needs a {expected} vault")]
    WrongMode { expected: Mode, found: Mode },

    #[error("header is {len} bytes, over the {max}-byte limit (too many enrolled credentials?)")]
    HeaderTooLarge { len: usize, max: usize },

    #[error("not yet implemented: {0}")]
    NotImplemented(&'static str),

    #[error("internal error: {0}")]
    Internal(String),
}
