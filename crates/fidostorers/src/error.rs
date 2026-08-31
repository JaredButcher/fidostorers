#[derive(thiserror::Error, Debug)]
pub enum VaultError {
    #[error("I/O error: {0}")]
    Io(#[from] std::io::Error),

    #[error("credential not enrolled in this vault")]
    UnknownCredential,

    #[error("refusing to revoke the last remaining credential")]
    LastCredential,

    #[error("authentication failed: wrong key, or the vault is corrupted or tampered with")]
    AuthenticationFailed,

    #[error("unsupported vault format version {found} (this build supports {supported})")]
    FormatVersionMismatch { found: u16, supported: u16 },

    #[error("not yet implemented: {0}")]
    NotImplemented(&'static str),
}
