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

    #[error("refusing to revoke the last remaining factor")]
    LastCredential,

    #[error("that security key is already enrolled in this vault")]
    AlreadyEnrolled,

    #[error("this vault already has the maximum of {max} enrolled credentials")]
    TooManyCredentials { max: usize },

    #[error("credential is for rp_id {found:?} but this vault uses {expected:?}")]
    RpIdMismatch { expected: String, found: String },

    #[error("authentication failed: wrong key, or the vault is corrupted or tampered with")]
    AuthenticationFailed,

    #[error("unsupported vault format version {found} (this build supports {supported})")]
    FormatVersionMismatch { found: u16, supported: u16 },

    #[error("this is a {found} vault; that operation needs a {expected} vault")]
    WrongMode { expected: Mode, found: Mode },

    #[error("header is {len} bytes, over the {max}-byte limit (too many enrolled credentials?)")]
    HeaderTooLarge { len: usize, max: usize },

    #[error("{0} is not a directory")]
    NotADirectory(std::path::PathBuf),

    #[error("malformed archive: {0}")]
    MalformedArchive(String),

    #[error("malformed payload: {0}")]
    MalformedPayload(String),

    #[error("no entry named {0:?} in this vault")]
    NoSuchEntry(String),

    #[error("invalid entry name: {0}")]
    InvalidEntryName(String),

    #[error("refusing to extract an unsafe archive path: {0}")]
    UnsafeArchivePath(String),

    #[error("keyfile cannot be used: {0}")]
    UnusableKeyfile(String),

    #[error("invalid key-derivation parameters: {0}")]
    InvalidKdfParams(String),

    #[error("this entry is a {found} factor; {expected} credentials were supplied")]
    WrongFactorKind {
        expected: &'static str,
        found: &'static str,
    },

    #[error("not yet implemented: {0}")]
    NotImplemented(&'static str),

    #[error("internal error: {0}")]
    Internal(String),
}
