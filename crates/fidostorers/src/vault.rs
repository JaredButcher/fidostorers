//! Vault: header format, credential enrollment, and the payload pipeline, per
//! plan/03-vault-format-and-crypto.md.
//!
//! All three modes and multi-key enrollment are implemented: file mode (M2),
//! directory mode (M3), kv mode (M4), and enroll/revoke (M5). See plan/06-roadmap.md.
//!
//! # On-disk layout
//!
//! ```text
//! magic         4          b"FSTR"
//! format_version 2         u16 little-endian
//! header_len    4          u32 little-endian, length of the header body
//! header body   header_len postcard: mode, rp_id, credentials, payload_nonce, payload_len
//! header_mac    32         HMAC-SHA256(mac key, every byte above)
//! payload       payload_len + 16   XChaCha20-Poly1305 ciphertext + tag
//! ```
//!
//! This is the layout sketched in plan/03 with one addition: an explicit
//! `header_len`. It earns its four bytes twice over — it caps the header
//! allocation before a single unauthenticated byte is parsed, and it locates
//! `header_mac` without having to parse the body first, so `open` (and therefore
//! `fidostorers info`) reads only the header of a multi-gigabyte vault.
//!
//! Nothing in the header is secret, so none of it is encrypted; it is authenticated
//! by `header_mac`, which cannot be checked without the data key. Everything that
//! *acts* on header contents therefore verifies the MAC first — see
//! [`Vault::unlock_with`].

use std::fmt;
use std::fs::File;
use std::io::{self, Read, Seek, SeekFrom, Write};
use std::path::{Path, PathBuf};
use std::str::FromStr;

use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use zeroize::Zeroizing;

use crate::archive::{self, ExtractReport};
use crate::crypto;
use crate::kv::KvMap;
use crate::VaultError;

/// Format version written by this build. Bumped whenever the on-disk layout
/// changes in an incompatible way.
pub const FORMAT_VERSION: u16 = 2;

/// Version 1 had no [`Factor`] enum and no per-entry id: every entry was a FIDO2
/// credential. Still readable; rewritten as v2 on the next write. See
/// plan/10-keyfile-password-auth.md.
const FORMAT_VERSION_V1: u16 = 1;

const MAGIC: [u8; 4] = *b"FSTR";
/// magic + format_version + header_len.
const PREFIX_LEN: usize = 4 + 2 + 4;
const MAC_LEN: usize = 32;
/// XChaCha20-Poly1305 tag length.
const TAG_LEN: usize = 16;
/// A wrapped 32-byte data key: ciphertext + tag.
const WRAPPED_DATA_KEY_LEN: usize = 32 + TAG_LEN;

// Parse-time caps. Length prefixes are read from a file whose `header_mac` cannot
// be verified until after the data key is recovered, so a hostile or corrupt length
// must fail cleanly rather than drive a huge allocation. See plan/07 #5.
const MAX_HEADER_LEN: usize = 1 << 20;
const MAX_CREDENTIALS: usize = 64;
const MAX_RP_ID_LEN: usize = 253;
const MAX_LABEL_LEN: usize = 256;
const MAX_CREDENTIAL_ID_LEN: usize = 1024;

/// The payload shape a vault was created with; fixed for the vault's lifetime.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum Mode {
    /// Payload is exactly one file's bytes.
    File,
    /// Payload is a `tar` stream of a directory tree.
    Dir,
    /// Payload is a serialized `name -> bytes` map.
    Kv,
}

impl fmt::Display for Mode {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Mode::File => "file",
            Mode::Dir => "dir",
            Mode::Kv => "kv",
        })
    }
}

impl FromStr for Mode {
    type Err = String;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s {
            "file" => Ok(Mode::File),
            "dir" => Ok(Mode::Dir),
            "kv" => Ok(Mode::Kv),
            other => Err(format!("unknown mode {other:?}, expected file, dir, or kv")),
        }
    }
}

/// How one enrolled entry produces its KEK.
///
/// Both routes end at 32 bytes that unwrap the same data key, which is why adding a
/// second factor type touched nothing below the KEK (plan/10).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum Factor {
    /// A security key, via the CTAP2 `hmac-secret` extension.
    Fido2(fido_token::Credential),
    /// A keyfile and a password, via Argon2id.
    Keyfile(crate::KeyfileParams),
}

impl Factor {
    /// Short name for messages and `info` output.
    pub fn kind(&self) -> &'static str {
        match self {
            Factor::Fido2(_) => "fido2",
            Factor::Keyfile(_) => "keyfile",
        }
    }

    pub fn credential(&self) -> Option<&fido_token::Credential> {
        match self {
            Factor::Fido2(credential) => Some(credential),
            Factor::Keyfile(_) => None,
        }
    }
}

/// One enrolled entry in the vault header: everything needed to re-derive its KEK and
/// unwrap the data key, none of it secret on its own.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FactorEntry {
    /// Random at enrollment. A stable name for this entry regardless of factor type,
    /// since a keyfile factor has no credential ID to be named by.
    pub id: [u8; 16],
    pub factor: Factor,
    /// User-supplied label (e.g. "primary", "backup in safe"), for UX only.
    pub label: String,
    /// Fed to the KDF to derive this entry's KEK. Not secret: its job is domain
    /// separation between this vault and any other using the same key or keyfile.
    pub salt: [u8; 32],
    pub wrap_nonce: [u8; 24],
    /// XChaCha20-Poly1305 ciphertext + tag of the data key, under this entry's KEK,
    /// with empty associated data.
    pub wrapped_data_key: Vec<u8>,
}

impl FactorEntry {
    /// Lowercase hex of [`FactorEntry::id`], as `info` prints it and `revoke --id`
    /// accepts it.
    pub fn id_hex(&self) -> String {
        fido_token::to_hex(&self.id)
    }
}

/// A version-1 header entry, kept only so v1 vaults still open.
#[derive(Debug, Clone, Serialize, Deserialize)]
struct CredentialEntryV1 {
    credential: fido_token::Credential,
    label: String,
    salt: [u8; 32],
    wrap_nonce: [u8; 24],
    wrapped_data_key: Vec<u8>,
}

impl From<CredentialEntryV1> for FactorEntry {
    fn from(old: CredentialEntryV1) -> Self {
        // A v1 entry has no id. Derive one from its credential ID so the value is
        // stable across opens: a random id would change every time the vault was
        // read, and `revoke --id` would name a different entry each session.
        let mut hasher = Sha256::new();
        hasher.update(b"fidostorers-v1-entry-id");
        hasher.update(&old.credential.credential_id);
        let digest = hasher.finalize();
        let mut id = [0u8; 16];
        id.copy_from_slice(&digest[..16]);

        FactorEntry {
            id,
            factor: Factor::Fido2(old.credential),
            label: old.label,
            salt: old.salt,
            wrap_nonce: old.wrap_nonce,
            wrapped_data_key: old.wrapped_data_key,
        }
    }
}

/// Everything the caller must supply to give one security key the ability to unlock
/// a vault.
///
/// The salt travels with the KEK because the two are inseparable: the KEK is
/// `HKDF(hmac-secret(credential, salt))`, so a vault that stores the KEK's salt
/// wrongly can never re-derive it. Bundling them makes that impossible to get
/// wrong at a call site.
pub struct Enrollment {
    pub factor: Factor,
    /// The vault's relying-party identifier.
    ///
    /// A FIDO2 credential carries its own and must agree with this. A keyfile factor
    /// has no relying party at all — there is no authenticator involved — so it simply
    /// adopts whatever the vault uses, which is why this cannot be inferred from the
    /// factor alone.
    pub rp_id: String,
    pub label: String,
    /// The salt used to derive `kek`. Stored in the header verbatim.
    pub salt: [u8; 32],
    /// For a `Fido2` factor:
    /// `crypto::kek_from_secret(&fido_token::derive_secret(&credential, &salt, ..))`.
    /// For a `Keyfile` factor: `keyfile::derive_kek(&hash, password, &salt, &params)`.
    pub kek: Zeroizing<[u8; 32]>,
}

/// The version-1 header body, kept only so v1 vaults still open.
#[derive(Debug, Clone, Serialize, Deserialize)]
struct HeaderBodyV1 {
    mode: Mode,
    rp_id: String,
    credentials: Vec<CredentialEntryV1>,
    payload_nonce: [u8; 24],
    payload_len: u64,
}

impl From<HeaderBodyV1> for HeaderBody {
    fn from(old: HeaderBodyV1) -> Self {
        HeaderBody {
            mode: old.mode,
            rp_id: old.rp_id,
            credentials: old.credentials.into_iter().map(FactorEntry::from).collect(),
            payload_nonce: old.payload_nonce,
            payload_len: old.payload_len,
        }
    }
}

impl Enrollment {
    /// A FIDO2 credential that disagrees with the vault's rp_id could never derive a
    /// working KEK, so catching it here beats enrolling a factor that silently never
    /// works.
    fn check_rp_id(&self, vault_rp_id: &str) -> Result<(), VaultError> {
        let found = match &self.factor {
            Factor::Fido2(credential) => &credential.rp_id,
            Factor::Keyfile(_) => &self.rp_id,
        };
        if found == vault_rp_id {
            Ok(())
        } else {
            Err(VaultError::RpIdMismatch {
                expected: vault_rp_id.to_string(),
                found: found.clone(),
            })
        }
    }
}

/// The postcard-serialized part of the header.
#[derive(Debug, Clone, Serialize, Deserialize)]
struct HeaderBody {
    mode: Mode,
    rp_id: String,
    credentials: Vec<FactorEntry>,
    payload_nonce: [u8; 24],
    /// Plaintext length. The payload occupies `payload_len + TAG_LEN` bytes on disk.
    payload_len: u64,
}

/// Where the payload bytes for a write come from.
///
/// `enroll` and `revoke` change only the header, and re-encrypting the payload to
/// rewrite it would be both wasteful and pointless — so they stream the existing
/// ciphertext across unchanged rather than decrypting and resealing a possibly
/// enormous `dir` payload.
enum PayloadSource<'a> {
    Bytes(&'a [u8]),
    /// Copy `len` bytes from `offset` in the vault's current file.
    Existing {
        offset: u64,
        len: u64,
    },
}

/// An opened vault: its header, plus the exact header bytes the MAC covers.
#[derive(Debug, Clone)]
pub struct Vault {
    path: PathBuf,
    format_version: u16,
    body: HeaderBody,
    /// The literal bytes `header_mac` is computed over, as written to or read back
    /// from disk. Retained rather than re-serialized so that postcard's encoding
    /// stability is an ordinary compatibility concern, never a security property
    /// (plan/07 #5).
    mac_covered: Vec<u8>,
    header_mac: [u8; MAC_LEN],
}

impl Vault {
    /// Create a new vault at `path`, enrolled with a single credential and holding
    /// an empty payload.
    ///
    /// The vault's `rp_id` is taken from the credential, so the header and the
    /// credential can never disagree about it.
    pub fn create(path: &Path, mode: Mode, enrollment: &Enrollment) -> Result<Self, VaultError> {
        enrollment.check_rp_id(&enrollment.rp_id)?;
        if let Factor::Keyfile(params) = &enrollment.factor {
            params.validate_for_write()?;
        }
        let data_key = crypto::random_key();
        let entry = wrap_for(enrollment, &data_key)?;

        // A new vault's payload must already be a valid encoding for its mode, so
        // that `unlock`/`kv ls` on a vault nothing has been sealed into yet reads an
        // empty tree or an empty store rather than failing to parse zero bytes.
        let initial = Zeroizing::new(empty_payload(mode)?);
        let payload_nonce = crypto::random_nonce();
        let payload = crypto::seal(&data_key, &payload_nonce, &initial)?;

        let body = HeaderBody {
            mode,
            rp_id: enrollment.rp_id.clone(),
            credentials: vec![entry],
            payload_nonce,
            payload_len: initial.len() as u64,
        };

        let mut vault = Vault {
            path: path.to_path_buf(),
            format_version: FORMAT_VERSION,
            body,
            mac_covered: Vec::new(),
            header_mac: [0u8; MAC_LEN],
        };
        vault.write(&data_key, PayloadSource::Bytes(&payload))?;
        Ok(vault)
    }

    /// Load a vault's header from `path`. Requires no touch — the header contains
    /// nothing secret.
    ///
    /// **The result is unauthenticated.** `header_mac` cannot be checked without the
    /// data key, which needs a security key. Only the parse-time bounds and the
    /// format version have been enforced here; anything that acts on the contents
    /// must go through [`Vault::unlock_with`] first. This is what
    /// `fidostorers info` labels as unverified.
    pub fn open(path: &Path) -> Result<Self, VaultError> {
        let mut file = File::open(path)?;
        let file_len = file.metadata()?.len();

        let mut prefix = [0u8; PREFIX_LEN];
        read_exact(&mut file, &mut prefix, "header prefix")?;

        if prefix[..4] != MAGIC {
            return Err(VaultError::NotAVault);
        }
        let format_version = u16::from_le_bytes([prefix[4], prefix[5]]);
        if format_version != FORMAT_VERSION && format_version != FORMAT_VERSION_V1 {
            return Err(VaultError::FormatVersionMismatch {
                found: format_version,
                supported: FORMAT_VERSION,
            });
        }

        let header_len = u32::from_le_bytes([prefix[6], prefix[7], prefix[8], prefix[9]]) as usize;
        if header_len > MAX_HEADER_LEN {
            return Err(VaultError::MalformedHeader(format!(
                "header length {header_len} exceeds the {MAX_HEADER_LEN}-byte cap"
            )));
        }

        // Bounded by the check above, so this allocation is safe to make from an
        // as-yet unauthenticated length.
        let mut body_bytes = vec![0u8; header_len];
        read_exact(&mut file, &mut body_bytes, "header body")?;

        let mut header_mac = [0u8; MAC_LEN];
        read_exact(&mut file, &mut header_mac, "header MAC")?;

        // A v1 header has no `Factor` tag and no per-entry id, so it needs its own
        // parse; the result converts into the current shape and is written back as v2
        // on the next write (plan/10). `header_mac` is verified over the literal bytes
        // read here, so an upgrade is just a normal write, not a re-encoding.
        let body: HeaderBody = if format_version == FORMAT_VERSION_V1 {
            postcard::from_bytes::<HeaderBodyV1>(&body_bytes)
                .map_err(|err| {
                    VaultError::MalformedHeader(format!("cannot parse v1 header: {err}"))
                })?
                .into()
        } else {
            postcard::from_bytes(&body_bytes)
                .map_err(|err| VaultError::MalformedHeader(format!("cannot parse header: {err}")))?
        };
        validate(&body)?;

        let payload_offset = (PREFIX_LEN + header_len + MAC_LEN) as u64;
        let expected_len = payload_offset
            .checked_add(body.payload_len)
            .and_then(|n| n.checked_add(TAG_LEN as u64))
            .ok_or_else(|| {
                VaultError::MalformedHeader("payload length overflows the file size".to_string())
            })?;
        if file_len != expected_len {
            return Err(VaultError::MalformedHeader(format!(
                "file is {file_len} bytes but the header describes {expected_len}"
            )));
        }

        let mut mac_covered = Vec::with_capacity(PREFIX_LEN + header_len);
        mac_covered.extend_from_slice(&prefix);
        mac_covered.extend_from_slice(&body_bytes);

        Ok(Vault {
            path: path.to_path_buf(),
            format_version,
            body,
            mac_covered,
            header_mac,
        })
    }

    pub fn path(&self) -> &Path {
        &self.path
    }

    pub fn mode(&self) -> Mode {
        self.body.mode
    }

    pub fn rp_id(&self) -> &str {
        &self.body.rp_id
    }

    pub fn format_version(&self) -> u16 {
        self.format_version
    }

    pub fn credentials(&self) -> &[FactorEntry] {
        &self.body.credentials
    }

    /// Look an entry up by its entry id, falling back to a FIDO2 credential id.
    ///
    /// The fallback keeps `unlock_with` working for callers that still hold a
    /// credential id (and for `revoke --credential`), without making a keyfile factor
    /// unaddressable.
    fn find_entry(&self, id: &[u8]) -> Result<&FactorEntry, VaultError> {
        self.body
            .credentials
            .iter()
            .find(|entry| entry.id == id)
            .or_else(|| {
                self.body.credentials.iter().find(|entry| {
                    entry
                        .factor
                        .credential()
                        .is_some_and(|c| c.credential_id == id)
                })
            })
            .ok_or(VaultError::UnknownCredential)
    }

    fn position_of(&self, id: &[u8]) -> Option<usize> {
        let target = self.find_entry(id).ok()?.id;
        self.body.credentials.iter().position(|e| e.id == target)
    }

    /// Unwrap the data key using `credential_id`'s already-derived KEK, then verify
    /// the header.
    ///
    /// Note that every method below takes the data key as a plain `&[u8; 32]` rather
    /// than a particular wrapper. A one-shot command holds it in a `Zeroizing`; a
    /// session holds it in a page-locked [`crate::hardening::SecretKey`]. Both deref
    /// to the same bytes, and the vault has no business caring which — the same
    /// reasoning that keeps `unlock_with` taking an already-derived KEK.
    ///
    /// The order matters and follows plan/03: unwrap the data key, derive the MAC
    /// key, verify `header_mac`, and only then may a caller act on `mode`, a label,
    /// or the payload. Using the data key solely to check a MAC before the header is
    /// trusted emits no plaintext and dispatches on nothing, so it is safe to do in
    /// that order — and it is the only possible order, since the MAC key comes from
    /// the data key.
    ///
    /// Returns [`VaultError::UnknownCredential`] if that credential is not enrolled,
    /// and [`VaultError::AuthenticationFailed`] if the KEK is wrong (the local
    /// stand-in for "touched the wrong security key") or the vault was tampered
    /// with.
    pub fn unlock_with(
        &self,
        credential_id: &[u8],
        kek: Zeroizing<[u8; 32]>,
    ) -> Result<Zeroizing<[u8; 32]>, VaultError> {
        let entry = self.find_entry(credential_id)?;
        let unwrapped = crypto::unseal(&kek, &entry.wrap_nonce, &entry.wrapped_data_key)?;

        let data_key: Zeroizing<[u8; 32]> = Zeroizing::new(
            unwrapped
                .as_slice()
                .try_into()
                .map_err(|_| VaultError::AuthenticationFailed)?,
        );
        self.verify_header(&data_key)?;
        Ok(data_key)
    }

    fn verify_header(&self, data_key: &[u8; 32]) -> Result<(), VaultError> {
        let mac_key = crypto::mac_key_from_data_key(data_key);
        crypto::verify_header_mac(&mac_key, &self.mac_covered, &self.header_mac)
    }

    fn expect_mode(&self, expected: Mode) -> Result<(), VaultError> {
        if self.body.mode == expected {
            Ok(())
        } else {
            Err(VaultError::WrongMode {
                expected,
                found: self.body.mode,
            })
        }
    }

    /// Enroll an additional credential, so it can independently unlock this vault.
    /// Requires the already-unwrapped `data_key` (from a prior `unlock_with`).
    ///
    /// Only this credential's entry is added; no other entry is re-wrapped, so a
    /// backup key sitting in a safe is unaffected and need not be present.
    pub fn enroll(
        &mut self,
        data_key: &[u8; 32],
        enrollment: &Enrollment,
    ) -> Result<(), VaultError> {
        self.verify_header(data_key)?;

        enrollment.check_rp_id(&self.body.rp_id)?;
        if let Factor::Keyfile(params) = &enrollment.factor {
            params.validate_for_write()?;
        }
        // Only a FIDO2 credential can be "already enrolled" in a detectable way. Two
        // keyfile factors over the same file and password are legitimate (different
        // salts, different labels) and indistinguishable from here without the
        // password, so there is nothing to check.
        if let Some(new) = enrollment.factor.credential() {
            if self.body.credentials.iter().any(|entry| {
                entry
                    .factor
                    .credential()
                    .is_some_and(|c| c.credential_id == new.credential_id)
            }) {
                return Err(VaultError::AlreadyEnrolled);
            }
        }
        if self.body.credentials.len() >= MAX_CREDENTIALS {
            return Err(VaultError::TooManyCredentials {
                max: MAX_CREDENTIALS,
            });
        }

        self.body.credentials.push(wrap_for(enrollment, data_key)?);
        if let Err(err) = self.rewrite_header(data_key) {
            self.body.credentials.pop();
            return Err(err);
        }
        Ok(())
    }

    /// Remove a credential's ability to unlock this vault. Refuses to remove the
    /// last remaining credential, so a vault can never be left unopenable.
    ///
    /// Takes `data_key` because removing an entry changes the header, and
    /// `header_mac` must be recomputed under a key derived from it. The caller
    /// already holds it: revoking requires unlocking with a surviving credential
    /// first. No other credential's wrapped key needs re-wrapping, which is what
    /// lets a backup key in a safe keep working without being present for the
    /// revoke (plan/07 #5b).
    /// **Revocation does not re-key the vault.** The data key is unchanged, so
    /// anyone holding both the revoked key *and* a copy of this file from before
    /// the revoke can still recover that data key — and it still decrypts the
    /// current payload. See plan/04-security-and-threat-model.md.
    pub fn revoke(&mut self, data_key: &[u8; 32], credential_id: &[u8]) -> Result<(), VaultError> {
        // Verify before acting on any header content, per plan/03's ordering.
        self.verify_header(data_key)?;

        let index = self
            .position_of(credential_id)
            .ok_or(VaultError::UnknownCredential)?;
        if self.body.credentials.len() <= 1 {
            return Err(VaultError::LastCredential);
        }

        let removed = self.body.credentials.remove(index);
        if let Err(err) = self.rewrite_header(data_key) {
            self.body.credentials.insert(index, removed);
            return Err(err);
        }
        Ok(())
    }

    /// Rewrite the header, carrying the existing payload ciphertext across
    /// untouched. Used by `enroll`/`revoke`, which change no payload bytes.
    fn rewrite_header(&mut self, data_key: &[u8; 32]) -> Result<(), VaultError> {
        let source = PayloadSource::Existing {
            offset: self.payload_offset(),
            len: self.body.payload_len + TAG_LEN as u64,
        };
        self.write(data_key, source)
    }

    /// (mode = File) Encrypt `input`'s bytes into this vault.
    ///
    /// Takes `&mut self` because sealing draws a fresh `payload_nonce` and changes
    /// `payload_len` — both header fields — so the in-memory header would otherwise
    /// go stale against the file just written.
    pub fn seal_file(&mut self, data_key: &[u8; 32], input: &Path) -> Result<(), VaultError> {
        self.expect_mode(Mode::File)?;
        let plaintext = Zeroizing::new(std::fs::read(input)?);
        self.seal_payload(data_key, &plaintext)
    }

    /// (mode = File) Decrypt this vault's payload to `output`.
    pub fn open_file(&self, data_key: &[u8; 32], output: &Path) -> Result<(), VaultError> {
        self.expect_mode(Mode::File)?;
        let plaintext = self.open_payload(data_key)?;
        std::fs::write(output, &plaintext[..])?;
        Ok(())
    }

    /// Encrypt `plaintext` as the whole payload and rewrite the vault atomically.
    /// Shared by every mode: file bytes today, a tar stream in M3, a serialized map
    /// in M4.
    fn seal_payload(&mut self, data_key: &[u8; 32], plaintext: &[u8]) -> Result<(), VaultError> {
        self.verify_header(data_key)?;
        let payload_nonce = crypto::random_nonce();
        let payload = crypto::seal(data_key, &payload_nonce, plaintext)?;

        let previous = (self.body.payload_nonce, self.body.payload_len);
        self.body.payload_nonce = payload_nonce;
        self.body.payload_len = plaintext.len() as u64;

        // Restore the in-memory header if the write fails, so a caller that ignores
        // the error can't go on to act on a header that never reached disk.
        if let Err(err) = self.write(data_key, PayloadSource::Bytes(&payload)) {
            self.body.payload_nonce = previous.0;
            self.body.payload_len = previous.1;
            return Err(err);
        }
        Ok(())
    }

    /// Verify the header, then decrypt and return the whole payload.
    fn open_payload(&self, data_key: &[u8; 32]) -> Result<Zeroizing<Vec<u8>>, VaultError> {
        self.verify_header(data_key)?;

        let payload_len = usize::try_from(self.body.payload_len).map_err(|_| {
            VaultError::MalformedHeader("payload is larger than this platform can address".into())
        })?;

        let mut file = File::open(&self.path)?;
        file.seek(SeekFrom::Start(self.payload_offset()))?;
        let mut ciphertext = vec![0u8; payload_len + TAG_LEN];
        read_exact(&mut file, &mut ciphertext, "payload")?;

        crypto::unseal(data_key, &self.body.payload_nonce, &ciphertext)
    }

    fn payload_offset(&self) -> u64 {
        (self.mac_covered.len() + MAC_LEN) as u64
    }

    /// Serialize the header, MAC it under a key derived from `data_key`, and write
    /// header + payload to a temp file in the vault's own directory before renaming
    /// it into place. The rename is atomic on both Linux and Windows for same-volume
    /// moves, so a crash mid-write cannot corrupt an existing vault.
    fn write(&mut self, data_key: &[u8; 32], payload: PayloadSource<'_>) -> Result<(), VaultError> {
        let body_bytes = postcard::to_stdvec(&self.body)
            .map_err(|err| VaultError::Internal(format!("cannot serialize header: {err}")))?;
        if body_bytes.len() > MAX_HEADER_LEN {
            return Err(VaultError::HeaderTooLarge {
                len: body_bytes.len(),
                max: MAX_HEADER_LEN,
            });
        }

        // Always emit the current version: a v1 vault read above is upgraded here.
        self.format_version = FORMAT_VERSION;

        let mut mac_covered = Vec::with_capacity(PREFIX_LEN + body_bytes.len());
        mac_covered.extend_from_slice(&MAGIC);
        mac_covered.extend_from_slice(&self.format_version.to_le_bytes());
        mac_covered.extend_from_slice(&(body_bytes.len() as u32).to_le_bytes());
        mac_covered.extend_from_slice(&body_bytes);

        let mac_key = crypto::mac_key_from_data_key(data_key);
        let header_mac = crypto::header_mac(&mac_key, &mac_covered);

        let directory = self.path.parent().filter(|p| !p.as_os_str().is_empty());
        let directory = directory.unwrap_or_else(|| Path::new("."));
        let mut temp = tempfile::NamedTempFile::new_in(directory)?;
        temp.write_all(&mac_covered)?;
        temp.write_all(&header_mac)?;
        match payload {
            PayloadSource::Bytes(bytes) => temp.write_all(bytes)?,
            PayloadSource::Existing { offset, len } => {
                // Stream it rather than buffering: a `dir` vault's payload can be
                // arbitrarily large, and none of it is changing.
                let mut current = File::open(&self.path)?;
                current.seek(SeekFrom::Start(offset))?;
                let copied = io::copy(&mut current.take(len), &mut temp)?;
                if copied != len {
                    return Err(VaultError::MalformedHeader(format!(
                        "expected {len} payload bytes but the file holds {copied}"
                    )));
                }
            }
        }
        temp.flush()?;
        temp.as_file().sync_all()?;
        temp.persist(&self.path)
            .map_err(|err| VaultError::Io(err.error))?;

        self.mac_covered = mac_covered;
        self.header_mac = header_mac;
        Ok(())
    }

    /// (mode = Dir) Archive `input_dir` into a tar stream and encrypt it into this
    /// vault. Symlinks are stored as symlinks, never followed; Unix mode bits are
    /// preserved (plan/07 #8).
    pub fn seal_dir(&mut self, data_key: &[u8; 32], input_dir: &Path) -> Result<(), VaultError> {
        self.expect_mode(Mode::Dir)?;
        let tar = Zeroizing::new(archive::build(input_dir)?);
        self.seal_payload(data_key, &tar)
    }

    /// (mode = File) Seal bytes that are already in hand.
    ///
    /// A session has just read the working file to decide whether anything changed
    /// ([`crate::workdir`]), so re-reading it through [`Vault::seal_file`] would be
    /// a second full read of the same bytes for no benefit.
    pub(crate) fn seal_file_bytes(
        &mut self,
        data_key: &[u8; 32],
        plaintext: &[u8],
    ) -> Result<(), VaultError> {
        self.expect_mode(Mode::File)?;
        self.seal_payload(data_key, plaintext)
    }

    /// (mode = Dir) Seal a tar stream that is already built.
    ///
    /// Same reason as [`Vault::seal_file_bytes`], and it matters more here: for a
    /// large tree, building the archive is the expensive half of a seal, and a
    /// session has already built it to decide whether the seal was needed at all.
    pub(crate) fn seal_dir_archive(
        &mut self,
        data_key: &[u8; 32],
        tar: &[u8],
    ) -> Result<(), VaultError> {
        self.expect_mode(Mode::Dir)?;
        self.seal_payload(data_key, tar)
    }

    /// (mode = File) Decrypt this vault's payload to a byte buffer.
    pub(crate) fn read_file_payload(
        &self,
        data_key: &[u8; 32],
    ) -> Result<Zeroizing<Vec<u8>>, VaultError> {
        self.expect_mode(Mode::File)?;
        self.open_payload(data_key)
    }

    /// (mode = Dir) Decrypt this vault's payload to its tar stream.
    pub(crate) fn read_dir_archive(
        &self,
        data_key: &[u8; 32],
    ) -> Result<Zeroizing<Vec<u8>>, VaultError> {
        self.expect_mode(Mode::Dir)?;
        self.open_payload(data_key)
    }

    /// (mode = Dir) Decrypt and extract this vault's payload into `output_dir`.
    ///
    /// Extraction is best-effort per platform, so this returns an
    /// [`ExtractReport`] rather than `()`: on Windows a symlink may be
    /// unreproducible, and the caller has to be able to tell a partial extraction
    /// from a complete one. Check [`ExtractReport::is_complete`].
    pub fn open_dir(
        &self,
        data_key: &[u8; 32],
        output_dir: &Path,
    ) -> Result<ExtractReport, VaultError> {
        self.expect_mode(Mode::Dir)?;
        let tar = self.open_payload(data_key)?;
        archive::extract(&tar, output_dir)
    }

    /// (mode = Kv) Set (inserting or overwriting) one entry.
    ///
    /// Rewrites the whole vault: the store is one AEAD-sealed blob, so there is no
    /// such thing as touching a single entry on disk. See the trade-off note in
    /// plan/02-crate-fidostorers.md.
    pub fn kv_set(
        &mut self,
        data_key: &[u8; 32],
        name: &str,
        value: &[u8],
    ) -> Result<(), VaultError> {
        let mut store = self.load_kv(data_key)?;
        store.insert(name, value)?;
        let encoded = Zeroizing::new(store.encode()?);
        self.seal_payload(data_key, &encoded)
    }

    /// (mode = Kv) Get one entry's value.
    pub fn kv_get(
        &self,
        data_key: &[u8; 32],
        name: &str,
    ) -> Result<Zeroizing<Vec<u8>>, VaultError> {
        let store = self.load_kv(data_key)?;
        store
            .get(name)
            .map(|value| Zeroizing::new(value.to_vec()))
            .ok_or_else(|| VaultError::NoSuchEntry(name.to_string()))
    }

    /// (mode = Kv) Remove one entry. Errors if it was not there, so a typo'd name
    /// cannot look like a successful deletion.
    pub fn kv_rm(&mut self, data_key: &[u8; 32], name: &str) -> Result<(), VaultError> {
        let mut store = self.load_kv(data_key)?;
        if !store.remove(name) {
            return Err(VaultError::NoSuchEntry(name.to_string()));
        }
        let encoded = Zeroizing::new(store.encode()?);
        self.seal_payload(data_key, &encoded)
    }

    /// (mode = Kv) List entry names, sorted.
    pub fn kv_ls(&self, data_key: &[u8; 32]) -> Result<Vec<String>, VaultError> {
        Ok(self.load_kv(data_key)?.names())
    }

    /// Verify the header, decrypt the payload, and parse it as a kv store.
    fn load_kv(&self, data_key: &[u8; 32]) -> Result<KvMap, VaultError> {
        self.expect_mode(Mode::Kv)?;
        let plaintext = self.open_payload(data_key)?;
        KvMap::decode(&plaintext)
    }
}

/// The payload a freshly created vault holds: empty, but valid for its mode.
fn empty_payload(mode: Mode) -> Result<Vec<u8>, VaultError> {
    match mode {
        Mode::File => Ok(Vec::new()),
        Mode::Dir => archive::empty(),
        Mode::Kv => KvMap::default().encode(),
    }
}

fn wrap_for(enrollment: &Enrollment, data_key: &[u8; 32]) -> Result<FactorEntry, VaultError> {
    let wrap_nonce = crypto::random_nonce();
    let wrapped_data_key = crypto::seal(&enrollment.kek, &wrap_nonce, &data_key[..])?;
    let mut id = [0u8; 16];
    rand::RngCore::fill_bytes(&mut rand::rngs::OsRng, &mut id);
    Ok(FactorEntry {
        id,
        factor: enrollment.factor.clone(),
        label: enrollment.label.clone(),
        salt: enrollment.salt,
        wrap_nonce,
        wrapped_data_key,
    })
}

/// Bounds that postcard's own framing does not imply. These run before the header
/// is authenticated, so they must be total: every one is a "this cannot be a vault
/// we wrote" check, never a judgement call.
fn validate(body: &HeaderBody) -> Result<(), VaultError> {
    let malformed = |msg: String| Err(VaultError::MalformedHeader(msg));

    if body.rp_id.len() > MAX_RP_ID_LEN {
        return malformed(format!(
            "rp_id is {} bytes, over the {MAX_RP_ID_LEN}-byte cap",
            body.rp_id.len()
        ));
    }
    if body.credentials.is_empty() {
        return malformed("vault has no enrolled credentials".to_string());
    }
    if body.credentials.len() > MAX_CREDENTIALS {
        return malformed(format!(
            "{} credentials, over the {MAX_CREDENTIALS} cap",
            body.credentials.len()
        ));
    }
    let mut seen_ids = std::collections::HashSet::new();
    for (i, entry) in body.credentials.iter().enumerate() {
        if !seen_ids.insert(entry.id) {
            return malformed(format!("entry {i} reuses another entry's id"));
        }
        match &entry.factor {
            Factor::Fido2(credential) => {
                if credential.credential_id.is_empty() {
                    return malformed(format!("credential {i} has an empty id"));
                }
                if credential.credential_id.len() > MAX_CREDENTIAL_ID_LEN {
                    return malformed(format!(
                        "credential {i}'s id is {} bytes, over the {MAX_CREDENTIAL_ID_LEN}-byte cap",
                        credential.credential_id.len()
                    ));
                }
                // `fido_token::Credential` carries its own rp_id, so the header states
                // it twice. `create` sources both from the same place; a file where
                // they disagree was not written by us.
                if credential.rp_id != body.rp_id {
                    return malformed(format!(
                        "credential {i}'s rp_id {:?} does not match the vault's {:?}",
                        credential.rp_id, body.rp_id
                    ));
                }
            }
            // Read before `header_mac` can be verified, and they drive an allocation,
            // so these are capped exactly like the header's length prefixes.
            Factor::Keyfile(params) => params.validate_for_read()?,
        }
        if entry.label.len() > MAX_LABEL_LEN {
            return malformed(format!(
                "credential {i}'s label is {} bytes, over the {MAX_LABEL_LEN}-byte cap",
                entry.label.len()
            ));
        }
        if entry.wrapped_data_key.len() != WRAPPED_DATA_KEY_LEN {
            return malformed(format!(
                "credential {i}'s wrapped key is {} bytes, expected {WRAPPED_DATA_KEY_LEN}",
                entry.wrapped_data_key.len()
            ));
        }
    }
    Ok(())
}

/// `read_exact`, but a short file reports as a malformed header rather than a bare
/// `UnexpectedEof`.
fn read_exact(file: &mut File, buf: &mut [u8], what: &str) -> Result<(), VaultError> {
    file.read_exact(buf).map_err(|err| {
        if err.kind() == std::io::ErrorKind::UnexpectedEof {
            VaultError::MalformedHeader(format!("file ends in the middle of the {what}"))
        } else {
            VaultError::Io(err)
        }
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use rand::rngs::OsRng;
    use rand::RngCore;
    use tempfile::TempDir;

    const KEK_A: [u8; 32] = [7u8; 32];
    const KEK_B: [u8; 32] = [9u8; 32];

    fn credential(id: u8) -> fido_token::Credential {
        fido_token::Credential {
            rp_id: "fidostorers.local".to_string(),
            credential_id: vec![id, id, id],
            device_hint: Some("Test Key".to_string()),
        }
    }

    /// Stands in for "the CLI touched a key and ran the output through HKDF" — the
    /// whole point of the KEK-in / KEK-out seam is that a test can just pick bytes.
    fn enrollment(id: u8, kek: [u8; 32]) -> Enrollment {
        Enrollment {
            factor: Factor::Fido2(credential(id)),
            rp_id: "fidostorers.local".to_string(),
            label: "primary".to_string(),
            salt: [id; 32],
            kek: Zeroizing::new(kek),
        }
    }

    /// A keyfile factor with the cheapest parameters the validator accepts, so tests
    /// exercising the format do not each pay for a real Argon2 run.
    fn keyfile_enrollment(kek: [u8; 32], label: &str) -> Enrollment {
        Enrollment {
            factor: Factor::Keyfile(crate::KeyfileParams {
                m_cost_kib: crate::keyfile::MIN_M_COST_KIB,
                t_cost: crate::keyfile::MIN_T_COST,
                parallelism: crate::keyfile::MIN_PARALLELISM,
            }),
            rp_id: "fidostorers.local".to_string(),
            label: label.to_string(),
            salt: [0x5A; 32],
            kek: Zeroizing::new(kek),
        }
    }

    fn new_vault(dir: &TempDir, mode: Mode) -> (PathBuf, Vault) {
        let path = dir.path().join("test.fido");
        let vault = Vault::create(&path, mode, &enrollment(1, KEK_A)).unwrap();
        (path, vault)
    }

    fn kek(bytes: [u8; 32]) -> Zeroizing<[u8; 32]> {
        Zeroizing::new(bytes)
    }

    fn corrupt(path: &Path, edit: impl FnOnce(&mut Vec<u8>)) {
        let mut bytes = std::fs::read(path).unwrap();
        edit(&mut bytes);
        std::fs::write(path, &bytes).unwrap();
    }

    // ---------- round trips ----------

    #[test]
    fn file_round_trip_over_a_range_of_sizes() {
        for size in [0usize, 1, 100, 3 * 1024 * 1024] {
            let dir = TempDir::new().unwrap();
            let (path, mut vault) = new_vault(&dir, Mode::File);

            let mut plaintext = vec![0u8; size];
            OsRng.fill_bytes(&mut plaintext);
            let input = dir.path().join("input.bin");
            std::fs::write(&input, &plaintext).unwrap();

            let data_key = vault
                .unlock_with(&credential(1).credential_id, kek(KEK_A))
                .unwrap();
            vault.seal_file(&data_key, &input).unwrap();

            // Reopen from disk rather than reusing the in-memory vault, so the test
            // exercises the parse path too.
            let reopened = Vault::open(&path).unwrap();
            let data_key = reopened
                .unlock_with(&credential(1).credential_id, kek(KEK_A))
                .unwrap();
            let output = dir.path().join("output.bin");
            reopened.open_file(&data_key, &output).unwrap();

            assert_eq!(std::fs::read(&output).unwrap(), plaintext, "size {size}");
        }
    }

    #[test]
    fn header_survives_a_round_trip_to_disk() {
        let dir = TempDir::new().unwrap();
        let (path, _) = new_vault(&dir, Mode::File);
        let vault = Vault::open(&path).unwrap();

        assert_eq!(vault.mode(), Mode::File);
        assert_eq!(vault.rp_id(), "fidostorers.local");
        assert_eq!(vault.format_version(), FORMAT_VERSION);
        assert_eq!(vault.credentials().len(), 1);
        assert_eq!(vault.credentials()[0].label, "primary");
        assert_eq!(vault.credentials()[0].salt, [1u8; 32]);
        assert_eq!(vault.path(), path);
    }

    #[test]
    fn the_data_key_is_stable_across_reopens() {
        let dir = TempDir::new().unwrap();
        let (path, vault) = new_vault(&dir, Mode::File);
        let first = vault
            .unlock_with(&credential(1).credential_id, kek(KEK_A))
            .unwrap();

        let reopened = Vault::open(&path).unwrap();
        let second = reopened
            .unlock_with(&credential(1).credential_id, kek(KEK_A))
            .unwrap();
        assert_eq!(*first, *second);
    }

    #[test]
    fn resealing_draws_a_fresh_payload_nonce() {
        // The data key is fixed for the vault's lifetime and every write re-encrypts
        // the whole payload, so a repeated nonce would leak the XOR of two versions
        // to anyone holding both (plan/03, "AEAD nonce discipline").
        let dir = TempDir::new().unwrap();
        let (path, mut vault) = new_vault(&dir, Mode::File);
        let input = dir.path().join("input.bin");
        std::fs::write(&input, b"same bytes every time").unwrap();

        let data_key = vault
            .unlock_with(&credential(1).credential_id, kek(KEK_A))
            .unwrap();
        vault.seal_file(&data_key, &input).unwrap();
        let first = std::fs::read(&path).unwrap();
        vault.seal_file(&data_key, &input).unwrap();
        let second = std::fs::read(&path).unwrap();

        assert_ne!(
            first, second,
            "identical input must not produce identical ciphertext"
        );
    }

    #[test]
    fn no_key_material_is_written_in_the_clear() {
        let dir = TempDir::new().unwrap();
        let (path, vault) = new_vault(&dir, Mode::File);
        let data_key = vault
            .unlock_with(&credential(1).credential_id, kek(KEK_A))
            .unwrap();

        let bytes = std::fs::read(&path).unwrap();
        assert!(
            !bytes.windows(32).any(|w| w == &data_key[..]),
            "the data key appears verbatim in the vault file"
        );
        assert!(
            !bytes.windows(32).any(|w| w == KEK_A),
            "the KEK appears verbatim in the vault file"
        );
    }

    // ---------- wrong key ----------

    #[test]
    fn unlock_with_wrong_kek_fails_cleanly() {
        // The local stand-in for "touched the wrong security key".
        let dir = TempDir::new().unwrap();
        let (_, vault) = new_vault(&dir, Mode::File);
        let err = vault
            .unlock_with(&credential(1).credential_id, kek(KEK_B))
            .unwrap_err();
        assert!(
            matches!(err, VaultError::AuthenticationFailed),
            "got {err:?}"
        );
    }

    #[test]
    fn unlock_with_rejects_unknown_credential() {
        let dir = TempDir::new().unwrap();
        let (_, vault) = new_vault(&dir, Mode::File);
        let err = vault.unlock_with(&[0xFF], kek(KEK_A)).unwrap_err();
        assert!(matches!(err, VaultError::UnknownCredential), "got {err:?}");
    }

    // ---------- tamper detection ----------

    #[test]
    fn tampering_with_the_payload_is_detected() {
        let dir = TempDir::new().unwrap();
        let (path, mut vault) = new_vault(&dir, Mode::File);
        let input = dir.path().join("input.bin");
        std::fs::write(&input, b"secret contents").unwrap();
        let data_key = vault
            .unlock_with(&credential(1).credential_id, kek(KEK_A))
            .unwrap();
        vault.seal_file(&data_key, &input).unwrap();

        corrupt(&path, |bytes| {
            let last = bytes.len() - 1;
            bytes[last] ^= 1;
        });

        let vault = Vault::open(&path).unwrap();
        let data_key = vault
            .unlock_with(&credential(1).credential_id, kek(KEK_A))
            .unwrap();
        let err = vault
            .open_file(&data_key, &dir.path().join("out.bin"))
            .unwrap_err();
        assert!(
            matches!(err, VaultError::AuthenticationFailed),
            "got {err:?}"
        );
        assert!(
            !dir.path().join("out.bin").exists(),
            "a failed decrypt must not write a partial file"
        );
    }

    #[test]
    fn relabelling_a_credential_is_detected_by_the_header_mac() {
        // A label feeds no key derivation, so the AEAD tags alone would not notice.
        // This is one of the three things header_mac exists for (plan/03).
        let dir = TempDir::new().unwrap();
        let (path, _) = new_vault(&dir, Mode::File);

        corrupt(&path, |bytes| {
            let at = bytes
                .windows(7)
                .position(|w| w == b"primary")
                .expect("the label is in the header");
            bytes[at] = b'P';
        });

        let vault = Vault::open(&path).unwrap();
        assert_eq!(vault.credentials()[0].label, "Primary", "the edit landed");
        let err = vault
            .unlock_with(&credential(1).credential_id, kek(KEK_A))
            .unwrap_err();
        assert!(
            matches!(err, VaultError::AuthenticationFailed),
            "got {err:?}"
        );
    }

    #[test]
    fn tampering_with_a_salt_is_detected() {
        let dir = TempDir::new().unwrap();
        let (path, _) = new_vault(&dir, Mode::File);

        corrupt(&path, |bytes| {
            let at = bytes
                .windows(32)
                .position(|w| w == [1u8; 32])
                .expect("the salt is in the header");
            bytes[at] ^= 0xFF;
        });

        let vault = Vault::open(&path).unwrap();
        let err = vault
            .unlock_with(&credential(1).credential_id, kek(KEK_A))
            .unwrap_err();
        assert!(
            matches!(err, VaultError::AuthenticationFailed),
            "got {err:?}"
        );
    }

    #[test]
    fn tampering_with_the_wrapped_key_is_detected() {
        let dir = TempDir::new().unwrap();
        let (path, vault) = new_vault(&dir, Mode::File);
        let wrapped = vault.credentials()[0].wrapped_data_key.clone();

        corrupt(&path, |bytes| {
            let at = bytes
                .windows(wrapped.len())
                .position(|w| w == wrapped)
                .expect("the wrapped data key is in the header");
            bytes[at] ^= 1;
        });

        let vault = Vault::open(&path).unwrap();
        let err = vault
            .unlock_with(&credential(1).credential_id, kek(KEK_A))
            .unwrap_err();
        assert!(
            matches!(err, VaultError::AuthenticationFailed),
            "got {err:?}"
        );
    }

    #[test]
    fn flipping_the_mode_is_detected_by_the_header_mac() {
        // Like a label, `mode` feeds no key derivation, so only header_mac catches
        // it. Silently turning a file vault into a dir vault is exactly the kind of
        // header edit plan/03 says the MAC is there for.
        let dir = TempDir::new().unwrap();
        let (path, _) = new_vault(&dir, Mode::File);

        // `mode` is the first field of the body, right after the 10-byte prefix.
        corrupt(&path, |bytes| bytes[PREFIX_LEN] = 1);

        let vault = Vault::open(&path).unwrap();
        assert_eq!(vault.mode(), Mode::Dir, "the edit landed");
        let err = vault
            .unlock_with(&credential(1).credential_id, kek(KEK_A))
            .unwrap_err();
        assert!(
            matches!(err, VaultError::AuthenticationFailed),
            "got {err:?}"
        );
    }

    // ---------- malformed input ----------

    #[test]
    fn rejects_a_file_that_is_not_a_vault() {
        let dir = TempDir::new().unwrap();
        let path = dir.path().join("not.fido");
        std::fs::write(&path, b"this is just some file, honestly").unwrap();
        assert!(matches!(Vault::open(&path), Err(VaultError::NotAVault)));
    }

    #[test]
    fn rejects_an_unknown_format_version() {
        let dir = TempDir::new().unwrap();
        let (path, _) = new_vault(&dir, Mode::File);
        corrupt(&path, |bytes| {
            bytes[4..6].copy_from_slice(&999u16.to_le_bytes())
        });

        match Vault::open(&path) {
            Err(VaultError::FormatVersionMismatch { found, supported }) => {
                assert_eq!(found, 999);
                assert_eq!(supported, FORMAT_VERSION);
            }
            other => panic!("expected a version mismatch, got {other:?}"),
        }
    }

    #[test]
    fn rejects_an_oversized_header_length_without_allocating_it() {
        let dir = TempDir::new().unwrap();
        let (path, _) = new_vault(&dir, Mode::File);
        corrupt(&path, |bytes| {
            bytes[6..10].copy_from_slice(&u32::MAX.to_le_bytes());
        });
        assert!(matches!(
            Vault::open(&path),
            Err(VaultError::MalformedHeader(_))
        ));
    }

    #[test]
    fn rejects_a_truncated_file() {
        let dir = TempDir::new().unwrap();
        let (path, _) = new_vault(&dir, Mode::File);
        corrupt(&path, |bytes| {
            bytes.truncate(bytes.len() - 1);
        });
        assert!(matches!(
            Vault::open(&path),
            Err(VaultError::MalformedHeader(_))
        ));
    }

    #[test]
    fn rejects_a_header_that_lies_about_the_payload_length() {
        let dir = TempDir::new().unwrap();
        let (path, _) = new_vault(&dir, Mode::File);
        corrupt(&path, |bytes| bytes.extend_from_slice(b"extra"));
        assert!(matches!(
            Vault::open(&path),
            Err(VaultError::MalformedHeader(_))
        ));
    }

    #[test]
    fn rejects_an_empty_file() {
        let dir = TempDir::new().unwrap();
        let path = dir.path().join("empty.fido");
        std::fs::write(&path, b"").unwrap();
        assert!(matches!(
            Vault::open(&path),
            Err(VaultError::MalformedHeader(_))
        ));
    }

    // ---------- mode guards ----------

    #[test]
    fn file_operations_refuse_a_non_file_vault() {
        let dir = TempDir::new().unwrap();
        let path = dir.path().join("dir.fido");
        let mut vault = Vault::create(&path, Mode::Dir, &enrollment(1, KEK_A)).unwrap();
        let data_key = vault
            .unlock_with(&credential(1).credential_id, kek(KEK_A))
            .unwrap();

        let input = dir.path().join("input.bin");
        std::fs::write(&input, b"x").unwrap();
        match vault.seal_file(&data_key, &input) {
            Err(VaultError::WrongMode { expected, found }) => {
                assert_eq!(expected, Mode::File);
                assert_eq!(found, Mode::Dir);
            }
            other => panic!("expected WrongMode, got {other:?}"),
        }
        assert!(matches!(
            vault.open_file(&data_key, &dir.path().join("out.bin")),
            Err(VaultError::WrongMode { .. })
        ));
    }

    // ---------- crash safety ----------

    #[test]
    fn a_failed_seal_leaves_the_original_vault_intact() {
        let dir = TempDir::new().unwrap();
        let (path, mut vault) = new_vault(&dir, Mode::File);
        let input = dir.path().join("input.bin");
        std::fs::write(&input, b"the good contents").unwrap();

        let data_key = vault
            .unlock_with(&credential(1).credential_id, kek(KEK_A))
            .unwrap();
        vault.seal_file(&data_key, &input).unwrap();
        let before = std::fs::read(&path).unwrap();

        // Fail partway: the input disappears between one seal and the next.
        let err = vault.seal_file(&data_key, &dir.path().join("gone.bin"));
        assert!(err.is_err());

        assert_eq!(
            std::fs::read(&path).unwrap(),
            before,
            "vault file was modified"
        );
        let reopened = Vault::open(&path).unwrap();
        let data_key = reopened
            .unlock_with(&credential(1).credential_id, kek(KEK_A))
            .unwrap();
        let output = dir.path().join("out.bin");
        reopened.open_file(&data_key, &output).unwrap();
        assert_eq!(std::fs::read(&output).unwrap(), b"the good contents");
    }

    #[test]
    fn writing_leaves_no_stray_temp_files() {
        let dir = TempDir::new().unwrap();
        let (path, mut vault) = new_vault(&dir, Mode::File);
        let input = dir.path().join("input.bin");
        std::fs::write(&input, b"contents").unwrap();
        let data_key = vault
            .unlock_with(&credential(1).credential_id, kek(KEK_A))
            .unwrap();
        vault.seal_file(&data_key, &input).unwrap();
        let _ = vault.seal_file(&data_key, &dir.path().join("gone.bin"));

        let mut left: Vec<_> = std::fs::read_dir(dir.path())
            .unwrap()
            .map(|e| e.unwrap().path())
            .collect();
        left.sort();
        assert_eq!(left, vec![input, path], "leftover files: {left:?}");
    }

    #[test]
    fn a_failed_seal_does_not_advance_the_in_memory_header() {
        let dir = TempDir::new().unwrap();
        let (path, mut vault) = new_vault(&dir, Mode::File);
        let input = dir.path().join("input.bin");
        std::fs::write(&input, b"contents").unwrap();
        let data_key = vault
            .unlock_with(&credential(1).credential_id, kek(KEK_A))
            .unwrap();
        vault.seal_file(&data_key, &input).unwrap();

        let _ = vault.seal_file(&data_key, &dir.path().join("gone.bin"));

        // The in-memory header must still describe what is actually on disk.
        let output = dir.path().join("out.bin");
        vault.open_file(&data_key, &output).unwrap();
        assert_eq!(std::fs::read(&output).unwrap(), b"contents");
        assert_eq!(std::fs::read(&path).unwrap().len(), {
            let on_disk = Vault::open(&path).unwrap();
            on_disk.payload_offset() as usize + 8 + TAG_LEN
        });
    }

    // ---------- directory mode (M3) ----------

    #[test]
    fn dir_round_trip_through_a_vault() {
        let dir = TempDir::new().unwrap();
        let path = dir.path().join("tree.fido");
        let mut vault = Vault::create(&path, Mode::Dir, &enrollment(1, KEK_A)).unwrap();

        let src = dir.path().join("src");
        std::fs::create_dir_all(src.join("nested/deeper")).unwrap();
        std::fs::create_dir(src.join("empty")).unwrap();
        std::fs::write(src.join("one.txt"), b"first").unwrap();
        std::fs::write(src.join("nested/deeper/two.bin"), [9u8; 100]).unwrap();

        let data_key = vault
            .unlock_with(&credential(1).credential_id, kek(KEK_A))
            .unwrap();
        vault.seal_dir(&data_key, &src).unwrap();

        let reopened = Vault::open(&path).unwrap();
        let data_key = reopened
            .unlock_with(&credential(1).credential_id, kek(KEK_A))
            .unwrap();
        let out = dir.path().join("out");
        let report = reopened.open_dir(&data_key, &out).unwrap();

        assert!(report.is_complete(), "{:?}", report.skipped);
        assert_eq!(std::fs::read(out.join("one.txt")).unwrap(), b"first");
        assert_eq!(
            std::fs::read(out.join("nested/deeper/two.bin")).unwrap(),
            [9u8; 100]
        );
        assert!(out.join("empty").is_dir());
    }

    #[test]
    fn a_sealed_tree_is_not_readable_from_the_vault_file() {
        let dir = TempDir::new().unwrap();
        let path = dir.path().join("tree.fido");
        let mut vault = Vault::create(&path, Mode::Dir, &enrollment(1, KEK_A)).unwrap();

        let src = dir.path().join("src");
        std::fs::create_dir(&src).unwrap();
        std::fs::write(src.join("secret.txt"), b"MOST-SECRET-VALUE").unwrap();

        let data_key = vault
            .unlock_with(&credential(1).credential_id, kek(KEK_A))
            .unwrap();
        vault.seal_dir(&data_key, &src).unwrap();

        let bytes = std::fs::read(&path).unwrap();
        // Neither the contents nor the file names may appear in the clear: a tar
        // stores names in plaintext, so this checks the payload really is encrypted.
        for needle in [&b"MOST-SECRET-VALUE"[..], &b"secret.txt"[..]] {
            assert!(
                !bytes.windows(needle.len()).any(|w| w == needle),
                "{:?} appears verbatim in the vault file",
                String::from_utf8_lossy(needle)
            );
        }
    }

    #[test]
    fn dir_operations_refuse_a_file_vault() {
        let dir = TempDir::new().unwrap();
        let (_, mut vault) = new_vault(&dir, Mode::File);
        let data_key = vault
            .unlock_with(&credential(1).credential_id, kek(KEK_A))
            .unwrap();
        let src = dir.path().join("src");
        std::fs::create_dir(&src).unwrap();

        assert!(matches!(
            vault.seal_dir(&data_key, &src),
            Err(VaultError::WrongMode {
                expected: Mode::Dir,
                found: Mode::File
            })
        ));
        assert!(matches!(
            vault.open_dir(&data_key, &dir.path().join("out")),
            Err(VaultError::WrongMode { .. })
        ));
    }

    #[test]
    fn sealing_a_missing_directory_leaves_the_vault_intact() {
        let dir = TempDir::new().unwrap();
        let path = dir.path().join("tree.fido");
        let mut vault = Vault::create(&path, Mode::Dir, &enrollment(1, KEK_A)).unwrap();
        let before = std::fs::read(&path).unwrap();

        let data_key = vault
            .unlock_with(&credential(1).credential_id, kek(KEK_A))
            .unwrap();
        let err = vault
            .seal_dir(&data_key, &dir.path().join("nope"))
            .unwrap_err();
        assert!(matches!(err, VaultError::NotADirectory(_)), "got {err:?}");
        assert_eq!(std::fs::read(&path).unwrap(), before);
    }

    #[cfg(unix)]
    #[test]
    fn a_symlinked_tree_round_trips_through_a_vault() {
        let dir = TempDir::new().unwrap();
        let path = dir.path().join("tree.fido");
        let mut vault = Vault::create(&path, Mode::Dir, &enrollment(1, KEK_A)).unwrap();

        let src = dir.path().join("src");
        std::fs::create_dir(&src).unwrap();
        std::fs::write(src.join("real.txt"), b"real contents").unwrap();
        std::os::unix::fs::symlink("real.txt", src.join("alias.txt")).unwrap();

        let data_key = vault
            .unlock_with(&credential(1).credential_id, kek(KEK_A))
            .unwrap();
        vault.seal_dir(&data_key, &src).unwrap();

        let out = dir.path().join("out");
        let report = vault.open_dir(&data_key, &out).unwrap();
        assert!(report.is_complete(), "{:?}", report.skipped);
        assert!(std::fs::symlink_metadata(out.join("alias.txt"))
            .unwrap()
            .file_type()
            .is_symlink());
        assert_eq!(
            std::fs::read(out.join("alias.txt")).unwrap(),
            b"real contents"
        );
    }

    #[test]
    fn the_header_stores_credential_ids_as_raw_bytes_not_hex() {
        // M7 made `fido-token` print credential IDs as hex in its JSON. That must not
        // reach the vault format: `fido_token::Credential`'s serde impl defines this
        // header's layout too, and hex would double the field's size and break every
        // existing vault. See plan/09-credential-encoding.md and plan/07 #17.
        let dir = TempDir::new().unwrap();
        let path = dir.path().join("v.fido");
        let mut enrolled = enrollment(1, KEK_A);
        enrolled.factor = Factor::Fido2(fido_token::Credential {
            rp_id: "fidostorers.local".to_string(),
            credential_id: vec![0xA1, 0xB2, 0xC3, 0xD4],
            device_hint: None,
        });
        Vault::create(&path, Mode::File, &enrolled).unwrap();

        let bytes = std::fs::read(&path).unwrap();
        // postcard writes a Vec<u8> as a varint length then the raw bytes.
        let raw = [0x04, 0xA1, 0xB2, 0xC3, 0xD4];
        assert!(
            bytes.windows(raw.len()).any(|w| w == raw),
            "credential_id is not stored as length-prefixed raw bytes"
        );
        assert!(
            !bytes.windows(8).any(|w| w == b"a1b2c3d4"),
            "credential_id leaked into the header as hex text"
        );
    }

    // ---------- multi-key enrollment and revocation (M5) ----------

    #[test]
    fn either_enrolled_key_unlocks_the_vault() {
        let dir = TempDir::new().unwrap();
        let (path, mut vault) = new_vault(&dir, Mode::File);
        let data_key = vault
            .unlock_with(&credential(1).credential_id, kek(KEK_A))
            .unwrap();
        vault.enroll(&data_key, &enrollment(2, KEK_B)).unwrap();

        let reopened = Vault::open(&path).unwrap();
        assert_eq!(reopened.credentials().len(), 2);

        let via_a = reopened
            .unlock_with(&credential(1).credential_id, kek(KEK_A))
            .unwrap();
        let via_b = reopened
            .unlock_with(&credential(2).credential_id, kek(KEK_B))
            .unwrap();
        assert_eq!(*via_a, *via_b, "both keys must yield the same data key");
        assert_eq!(*via_a, *data_key);
    }

    #[test]
    fn enrolling_does_not_disturb_the_payload() {
        // The point of wrapping one data key per credential: adding a key must not
        // re-encrypt a potentially enormous payload.
        let dir = TempDir::new().unwrap();
        let (path, mut vault) = new_vault(&dir, Mode::File);
        let input = dir.path().join("input.bin");
        let contents = vec![0xA5u8; 4096];
        std::fs::write(&input, &contents).unwrap();

        let data_key = vault
            .unlock_with(&credential(1).credential_id, kek(KEK_A))
            .unwrap();
        vault.seal_file(&data_key, &input).unwrap();

        let before = std::fs::read(&path).unwrap();
        let payload_before = before[vault.payload_offset() as usize..].to_vec();

        vault.enroll(&data_key, &enrollment(2, KEK_B)).unwrap();

        let after = std::fs::read(&path).unwrap();
        let payload_after = after[vault.payload_offset() as usize..].to_vec();
        assert_eq!(
            payload_before, payload_after,
            "the payload ciphertext was rewritten by an enroll"
        );

        // ...and it still decrypts, through the newly added key.
        let reopened = Vault::open(&path).unwrap();
        let via_b = reopened
            .unlock_with(&credential(2).credential_id, kek(KEK_B))
            .unwrap();
        let out = dir.path().join("out.bin");
        reopened.open_file(&via_b, &out).unwrap();
        assert_eq!(std::fs::read(&out).unwrap(), contents);
    }

    #[test]
    fn a_revoked_key_can_no_longer_unlock_but_the_survivor_can() {
        let dir = TempDir::new().unwrap();
        let (path, mut vault) = new_vault(&dir, Mode::File);
        let data_key = vault
            .unlock_with(&credential(1).credential_id, kek(KEK_A))
            .unwrap();
        vault.enroll(&data_key, &enrollment(2, KEK_B)).unwrap();
        vault
            .revoke(&data_key, &credential(1).credential_id)
            .unwrap();

        let reopened = Vault::open(&path).unwrap();
        assert_eq!(reopened.credentials().len(), 1);
        assert!(matches!(
            reopened.unlock_with(&credential(1).credential_id, kek(KEK_A)),
            Err(VaultError::UnknownCredential)
        ));
        let via_b = reopened
            .unlock_with(&credential(2).credential_id, kek(KEK_B))
            .unwrap();
        assert_eq!(*via_b, *data_key);
    }

    #[test]
    fn revoking_leaves_the_payload_readable_through_the_remaining_key() {
        let dir = TempDir::new().unwrap();
        let (path, mut vault) = new_vault(&dir, Mode::File);
        let input = dir.path().join("input.bin");
        std::fs::write(&input, b"still here after a revoke").unwrap();

        let data_key = vault
            .unlock_with(&credential(1).credential_id, kek(KEK_A))
            .unwrap();
        vault.seal_file(&data_key, &input).unwrap();
        vault.enroll(&data_key, &enrollment(2, KEK_B)).unwrap();
        vault
            .revoke(&data_key, &credential(1).credential_id)
            .unwrap();

        let reopened = Vault::open(&path).unwrap();
        let via_b = reopened
            .unlock_with(&credential(2).credential_id, kek(KEK_B))
            .unwrap();
        let out = dir.path().join("out.bin");
        reopened.open_file(&via_b, &out).unwrap();
        assert_eq!(std::fs::read(&out).unwrap(), b"still here after a revoke");
    }

    #[test]
    fn enroll_rejects_a_key_that_is_already_enrolled() {
        let dir = TempDir::new().unwrap();
        let (_, mut vault) = new_vault(&dir, Mode::File);
        let data_key = vault
            .unlock_with(&credential(1).credential_id, kek(KEK_A))
            .unwrap();
        let err = vault.enroll(&data_key, &enrollment(1, KEK_B)).unwrap_err();
        assert!(matches!(err, VaultError::AlreadyEnrolled), "got {err:?}");
        assert_eq!(vault.credentials().len(), 1);
    }

    #[test]
    fn enroll_rejects_a_credential_for_a_different_rp_id() {
        let dir = TempDir::new().unwrap();
        let (_, mut vault) = new_vault(&dir, Mode::File);
        let data_key = vault
            .unlock_with(&credential(1).credential_id, kek(KEK_A))
            .unwrap();

        let mut foreign = enrollment(2, KEK_B);
        foreign.factor = Factor::Fido2(fido_token::Credential {
            rp_id: "somewhere.else".to_string(),
            credential_id: credential(2).credential_id,
            device_hint: None,
        });
        let err = vault.enroll(&data_key, &foreign).unwrap_err();
        assert!(
            matches!(err, VaultError::RpIdMismatch { .. }),
            "got {err:?}"
        );
    }

    #[test]
    fn enrollment_survives_a_round_trip_with_its_label_and_salt() {
        let dir = TempDir::new().unwrap();
        let (path, mut vault) = new_vault(&dir, Mode::File);
        let data_key = vault
            .unlock_with(&credential(1).credential_id, kek(KEK_A))
            .unwrap();

        let mut second = enrollment(2, KEK_B);
        second.label = "backup in safe".to_string();
        second.salt = [0x2Bu8; 32];
        vault.enroll(&data_key, &second).unwrap();

        let reopened = Vault::open(&path).unwrap();
        let entry = &reopened.credentials()[1];
        assert_eq!(entry.label, "backup in safe");
        assert_eq!(entry.salt, [0x2Bu8; 32]);
        assert_eq!(
            entry.factor.credential().unwrap().credential_id,
            credential(2).credential_id
        );
    }

    #[test]
    fn enroll_and_revoke_work_across_every_mode() {
        for mode in [Mode::File, Mode::Dir, Mode::Kv] {
            let dir = TempDir::new().unwrap();
            let path = dir.path().join("v.fido");
            let mut vault = Vault::create(&path, mode, &enrollment(1, KEK_A)).unwrap();
            let data_key = vault
                .unlock_with(&credential(1).credential_id, kek(KEK_A))
                .unwrap();

            vault.enroll(&data_key, &enrollment(2, KEK_B)).unwrap();
            vault
                .revoke(&data_key, &credential(1).credential_id)
                .unwrap();

            let reopened = Vault::open(&path).unwrap();
            assert_eq!(reopened.mode(), mode);
            let via_b = reopened
                .unlock_with(&credential(2).credential_id, kek(KEK_B))
                .unwrap();
            assert_eq!(*via_b, *data_key, "mode {mode}");
        }
    }

    #[test]
    fn many_keys_can_be_enrolled_and_all_still_work() {
        let dir = TempDir::new().unwrap();
        let (path, mut vault) = new_vault(&dir, Mode::File);
        let data_key = vault
            .unlock_with(&credential(1).credential_id, kek(KEK_A))
            .unwrap();

        for id in 2..=8u8 {
            vault.enroll(&data_key, &enrollment(id, [id; 32])).unwrap();
        }

        let reopened = Vault::open(&path).unwrap();
        assert_eq!(reopened.credentials().len(), 8);
        for id in 1..=8u8 {
            let this_kek = if id == 1 { KEK_A } else { [id; 32] };
            let unlocked = reopened
                .unlock_with(&credential(id).credential_id, kek(this_kek))
                .unwrap();
            assert_eq!(*unlocked, *data_key, "key {id}");
        }
    }

    #[test]
    fn revoking_down_to_one_key_then_stopping() {
        let dir = TempDir::new().unwrap();
        let (_, mut vault) = new_vault(&dir, Mode::File);
        let data_key = vault
            .unlock_with(&credential(1).credential_id, kek(KEK_A))
            .unwrap();
        vault.enroll(&data_key, &enrollment(2, KEK_B)).unwrap();

        vault
            .revoke(&data_key, &credential(2).credential_id)
            .unwrap();
        assert_eq!(vault.credentials().len(), 1);
        // The guard must hold on the last one however we got there.
        assert!(matches!(
            vault.revoke(&data_key, &credential(1).credential_id),
            Err(VaultError::LastCredential)
        ));
        assert_eq!(vault.credentials().len(), 1);
    }

    // ---------- keyfile + password factors (M8) ----------

    #[test]
    fn a_vault_can_be_created_from_a_keyfile_factor_alone() {
        let dir = TempDir::new().unwrap();
        let path = dir.path().join("kf.fido");
        let enrolled = keyfile_enrollment(KEK_B, "keyfile");
        let vault = Vault::create(&path, Mode::File, &enrolled).unwrap();
        let id = vault.credentials()[0].id;

        let reopened = Vault::open(&path).unwrap();
        assert_eq!(reopened.credentials().len(), 1);
        assert_eq!(reopened.credentials()[0].factor.kind(), "keyfile");
        assert!(reopened.credentials()[0].factor.credential().is_none());
        assert!(reopened.unlock_with(&id, kek(KEK_B)).is_ok());
    }

    #[test]
    fn a_vault_can_hold_both_factor_kinds_and_either_unlocks_it() {
        let dir = TempDir::new().unwrap();
        let (path, mut vault) = new_vault(&dir, Mode::File);
        let data_key = vault
            .unlock_with(&credential(1).credential_id, kek(KEK_A))
            .unwrap();
        vault
            .enroll(&data_key, &keyfile_enrollment(KEK_B, "keyfile backup"))
            .unwrap();

        let reopened = Vault::open(&path).unwrap();
        assert_eq!(reopened.credentials().len(), 2);
        assert_eq!(reopened.credentials()[0].factor.kind(), "fido2");
        assert_eq!(reopened.credentials()[1].factor.kind(), "keyfile");

        let via_fido = reopened
            .unlock_with(&credential(1).credential_id, kek(KEK_A))
            .unwrap();
        let via_keyfile = reopened
            .unlock_with(&reopened.credentials()[1].id, kek(KEK_B))
            .unwrap();
        assert_eq!(*via_fido, *via_keyfile);
        assert_eq!(*via_fido, *data_key);
    }

    #[test]
    fn revoking_one_factor_kind_leaves_the_other_working() {
        let dir = TempDir::new().unwrap();
        let (path, mut vault) = new_vault(&dir, Mode::File);
        let data_key = vault
            .unlock_with(&credential(1).credential_id, kek(KEK_A))
            .unwrap();
        vault
            .enroll(&data_key, &keyfile_enrollment(KEK_B, "keyfile backup"))
            .unwrap();
        let keyfile_id = vault.credentials()[1].id;

        vault
            .revoke(&data_key, &credential(1).credential_id)
            .unwrap();

        let reopened = Vault::open(&path).unwrap();
        assert_eq!(reopened.credentials().len(), 1);
        assert!(matches!(
            reopened.unlock_with(&credential(1).credential_id, kek(KEK_A)),
            Err(VaultError::UnknownCredential)
        ));
        assert_eq!(
            *reopened.unlock_with(&keyfile_id, kek(KEK_B)).unwrap(),
            *data_key
        );
    }

    #[test]
    fn entry_ids_are_unique_and_addressable() {
        let dir = TempDir::new().unwrap();
        let (_, mut vault) = new_vault(&dir, Mode::File);
        let data_key = vault
            .unlock_with(&credential(1).credential_id, kek(KEK_A))
            .unwrap();
        vault
            .enroll(&data_key, &keyfile_enrollment(KEK_B, "one"))
            .unwrap();
        let mut third = keyfile_enrollment([0x11; 32], "two");
        third.salt = [0x77; 32];
        vault.enroll(&data_key, &third).unwrap();

        let ids: Vec<_> = vault.credentials().iter().map(|e| e.id).collect();
        assert_eq!(ids.len(), 3);
        assert_ne!(ids[0], ids[1]);
        assert_ne!(ids[1], ids[2]);
        // Two keyfile factors over the same file are legitimate and must both work.
        assert!(vault.unlock_with(&ids[1], kek(KEK_B)).is_ok());
        assert!(vault.unlock_with(&ids[2], kek([0x11; 32])).is_ok());
        assert_eq!(vault.credentials()[1].id_hex().len(), 32);
    }

    #[test]
    fn enroll_rejects_out_of_range_argon2_parameters() {
        let dir = TempDir::new().unwrap();
        let (_, mut vault) = new_vault(&dir, Mode::File);
        let data_key = vault
            .unlock_with(&credential(1).credential_id, kek(KEK_A))
            .unwrap();

        let mut weak = keyfile_enrollment(KEK_B, "too weak");
        weak.factor = Factor::Keyfile(crate::KeyfileParams {
            m_cost_kib: 8,
            t_cost: 1,
            parallelism: 1,
        });
        assert!(matches!(
            vault.enroll(&data_key, &weak),
            Err(VaultError::InvalidKdfParams(_))
        ));
        assert_eq!(vault.credentials().len(), 1);
    }

    #[test]
    fn argon2_parameters_survive_a_round_trip() {
        let dir = TempDir::new().unwrap();
        let path = dir.path().join("kf.fido");
        let mut enrolled = keyfile_enrollment(KEK_B, "keyfile");
        let params = crate::KeyfileParams {
            m_cost_kib: 16 * 1024,
            t_cost: 2,
            parallelism: 2,
        };
        enrolled.factor = Factor::Keyfile(params);
        Vault::create(&path, Mode::File, &enrolled).unwrap();

        let reopened = Vault::open(&path).unwrap();
        match &reopened.credentials()[0].factor {
            Factor::Keyfile(stored) => assert_eq!(*stored, params),
            other => panic!("expected a keyfile factor, got {other:?}"),
        }
    }

    #[test]
    fn a_hostile_kdf_parameter_is_rejected_at_parse_time() {
        // Same discipline as the header's length prefixes: these are read before
        // header_mac can be verified and they drive an allocation, so an absurd
        // m_cost must fail on the bound rather than be attempted. Built by hand
        // because no honest writer would ever produce it.
        let body = HeaderBody {
            mode: Mode::File,
            rp_id: "fidostorers.local".to_string(),
            credentials: vec![FactorEntry {
                id: [1u8; 16],
                factor: Factor::Keyfile(crate::KeyfileParams {
                    m_cost_kib: u32::MAX,
                    t_cost: 1,
                    parallelism: 1,
                }),
                label: "hostile".to_string(),
                salt: [0u8; 32],
                wrap_nonce: [0u8; 24],
                wrapped_data_key: vec![0u8; WRAPPED_DATA_KEY_LEN],
            }],
            payload_nonce: [0u8; 24],
            payload_len: 0,
        };
        let body_bytes = postcard::to_stdvec(&body).unwrap();

        let mut file = Vec::new();
        file.extend_from_slice(&MAGIC);
        file.extend_from_slice(&FORMAT_VERSION.to_le_bytes());
        file.extend_from_slice(&(body_bytes.len() as u32).to_le_bytes());
        file.extend_from_slice(&body_bytes);
        file.extend_from_slice(&[0u8; MAC_LEN]);
        file.extend_from_slice(&[0u8; TAG_LEN]);

        let dir = TempDir::new().unwrap();
        let path = dir.path().join("hostile.fido");
        std::fs::write(&path, &file).unwrap();

        match Vault::open(&path) {
            Err(VaultError::MalformedHeader(msg)) => assert!(msg.contains("Argon2"), "{msg}"),
            other => panic!("expected MalformedHeader, got {other:?}"),
        }
    }

    #[test]
    fn a_keyfile_factor_needs_no_relying_party() {
        // The rp_id comes from the vault, since a keyfile factor has no authenticator
        // and therefore no relying party of its own.
        let dir = TempDir::new().unwrap();
        let path = dir.path().join("kf.fido");
        let mut enrolled = keyfile_enrollment(KEK_B, "keyfile");
        enrolled.rp_id = "something.custom".to_string();
        let vault = Vault::create(&path, Mode::File, &enrolled).unwrap();
        assert_eq!(vault.rp_id(), "something.custom");
        assert_eq!(Vault::open(&path).unwrap().rp_id(), "something.custom");
    }

    // ---------- format version 1 compatibility (M8) ----------

    /// Build a v1 vault by hand: the format M2-M7 wrote, before factors existed.
    fn write_v1_vault(path: &Path, data_key: &[u8; 32], kek: &[u8; 32]) {
        let wrap_nonce = crypto::random_nonce();
        let wrapped_data_key = crypto::seal(kek, &wrap_nonce, &data_key[..]).unwrap();

        let body = HeaderBodyV1 {
            mode: Mode::File,
            rp_id: "fidostorers.local".to_string(),
            credentials: vec![CredentialEntryV1 {
                credential: credential(1),
                label: "primary".to_string(),
                salt: [1u8; 32],
                wrap_nonce,
                wrapped_data_key,
            }],
            payload_nonce: crypto::random_nonce(),
            payload_len: 0,
        };
        let body_bytes = postcard::to_stdvec(&body).unwrap();

        let mut covered = Vec::new();
        covered.extend_from_slice(&MAGIC);
        covered.extend_from_slice(&FORMAT_VERSION_V1.to_le_bytes());
        covered.extend_from_slice(&(body_bytes.len() as u32).to_le_bytes());
        covered.extend_from_slice(&body_bytes);

        let mac_key = crypto::mac_key_from_data_key(data_key);
        let mac = crypto::header_mac(&mac_key, &covered);
        let payload = crypto::seal(data_key, &body.payload_nonce, &[]).unwrap();

        let mut file = covered;
        file.extend_from_slice(&mac);
        file.extend_from_slice(&payload);
        std::fs::write(path, &file).unwrap();
    }

    #[test]
    fn a_v1_vault_still_opens_and_unlocks() {
        let dir = TempDir::new().unwrap();
        let path = dir.path().join("old.fido");
        let data_key = [0x42u8; 32];
        write_v1_vault(&path, &data_key, &KEK_A);

        let vault = Vault::open(&path).unwrap();
        assert_eq!(vault.format_version(), FORMAT_VERSION_V1);
        assert_eq!(vault.credentials().len(), 1);
        assert_eq!(vault.credentials()[0].factor.kind(), "fido2");
        assert_eq!(vault.credentials()[0].label, "primary");

        let unlocked = vault
            .unlock_with(&credential(1).credential_id, kek(KEK_A))
            .unwrap();
        assert_eq!(*unlocked, data_key);
    }

    #[test]
    fn a_v1_vault_is_rewritten_as_v2_on_the_next_write() {
        let dir = TempDir::new().unwrap();
        let path = dir.path().join("old.fido");
        write_v1_vault(&path, &[0x42u8; 32], &KEK_A);

        let mut vault = Vault::open(&path).unwrap();
        let data_key = vault
            .unlock_with(&credential(1).credential_id, kek(KEK_A))
            .unwrap();

        let input = dir.path().join("input.bin");
        std::fs::write(&input, b"written after the upgrade").unwrap();
        vault.seal_file(&data_key, &input).unwrap();

        let upgraded = Vault::open(&path).unwrap();
        assert_eq!(upgraded.format_version(), FORMAT_VERSION);
        // Same key, same label, same data — only the encoding moved.
        let via_upgraded = upgraded
            .unlock_with(&credential(1).credential_id, kek(KEK_A))
            .unwrap();
        assert_eq!(*via_upgraded, *data_key);
        assert_eq!(upgraded.credentials()[0].label, "primary");

        let out = dir.path().join("out.bin");
        upgraded.open_file(&via_upgraded, &out).unwrap();
        assert_eq!(std::fs::read(&out).unwrap(), b"written after the upgrade");
    }

    #[test]
    fn a_v1_entry_gets_a_stable_id() {
        // Derived from the credential ID rather than drawn at random: a random id
        // would differ on every open, so `revoke --id` would name a different entry
        // each time the vault was read.
        let dir = TempDir::new().unwrap();
        let path = dir.path().join("old.fido");
        write_v1_vault(&path, &[0x42u8; 32], &KEK_A);

        let first = Vault::open(&path).unwrap().credentials()[0].id;
        let second = Vault::open(&path).unwrap().credentials()[0].id;
        assert_eq!(first, second);
        assert_ne!(first, [0u8; 16]);
    }

    #[test]
    fn a_future_format_version_is_still_rejected() {
        let dir = TempDir::new().unwrap();
        let (path, _) = new_vault(&dir, Mode::File);
        corrupt(&path, |bytes| {
            bytes[4..6].copy_from_slice(&999u16.to_le_bytes())
        });
        assert!(matches!(
            Vault::open(&path),
            Err(VaultError::FormatVersionMismatch { found: 999, .. })
        ));
    }

    // ---------- kv mode (M4) ----------

    fn new_kv_vault(dir: &TempDir) -> (PathBuf, Vault, Zeroizing<[u8; 32]>) {
        let path = dir.path().join("kv.fido");
        let vault = Vault::create(&path, Mode::Kv, &enrollment(1, KEK_A)).unwrap();
        let data_key = vault
            .unlock_with(&credential(1).credential_id, kek(KEK_A))
            .unwrap();
        (path, vault, data_key)
    }

    #[test]
    fn a_fresh_kv_vault_is_an_empty_store() {
        let dir = TempDir::new().unwrap();
        let (path, vault, data_key) = new_kv_vault(&dir);
        assert!(vault.kv_ls(&data_key).unwrap().is_empty());

        // And still so after a round trip through disk.
        let reopened = Vault::open(&path).unwrap();
        let data_key = reopened
            .unlock_with(&credential(1).credential_id, kek(KEK_A))
            .unwrap();
        assert!(reopened.kv_ls(&data_key).unwrap().is_empty());
    }

    #[test]
    fn kv_set_get_ls_rm_round_trip() {
        let dir = TempDir::new().unwrap();
        let (path, mut vault, data_key) = new_kv_vault(&dir);

        vault.kv_set(&data_key, "api-token", b"tok-12345").unwrap();
        vault
            .kv_set(&data_key, "recovery", b"one two three")
            .unwrap();
        vault.kv_set(&data_key, "binary", &[0u8, 255, 128]).unwrap();

        assert_eq!(
            vault.kv_ls(&data_key).unwrap(),
            vec!["api-token", "binary", "recovery"]
        );
        assert_eq!(
            &vault.kv_get(&data_key, "api-token").unwrap()[..],
            b"tok-12345"
        );

        // Reopen from disk: every set must have been persisted, not just cached.
        let mut reopened = Vault::open(&path).unwrap();
        let data_key = reopened
            .unlock_with(&credential(1).credential_id, kek(KEK_A))
            .unwrap();
        assert_eq!(
            &reopened.kv_get(&data_key, "binary").unwrap()[..],
            &[0u8, 255, 128]
        );

        reopened.kv_rm(&data_key, "recovery").unwrap();
        assert_eq!(
            reopened.kv_ls(&data_key).unwrap(),
            vec!["api-token", "binary"]
        );
        assert!(matches!(
            reopened.kv_get(&data_key, "recovery"),
            Err(VaultError::NoSuchEntry(_))
        ));
    }

    #[test]
    fn kv_set_overwrites_an_existing_entry() {
        let dir = TempDir::new().unwrap();
        let (_, mut vault, data_key) = new_kv_vault(&dir);
        vault.kv_set(&data_key, "k", b"first").unwrap();
        vault.kv_set(&data_key, "k", b"second").unwrap();
        assert_eq!(&vault.kv_get(&data_key, "k").unwrap()[..], b"second");
        assert_eq!(vault.kv_ls(&data_key).unwrap().len(), 1);
    }

    #[test]
    fn kv_rm_of_a_missing_entry_is_an_error() {
        // A typo'd name must not look like a successful deletion.
        let dir = TempDir::new().unwrap();
        let (_, mut vault, data_key) = new_kv_vault(&dir);
        vault.kv_set(&data_key, "present", b"x").unwrap();
        assert!(matches!(
            vault.kv_rm(&data_key, "absent"),
            Err(VaultError::NoSuchEntry(_))
        ));
        assert_eq!(vault.kv_ls(&data_key).unwrap(), vec!["present"]);
    }

    #[test]
    fn kv_rejects_an_unusable_name() {
        let dir = TempDir::new().unwrap();
        let (_, mut vault, data_key) = new_kv_vault(&dir);
        assert!(matches!(
            vault.kv_set(&data_key, "", b"x"),
            Err(VaultError::InvalidEntryName(_))
        ));
    }

    #[test]
    fn kv_values_are_not_readable_from_the_vault_file() {
        let dir = TempDir::new().unwrap();
        let (path, mut vault, data_key) = new_kv_vault(&dir);
        vault
            .kv_set(&data_key, "the-name", b"MOST-SECRET-VALUE")
            .unwrap();

        let bytes = std::fs::read(&path).unwrap();
        for needle in [&b"MOST-SECRET-VALUE"[..], &b"the-name"[..]] {
            assert!(
                !bytes.windows(needle.len()).any(|w| w == needle),
                "{:?} appears verbatim in the vault file",
                String::from_utf8_lossy(needle)
            );
        }
    }

    #[test]
    fn every_kv_write_draws_a_fresh_nonce() {
        // Each `set` re-encrypts the whole store under a data key fixed for the
        // vault's lifetime, so this is the case plan/03's nonce discipline is
        // really about: anyone holding two versions of the file must not be able to
        // XOR them and see which entry changed.
        let dir = TempDir::new().unwrap();
        let (path, mut vault, data_key) = new_kv_vault(&dir);

        let mut seen = std::collections::HashSet::new();
        for i in 0..5 {
            vault
                .kv_set(&data_key, "k", format!("value-{i}").as_bytes())
                .unwrap();
            let bytes = std::fs::read(&path).unwrap();
            let offset = vault.payload_offset() as usize;
            assert!(seen.insert(bytes[offset..].to_vec()), "ciphertext repeated");
        }
    }

    #[test]
    fn kv_operations_refuse_a_non_kv_vault() {
        let dir = TempDir::new().unwrap();
        let (_, mut vault) = new_vault(&dir, Mode::File);
        let data_key = vault
            .unlock_with(&credential(1).credential_id, kek(KEK_A))
            .unwrap();
        assert!(matches!(
            vault.kv_set(&data_key, "k", b"v"),
            Err(VaultError::WrongMode {
                expected: Mode::Kv,
                found: Mode::File
            })
        ));
        assert!(matches!(
            vault.kv_ls(&data_key),
            Err(VaultError::WrongMode { .. })
        ));
    }

    #[test]
    fn a_failed_kv_set_leaves_the_store_untouched() {
        let dir = TempDir::new().unwrap();
        let (path, mut vault, data_key) = new_kv_vault(&dir);
        vault.kv_set(&data_key, "good", b"value").unwrap();
        let before = std::fs::read(&path).unwrap();

        assert!(vault.kv_set(&data_key, "", b"x").is_err());

        assert_eq!(std::fs::read(&path).unwrap(), before);
        assert_eq!(vault.kv_ls(&data_key).unwrap(), vec!["good"]);
    }

    // ---------- mode parsing ----------

    #[test]
    fn mode_display_and_from_str_round_trip() {
        for mode in [Mode::File, Mode::Dir, Mode::Kv] {
            assert_eq!(mode.to_string().parse::<Mode>().unwrap(), mode);
        }
        assert!("bogus".parse::<Mode>().is_err());
    }

    // ---------- guards for milestones not yet implemented ----------

    #[test]
    fn revoke_rejects_the_last_credential() {
        let dir = TempDir::new().unwrap();
        let (_, mut vault) = new_vault(&dir, Mode::File);
        let data_key = vault
            .unlock_with(&credential(1).credential_id, kek(KEK_A))
            .unwrap();
        let err = vault
            .revoke(&data_key, &credential(1).credential_id)
            .unwrap_err();
        assert!(matches!(err, VaultError::LastCredential), "got {err:?}");
    }

    #[test]
    fn revoke_rejects_an_unknown_credential() {
        let dir = TempDir::new().unwrap();
        let (_, mut vault) = new_vault(&dir, Mode::File);
        let data_key = vault
            .unlock_with(&credential(1).credential_id, kek(KEK_A))
            .unwrap();
        let err = vault.revoke(&data_key, &[0xFF]).unwrap_err();
        assert!(matches!(err, VaultError::UnknownCredential), "got {err:?}");
    }

    #[test]
    fn enroll_and_revoke_refuse_a_wrong_data_key() {
        // Both act on header contents, so both must verify the MAC before doing
        // anything at all (plan/03's ordering).
        let dir = TempDir::new().unwrap();
        let (_, mut vault) = new_vault(&dir, Mode::File);
        let wrong = Zeroizing::new([0u8; 32]);

        assert!(matches!(
            vault.enroll(&wrong, &enrollment(2, KEK_B)),
            Err(VaultError::AuthenticationFailed)
        ));
        assert!(matches!(
            vault.revoke(&wrong, &credential(1).credential_id),
            Err(VaultError::AuthenticationFailed)
        ));
    }

    // ---------- header validation ----------

    #[test]
    fn validate_rejects_out_of_bounds_fields() {
        let base = HeaderBody {
            mode: Mode::File,
            rp_id: "fidostorers.local".to_string(),
            credentials: vec![FactorEntry {
                id: [1u8; 16],
                factor: Factor::Fido2(credential(1)),
                label: "primary".to_string(),
                salt: [1u8; 32],
                wrap_nonce: [1u8; 24],
                wrapped_data_key: vec![0u8; WRAPPED_DATA_KEY_LEN],
            }],
            payload_nonce: [1u8; 24],
            payload_len: 0,
        };
        assert!(validate(&base).is_ok());

        let mut no_credentials = base.clone();
        no_credentials.credentials.clear();
        assert!(validate(&no_credentials).is_err());

        let mut long_rp_id = base.clone();
        long_rp_id.rp_id = "x".repeat(MAX_RP_ID_LEN + 1);
        assert!(validate(&long_rp_id).is_err());

        let mut too_many = base.clone();
        too_many.credentials = (0..=MAX_CREDENTIALS as u8)
            .map(|i| {
                let mut entry = base.credentials[0].clone();
                entry.id = [i; 16];
                entry
            })
            .collect();
        assert!(validate(&too_many).is_err());

        let mut long_label = base.clone();
        long_label.credentials[0].label = "x".repeat(MAX_LABEL_LEN + 1);
        assert!(validate(&long_label).is_err());

        let mut empty_id = base.clone();
        empty_id.credentials[0].factor = Factor::Fido2(fido_token::Credential {
            rp_id: "fidostorers.local".to_string(),
            credential_id: vec![],
            device_hint: None,
        });
        assert!(validate(&empty_id).is_err());

        let mut long_id = base.clone();
        long_id.credentials[0].factor = Factor::Fido2(fido_token::Credential {
            rp_id: "fidostorers.local".to_string(),
            credential_id: vec![0u8; MAX_CREDENTIAL_ID_LEN + 1],
            device_hint: None,
        });
        assert!(validate(&long_id).is_err());

        let mut duplicate_ids = base.clone();
        duplicate_ids.credentials = vec![base.credentials[0].clone(), base.credentials[0].clone()];
        assert!(validate(&duplicate_ids).is_err());

        let mut hostile_kdf = base.clone();
        hostile_kdf.credentials[0].factor = Factor::Keyfile(crate::KeyfileParams {
            m_cost_kib: u32::MAX,
            t_cost: 1,
            parallelism: 1,
        });
        assert!(validate(&hostile_kdf).is_err());

        let mut short_wrap = base.clone();
        short_wrap.credentials[0].wrapped_data_key = vec![0u8; 8];
        assert!(validate(&short_wrap).is_err());

        let mut mismatched_rp_id = base.clone();
        mismatched_rp_id.credentials[0].factor = Factor::Fido2(fido_token::Credential {
            rp_id: "elsewhere.local".to_string(),
            credential_id: credential(1).credential_id,
            device_hint: None,
        });
        assert!(validate(&mismatched_rp_id).is_err());
    }

    #[test]
    fn a_hostile_header_length_cannot_drive_a_huge_allocation() {
        // The cap is checked before the body buffer is allocated, so a 4 GiB claim
        // in a 60-byte file fails on the bound rather than on memory.
        let dir = TempDir::new().unwrap();
        let path = dir.path().join("hostile.fido");
        let mut file = std::fs::File::create(&path).unwrap();
        file.write_all(&MAGIC).unwrap();
        file.write_all(&FORMAT_VERSION.to_le_bytes()).unwrap();
        file.write_all(&u32::MAX.to_le_bytes()).unwrap();
        file.write_all(&[0u8; 32]).unwrap();
        drop(file);

        match Vault::open(&path) {
            Err(VaultError::MalformedHeader(msg)) => assert!(msg.contains("cap"), "{msg}"),
            other => panic!("expected MalformedHeader, got {other:?}"),
        }
    }
}
