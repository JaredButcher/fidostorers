//! Vault: header format, credential enrollment, and the payload pipeline, per
//! plan/03-vault-format-and-crypto.md.
//!
//! File mode (`create`/`open`/`unlock_with`/`seal_file`/`open_file`) is milestone
//! M2 and is implemented. Directory support is M3, KV support is M4, and
//! enrollment/revocation are M5; those bodies still return
//! [`VaultError::NotImplemented`] — see plan/06-roadmap.md.
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
use std::io::{Read, Seek, SeekFrom, Write};
use std::path::{Path, PathBuf};
use std::str::FromStr;

use serde::{Deserialize, Serialize};
use zeroize::Zeroizing;

use crate::crypto;
use crate::VaultError;

/// Format version written by this build. Bumped whenever the on-disk layout
/// changes in an incompatible way.
pub const FORMAT_VERSION: u16 = 1;

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

/// One enrolled credential's entry in the vault header: everything needed to
/// re-derive its KEK and unwrap the data key, none of it secret on its own.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CredentialEntry {
    pub credential: fido_token::Credential,
    /// User-supplied label (e.g. "primary", "backup in safe"), for UX only.
    pub label: String,
    /// Fed to `hmac-secret` to derive this credential's KEK. Not secret: its job is
    /// domain separation between this vault and any other using the same key.
    pub salt: [u8; 32],
    pub wrap_nonce: [u8; 24],
    /// XChaCha20-Poly1305 ciphertext + tag of the data key, under this entry's KEK,
    /// with empty associated data.
    pub wrapped_data_key: Vec<u8>,
}

/// Everything the caller must supply to give one security key the ability to unlock
/// a vault.
///
/// The salt travels with the KEK because the two are inseparable: the KEK is
/// `HKDF(hmac-secret(credential, salt))`, so a vault that stores the KEK's salt
/// wrongly can never re-derive it. Bundling them makes that impossible to get
/// wrong at a call site.
pub struct Enrollment {
    pub credential: fido_token::Credential,
    pub label: String,
    /// The salt used to derive `kek`. Stored in the header verbatim.
    pub salt: [u8; 32],
    /// `crypto::kek_from_secret(&fido_token::derive_secret(&credential, &salt, ..))`.
    pub kek: Zeroizing<[u8; 32]>,
}

/// The postcard-serialized part of the header.
#[derive(Debug, Clone, Serialize, Deserialize)]
struct HeaderBody {
    mode: Mode,
    rp_id: String,
    credentials: Vec<CredentialEntry>,
    payload_nonce: [u8; 24],
    /// Plaintext length. The payload occupies `payload_len + TAG_LEN` bytes on disk.
    payload_len: u64,
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
        let data_key = crypto::random_key();
        let entry = wrap_for(enrollment, &data_key)?;

        let payload_nonce = crypto::random_nonce();
        let payload = crypto::seal(&data_key, &payload_nonce, &[])?;

        let body = HeaderBody {
            mode,
            rp_id: enrollment.credential.rp_id.clone(),
            credentials: vec![entry],
            payload_nonce,
            payload_len: 0,
        };

        let mut vault = Vault {
            path: path.to_path_buf(),
            format_version: FORMAT_VERSION,
            body,
            mac_covered: Vec::new(),
            header_mac: [0u8; MAC_LEN],
        };
        vault.write(&data_key, &payload)?;
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
        if format_version != FORMAT_VERSION {
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

        let body: HeaderBody = postcard::from_bytes(&body_bytes)
            .map_err(|err| VaultError::MalformedHeader(format!("cannot parse header: {err}")))?;
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

    pub fn credentials(&self) -> &[CredentialEntry] {
        &self.body.credentials
    }

    fn find_credential(&self, credential_id: &[u8]) -> Result<&CredentialEntry, VaultError> {
        self.body
            .credentials
            .iter()
            .find(|entry| entry.credential.credential_id == credential_id)
            .ok_or(VaultError::UnknownCredential)
    }

    /// Unwrap the data key using `credential_id`'s already-derived KEK, then verify
    /// the header.
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
        let entry = self.find_credential(credential_id)?;
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
    pub fn enroll(
        &mut self,
        data_key: &Zeroizing<[u8; 32]>,
        enrollment: &Enrollment,
    ) -> Result<(), VaultError> {
        let _ = (data_key, enrollment);
        Err(VaultError::NotImplemented(
            "enrollment lands in M5, see plan/06-roadmap.md",
        ))
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
    pub fn revoke(
        &mut self,
        data_key: &Zeroizing<[u8; 32]>,
        credential_id: &[u8],
    ) -> Result<(), VaultError> {
        self.find_credential(credential_id)?;
        if self.body.credentials.len() <= 1 {
            return Err(VaultError::LastCredential);
        }
        let _ = data_key;
        Err(VaultError::NotImplemented(
            "revocation lands in M5, see plan/06-roadmap.md",
        ))
    }

    /// (mode = File) Encrypt `input`'s bytes into this vault.
    ///
    /// Takes `&mut self` because sealing draws a fresh `payload_nonce` and changes
    /// `payload_len` — both header fields — so the in-memory header would otherwise
    /// go stale against the file just written.
    pub fn seal_file(
        &mut self,
        data_key: &Zeroizing<[u8; 32]>,
        input: &Path,
    ) -> Result<(), VaultError> {
        self.expect_mode(Mode::File)?;
        let plaintext = Zeroizing::new(std::fs::read(input)?);
        self.seal_payload(data_key, &plaintext)
    }

    /// (mode = File) Decrypt this vault's payload to `output`.
    pub fn open_file(
        &self,
        data_key: &Zeroizing<[u8; 32]>,
        output: &Path,
    ) -> Result<(), VaultError> {
        self.expect_mode(Mode::File)?;
        let plaintext = self.open_payload(data_key)?;
        std::fs::write(output, &plaintext[..])?;
        Ok(())
    }

    /// Encrypt `plaintext` as the whole payload and rewrite the vault atomically.
    /// Shared by every mode: file bytes today, a tar stream in M3, a serialized map
    /// in M4.
    fn seal_payload(
        &mut self,
        data_key: &Zeroizing<[u8; 32]>,
        plaintext: &[u8],
    ) -> Result<(), VaultError> {
        self.verify_header(data_key)?;
        let payload_nonce = crypto::random_nonce();
        let payload = crypto::seal(data_key, &payload_nonce, plaintext)?;

        let previous = (self.body.payload_nonce, self.body.payload_len);
        self.body.payload_nonce = payload_nonce;
        self.body.payload_len = plaintext.len() as u64;

        // Restore the in-memory header if the write fails, so a caller that ignores
        // the error can't go on to act on a header that never reached disk.
        if let Err(err) = self.write(data_key, &payload) {
            self.body.payload_nonce = previous.0;
            self.body.payload_len = previous.1;
            return Err(err);
        }
        Ok(())
    }

    /// Verify the header, then decrypt and return the whole payload.
    fn open_payload(
        &self,
        data_key: &Zeroizing<[u8; 32]>,
    ) -> Result<Zeroizing<Vec<u8>>, VaultError> {
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
    fn write(&mut self, data_key: &[u8; 32], payload: &[u8]) -> Result<(), VaultError> {
        let body_bytes = postcard::to_stdvec(&self.body)
            .map_err(|err| VaultError::Internal(format!("cannot serialize header: {err}")))?;
        if body_bytes.len() > MAX_HEADER_LEN {
            return Err(VaultError::HeaderTooLarge {
                len: body_bytes.len(),
                max: MAX_HEADER_LEN,
            });
        }

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
        temp.write_all(payload)?;
        temp.flush()?;
        temp.as_file().sync_all()?;
        temp.persist(&self.path)
            .map_err(|err| VaultError::Io(err.error))?;

        self.mac_covered = mac_covered;
        self.header_mac = header_mac;
        Ok(())
    }

    /// (mode = Dir) Archive `input_dir` and encrypt it into this vault.
    pub fn seal_dir(
        &mut self,
        data_key: &Zeroizing<[u8; 32]>,
        input_dir: &Path,
    ) -> Result<(), VaultError> {
        let _ = (data_key, input_dir);
        Err(VaultError::NotImplemented(
            "directory sealing lands in M3, see plan/06-roadmap.md",
        ))
    }

    /// (mode = Dir) Decrypt and extract this vault's payload into `output_dir`.
    pub fn open_dir(
        &self,
        data_key: &Zeroizing<[u8; 32]>,
        output_dir: &Path,
    ) -> Result<(), VaultError> {
        let _ = (data_key, output_dir);
        Err(VaultError::NotImplemented(
            "directory opening lands in M3, see plan/06-roadmap.md",
        ))
    }

    /// (mode = Kv) Set (inserting or overwriting) one entry.
    pub fn kv_set(
        &mut self,
        data_key: &Zeroizing<[u8; 32]>,
        name: &str,
        value: &[u8],
    ) -> Result<(), VaultError> {
        let _ = (data_key, name, value);
        Err(VaultError::NotImplemented(
            "kv support lands in M4, see plan/06-roadmap.md",
        ))
    }

    /// (mode = Kv) Get one entry's value.
    pub fn kv_get(
        &self,
        data_key: &Zeroizing<[u8; 32]>,
        name: &str,
    ) -> Result<Zeroizing<Vec<u8>>, VaultError> {
        let _ = (data_key, name);
        Err(VaultError::NotImplemented(
            "kv support lands in M4, see plan/06-roadmap.md",
        ))
    }

    /// (mode = Kv) Remove one entry.
    pub fn kv_rm(&mut self, data_key: &Zeroizing<[u8; 32]>, name: &str) -> Result<(), VaultError> {
        let _ = (data_key, name);
        Err(VaultError::NotImplemented(
            "kv support lands in M4, see plan/06-roadmap.md",
        ))
    }

    /// (mode = Kv) List entry names.
    pub fn kv_ls(&self, data_key: &Zeroizing<[u8; 32]>) -> Result<Vec<String>, VaultError> {
        let _ = data_key;
        Err(VaultError::NotImplemented(
            "kv support lands in M4, see plan/06-roadmap.md",
        ))
    }
}

fn wrap_for(
    enrollment: &Enrollment,
    data_key: &Zeroizing<[u8; 32]>,
) -> Result<CredentialEntry, VaultError> {
    let wrap_nonce = crypto::random_nonce();
    let wrapped_data_key = crypto::seal(&enrollment.kek, &wrap_nonce, &data_key[..])?;
    Ok(CredentialEntry {
        credential: enrollment.credential.clone(),
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
    for (i, entry) in body.credentials.iter().enumerate() {
        if entry.credential.credential_id.is_empty() {
            return malformed(format!("credential {i} has an empty id"));
        }
        if entry.credential.credential_id.len() > MAX_CREDENTIAL_ID_LEN {
            return malformed(format!(
                "credential {i}'s id is {} bytes, over the {MAX_CREDENTIAL_ID_LEN}-byte cap",
                entry.credential.credential_id.len()
            ));
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
        // `fido_token::Credential` carries its own rp_id, so the header states it
        // twice. `create` sources both from the same place; a file where they
        // disagree was not written by us.
        if entry.credential.rp_id != body.rp_id {
            return malformed(format!(
                "credential {i}'s rp_id {:?} does not match the vault's {:?}",
                entry.credential.rp_id, body.rp_id
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
            credential: credential(id),
            label: "primary".to_string(),
            salt: [id; 32],
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
        let data_key = Zeroizing::new([0u8; 32]);
        let err = vault
            .revoke(&data_key, &credential(1).credential_id)
            .unwrap_err();
        assert!(matches!(err, VaultError::LastCredential), "got {err:?}");
    }

    #[test]
    fn revoke_rejects_an_unknown_credential() {
        let dir = TempDir::new().unwrap();
        let (_, mut vault) = new_vault(&dir, Mode::File);
        let data_key = Zeroizing::new([0u8; 32]);
        let err = vault.revoke(&data_key, &[0xFF]).unwrap_err();
        assert!(matches!(err, VaultError::UnknownCredential), "got {err:?}");
    }

    #[test]
    fn later_milestones_report_themselves_as_unimplemented() {
        let dir = TempDir::new().unwrap();
        let (_, mut vault) = new_vault(&dir, Mode::File);
        let data_key = vault
            .unlock_with(&credential(1).credential_id, kek(KEK_A))
            .unwrap();

        assert!(matches!(
            vault.enroll(&data_key, &enrollment(2, KEK_B)),
            Err(VaultError::NotImplemented(_))
        ));
        assert!(matches!(
            vault.kv_get(&data_key, "name"),
            Err(VaultError::NotImplemented(_))
        ));
        assert!(matches!(
            vault.seal_dir(&data_key, dir.path()),
            Err(VaultError::NotImplemented(_))
        ));
    }

    // ---------- header validation ----------

    #[test]
    fn validate_rejects_out_of_bounds_fields() {
        let base = HeaderBody {
            mode: Mode::File,
            rp_id: "fidostorers.local".to_string(),
            credentials: vec![CredentialEntry {
                credential: credential(1),
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
        too_many.credentials = std::iter::repeat(base.credentials[0].clone())
            .take(MAX_CREDENTIALS + 1)
            .collect();
        assert!(validate(&too_many).is_err());

        let mut long_label = base.clone();
        long_label.credentials[0].label = "x".repeat(MAX_LABEL_LEN + 1);
        assert!(validate(&long_label).is_err());

        let mut empty_id = base.clone();
        empty_id.credentials[0].credential.credential_id.clear();
        assert!(validate(&empty_id).is_err());

        let mut long_id = base.clone();
        long_id.credentials[0].credential.credential_id = vec![0u8; MAX_CREDENTIAL_ID_LEN + 1];
        assert!(validate(&long_id).is_err());

        let mut short_wrap = base.clone();
        short_wrap.credentials[0].wrapped_data_key = vec![0u8; 8];
        assert!(validate(&short_wrap).is_err());

        let mut mismatched_rp_id = base.clone();
        mismatched_rp_id.credentials[0].credential.rp_id = "elsewhere.local".to_string();
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
