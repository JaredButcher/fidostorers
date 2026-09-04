//! Working directories: the plaintext tree an open `file` or `dir` store is edited
//! through (plan/08, "Working directories").
//!
//! This is the part of a session that puts **unencrypted user data in the
//! filesystem**, for as long as the store is open. It is not a cache or an
//! implementation detail, and the code treats it as the security event it is:
//! placed in a runtime directory rather than beside the vault, created `0700`,
//! removed on close, and bounded by the same idle timeout as the key.
//!
//! **Secure erasure is explicitly out of scope.** Removing a working directory is
//! `unlink`, and on an SSD, a CoW filesystem, or any journalling filesystem that
//! does not reliably destroy the prior contents. Nothing here pretends otherwise.
//! A user who needs plaintext never to reach stable storage should keep the working
//! directory on a tmpfs or ramdisk — which is what the default location already is
//! on Linux, and what `--work-dir` exists to point elsewhere.

use std::path::{Path, PathBuf};

use sha2::{Digest, Sha256};
use zeroize::Zeroizing;

use crate::{archive, ExtractReport, Mode, VaultError};

/// What a store's working tree looks like right now, and the bytes that would be
/// sealed if it were written.
///
/// The two travel together because taking them separately would mean walking the
/// tree twice — once to decide whether to write and once to build what is written —
/// and for a `dir` store that walk is the expensive part.
pub(crate) struct Snapshot {
    /// `SHA-256` of `payload`. Comparing this against the digest recorded at the
    /// last extract or seal answers exactly the question that matters: *would
    /// sealing now produce different bytes?*
    pub digest: [u8; 32],
    pub payload: Zeroizing<Vec<u8>>,
}

/// A cheap, stat-only summary of a tree.
///
/// Used where an exact answer is not worth reading every byte: deciding whether a
/// user has been active, and the `stores` display. **Never** used to decide whether
/// to write, because a change that preserved size and mtime would be missed, and a
/// missed change silently discards the user's edits.
#[derive(Clone, Copy, PartialEq, Eq, Default, Debug)]
pub struct Scan {
    entries: u64,
    bytes: u64,
    newest_mtime_nanos: u64,
}

/// One store's extracted plaintext.
pub struct WorkDir {
    path: PathBuf,
    mode: Mode,
    /// Digest of the tree as of the last extract or successful seal.
    sealed: [u8; 32],
    /// Whether this path is ours to delete. False only for a `--work-dir` we were
    /// handed that already existed, where removing the directory itself would be
    /// deleting something the user made.
    owns_directory: bool,
    /// Cleared when the plaintext must outlive the store — a seal that failed. See
    /// [`WorkDir::keep`].
    remove_on_drop: bool,
}

impl WorkDir {
    /// Extract `payload` into `path`, which must not already hold anything.
    ///
    /// Returns the extraction report as well, because a `dir` payload can contain
    /// entries this platform cannot create and the caller has to be able to say so
    /// — the same reason `Vault::open_dir` returns one.
    pub(crate) fn extract_into(
        path: &Path,
        mode: Mode,
        payload: &[u8],
    ) -> Result<(Self, ExtractReport), VaultError> {
        let owns_directory = !path.exists();
        let report = match mode {
            Mode::File => {
                if let Some(parent) = path.parent() {
                    std::fs::create_dir_all(parent)?;
                }
                std::fs::write(path, payload)?;
                restrict_permissions(path)?;
                ExtractReport {
                    extracted: 1,
                    ..Default::default()
                }
            }
            Mode::Dir => {
                std::fs::create_dir_all(path)?;
                restrict_permissions(path)?;
                archive::extract(payload, path)?
            }
            Mode::Kv => {
                return Err(VaultError::Internal(
                    "a kv store has no working directory".into(),
                ))
            }
        };

        let mut work = WorkDir {
            path: path.to_path_buf(),
            mode,
            sealed: [0u8; 32],
            owns_directory,
            remove_on_drop: true,
        };
        // The baseline is the tree *as extracted*, not the payload that produced
        // it: extraction does not restore mtimes, so an archive rebuilt from the
        // fresh tree differs from the one that made it in every header. Digesting
        // what is actually on disk is what makes "unchanged" mean unchanged.
        work.sealed = work.snapshot()?.digest;
        Ok((work, report))
    }

    pub fn path(&self) -> &Path {
        &self.path
    }

    /// The bytes a seal would write, and their digest.
    pub(crate) fn snapshot(&self) -> Result<Snapshot, VaultError> {
        let payload = match self.mode {
            Mode::File => Zeroizing::new(std::fs::read(&self.path)?),
            Mode::Dir => Zeroizing::new(archive::build(&self.path)?),
            Mode::Kv => {
                return Err(VaultError::Internal(
                    "a kv store has no working directory".into(),
                ))
            }
        };
        let digest: [u8; 32] = Sha256::digest(&payload[..]).into();
        Ok(Snapshot { digest, payload })
    }

    /// Whether sealing would change the vault. Reads the whole tree, deliberately:
    /// this is the answer a write is decided from, and a cheap approximation that
    /// guessed "unchanged" would throw away the user's work.
    pub(crate) fn pending(&self) -> Result<Option<Snapshot>, VaultError> {
        let snapshot = self.snapshot()?;
        Ok((snapshot.digest != self.sealed).then_some(snapshot))
    }

    /// Record that `digest` is now what the vault holds.
    pub(crate) fn mark_sealed(&mut self, digest: [u8; 32]) {
        self.sealed = digest;
    }

    /// Leave the plaintext on disk when this store closes.
    ///
    /// For the one case where removing it would be wrong: a seal that failed. The
    /// tree is then the *only* copy of the user's changes, and deleting it would
    /// turn a write error into data loss. It becomes an orphan, which the next
    /// session offers to recover.
    pub(crate) fn keep(&mut self) {
        self.remove_on_drop = false;
    }

    /// Stat-only summary, for activity detection and status display.
    pub fn scan(&self) -> Scan {
        let mut scan = Scan::default();
        accumulate(&self.path, &mut scan);
        scan
    }
}

impl Drop for WorkDir {
    fn drop(&mut self) {
        if !self.remove_on_drop {
            return;
        }
        // Plain deletion, and the module docs say so: this is unlinking, not
        // erasure. Best effort — a failure here leaves plaintext behind, which the
        // caller reports; panicking in a drop would be worse.
        let _ = if self.owns_directory && self.mode == Mode::Dir {
            std::fs::remove_dir_all(&self.path)
        } else if self.mode == Mode::Dir {
            // A directory the user pointed us at: remove what we put in it, not it.
            clear_directory(&self.path)
        } else {
            std::fs::remove_file(&self.path)
        };
    }
}

impl std::fmt::Debug for WorkDir {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("WorkDir")
            .field("path", &self.path)
            .field("mode", &self.mode)
            .finish_non_exhaustive()
    }
}

fn clear_directory(path: &Path) -> std::io::Result<()> {
    for entry in std::fs::read_dir(path)? {
        let entry = entry?;
        if entry.file_type()?.is_dir() {
            std::fs::remove_dir_all(entry.path())?;
        } else {
            std::fs::remove_file(entry.path())?;
        }
    }
    Ok(())
}

fn accumulate(path: &Path, scan: &mut Scan) {
    let Ok(meta) = std::fs::symlink_metadata(path) else {
        return;
    };
    scan.entries += 1;
    scan.bytes += meta.len();
    if let Ok(modified) = meta.modified() {
        if let Ok(since) = modified.duration_since(std::time::UNIX_EPOCH) {
            scan.newest_mtime_nanos = scan.newest_mtime_nanos.max(since.as_nanos() as u64);
        }
    }
    // Never follow a symlink: a link pointing outside the tree would drag unrelated
    // files into the summary, and a cycle would not terminate.
    if meta.is_dir() && !meta.file_type().is_symlink() {
        let Ok(children) = std::fs::read_dir(path) else {
            return;
        };
        for child in children.flatten() {
            accumulate(&child.path(), scan);
        }
    }
}

/// Where working directories live when the user does not choose.
///
/// `$XDG_RUNTIME_DIR` first, because on Linux it is normally a `tmpfs` — so the
/// plaintext lives in RAM, is already private to the user, and is cleared on
/// logout. That is the closest thing to a good answer available by default, and it
/// is the reason this is preferred over the system temp directory rather than the
/// other way round.
///
/// **Never beside the vault.** A vault commonly sits in a synced folder, a git
/// repo, or a backed-up home directory, and extracting plaintext next to it would
/// push the decrypted contents straight into cloud sync or version history.
pub fn runtime_root() -> PathBuf {
    #[cfg(unix)]
    if let Some(dir) = std::env::var_os("XDG_RUNTIME_DIR") {
        let dir = PathBuf::from(dir);
        if dir.is_dir() {
            return dir.join("fidostorers");
        }
    }
    std::env::temp_dir().join("fidostorers")
}

/// A fresh, private directory for one session's working trees.
///
/// The pid alone would not do: a session that was killed leaves its directory
/// behind as an orphan, and a later process that happened to reuse the pid would
/// extract straight over the plaintext that orphan recovery is meant to offer back.
pub fn new_session_dir(root: &Path) -> Result<PathBuf, VaultError> {
    use rand::RngCore;
    let mut suffix = [0u8; 4];
    rand::rngs::OsRng.fill_bytes(&mut suffix);
    let path = root.join(format!(
        "work-{}-{}",
        std::process::id(),
        fido_token::to_hex(&suffix)
    ));
    create_private_dir(&path)?;
    Ok(path)
}

/// A working path for `alias` under `base` that is not already taken.
pub fn work_path_for(base: &Path, alias: &str) -> PathBuf {
    let first = base.join(alias);
    if !first.exists() {
        return first;
    }
    (2..)
        .map(|n| base.join(format!("{alias}-{n}")))
        .find(|candidate| !candidate.exists())
        .expect("the range is unbounded")
}

/// Create `path` (and its parents) as a directory only this user can enter.
///
/// On Windows there is no one-line equivalent, so the directory inherits the user
/// profile's ACLs and the documentation says plainly that a Windows working
/// directory is only as private as the profile it sits in, rather than claiming a
/// protection that was not applied.
pub fn create_private_dir(path: &Path) -> Result<(), VaultError> {
    std::fs::create_dir_all(path)?;
    restrict_permissions(path)?;
    Ok(())
}

fn restrict_permissions(path: &Path) -> Result<(), VaultError> {
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let meta = std::fs::metadata(path)?;
        let mode = if meta.is_dir() { 0o700 } else { 0o600 };
        std::fs::set_permissions(path, std::fs::Permissions::from_mode(mode))?;
    }
    #[cfg(not(unix))]
    let _ = path;
    Ok(())
}

/// Whether a path looks like somewhere plaintext should not be written: a git
/// working tree or a folder a sync client watches.
///
/// Shared with the keyfile checks, which reject the same places for the same
/// reason — anything written here is about to be copied somewhere else.
pub fn looks_synced(path: &Path) -> bool {
    path.ancestors().any(|ancestor| {
        ancestor.file_name().is_some_and(|name| {
            let name = name.to_string_lossy().to_lowercase();
            name == ".git"
                || name == "dropbox"
                || name == "onedrive"
                || name.contains("google drive")
        }) || ancestor.join(".git").is_dir()
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn dir_payload(files: &[(&str, &[u8])]) -> Vec<u8> {
        let source = tempfile::tempdir().unwrap();
        for (name, contents) in files {
            let path = source.path().join(name);
            std::fs::create_dir_all(path.parent().unwrap()).unwrap();
            std::fs::write(path, contents).unwrap();
        }
        archive::build(source.path()).unwrap()
    }

    #[test]
    fn an_untouched_tree_is_not_pending() {
        let base = tempfile::tempdir().unwrap();
        let payload = dir_payload(&[("a.txt", b"one"), ("sub/b.txt", b"two")]);
        let (work, report) =
            WorkDir::extract_into(&base.path().join("store"), Mode::Dir, &payload).unwrap();

        assert!(report.is_complete());
        // The baseline is the extracted tree, so a store nobody has touched must
        // not be rewritten on exit.
        assert!(work.pending().unwrap().is_none());
    }

    #[test]
    fn editing_a_file_makes_the_store_pending() {
        let base = tempfile::tempdir().unwrap();
        let payload = dir_payload(&[("a.txt", b"one")]);
        let (work, _) =
            WorkDir::extract_into(&base.path().join("store"), Mode::Dir, &payload).unwrap();

        std::fs::write(work.path().join("a.txt"), b"changed").unwrap();
        assert!(work.pending().unwrap().is_some());
    }

    #[test]
    fn adding_and_removing_entries_is_detected() {
        let base = tempfile::tempdir().unwrap();
        let payload = dir_payload(&[("a.txt", b"one")]);
        let (mut work, _) =
            WorkDir::extract_into(&base.path().join("store"), Mode::Dir, &payload).unwrap();

        std::fs::write(work.path().join("new.txt"), b"added").unwrap();
        let pending = work.pending().unwrap().expect("a new file is a change");
        work.mark_sealed(pending.digest);
        assert!(work.pending().unwrap().is_none(), "sealing clears pending");

        std::fs::remove_file(work.path().join("a.txt")).unwrap();
        assert!(work.pending().unwrap().is_some(), "a deletion is a change");
    }

    #[cfg(unix)]
    #[test]
    fn a_permission_change_alone_is_detected() {
        use std::os::unix::fs::PermissionsExt;
        let base = tempfile::tempdir().unwrap();
        let payload = dir_payload(&[("script.sh", b"#!/bin/sh\n")]);
        let (work, _) =
            WorkDir::extract_into(&base.path().join("store"), Mode::Dir, &payload).unwrap();

        // The archive preserves mode bits, so making a script executable is a real
        // change to what the vault would hold.
        let path = work.path().join("script.sh");
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o755)).unwrap();
        assert!(work.pending().unwrap().is_some());
    }

    #[test]
    fn a_file_store_round_trips_through_its_working_path() {
        let base = tempfile::tempdir().unwrap();
        let path = base.path().join("secrets");
        let (mut work, _) = WorkDir::extract_into(&path, Mode::File, b"original").unwrap();

        assert_eq!(std::fs::read(&path).unwrap(), b"original");
        assert!(work.pending().unwrap().is_none());

        std::fs::write(&path, b"edited").unwrap();
        let pending = work.pending().unwrap().expect("an edit is pending");
        assert_eq!(&pending.payload[..], b"edited");
        work.mark_sealed(pending.digest);
        assert!(work.pending().unwrap().is_none());
    }

    #[test]
    fn dropping_removes_the_tree_it_created() {
        let base = tempfile::tempdir().unwrap();
        let path = base.path().join("store");
        let payload = dir_payload(&[("a.txt", b"one")]);
        let (work, _) = WorkDir::extract_into(&path, Mode::Dir, &payload).unwrap();

        assert!(path.exists());
        drop(work);
        assert!(!path.exists(), "closing a store must remove its plaintext");
    }

    #[test]
    fn dropping_empties_but_keeps_a_directory_it_was_handed() {
        let base = tempfile::tempdir().unwrap();
        let path = base.path().join("chosen");
        std::fs::create_dir(&path).unwrap();

        let payload = dir_payload(&[("a.txt", b"one")]);
        let (work, _) = WorkDir::extract_into(&path, Mode::Dir, &payload).unwrap();
        drop(work);

        // A --work-dir the user made is theirs; we remove what we put in it and
        // leave the directory. Deleting it would be deleting something we did not
        // create.
        assert!(path.is_dir());
        assert_eq!(std::fs::read_dir(&path).unwrap().count(), 0);
    }

    #[test]
    fn keeping_leaves_the_plaintext_for_recovery() {
        let base = tempfile::tempdir().unwrap();
        let path = base.path().join("store");
        let payload = dir_payload(&[("a.txt", b"one")]);
        let (mut work, _) = WorkDir::extract_into(&path, Mode::Dir, &payload).unwrap();

        // A seal that failed makes this tree the only copy of the user's changes.
        work.keep();
        drop(work);
        assert!(path.join("a.txt").exists());
    }

    #[test]
    fn session_directories_do_not_collide_on_a_reused_pid() {
        let root = tempfile::tempdir().unwrap();
        let first = new_session_dir(root.path()).unwrap();
        let second = new_session_dir(root.path()).unwrap();
        assert_ne!(first, second);

        // And two stores wanting the same alias get separate trees.
        std::fs::create_dir(work_path_for(&first, "backup")).unwrap();
        assert_eq!(
            work_path_for(&first, "backup").file_name().unwrap(),
            "backup-2"
        );
    }

    #[test]
    fn a_scan_notices_an_edit_without_reading_the_tree() {
        let base = tempfile::tempdir().unwrap();
        let payload = dir_payload(&[("a.txt", b"one")]);
        let (work, _) =
            WorkDir::extract_into(&base.path().join("store"), Mode::Dir, &payload).unwrap();

        let before = work.scan();
        std::fs::write(work.path().join("a.txt"), b"a much longer value").unwrap();
        assert_ne!(before, work.scan());
    }

    #[cfg(unix)]
    #[test]
    fn a_created_directory_is_private_to_this_user() {
        use std::os::unix::fs::PermissionsExt;
        let base = tempfile::tempdir().unwrap();
        let path = base.path().join("nested/run");
        create_private_dir(&path).unwrap();

        let mode = std::fs::metadata(&path).unwrap().permissions().mode();
        assert_eq!(mode & 0o777, 0o700, "working directories must be 0700");
    }

    #[test]
    fn synced_locations_are_recognised() {
        let dir = tempfile::tempdir().unwrap();
        let repo = dir.path().join("project");
        std::fs::create_dir_all(repo.join(".git")).unwrap();
        assert!(looks_synced(&repo.join("sub")));
        assert!(looks_synced(Path::new("/home/u/Dropbox/vaults")));
        assert!(!looks_synced(dir.path()));
    }

    #[test]
    fn a_kv_store_has_no_working_directory() {
        let base = tempfile::tempdir().unwrap();
        assert!(WorkDir::extract_into(&base.path().join("s"), Mode::Kv, b"").is_err());
    }
}
