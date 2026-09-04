//! Advisory locking for a vault file.
//!
//! Two sessions with the same vault open would silently lose one side's work: both
//! hold the same data key, both write, last writer wins (plan/08, "Concurrency").
//! A lock file beside the vault makes the second one refuse instead.
//!
//! It is **advisory**. Nothing in the operating system enforces it; a process that
//! does not look for it can still write the vault. What it buys is that this tool's
//! own commands do not collide with each other — which is the collision that
//! actually happens, since a session holds a vault open for minutes or hours.

use std::fs::{File, OpenOptions};
use std::io::Write;
use std::path::{Path, PathBuf};
use std::time::{SystemTime, UNIX_EPOCH};

use serde::{Deserialize, Serialize};

use crate::VaultError;

/// What a lock file records about its holder, so a second process can say who has
/// the vault rather than only that someone does.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LockInfo {
    pub pid: u32,
    pub hostname: String,
    /// Seconds since the Unix epoch, for a human-readable "held since".
    pub acquired_unix: u64,
    /// The vault this lock is for. Recorded for a human reading the file directly.
    pub vault: PathBuf,
}

/// A held advisory lock. Releasing is [`Drop`], so every exit path — including `?`
/// out of the middle of a command — gives the lock back.
#[derive(Debug)]
pub struct VaultLock {
    path: PathBuf,
}

impl VaultLock {
    /// Take the lock for `vault`, or fail saying who holds it.
    ///
    /// A lock whose holder is *provably* gone (same host, no such process) is stale
    /// and is cleared automatically: leaving a crashed session's lock to be removed
    /// by hand would make a `SIGKILL` cost the user their vault until they found
    /// out about the file.
    pub fn acquire(vault: &Path) -> Result<Self, VaultError> {
        Self::acquire_inner(vault, false)
    }

    /// Take the lock even though someone else holds it.
    ///
    /// For the case the session cannot decide for itself: a lock recorded by a pid
    /// on another machine, where liveness is unknowable from here. The caller is
    /// expected to have confirmed with the user first.
    pub fn steal(vault: &Path) -> Result<Self, VaultError> {
        Self::acquire_inner(vault, true)
    }

    fn acquire_inner(vault: &Path, force: bool) -> Result<Self, VaultError> {
        let path = lock_path(vault);

        // Two attempts at most. The retry exists for the one case that resolves
        // itself — clearing a stale lock — and stopping there means two processes
        // racing to clear the same stale lock cannot spin.
        for attempt in 0..2 {
            match OpenOptions::new().write(true).create_new(true).open(&path) {
                Ok(file) => return Self::write_info(file, path, vault),
                Err(err) if err.kind() == std::io::ErrorKind::AlreadyExists => {
                    let holder = read_info(&path);
                    // A lock we cannot parse is still a lock: only a holder we can
                    // read *and* prove is gone gets cleared without being asked.
                    // The cost is that a lock file truncated by a crash between
                    // creating and writing it needs `--force`, which is a better
                    // failure than handing the vault to a second writer.
                    let clearable = force || attempt == 0 && holder.as_ref().is_some_and(is_stale);
                    if !clearable {
                        return Err(busy(vault, holder));
                    }
                    // Racy by nature: another process may create the lock between
                    // this remove and our next `create_new`. That process then wins
                    // and we report it busy, which is the correct outcome.
                    if let Err(err) = std::fs::remove_file(&path) {
                        if err.kind() != std::io::ErrorKind::NotFound {
                            return Err(VaultError::Io(err));
                        }
                    }
                }
                Err(err) => return Err(VaultError::Io(err)),
            }
        }
        Err(busy(vault, read_info(&path)))
    }

    fn write_info(mut file: File, path: PathBuf, vault: &Path) -> Result<Self, VaultError> {
        let info = LockInfo {
            pid: std::process::id(),
            hostname: hostname(),
            acquired_unix: SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .map(|d| d.as_secs())
                .unwrap_or_default(),
            vault: vault.to_path_buf(),
        };
        // Hold the lock even if describing it fails: an unreadable lock file still
        // excludes a second process, which is the job. The alternative — unlinking
        // on a write error — would hand the vault to a racing session.
        let encoded = serde_json::to_vec_pretty(&info)
            .map_err(|err| VaultError::Internal(format!("cannot encode lock file: {err}")))?;
        file.write_all(&encoded)?;
        file.write_all(b"\n")?;
        file.sync_all()?;
        Ok(VaultLock { path })
    }

    /// The lock file's path, for messages.
    pub fn path(&self) -> &Path {
        &self.path
    }
}

impl Drop for VaultLock {
    fn drop(&mut self) {
        // Best effort. A lock file left behind by a failed removal is recovered by
        // the staleness check on the next acquire, so there is nothing useful to do
        // with the error here and a panic in a drop would be worse.
        let _ = std::fs::remove_file(&self.path);
    }
}

/// Who holds `vault`'s lock, if anyone. `None` also covers an unreadable or
/// malformed lock file, which is why callers must not read it as "free".
pub fn holder(vault: &Path) -> Option<LockInfo> {
    read_info(&lock_path(vault))
}

/// `backup.fido` -> `backup.fido.lock`. Appended rather than substituted so the
/// lock cannot collide with a second vault whose name differs only by extension.
pub fn lock_path(vault: &Path) -> PathBuf {
    let mut name = vault.file_name().unwrap_or_default().to_os_string();
    name.push(".lock");
    vault.with_file_name(name)
}

fn read_info(path: &Path) -> Option<LockInfo> {
    serde_json::from_slice(&std::fs::read(path).ok()?).ok()
}

fn busy(vault: &Path, holder: Option<LockInfo>) -> VaultError {
    match holder {
        Some(info) => VaultError::VaultBusy {
            vault: vault.to_path_buf(),
            pid: info.pid,
            hostname: info.hostname,
        },
        // An unparseable lock file is still a lock. Reporting it as free would be
        // the one answer that loses data.
        None => VaultError::VaultBusy {
            vault: vault.to_path_buf(),
            pid: 0,
            hostname: "unknown".to_string(),
        },
    }
}

/// Whether this lock can be cleared without asking anyone.
///
/// Only a holder we can *prove* is gone qualifies. "I cannot tell" is not staleness:
/// a lock recorded on another machine, or on a platform with no liveness check,
/// stays until the user says otherwise with `--force`.
fn is_stale(info: &LockInfo) -> bool {
    info.hostname == hostname() && process_is_alive(info.pid) == Some(false)
}

/// `Some(false)` only when the answer is certain.
///
/// Linux can answer from `/proc`. Windows would need `OpenProcess`, which means a
/// dependency purely to make `--force` unnecessary in one case, so it returns
/// `None` and the user is told to pass `--force` instead. Claiming a process is
/// dead when we cannot check would steal a live session's lock.
fn process_is_alive(pid: u32) -> Option<bool> {
    #[cfg(target_os = "linux")]
    {
        Some(Path::new(&format!("/proc/{pid}")).exists())
    }
    #[cfg(not(target_os = "linux"))]
    {
        let _ = pid;
        None
    }
}

/// Best effort, and only ever compared against itself, so a wrong answer costs an
/// unnecessary `--force` rather than a stolen lock.
fn hostname() -> String {
    #[cfg(target_os = "linux")]
    {
        if let Ok(name) = std::fs::read_to_string("/proc/sys/kernel/hostname") {
            let name = name.trim();
            if !name.is_empty() {
                return name.to_string();
            }
        }
    }
    #[cfg(windows)]
    {
        if let Ok(name) = std::env::var("COMPUTERNAME") {
            if !name.is_empty() {
                return name;
            }
        }
    }
    "unknown".to_string()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn vault_path(dir: &tempfile::TempDir) -> PathBuf {
        dir.path().join("v.fido")
    }

    #[test]
    fn lock_path_appends_rather_than_replaces() {
        assert_eq!(
            lock_path(Path::new("/tmp/backup.fido")),
            PathBuf::from("/tmp/backup.fido.lock")
        );
    }

    #[test]
    fn acquiring_twice_reports_the_holder() {
        let dir = tempfile::tempdir().unwrap();
        let vault = vault_path(&dir);
        let _held = VaultLock::acquire(&vault).unwrap();

        match VaultLock::acquire(&vault) {
            Err(VaultError::VaultBusy { pid, .. }) => assert_eq!(pid, std::process::id()),
            other => panic!("expected VaultBusy, got {other:?}"),
        }
    }

    #[test]
    fn releasing_lets_the_next_acquire_succeed() {
        let dir = tempfile::tempdir().unwrap();
        let vault = vault_path(&dir);

        let held = VaultLock::acquire(&vault).unwrap();
        let lock_file = held.path().to_path_buf();
        assert!(lock_file.exists());
        drop(held);
        assert!(!lock_file.exists(), "drop must release the lock");

        VaultLock::acquire(&vault).unwrap();
    }

    #[test]
    fn holder_reports_who_has_it() {
        let dir = tempfile::tempdir().unwrap();
        let vault = vault_path(&dir);
        assert!(holder(&vault).is_none());

        let _held = VaultLock::acquire(&vault).unwrap();
        let info = holder(&vault).expect("a held lock has a holder");
        assert_eq!(info.pid, std::process::id());
        assert_eq!(info.vault, vault);
    }

    #[test]
    fn steal_takes_a_live_lock() {
        let dir = tempfile::tempdir().unwrap();
        let vault = vault_path(&dir);
        let first = VaultLock::acquire(&vault).unwrap();

        let stolen = VaultLock::steal(&vault).unwrap();
        assert_eq!(holder(&vault).unwrap().pid, std::process::id());
        drop(first);
        drop(stolen);
    }

    #[test]
    fn an_unparseable_lock_file_still_excludes() {
        let dir = tempfile::tempdir().unwrap();
        let vault = vault_path(&dir);
        std::fs::write(lock_path(&vault), b"not json").unwrap();

        // The safe reading of a lock file we cannot understand is "someone has it".
        assert!(matches!(
            VaultLock::acquire(&vault),
            Err(VaultError::VaultBusy { .. })
        ));
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn a_dead_holder_is_cleared_automatically() {
        let dir = tempfile::tempdir().unwrap();
        let vault = vault_path(&dir);

        // pid 0 is never a live process, so this stands in for a session that was
        // SIGKILLed and never released its lock.
        let stale = LockInfo {
            pid: 0,
            hostname: hostname(),
            acquired_unix: 0,
            vault: vault.clone(),
        };
        std::fs::write(lock_path(&vault), serde_json::to_vec(&stale).unwrap()).unwrap();

        let held = VaultLock::acquire(&vault).expect("a stale lock must not block");
        assert_eq!(holder(&vault).unwrap().pid, std::process::id());
        drop(held);
    }

    #[test]
    fn a_lock_from_another_host_is_never_assumed_stale() {
        let dir = tempfile::tempdir().unwrap();
        let vault = vault_path(&dir);

        let elsewhere = LockInfo {
            pid: 0,
            hostname: "some-other-machine".to_string(),
            acquired_unix: 0,
            vault: vault.clone(),
        };
        std::fs::write(lock_path(&vault), serde_json::to_vec(&elsewhere).unwrap()).unwrap();

        // pid 0 is dead *here*, but says nothing about that host. Only --force.
        assert!(matches!(
            VaultLock::acquire(&vault),
            Err(VaultError::VaultBusy { .. })
        ));
        VaultLock::steal(&vault).unwrap();
    }
}
