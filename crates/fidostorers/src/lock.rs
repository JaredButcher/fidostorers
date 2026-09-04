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

/// Refuse if anyone holds `vault`, without taking the lock.
///
/// For commands that only read. A session holds its stores' locks for as long as
/// they are open, and while it does, **no other `fidostorers` process may open or
/// write that vault** — including to read it, because a session's working directory
/// can hold edits that are not in the file yet, so what a reader would get is a
/// version that is about to be replaced.
///
/// Taking nothing means concurrent readers never block each other; they only ever
/// honour a lock somebody else holds.
pub fn ensure_available(vault: &Path) -> Result<(), VaultError> {
    let path = lock_path(vault);
    if !path.exists() {
        return Ok(());
    }
    match read_info(&path) {
        // Our own lock is not a conflict. A writing command takes the lock and then
        // opens the vault through the same check a reader uses, so without this it
        // would refuse itself.
        Some(info) if info.pid == std::process::id() && info.hostname == hostname() => Ok(()),
        // A holder we can prove is gone is not a holder. The lock file is left
        // alone: clearing it is a writer's job, and a reader that tidied up would
        // be mutating a vault's directory to answer a question.
        Some(info) if is_stale(&info) => Ok(()),
        holder => Err(busy(vault, holder)),
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
/// a lock recorded on another machine, or one naming a process we are not allowed
/// to query, stays until the user says otherwise with `--force`.
fn is_stale(info: &LockInfo) -> bool {
    is_definitely_gone(info.pid, &info.hostname)
}

/// Whether `pid` on `host` is certainly not running any more.
///
/// The conservative half of every "is this leftover state safe to touch?" question
/// in the crate — vault locks here, and session records in [`crate::orphan`]. It
/// answers `false` whenever the answer is unknown, so the failure mode is an
/// unnecessary `--force` rather than trampling a live process's state.
pub(crate) fn is_definitely_gone(pid: u32, host: &str) -> bool {
    host == hostname() && process_is_alive(pid) == Some(false)
}

/// `Some(false)` only when the answer is certain; `None` when it cannot be known.
///
/// Claiming a process is dead when we cannot check would steal a live session's lock
/// and offer up a working directory it is still editing, so "I cannot tell" must
/// stay distinguishable from "gone".
#[cfg(target_os = "linux")]
fn process_is_alive(pid: u32) -> Option<bool> {
    Some(Path::new(&format!("/proc/{pid}")).exists())
}

/// Windows, via `OpenProcess`.
///
/// This was originally left unimplemented, on the reasoning that it would only save
/// the user an occasional `--force`. That was wrong: [`crate::orphan`] decides
/// whether a crashed session's **plaintext working directory** may be recovered
/// using the same predicate, so returning "I cannot tell" here meant a killed
/// session on Windows left its plaintext on disk and never offered it back.
#[cfg(windows)]
fn process_is_alive(pid: u32) -> Option<bool> {
    use winapi::shared::winerror::ERROR_INVALID_PARAMETER;
    use winapi::um::handleapi::CloseHandle;
    use winapi::um::minwinbase::STILL_ACTIVE;
    use winapi::um::processthreadsapi::{GetExitCodeProcess, OpenProcess};
    use winapi::um::winnt::PROCESS_QUERY_LIMITED_INFORMATION;

    // SAFETY: a valid access mask and pid; the handle is closed on every path.
    let handle = unsafe { OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, 0, pid) };
    if handle.is_null() {
        let code = std::io::Error::last_os_error().raw_os_error().unwrap_or(0);
        // A pid that does not exist is reported as an invalid parameter. Anything
        // else — access denied for a process owned by someone else, most likely —
        // means it does exist, or that we simply cannot say.
        return if code == ERROR_INVALID_PARAMETER as i32 {
            Some(false)
        } else {
            None
        };
    }

    let mut status: u32 = 0;
    // SAFETY: `handle` is a live process handle and `status` is a valid out param.
    let queried = unsafe { GetExitCodeProcess(handle, &mut status) };
    // SAFETY: closing a handle we opened, exactly once.
    unsafe { CloseHandle(handle) };

    if queried == 0 {
        return None;
    }
    // A handle can outlive the process it names, so "opened successfully" is not
    // the same as "running": ask for the exit code and let STILL_ACTIVE decide.
    Some(status == STILL_ACTIVE)
}

#[cfg(not(any(target_os = "linux", windows)))]
fn process_is_alive(_pid: u32) -> Option<bool> {
    None
}

/// Best effort, and only ever compared against itself, so a wrong answer costs an
/// unnecessary `--force` rather than a stolen lock.
pub(crate) fn hostname() -> String {
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

    /// A lock file as some *other* live process would have written it. Another
    /// host, so liveness is unknowable from here and the lock is therefore held —
    /// which is the state a reader has to honour.
    fn write_foreign_lock(vault: &Path) {
        let info = LockInfo {
            pid: 4321,
            hostname: "some-other-machine".to_string(),
            acquired_unix: 0,
            vault: vault.to_path_buf(),
        };
        std::fs::write(lock_path(vault), serde_json::to_vec(&info).unwrap()).unwrap();
    }

    #[test]
    fn ensure_available_honours_someone_elses_lock_without_taking_one() {
        let dir = tempfile::tempdir().unwrap();
        let vault = vault_path(&dir);
        assert!(ensure_available(&vault).is_ok());

        write_foreign_lock(&vault);
        // Reading is refused too: a session's working directory can hold edits the
        // vault file does not have yet.
        assert!(matches!(
            ensure_available(&vault),
            Err(VaultError::VaultBusy { .. })
        ));
    }

    /// A pid that has certainly exited. Spawned and reaped, so the answer does not
    /// depend on guessing a number no process happens to be using.
    fn reaped_pid() -> u32 {
        #[cfg(windows)]
        let mut child = std::process::Command::new("cmd")
            .args(["/C", "exit"])
            .spawn()
            .expect("spawning cmd");
        #[cfg(unix)]
        let mut child = std::process::Command::new("/bin/sh")
            .args(["-c", "exit"])
            .spawn()
            .expect("spawning sh");

        let pid = child.id();
        child.wait().expect("waiting for the child");
        pid
    }

    #[test]
    fn this_process_is_never_mistaken_for_a_dead_one() {
        // The dangerous direction. A false "gone" steals a live session's lock and
        // offers up a working directory it is still editing, so this must hold on
        // every platform that can answer at all.
        assert!(!is_definitely_gone(std::process::id(), &hostname()));
    }

    #[test]
    fn a_process_that_has_exited_is_reported_gone() {
        // And the other direction, which is what makes stale locks clear
        // themselves and orphaned working directories get offered back. A platform
        // that cannot tell answers `None`, and `is_definitely_gone` is false there
        // — so this asserts the capability, not merely the absence of a mistake.
        let pid = reaped_pid();
        if process_is_alive(pid).is_none() {
            return; // this platform genuinely cannot say; nothing to assert
        }
        assert!(
            is_definitely_gone(pid, &hostname()),
            "a reaped process should be reported gone"
        );
    }

    #[test]
    fn a_writer_does_not_refuse_its_own_lock() {
        let dir = tempfile::tempdir().unwrap();
        let vault = vault_path(&dir);
        // `kv set` takes the lock, then opens the vault through the reader check.
        let _held = VaultLock::acquire(&vault).unwrap();
        ensure_available(&vault).expect("a process must not exclude itself");
    }

    #[test]
    fn two_readers_never_block_each_other() {
        let dir = tempfile::tempdir().unwrap();
        let vault = vault_path(&dir);
        // Readers take nothing, so checking twice must not create a lock that the
        // second check then trips over.
        ensure_available(&vault).unwrap();
        ensure_available(&vault).unwrap();
        assert!(holder(&vault).is_none());
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn a_reader_ignores_a_provably_dead_holder() {
        let dir = tempfile::tempdir().unwrap();
        let vault = vault_path(&dir);
        let stale = LockInfo {
            pid: 0,
            hostname: hostname(),
            acquired_unix: 0,
            vault: vault.clone(),
        };
        let lock_file = lock_path(&vault);
        std::fs::write(&lock_file, serde_json::to_vec(&stale).unwrap()).unwrap();

        ensure_available(&vault).unwrap();
        // ...and leaves the tidying to whoever writes next.
        assert!(lock_file.exists());
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
