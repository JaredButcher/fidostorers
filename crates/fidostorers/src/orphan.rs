//! Recovering working directories left behind by a session that did not exit
//! cleanly (plan/08, "Orphan recovery").
//!
//! A `SIGKILL`, a panic, or a power loss skips shutdown entirely and leaves a
//! plaintext working directory on disk, with the changes in it never sealed. That
//! is the worst of both outcomes — the data is exposed *and*, from the user's point
//! of view, lost — so a session records what it has open, and the next session
//! looks for records whose owner is gone.
//!
//! The record contains no secret material: vault paths, working paths, aliases, and
//! a pid. The data key died with the process, which is why sealing an orphan costs
//! an unlock.

use std::path::{Path, PathBuf};

use serde::{Deserialize, Serialize};

use crate::{Mode, VaultError};

/// One session's open stores, rewritten whenever that set changes.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SessionRecord {
    pub pid: u32,
    pub hostname: String,
    pub started_unix: u64,
    pub stores: Vec<StoreRecord>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StoreRecord {
    pub alias: String,
    pub vault: PathBuf,
    pub work: PathBuf,
    pub mode: Mode,
}

/// A working directory whose session is gone.
#[derive(Debug, Clone)]
pub struct Orphan {
    pub store: StoreRecord,
    /// The record this came from, so acting on one orphan can rewrite the file
    /// without disturbing the others.
    pub record_path: PathBuf,
    pub pid: u32,
    /// Entries under the working path, and the newest modification time found, so
    /// the user has something concrete to decide from.
    pub entries: usize,
    pub last_modified: Option<std::time::SystemTime>,
}

/// Where session records live. Alongside the working directories, so a machine that
/// clears its runtime directory on reboot clears both together.
pub fn records_dir(root: &Path) -> PathBuf {
    root.join("sessions")
}

fn record_path(root: &Path, pid: u32) -> PathBuf {
    records_dir(root).join(format!("session-{pid}.json"))
}

/// Write this process's record, replacing any previous one.
///
/// Called whenever the open set changes, so a crash at any moment leaves a record
/// that matches what was actually open.
pub fn write_record(root: &Path, stores: Vec<StoreRecord>) -> Result<(), VaultError> {
    let dir = records_dir(root);
    crate::workdir::create_private_dir(&dir)?;

    let record = SessionRecord {
        pid: std::process::id(),
        hostname: crate::lock::hostname(),
        started_unix: now_unix(),
        stores,
    };
    let encoded = serde_json::to_vec_pretty(&record)
        .map_err(|err| VaultError::Internal(format!("cannot encode session record: {err}")))?;
    std::fs::write(record_path(root, std::process::id()), encoded)?;
    Ok(())
}

/// Remove this process's record. Called on a clean exit, which is what makes a
/// *remaining* record mean "did not exit cleanly".
pub fn clear_record(root: &Path) {
    let _ = std::fs::remove_file(record_path(root, std::process::id()));
}

/// Working directories left by sessions that are no longer running.
///
/// Only records this host wrote, whose pid is *provably* dead, are reported: the
/// same rule the vault lock uses, and for the same reason — offering to seal or
/// discard a directory a live session is still editing would be the one mistake
/// that destroys data.
pub fn find(root: &Path) -> Vec<Orphan> {
    let mut orphans = Vec::new();
    let Ok(entries) = std::fs::read_dir(records_dir(root)) else {
        return orphans;
    };

    for entry in entries.flatten() {
        let path = entry.path();
        let Some(record) = std::fs::read(&path)
            .ok()
            .and_then(|bytes| serde_json::from_slice::<SessionRecord>(&bytes).ok())
        else {
            continue;
        };
        if record.pid == std::process::id() {
            continue;
        }
        if !crate::lock::is_definitely_gone(record.pid, &record.hostname) {
            continue;
        }

        for store in record.stores {
            // A working directory that is already gone needs no recovery: the
            // session got far enough to clean up before it died.
            if !store.work.exists() {
                continue;
            }
            let (entries, last_modified) = summarize(&store.work);
            orphans.push(Orphan {
                store,
                record_path: path.clone(),
                pid: record.pid,
                entries,
                last_modified,
            });
        }
    }
    orphans
}

/// Drop one store from its session record, leaving the others for a later prompt.
///
/// Removing the record file once every store in it is resolved is what stops a
/// dealt-with orphan from being offered again — while "leave it for now" writes
/// nothing, so that one *does* come back next session, as plan/08 requires.
pub fn resolve(orphan: &Orphan) -> Result<(), VaultError> {
    let Ok(bytes) = std::fs::read(&orphan.record_path) else {
        return Ok(());
    };
    let Ok(mut record) = serde_json::from_slice::<SessionRecord>(&bytes) else {
        return Ok(());
    };

    record
        .stores
        .retain(|store| store.work != orphan.store.work);
    if record.stores.is_empty() {
        let _ = std::fs::remove_file(&orphan.record_path);
        return Ok(());
    }
    let encoded = serde_json::to_vec_pretty(&record)
        .map_err(|err| VaultError::Internal(format!("cannot encode session record: {err}")))?;
    std::fs::write(&orphan.record_path, encoded)?;
    Ok(())
}

fn summarize(path: &Path) -> (usize, Option<std::time::SystemTime>) {
    fn walk(path: &Path, count: &mut usize, newest: &mut Option<std::time::SystemTime>) {
        let Ok(meta) = std::fs::symlink_metadata(path) else {
            return;
        };
        *count += 1;
        if let Ok(modified) = meta.modified() {
            // Not `is_none_or`: that is Rust 1.82 and this workspace targets 1.75.
            if newest.map_or(true, |current| modified > current) {
                *newest = Some(modified);
            }
        }
        if meta.is_dir() && !meta.file_type().is_symlink() {
            if let Ok(children) = std::fs::read_dir(path) {
                for child in children.flatten() {
                    walk(&child.path(), count, newest);
                }
            }
        }
    }

    let mut count = 0;
    let mut newest = None;
    walk(path, &mut count, &mut newest);
    // The working path itself is not an entry the user put there.
    (count.saturating_sub(1), newest)
}

fn now_unix() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or_default()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn a_store(dir: &Path, alias: &str) -> StoreRecord {
        let work = dir.join(alias);
        std::fs::create_dir_all(&work).unwrap();
        std::fs::write(work.join("a.txt"), b"contents").unwrap();
        StoreRecord {
            alias: alias.to_string(),
            vault: dir.join(format!("{alias}.fido")),
            work,
            mode: Mode::Dir,
        }
    }

    fn write_foreign_record(root: &Path, pid: u32, stores: Vec<StoreRecord>) -> PathBuf {
        let dir = records_dir(root);
        std::fs::create_dir_all(&dir).unwrap();
        let record = SessionRecord {
            pid,
            hostname: crate::lock::hostname(),
            started_unix: 0,
            stores,
        };
        let path = dir.join(format!("session-{pid}.json"));
        std::fs::write(&path, serde_json::to_vec(&record).unwrap()).unwrap();
        path
    }

    #[test]
    fn a_live_session_leaves_no_orphans() {
        let dir = tempfile::tempdir().unwrap();
        let root = dir.path();
        write_record(root, vec![a_store(root, "tokens")]).unwrap();

        // Our own record describes stores that are still open, not orphans.
        assert!(find(root).is_empty());
        clear_record(root);
        assert!(find(root).is_empty());
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn a_dead_session_with_a_working_directory_is_an_orphan() {
        let dir = tempfile::tempdir().unwrap();
        let root = dir.path();
        // pid 0 is never a live process, so it stands in for a session that was
        // killed before it could clean up.
        write_foreign_record(root, 0, vec![a_store(root, "backup")]);

        let orphans = find(root);
        assert_eq!(orphans.len(), 1);
        assert_eq!(orphans[0].store.alias, "backup");
        assert_eq!(orphans[0].entries, 1);
        assert!(orphans[0].last_modified.is_some());
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn a_record_whose_working_directory_is_gone_is_not_offered() {
        let dir = tempfile::tempdir().unwrap();
        let root = dir.path();
        let mut store = a_store(root, "backup");
        std::fs::remove_dir_all(&store.work).unwrap();
        store.work = root.join("backup");
        write_foreign_record(root, 0, vec![store]);

        // The session cleaned up before dying; there is nothing to recover.
        assert!(find(root).is_empty());
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn resolving_one_store_leaves_the_others_to_be_offered() {
        let dir = tempfile::tempdir().unwrap();
        let root = dir.path();
        let record =
            write_foreign_record(root, 0, vec![a_store(root, "one"), a_store(root, "two")]);

        let orphans = find(root);
        assert_eq!(orphans.len(), 2);
        resolve(&orphans[0]).unwrap();

        let remaining = find(root);
        assert_eq!(remaining.len(), 1);
        assert_eq!(remaining[0].store.alias, "two");

        resolve(&remaining[0]).unwrap();
        assert!(find(root).is_empty());
        assert!(!record.exists(), "an emptied record is removed");
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn leaving_an_orphan_alone_offers_it_again() {
        let dir = tempfile::tempdir().unwrap();
        let root = dir.path();
        write_foreign_record(root, 0, vec![a_store(root, "backup")]);

        // "Leave it for now" writes nothing, so the prompt must return.
        assert_eq!(find(root).len(), 1);
        assert_eq!(find(root).len(), 1);
    }

    #[test]
    fn a_record_from_another_host_is_never_treated_as_dead() {
        let dir = tempfile::tempdir().unwrap();
        let root = dir.path();
        let store = a_store(root, "backup");
        let records = records_dir(root);
        std::fs::create_dir_all(&records).unwrap();
        let record = SessionRecord {
            pid: 0,
            hostname: "some-other-machine".to_string(),
            started_unix: 0,
            stores: vec![store],
        };
        std::fs::write(
            records.join("session-0.json"),
            serde_json::to_vec(&record).unwrap(),
        )
        .unwrap();

        // pid 0 is dead here, but says nothing about that machine — and the
        // working path may be on a share that machine is still editing.
        assert!(find(root).is_empty());
    }
}
