//! `tar` archiving and extraction for directory-mode vaults.
//!
//! The policy this implements is settled in plan/07-open-decisions.md #8: the
//! archive is always full fidelity — symlinks stored as symlinks and never
//! followed, Unix mode bits stored as-is on every OS — while *extraction* is
//! best-effort per platform. A Windows box that cannot create symlinks warns and
//! continues rather than failing the whole extraction, but the caller is told
//! exactly what was skipped so it can exit non-zero.
//!
//! # Untrusted contents
//!
//! A vault's ciphertext is authenticated, which proves it has not been altered
//! since it was sealed — it does *not* prove the person who sealed it meant you
//! well. Someone can hand you a vault and a key that opens it. So entry paths are
//! treated as hostile input: [`safe_relative`] rejects absolute paths, `..`
//! traversal, and Windows path prefixes, and every entry's parent directory is
//! canonicalized and checked to be inside the output directory before anything is
//! written. That second check is what stops the symlink variant of the attack,
//! where an archive stores a symlink `a -> /etc` and then an entry `a/passwd`.

use std::fs;
use std::io;
use std::path::{Component, Path, PathBuf};

use crate::VaultError;

/// What an extraction actually managed to do.
///
/// `open_dir` returns this rather than `()` because a partial extraction is a real
/// outcome on Windows, and callers must be able to tell it from a complete one —
/// plan/07 #8 requires a distinct non-zero exit for it.
#[derive(Debug, Default)]
pub struct ExtractReport {
    /// Entries written successfully.
    pub extracted: usize,
    /// Entries that could not be created, with why.
    pub skipped: Vec<SkippedEntry>,
    /// True if Unix mode bits were discarded because this platform has none.
    pub modes_ignored: bool,
}

#[derive(Debug)]
pub struct SkippedEntry {
    pub path: PathBuf,
    pub reason: String,
}

impl ExtractReport {
    /// False if anything was skipped, i.e. the extracted tree is incomplete.
    pub fn is_complete(&self) -> bool {
        self.skipped.is_empty()
    }
}

/// Archive `root` into a deterministic tar stream.
///
/// Entries are emitted in sorted path order, and uid/gid are zeroed, so sealing an
/// unchanged tree twice produces identical bytes. (The vault around it still
/// differs, because every write draws a fresh payload nonce — plan/03.)
pub(crate) fn build(root: &Path) -> Result<Vec<u8>, VaultError> {
    if !root.is_dir() {
        return Err(VaultError::NotADirectory(root.to_path_buf()));
    }

    let mut entries = Vec::new();
    collect(root, PathBuf::new(), &mut entries)?;
    // Sort on the '/'-joined form so the order does not depend on the host's path
    // separator; this also puts every parent directory before its children.
    entries.sort_by_key(|path| sort_key(path));

    let mut builder = tar::Builder::new(Vec::new());
    for rel in &entries {
        let full = root.join(rel);
        // `symlink_metadata`, never `metadata`: a symlink must be archived as a
        // symlink, not as a copy of whatever it points at.
        let meta = fs::symlink_metadata(&full)?;

        let mut header = tar::Header::new_gnu();
        header.set_uid(0);
        header.set_gid(0);
        header.set_mtime(mtime_of(&meta));
        header.set_mode(mode_of(&meta));

        if meta.file_type().is_symlink() {
            let target = fs::read_link(&full)?;
            header.set_entry_type(tar::EntryType::Symlink);
            header.set_size(0);
            builder
                .append_link(&mut header, rel, &target)
                .map_err(VaultError::Io)?;
        } else if meta.is_dir() {
            header.set_entry_type(tar::EntryType::Directory);
            header.set_size(0);
            builder
                .append_data(&mut header, rel, io::empty())
                .map_err(VaultError::Io)?;
        } else {
            header.set_entry_type(tar::EntryType::Regular);
            header.set_size(meta.len());
            let file = fs::File::open(&full)?;
            builder
                .append_data(&mut header, rel, file)
                .map_err(VaultError::Io)?;
        }
    }

    builder.into_inner().map_err(VaultError::Io)
}

/// A valid, empty tar stream — the payload a freshly created `dir` vault holds
/// before anything is sealed into it.
pub(crate) fn empty() -> Result<Vec<u8>, VaultError> {
    tar::Builder::new(Vec::new())
        .into_inner()
        .map_err(VaultError::Io)
}

fn sort_key(path: &Path) -> String {
    path.components()
        .map(|c| c.as_os_str().to_string_lossy().into_owned())
        .collect::<Vec<_>>()
        .join("/")
}

fn collect(root: &Path, rel: PathBuf, out: &mut Vec<PathBuf>) -> Result<(), VaultError> {
    for entry in fs::read_dir(root.join(&rel))? {
        let entry = entry?;
        let child = rel.join(entry.file_name());
        let file_type = entry.file_type()?;

        out.push(child.clone());
        // Never recurse through a symlink: it is stored as a link, and following it
        // would duplicate bytes and could loop.
        if file_type.is_dir() && !file_type.is_symlink() {
            collect(root, child, out)?;
        }
    }
    Ok(())
}

/// Extract a tar stream into `output`, applying what this platform allows.
pub(crate) fn extract(tar_bytes: &[u8], output: &Path) -> Result<ExtractReport, VaultError> {
    fs::create_dir_all(output)?;
    let root = fs::canonicalize(output)?;

    let mut report = ExtractReport::default();
    // Directory modes are applied last: setting a read-only mode on a directory
    // before writing its children would lock us out of it.
    let mut directory_modes: Vec<(PathBuf, u32)> = Vec::new();

    let mut archive = tar::Archive::new(io::Cursor::new(tar_bytes));
    for entry in archive.entries().map_err(VaultError::Io)? {
        let mut entry = entry.map_err(VaultError::Io)?;
        let raw = entry.path().map_err(VaultError::Io)?.into_owned();
        let rel = safe_relative(&raw)?;
        let dest = root.join(&rel);
        let mode = entry.header().mode().unwrap_or(0o644);

        ensure_parent_inside(&root, &dest, &rel)?;

        match entry.header().entry_type() {
            tar::EntryType::Directory => {
                fs::create_dir_all(&dest)?;
                directory_modes.push((dest, mode));
                report.extracted += 1;
            }
            tar::EntryType::Symlink => {
                let target = entry
                    .link_name()
                    .map_err(VaultError::Io)?
                    .ok_or_else(|| {
                        VaultError::MalformedArchive(format!(
                            "symlink entry {} has no target",
                            rel.display()
                        ))
                    })?
                    .into_owned();
                match create_symlink(&target, &dest) {
                    Ok(()) => report.extracted += 1,
                    Err(err) => report.skipped.push(SkippedEntry {
                        path: rel.clone(),
                        reason: format!("could not create symlink to {}: {err}", target.display()),
                    }),
                }
            }
            tar::EntryType::Regular | tar::EntryType::Continuous => {
                // Remove first so we never write *through* a symlink left in place
                // by an earlier entry or a pre-existing output tree.
                let _ = fs::remove_file(&dest);
                let mut file = fs::File::create(&dest)?;
                io::copy(&mut entry, &mut file)?;
                drop(file);
                if !apply_mode(&dest, mode)? {
                    report.modes_ignored = true;
                }
                report.extracted += 1;
            }
            other => {
                report.skipped.push(SkippedEntry {
                    path: rel.clone(),
                    reason: format!("unsupported tar entry type {other:?}"),
                });
            }
        }
    }

    // Deepest first, so a parent's mode is not applied before its children exist.
    directory_modes.sort_by_key(|(path, _)| std::cmp::Reverse(path.components().count()));
    for (path, mode) in directory_modes {
        if !apply_mode(&path, mode)? {
            report.modes_ignored = true;
        }
    }

    Ok(report)
}

/// Reduce an archive path to a relative one, rejecting anything that could escape
/// the output directory.
fn safe_relative(path: &Path) -> Result<PathBuf, VaultError> {
    let mut out = PathBuf::new();
    for component in path.components() {
        match component {
            Component::Normal(part) => out.push(part),
            // Harmless, just noise.
            Component::CurDir => {}
            Component::ParentDir | Component::RootDir | Component::Prefix(_) => {
                return Err(VaultError::UnsafeArchivePath(format!(
                    "{} escapes the output directory",
                    path.display()
                )));
            }
        }
    }
    if out.as_os_str().is_empty() {
        return Err(VaultError::UnsafeArchivePath(
            "archive contains an empty path".to_string(),
        ));
    }
    Ok(out)
}

/// Create `dest`'s parent and confirm it really resolves inside `root`.
///
/// `safe_relative` alone is not enough: it rejects `../x`, but not the two-entry
/// sequence "symlink `a` -> /etc" then "file `a/passwd`", where every component is
/// `Normal`. Canonicalizing the parent resolves that symlink and catches it.
fn ensure_parent_inside(root: &Path, dest: &Path, rel: &Path) -> Result<(), VaultError> {
    let parent = match dest.parent() {
        Some(parent) => parent,
        None => return Ok(()),
    };
    fs::create_dir_all(parent)?;
    let canonical = fs::canonicalize(parent)?;
    if !canonical.starts_with(root) {
        return Err(VaultError::UnsafeArchivePath(format!(
            "{} resolves to {}, outside the output directory",
            rel.display(),
            canonical.display()
        )));
    }
    Ok(())
}

#[cfg(unix)]
fn mode_of(meta: &fs::Metadata) -> u32 {
    use std::os::unix::fs::PermissionsExt;
    meta.permissions().mode() & 0o7777
}

/// Windows has no Unix mode bits, so synthesize conventional ones. A vault written
/// on Linux keeps its real modes; one written on Windows gets plausible defaults,
/// which is the best that can be said for a platform that does not track them.
#[cfg(windows)]
fn mode_of(meta: &fs::Metadata) -> u32 {
    if meta.is_dir() {
        0o755
    } else if meta.permissions().readonly() {
        0o444
    } else {
        0o644
    }
}

fn mtime_of(meta: &fs::Metadata) -> u64 {
    meta.modified()
        .ok()
        .and_then(|t| t.duration_since(std::time::UNIX_EPOCH).ok())
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

/// Returns whether the mode was actually applied; `false` means this platform has
/// no mode bits to apply, which the caller reports once rather than per entry.
#[cfg(unix)]
fn apply_mode(path: &Path, mode: u32) -> Result<bool, VaultError> {
    use std::os::unix::fs::PermissionsExt;
    fs::set_permissions(path, fs::Permissions::from_mode(mode & 0o7777))?;
    Ok(true)
}

#[cfg(windows)]
fn apply_mode(_path: &Path, _mode: u32) -> Result<bool, VaultError> {
    Ok(false)
}

#[cfg(unix)]
fn create_symlink(target: &Path, dest: &Path) -> io::Result<()> {
    let _ = fs::remove_file(dest);
    std::os::unix::fs::symlink(target, dest)
}

/// On Windows, symlink creation needs Developer Mode or elevation, and the call
/// differs for file and directory targets. Both failure modes surface as an
/// `io::Error`, which the caller turns into a skipped entry rather than a hard
/// failure (plan/07 #8).
#[cfg(windows)]
fn create_symlink(target: &Path, dest: &Path) -> io::Result<()> {
    let _ = fs::remove_file(dest);
    let resolved = dest.parent().map(|p| p.join(target));
    let target_is_dir = resolved.map(|p| p.is_dir()).unwrap_or(false);
    if target_is_dir {
        std::os::windows::fs::symlink_dir(target, dest)
    } else {
        std::os::windows::fs::symlink_file(target, dest)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::TempDir;

    /// nested dirs, an empty dir, a nested empty dir, and files at two depths.
    fn sample_tree(root: &Path) {
        fs::create_dir_all(root.join("a/b/c")).unwrap();
        fs::create_dir_all(root.join("empty")).unwrap();
        fs::create_dir_all(root.join("a/also-empty")).unwrap();
        fs::write(root.join("top.txt"), b"top level").unwrap();
        fs::write(root.join("a/mid.txt"), b"middle").unwrap();
        fs::write(root.join("a/b/c/deep.bin"), [0u8, 1, 2, 255]).unwrap();
    }

    fn entry_names(tar_bytes: &[u8]) -> Vec<String> {
        let mut archive = tar::Archive::new(io::Cursor::new(tar_bytes));
        archive
            .entries()
            .unwrap()
            .map(|e| e.unwrap().path().unwrap().to_string_lossy().into_owned())
            .collect()
    }

    #[test]
    fn round_trips_a_tree_including_empty_directories() {
        let src = TempDir::new().unwrap();
        sample_tree(src.path());

        let tar = build(src.path()).unwrap();
        let dst = TempDir::new().unwrap();
        let report = extract(&tar, dst.path()).unwrap();

        assert!(report.is_complete(), "{:?}", report.skipped);
        assert_eq!(fs::read(dst.path().join("top.txt")).unwrap(), b"top level");
        assert_eq!(fs::read(dst.path().join("a/mid.txt")).unwrap(), b"middle");
        assert_eq!(
            fs::read(dst.path().join("a/b/c/deep.bin")).unwrap(),
            [0u8, 1, 2, 255]
        );
        assert!(dst.path().join("empty").is_dir(), "empty dir was dropped");
        assert!(
            dst.path().join("a/also-empty").is_dir(),
            "nested empty dir was dropped"
        );
    }

    #[test]
    fn entries_are_sorted_so_the_archive_is_reproducible() {
        let src = TempDir::new().unwrap();
        sample_tree(src.path());

        let first = build(src.path()).unwrap();
        let second = build(src.path()).unwrap();
        assert_eq!(first, second, "sealing an unchanged tree twice must agree");

        let mut names = entry_names(&first);
        let sorted = {
            let mut n = names.clone();
            n.sort();
            n
        };
        assert_eq!(names, sorted, "entries are not in sorted order");
        // A parent must precede its children, or extraction creates them implicitly
        // and loses the parent's own metadata.
        names.dedup();
        assert!(
            names.iter().position(|n| n == "a").unwrap()
                < names.iter().position(|n| n == "a/b").unwrap()
        );
    }

    #[test]
    fn rejects_a_root_that_is_not_a_directory() {
        let dir = TempDir::new().unwrap();
        let file = dir.path().join("f.txt");
        fs::write(&file, b"x").unwrap();
        assert!(matches!(build(&file), Err(VaultError::NotADirectory(_))));
    }

    #[test]
    fn safe_relative_rejects_traversal() {
        assert!(safe_relative(Path::new("../evil")).is_err());
        assert!(safe_relative(Path::new("a/../../evil")).is_err());
        assert!(safe_relative(Path::new("/etc/passwd")).is_err());
        assert!(safe_relative(Path::new("")).is_err());
        assert_eq!(safe_relative(Path::new("./a/b")).unwrap(), Path::new("a/b"));
        assert_eq!(safe_relative(Path::new("a/b")).unwrap(), Path::new("a/b"));
    }

    /// Build a tar whose entry name is written straight into the header bytes.
    ///
    /// `Header::set_path` refuses `..` and absolute paths, which is the right
    /// behaviour for a writer but means the safe API cannot produce the archive an
    /// attacker would send. So the name field is patched in place and the checksum
    /// recomputed — this is what a hostile archive actually looks like on the wire.
    fn tar_with_raw_path(path: &str, contents: &[u8]) -> Vec<u8> {
        let mut header = tar::Header::new_gnu();
        header.set_size(contents.len() as u64);
        header.set_mode(0o644);
        header.set_entry_type(tar::EntryType::Regular);
        header.set_path("placeholder").unwrap();
        header.set_cksum();

        let mut builder = tar::Builder::new(Vec::new());
        builder.append(&header, contents).unwrap();
        let mut bytes = builder.into_inner().unwrap();

        let name = path.as_bytes();
        assert!(name.len() < 100, "test names fit the ustar name field");
        bytes[0..100].fill(0);
        bytes[0..name.len()].copy_from_slice(name);

        // ustar checksum: sum every header byte with the checksum field blanked,
        // then write it back as six octal digits, NUL, space.
        bytes[148..156].fill(b' ');
        let sum: u32 = bytes[0..512].iter().map(|&b| u32::from(b)).sum();
        bytes[148..156].copy_from_slice(format!("{sum:06o}\0 ").as_bytes());
        bytes
    }

    #[test]
    fn extraction_refuses_a_path_that_escapes_the_output_directory() {
        let dst = TempDir::new().unwrap();
        let tar = tar_with_raw_path("../escaped.txt", b"pwned");
        let err = extract(&tar, dst.path()).unwrap_err();
        assert!(
            matches!(err, VaultError::UnsafeArchivePath(_)),
            "got {err:?}"
        );
        assert!(
            !dst.path().parent().unwrap().join("escaped.txt").exists(),
            "the escaping file was actually written"
        );
    }

    #[test]
    fn extraction_refuses_an_absolute_path() {
        let dst = TempDir::new().unwrap();
        let tar = tar_with_raw_path("/tmp/absolute-escape.txt", b"pwned");
        assert!(matches!(
            extract(&tar, dst.path()),
            Err(VaultError::UnsafeArchivePath(_))
        ));
    }

    #[cfg(unix)]
    #[test]
    fn symlinks_are_stored_as_links_and_never_followed() {
        let src = TempDir::new().unwrap();
        fs::write(src.path().join("real.txt"), b"the real contents").unwrap();
        std::os::unix::fs::symlink("real.txt", src.path().join("link.txt")).unwrap();
        fs::create_dir(src.path().join("realdir")).unwrap();
        std::os::unix::fs::symlink("realdir", src.path().join("linkdir")).unwrap();

        let tar = build(src.path()).unwrap();

        // The link must be a Symlink entry of size 0, not a second copy of the file.
        let mut archive = tar::Archive::new(io::Cursor::new(&tar[..]));
        let link = archive
            .entries()
            .unwrap()
            .map(|e| e.unwrap())
            .find(|e| e.path().unwrap() == Path::new("link.txt"))
            .expect("link.txt is in the archive");
        assert_eq!(link.header().entry_type(), tar::EntryType::Symlink);
        assert_eq!(link.header().size().unwrap(), 0);
        assert_eq!(link.link_name().unwrap().unwrap(), Path::new("real.txt"));

        let dst = TempDir::new().unwrap();
        let report = extract(&tar, dst.path()).unwrap();
        assert!(report.is_complete(), "{:?}", report.skipped);
        assert!(fs::symlink_metadata(dst.path().join("link.txt"))
            .unwrap()
            .file_type()
            .is_symlink());
        assert_eq!(
            fs::read_link(dst.path().join("link.txt")).unwrap(),
            Path::new("real.txt")
        );
    }

    #[cfg(unix)]
    #[test]
    fn a_symlink_cycle_does_not_hang_the_archiver() {
        let src = TempDir::new().unwrap();
        fs::create_dir(src.path().join("d")).unwrap();
        // d/loop -> .., which a follow-the-links walker would recurse forever on.
        std::os::unix::fs::symlink("..", src.path().join("d/loop")).unwrap();

        let tar = build(src.path()).unwrap();
        let names = entry_names(&tar);
        assert_eq!(names, vec!["d".to_string(), "d/loop".to_string()]);
    }

    #[cfg(unix)]
    #[test]
    fn unix_mode_bits_survive_a_round_trip() {
        use std::os::unix::fs::PermissionsExt;

        let src = TempDir::new().unwrap();
        let script = src.path().join("run.sh");
        fs::write(&script, b"#!/bin/sh\necho hi\n").unwrap();
        fs::set_permissions(&script, fs::Permissions::from_mode(0o755)).unwrap();
        let secret = src.path().join("secret");
        fs::write(&secret, b"private").unwrap();
        fs::set_permissions(&secret, fs::Permissions::from_mode(0o600)).unwrap();

        let tar = build(src.path()).unwrap();
        let dst = TempDir::new().unwrap();
        extract(&tar, dst.path()).unwrap();

        let mode = |p: &Path| fs::metadata(p).unwrap().permissions().mode() & 0o777;
        assert_eq!(
            mode(&dst.path().join("run.sh")),
            0o755,
            "executable bit lost"
        );
        assert_eq!(mode(&dst.path().join("secret")), 0o600, "private bit lost");
    }

    #[cfg(unix)]
    #[test]
    fn a_read_only_directory_can_still_have_its_children_written() {
        use std::os::unix::fs::PermissionsExt;

        let src = TempDir::new().unwrap();
        fs::create_dir(src.path().join("ro")).unwrap();
        fs::write(src.path().join("ro/inside.txt"), b"contents").unwrap();
        fs::set_permissions(src.path().join("ro"), fs::Permissions::from_mode(0o555)).unwrap();

        let tar = build(src.path()).unwrap();
        let dst = TempDir::new().unwrap();
        let report = extract(&tar, dst.path()).unwrap();

        assert!(report.is_complete(), "{:?}", report.skipped);
        assert_eq!(
            fs::read(dst.path().join("ro/inside.txt")).unwrap(),
            b"contents"
        );
        assert_eq!(
            fs::metadata(dst.path().join("ro"))
                .unwrap()
                .permissions()
                .mode()
                & 0o777,
            0o555
        );
        // Leave it writable so TempDir can clean up.
        fs::set_permissions(dst.path().join("ro"), fs::Permissions::from_mode(0o755)).unwrap();
    }

    #[cfg(unix)]
    #[test]
    fn extraction_refuses_to_write_through_a_symlink_out_of_the_tree() {
        // The two-step attack: store a symlink pointing outside, then an entry
        // underneath it. Every path component is `Normal`, so only canonicalizing
        // the parent catches this.
        let elsewhere = TempDir::new().unwrap();
        let dst = TempDir::new().unwrap();

        let mut builder = tar::Builder::new(Vec::new());
        let mut link = tar::Header::new_gnu();
        link.set_entry_type(tar::EntryType::Symlink);
        link.set_size(0);
        link.set_mode(0o777);
        builder
            .append_link(&mut link, "escape", elsewhere.path())
            .unwrap();

        let payload = b"pwned";
        let mut file = tar::Header::new_gnu();
        file.set_entry_type(tar::EntryType::Regular);
        file.set_size(payload.len() as u64);
        file.set_mode(0o644);
        file.set_path("escape/pwned.txt").unwrap();
        file.set_cksum();
        builder.append(&file, &payload[..]).unwrap();
        let tar = builder.into_inner().unwrap();

        let err = extract(&tar, dst.path()).unwrap_err();
        assert!(
            matches!(err, VaultError::UnsafeArchivePath(_)),
            "got {err:?}"
        );
        assert!(
            !elsewhere.path().join("pwned.txt").exists(),
            "wrote outside the output directory"
        );
    }

    #[test]
    fn unsupported_entry_types_are_skipped_not_fatal() {
        let mut header = tar::Header::new_gnu();
        header.set_entry_type(tar::EntryType::Fifo);
        header.set_size(0);
        header.set_mode(0o644);
        header.set_path("a-fifo").unwrap();
        header.set_cksum();
        let mut builder = tar::Builder::new(Vec::new());
        builder.append(&header, io::empty()).unwrap();
        let tar = builder.into_inner().unwrap();

        let dst = TempDir::new().unwrap();
        let report = extract(&tar, dst.path()).unwrap();
        assert!(!report.is_complete());
        assert_eq!(report.skipped.len(), 1);
        assert_eq!(report.skipped[0].path, Path::new("a-fifo"));
    }

    #[test]
    fn an_empty_tree_round_trips() {
        let src = TempDir::new().unwrap();
        let tar = build(src.path()).unwrap();
        let dst = TempDir::new().unwrap();
        let report = extract(&tar, dst.path()).unwrap();
        assert!(report.is_complete());
        assert_eq!(report.extracted, 0);
    }
}
