//! Property tests for the kv and directory round trips, per plan/05-testing-strategy.md.
//!
//! Fixed examples cover the cases we thought of; these cover the ones we did not —
//! empty values, names with unusual characters, near-duplicate paths, trees whose
//! shape collides with itself.
//!
//! Both build a real vault on disk with an arbitrary KEK, which is exactly what the
//! hardware seam is for (plan/02): no authenticator, real crypto, real file I/O.

use std::collections::BTreeMap;
use std::fs;
use std::path::{Path, PathBuf};

use fidostorers::{Enrollment, Mode, Vault};
use proptest::prelude::*;
use zeroize::Zeroizing;

const KEK: [u8; 32] = [0x5Au8; 32];
const CREDENTIAL_ID: &[u8] = &[1, 2, 3];

fn make_vault(path: &Path, mode: Mode) -> (Vault, Zeroizing<[u8; 32]>) {
    let vault = Vault::create(
        path,
        mode,
        &Enrollment {
            credential: fido_token::Credential {
                rp_id: "fidostorers.local".to_string(),
                credential_id: CREDENTIAL_ID.to_vec(),
                device_hint: None,
            },
            label: "primary".to_string(),
            salt: [7u8; 32],
            kek: Zeroizing::new(KEK),
        },
    )
    .unwrap();
    let data_key = vault
        .unlock_with(CREDENTIAL_ID, Zeroizing::new(KEK))
        .unwrap();
    (vault, data_key)
}

/// Entry names: any scalar values, since the store's keys are arbitrary strings.
/// Capped well under the 255-byte limit so the generator does not spend its time
/// rediscovering that one rejection.
fn entry_name() -> impl Strategy<Value = String> {
    proptest::collection::vec(any::<char>(), 1..12)
        .prop_map(|chars| chars.into_iter().collect::<String>())
        .prop_filter("name must fit the length limit", |s| {
            !s.is_empty() && s.len() <= 255
        })
}

proptest! {
    #![proptest_config(ProptestConfig::with_cases(48))]

    /// Whatever goes into a kv store comes back out, byte for byte, after a round
    /// trip through disk.
    #[test]
    fn kv_round_trips_arbitrary_entries(
        entries in proptest::collection::btree_map(
            entry_name(),
            proptest::collection::vec(any::<u8>(), 0..64),
            0..8,
        )
    ) {
        let dir = tempfile::TempDir::new().unwrap();
        let path = dir.path().join("kv.fido");
        let (mut vault, data_key) = make_vault(&path, Mode::Kv);

        for (name, value) in &entries {
            vault.kv_set(&data_key, name, value).unwrap();
        }

        // Reopen so the assertions run against what actually reached the file.
        let reopened = Vault::open(&path).unwrap();
        let data_key = reopened.unlock_with(CREDENTIAL_ID, Zeroizing::new(KEK)).unwrap();

        let names = reopened.kv_ls(&data_key).unwrap();
        prop_assert_eq!(&names, &entries.keys().cloned().collect::<Vec<_>>());
        for (name, value) in &entries {
            prop_assert_eq!(&reopened.kv_get(&data_key, name).unwrap()[..], &value[..]);
        }
    }

    /// Removing entries one at a time leaves exactly the rest, and never resurrects
    /// or corrupts a neighbour.
    #[test]
    fn kv_removal_leaves_the_rest_intact(
        entries in proptest::collection::btree_map(
            entry_name(),
            proptest::collection::vec(any::<u8>(), 0..32),
            1..6,
        )
    ) {
        let dir = tempfile::TempDir::new().unwrap();
        let path = dir.path().join("kv.fido");
        let (mut vault, data_key) = make_vault(&path, Mode::Kv);

        for (name, value) in &entries {
            vault.kv_set(&data_key, name, value).unwrap();
        }

        let mut remaining: BTreeMap<_, _> = entries.clone();
        while let Some(name) = remaining.keys().next().cloned() {
            vault.kv_rm(&data_key, &name).unwrap();
            remaining.remove(&name);

            prop_assert_eq!(
                vault.kv_ls(&data_key).unwrap(),
                remaining.keys().cloned().collect::<Vec<_>>()
            );
            for (name, value) in &remaining {
                prop_assert_eq!(&vault.kv_get(&data_key, name).unwrap()[..], &value[..]);
            }
        }
    }

    /// An arbitrary small tree survives archiving and extraction unchanged.
    #[test]
    fn dir_round_trips_arbitrary_trees(paths in tree_paths()) {
        let dir = tempfile::TempDir::new().unwrap();
        let src = dir.path().join("src");
        fs::create_dir(&src).unwrap();
        // Creating these is best-effort: a generated set can ask for both a file
        // `a` and a file `a/b`, which no filesystem allows. Whatever lands on disk
        // is the ground truth, which is a stronger comparison than predicting it.
        for (rel, contents) in &paths {
            let full = src.join(rel);
            if let Some(parent) = full.parent() {
                if fs::create_dir_all(parent).is_err() {
                    continue;
                }
            }
            let _ = fs::write(&full, contents);
        }
        let expected = walk(&src);

        let path = dir.path().join("tree.fido");
        let (mut vault, data_key) = make_vault(&path, Mode::Dir);
        vault.seal_dir(&data_key, &src).unwrap();

        let reopened = Vault::open(&path).unwrap();
        let data_key = reopened.unlock_with(CREDENTIAL_ID, Zeroizing::new(KEK)).unwrap();
        let out = dir.path().join("out");
        let report = reopened.open_dir(&data_key, &out).unwrap();

        prop_assert!(report.is_complete(), "skipped: {:?}", report.skipped);
        prop_assert_eq!(walk(&out), expected);
    }
}

/// Relative paths one to three segments deep, drawn from a small alphabet so
/// near-duplicates ("a" vs "a/a") actually collide often enough to matter.
fn tree_paths() -> impl Strategy<Value = Vec<(PathBuf, Vec<u8>)>> {
    let segment = "[ab][cd]?";
    let path = proptest::collection::vec(segment, 1..4)
        .prop_map(|segments| segments.iter().collect::<PathBuf>());
    proptest::collection::vec((path, proptest::collection::vec(any::<u8>(), 0..24)), 0..8)
}

#[derive(Debug, PartialEq, Eq, PartialOrd, Ord)]
enum Entry {
    Dir,
    File(Vec<u8>),
}

/// Every path under `root`, sorted, with directories and file contents — the
/// ground truth for comparing two trees.
fn walk(root: &Path) -> Vec<(String, Entry)> {
    fn recurse(root: &Path, rel: &Path, out: &mut Vec<(String, Entry)>) {
        let mut children: Vec<_> = fs::read_dir(root.join(rel))
            .unwrap()
            .map(|e| e.unwrap())
            .collect();
        children.sort_by_key(|e| e.file_name());

        for child in children {
            let child_rel = rel.join(child.file_name());
            let key = child_rel.to_string_lossy().replace('\\', "/");
            let meta = fs::symlink_metadata(root.join(&child_rel)).unwrap();
            if meta.is_dir() {
                out.push((key, Entry::Dir));
                recurse(root, &child_rel, out);
            } else {
                out.push((key, Entry::File(fs::read(root.join(&child_rel)).unwrap())));
            }
        }
    }

    let mut out = Vec::new();
    recurse(root, Path::new(""), &mut out);
    out.sort();
    out
}
