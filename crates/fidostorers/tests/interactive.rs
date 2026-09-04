//! End-to-end checks of `fidostorers interactive` (plan/08-interactive-mode.md).
//!
//! These drive the real binary with a real vault, which is possible without a
//! security key only because of the keyfile+password factor from M8 — the same
//! reason that milestone gave CI its first full unlock path.
//!
//! What is covered here is the part unit tests structurally cannot reach: that a
//! typed line becomes the right `Vault` call, that one unlock really does serve
//! many commands, and that the advisory lock excludes a concurrent writer.

use std::io::Write;
use std::path::Path;
use std::process::{Command, Stdio};

const PASSWORD: &str = "correct horse battery staple";

fn bin() -> Command {
    Command::new(env!("CARGO_BIN_EXE_fidostorers"))
}

/// Argon2's defaults are deliberately expensive, and an unoptimised test build makes
/// them several seconds each. Every vault here uses the cheapest legal parameters so
/// the suite spends its time on the session, not the KDF (plan/10, "Testing").
fn make_keyfile_vault(dir: &Path, mode: &str) -> (std::path::PathBuf, std::path::PathBuf) {
    let vault = dir.join("v.fido");
    let keyfile = dir.join("k.key");

    let status = bin()
        .args(["keyfile", "new"])
        .arg(&keyfile)
        .status()
        .unwrap();
    assert!(status.success());

    let mut child = bin()
        .arg("init")
        .arg(&vault)
        .args(["--mode", mode, "--auth", "keyfile", "--keyfile"])
        .arg(&keyfile)
        .args([
            "--password-stdin",
            "--argon2-memory",
            "8192",
            "--argon2-time",
            "1",
            "--argon2-parallelism",
            "1",
        ])
        .stdin(Stdio::piped())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()
        .unwrap();
    child
        .stdin
        .as_mut()
        .unwrap()
        .write_all(format!("{PASSWORD}\n").as_bytes())
        .unwrap();
    assert!(child.wait().unwrap().success(), "init failed");

    (vault, keyfile)
}

/// Run a session, feeding it `script` on stdin. The first line is expected to be an
/// `open`, so the password follows it.
fn session(vault: &Path, keyfile: &Path, script: &str) -> (String, String) {
    let mut child = bin()
        .args(["interactive", "--idle-timeout", "0"])
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .unwrap();

    let input = format!(
        "open {} --keyfile {} --password-stdin\n{PASSWORD}\n{script}\nexit\n",
        vault.display(),
        keyfile.display()
    );
    child
        .stdin
        .take()
        .unwrap()
        .write_all(input.as_bytes())
        .unwrap();

    let out = child.wait_with_output().unwrap();
    assert!(out.status.success(), "session exited with {:?}", out.status);
    (
        String::from_utf8_lossy(&out.stdout).into_owned(),
        String::from_utf8_lossy(&out.stderr).into_owned(),
    )
}

#[test]
fn one_unlock_serves_many_commands() {
    let dir = tempfile::tempdir().unwrap();
    let (vault, keyfile) = make_keyfile_vault(dir.path(), "kv");

    // The whole point of the milestone: one `open`, several operations, no second
    // password prompt anywhere in between.
    let (stdout, _) = session(
        &vault,
        &keyfile,
        "kv set v github --value ghp_token\n\
         kv set v gitlab --value glpat\n\
         kv ls v\n\
         kv get v github\n\
         kv rm v gitlab\n\
         kv ls v",
    );

    assert!(stdout.contains("opened \"v\" (kv)"), "{stdout}");
    assert!(stdout.contains("ghp_token"), "{stdout}");
    assert!(stdout.contains("removed \"gitlab\""), "{stdout}");
    assert_eq!(
        stdout.matches("Password").count(),
        0,
        "a session must not re-prompt: {stdout}"
    );
}

#[test]
fn session_writes_are_durable_and_readable_by_a_one_shot_command() {
    let dir = tempfile::tempdir().unwrap();
    let (vault, keyfile) = make_keyfile_vault(dir.path(), "kv");

    session(&vault, &keyfile, "kv set v github --value ghp_token");

    // A separate process, after the session has exited: the vault file really was
    // written, not merely held in memory.
    let mut child = bin()
        .arg("kv")
        .arg("get")
        .arg(&vault)
        .arg("github")
        .arg("--keyfile")
        .arg(&keyfile)
        .arg("--password-stdin")
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::null())
        .spawn()
        .unwrap();
    child
        .stdin
        .take()
        .unwrap()
        .write_all(format!("{PASSWORD}\n").as_bytes())
        .unwrap();
    let out = child.wait_with_output().unwrap();

    assert!(out.status.success());
    assert_eq!(String::from_utf8_lossy(&out.stdout), "ghp_token");
}

#[test]
fn closing_releases_the_lock_and_exiting_leaves_none_behind() {
    let dir = tempfile::tempdir().unwrap();
    let (vault, keyfile) = make_keyfile_vault(dir.path(), "kv");
    let lock = fidostorers::lock::lock_path(&vault);

    let (stdout, _) = session(&vault, &keyfile, "stores\nclose v\nstores");

    assert!(stdout.contains("closed \"v\""), "{stdout}");
    assert!(stdout.contains("no open stores"), "{stdout}");
    assert!(
        !lock.exists(),
        "a finished session must leave no lock file behind"
    );
}

#[test]
fn a_one_shot_write_refuses_while_a_session_holds_the_vault() {
    let dir = tempfile::tempdir().unwrap();
    let (vault, keyfile) = make_keyfile_vault(dir.path(), "kv");

    // Hold the lock the way an open store does, without needing a live session:
    // the exclusion being tested is the lock's, not the REPL's.
    let held = fidostorers::VaultLock::acquire(&vault).unwrap();

    let mut child = bin()
        .arg("kv")
        .arg("set")
        .arg(&vault)
        .args(["name", "--value", "x", "--keyfile"])
        .arg(&keyfile)
        .arg("--password-stdin")
        .stdin(Stdio::piped())
        .stdout(Stdio::null())
        .stderr(Stdio::piped())
        .spawn()
        .unwrap();
    child
        .stdin
        .take()
        .unwrap()
        .write_all(format!("{PASSWORD}\n").as_bytes())
        .unwrap();
    let out = child.wait_with_output().unwrap();
    let stderr = String::from_utf8_lossy(&out.stderr);

    assert!(!out.status.success(), "a writer must refuse a locked vault");
    assert!(
        stderr.contains("open in another fidostorers process"),
        "{stderr}"
    );

    // A reader is deliberately not excluded: a session holds its lock for minutes,
    // and reading cannot corrupt anything.
    drop(held);
}

#[test]
fn a_reader_is_not_excluded_by_a_held_lock() {
    let dir = tempfile::tempdir().unwrap();
    let (vault, _keyfile) = make_keyfile_vault(dir.path(), "kv");
    let _held = fidostorers::VaultLock::acquire(&vault).unwrap();

    let out = bin().arg("info").arg(&vault).output().unwrap();
    assert!(out.status.success(), "`info` must work on a locked vault");
    assert!(String::from_utf8_lossy(&out.stdout).contains("mode: kv"));
}

#[test]
fn session_info_is_authenticated_unlike_the_one_shot() {
    let dir = tempfile::tempdir().unwrap();
    let (vault, keyfile) = make_keyfile_vault(dir.path(), "kv");

    // The one-shot cannot verify `header_mac` without a touch; a session already
    // has, because opening the store unwrapped the data key.
    let one_shot = bin().arg("info").arg(&vault).output().unwrap();
    assert!(String::from_utf8_lossy(&one_shot.stdout).contains("UNAUTHENTICATED"));

    let (stdout, _) = session(&vault, &keyfile, "info");
    assert!(stdout.contains("verified:"), "{stdout}");
    assert!(!stdout.contains("UNAUTHENTICATED"), "{stdout}");
}

#[test]
fn a_bad_command_is_reported_without_ending_the_session() {
    let dir = tempfile::tempdir().unwrap();
    let (vault, keyfile) = make_keyfile_vault(dir.path(), "kv");

    // A typo must not cost the user their unlocked session.
    let (stdout, stderr) = session(
        &vault,
        &keyfile,
        "frobnicate\nkv get v nope\nkv set v ok --value fine\nkv ls v",
    );

    assert!(stderr.contains("no entry named"), "{stderr}");
    assert!(
        stdout.contains("ok"),
        "the session must keep working after errors: {stdout}"
    );
}

#[test]
fn stdin_sources_are_refused_inside_a_session() {
    let dir = tempfile::tempdir().unwrap();
    let (vault, keyfile) = make_keyfile_vault(dir.path(), "kv");

    // `--stdin` would eat the rest of the user's input, since stdin is the prompt.
    let (_, stderr) = session(&vault, &keyfile, "kv set v name --stdin");
    assert!(
        stderr.contains("--stdin cannot be used inside a session"),
        "{stderr}"
    );
}

#[test]
fn a_file_mode_store_opens_but_says_its_contents_are_not_extracted() {
    let dir = tempfile::tempdir().unwrap();
    let (vault, keyfile) = make_keyfile_vault(dir.path(), "file");

    // Working directories are the next milestone. Opening still earns its keep:
    // the key is cached, so `info`/`enroll`/`revoke` need no further touches.
    let (stdout, _) = session(&vault, &keyfile, "stores\ninfo");
    assert!(stdout.contains("opened \"v\" (file)"), "{stdout}");
    assert!(stdout.contains("not implemented yet"), "{stdout}");
    assert!(stdout.contains("mode: file"), "{stdout}");
}
