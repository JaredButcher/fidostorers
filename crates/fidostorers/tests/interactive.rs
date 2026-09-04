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
use std::path::{Path, PathBuf};
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

/// Spawn a session with this test's runtime directory, so working directories and
/// session records never touch the developer's real one.
fn spawn_session(runtime: &Path) -> std::process::Child {
    bin()
        .args(["interactive", "--idle-timeout", "0"])
        .env("XDG_RUNTIME_DIR", runtime)
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .unwrap()
}

/// Run a session, feeding it `script` on stdin. The first line is an `open`, so the
/// password follows it; `open_args` is appended to that line.
fn session(vault: &Path, keyfile: &Path, open_args: &str, script: &str) -> (String, String) {
    let runtime = vault.parent().unwrap().join("runtime");
    std::fs::create_dir_all(&runtime).unwrap();
    let mut child = spawn_session(&runtime);

    let input = format!(
        "open \"{}\" {open_args} --keyfile \"{}\" --password-stdin\n{PASSWORD}\n{script}\nexit\n",
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
    (
        String::from_utf8_lossy(&out.stdout).into_owned(),
        String::from_utf8_lossy(&out.stderr).into_owned(),
    )
}

/// Open a store, wait for its working directory to appear, run `edit` against it,
/// then exit -- which is what exercises extract/edit/seal end to end.
fn session_with_edit(
    vault: &Path,
    keyfile: &Path,
    work: &Path,
    edit: impl FnOnce(&Path),
) -> (String, String) {
    let runtime = vault.parent().unwrap().join("runtime");
    std::fs::create_dir_all(&runtime).unwrap();
    let mut child = spawn_session(&runtime);
    let mut stdin = child.stdin.take().unwrap();

    stdin
        .write_all(
            format!(
                "open \"{}\" --work-dir \"{}\" --keyfile \"{}\" --password-stdin\n{PASSWORD}\n",
                vault.display(),
                work.display(),
                keyfile.display()
            )
            .as_bytes(),
        )
        .unwrap();

    // The unlock runs Argon2, which is slow in an unoptimised test build.
    let deadline = std::time::Instant::now() + std::time::Duration::from_secs(60);
    while !work.exists() && std::time::Instant::now() < deadline {
        std::thread::sleep(std::time::Duration::from_millis(50));
    }
    assert!(
        work.exists(),
        "the session never extracted a working directory"
    );

    edit(work);
    stdin.write_all(b"exit\n").unwrap();
    drop(stdin);

    let out = child.wait_with_output().unwrap();
    (
        String::from_utf8_lossy(&out.stdout).into_owned(),
        String::from_utf8_lossy(&out.stderr).into_owned(),
    )
}

/// Decrypt a file vault with a one-shot command and return its contents.
fn one_shot_unlock(vault: &Path, keyfile: &Path, out_path: PathBuf) -> Vec<u8> {
    let mut child = bin()
        .arg("unlock")
        .arg(vault)
        .arg(&out_path)
        .arg("--keyfile")
        .arg(keyfile)
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
    assert!(
        out.status.success(),
        "unlock failed: {}",
        String::from_utf8_lossy(&out.stderr)
    );
    std::fs::read(&out_path).unwrap()
}

/// A lock file as another live process on another machine would have written it.
fn write_foreign_lock(vault: &Path) {
    let info = serde_json::json!({
        "pid": 4321,
        "hostname": "some-other-machine",
        "acquired_unix": 0,
        "vault": vault,
    });
    std::fs::write(
        fidostorers::lock::lock_path(vault),
        serde_json::to_vec(&info).unwrap(),
    )
    .unwrap();
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
        "",
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

    session(&vault, &keyfile, "", "kv set v github --value ghp_token");

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

    let (stdout, _) = session(&vault, &keyfile, "", "stores\nclose v\nstores");

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
fn a_reader_is_excluded_too_while_a_vault_is_held() {
    let dir = tempfile::tempdir().unwrap();
    let (vault, _keyfile) = make_keyfile_vault(dir.path(), "kv");
    write_foreign_lock(&vault);

    // While a session holds a vault, no other fidostorers process may open it --
    // reading included, because the session's working directory can hold edits the
    // vault file does not have yet.
    let out = bin().arg("info").arg(&vault).output().unwrap();
    assert!(!out.status.success(), "a reader must refuse a held vault");
    assert!(String::from_utf8_lossy(&out.stderr).contains("open in another fidostorers process"));
}

#[test]
fn a_reader_is_unaffected_once_the_holder_is_gone() {
    let dir = tempfile::tempdir().unwrap();
    let (vault, _keyfile) = make_keyfile_vault(dir.path(), "kv");

    let out = bin().arg("info").arg(&vault).output().unwrap();
    assert!(out.status.success(), "{out:?}");
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

    let (stdout, _) = session(&vault, &keyfile, "", "info");
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
        "",
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
    let (_, stderr) = session(&vault, &keyfile, "", "kv set v name --stdin");
    assert!(
        stderr.contains("--stdin cannot be used inside a session"),
        "{stderr}"
    );
}

#[test]
fn a_file_store_is_extracted_edited_and_sealed_back() {
    let dir = tempfile::tempdir().unwrap();
    let (vault, keyfile) = make_keyfile_vault(dir.path(), "file");
    let work = dir.path().join("work");

    let (stdout, _) = session_with_edit(&vault, &keyfile, &work, |path| {
        std::fs::write(path, b"edited in the session").unwrap();
    });

    assert!(stdout.contains("(file) at"), "{stdout}");
    assert!(stdout.contains("sealed"), "{stdout}");
    assert!(!work.exists(), "closing must remove the plaintext");
    assert_eq!(
        one_shot_unlock(&vault, &keyfile, dir.path().join("out")),
        b"edited in the session"
    );
}

#[test]
fn an_unchanged_store_is_not_rewritten() {
    let dir = tempfile::tempdir().unwrap();
    let (vault, keyfile) = make_keyfile_vault(dir.path(), "dir");
    let work = dir.path().join("work");

    let before = std::fs::read(&vault).unwrap();
    let (stdout, _) = session(
        &vault,
        &keyfile,
        &format!("--work-dir \"{}\"", work.display()),
        "stores",
    );

    assert!(stdout.contains("unchanged, nothing to write"), "{stdout}");
    assert_eq!(
        std::fs::read(&vault).unwrap(),
        before,
        "a store nobody touched must leave the vault byte-identical"
    );
}

#[test]
fn a_dir_store_round_trips_edits_through_its_working_directory() {
    let dir = tempfile::tempdir().unwrap();
    let (vault, keyfile) = make_keyfile_vault(dir.path(), "dir");
    let work = dir.path().join("work");

    let (stdout, _) = session_with_edit(&vault, &keyfile, &work, |path| {
        std::fs::create_dir_all(path.join("sub")).unwrap();
        std::fs::write(path.join("sub/note.txt"), b"hello").unwrap();
    });
    assert!(stdout.contains("sealed"), "{stdout}");

    let restored = dir.path().join("restored");
    let mut child = bin()
        .arg("unlock")
        .arg(&vault)
        .arg(&restored)
        .arg("--keyfile")
        .arg(&keyfile)
        .arg("--password-stdin")
        .stdin(Stdio::piped())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()
        .unwrap();
    child
        .stdin
        .take()
        .unwrap()
        .write_all(format!("{PASSWORD}\n").as_bytes())
        .unwrap();
    assert!(child.wait().unwrap().success());
    assert_eq!(
        std::fs::read(restored.join("sub/note.txt")).unwrap(),
        b"hello"
    );
}

#[test]
fn work_dir_refuses_a_directory_that_is_not_empty() {
    let dir = tempfile::tempdir().unwrap();
    let (vault, keyfile) = make_keyfile_vault(dir.path(), "dir");
    let work = dir.path().join("occupied");
    std::fs::create_dir(&work).unwrap();
    std::fs::write(work.join("mine.txt"), b"do not delete me").unwrap();

    let (_, stderr) = session(
        &vault,
        &keyfile,
        &format!("--work-dir \"{}\"", work.display()),
        "stores",
    );
    assert!(stderr.contains("is not empty"), "{stderr}");
    // And the user's file is still there.
    assert_eq!(
        std::fs::read(work.join("mine.txt")).unwrap(),
        b"do not delete me"
    );
}

#[test]
fn a_kv_store_rejects_a_work_dir() {
    let dir = tempfile::tempdir().unwrap();
    let (vault, keyfile) = make_keyfile_vault(dir.path(), "kv");
    let (_, stderr) = session(
        &vault,
        &keyfile,
        &format!("--work-dir \"{}\"", dir.path().join("w").display()),
        "stores",
    );
    assert!(stderr.contains("no working directory"), "{stderr}");
}

#[test]
fn a_crashed_session_leaves_a_recoverable_orphan() {
    let dir = tempfile::tempdir().unwrap();
    let (vault, keyfile) = make_keyfile_vault(dir.path(), "dir");
    let runtime = dir.path().join("runtime");
    std::fs::create_dir_all(&runtime).unwrap();
    let work = dir.path().join("work");

    // Start a session, let it extract, then kill it outright -- no shutdown, so
    // the working directory and the session record both survive.
    let mut child = bin()
        .args(["interactive", "--idle-timeout", "0"])
        .env("XDG_RUNTIME_DIR", &runtime)
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::null())
        .spawn()
        .unwrap();
    let mut stdin = child.stdin.take().unwrap();
    stdin
        .write_all(
            format!(
                "open {} --work-dir {} --keyfile {} --password-stdin
{PASSWORD}
",
                vault.display(),
                work.display(),
                keyfile.display()
            )
            .as_bytes(),
        )
        .unwrap();

    let deadline = std::time::Instant::now() + std::time::Duration::from_secs(30);
    while !work.exists() && std::time::Instant::now() < deadline {
        std::thread::sleep(std::time::Duration::from_millis(50));
    }
    assert!(work.exists(), "the session never extracted");
    std::fs::write(work.join("unsaved.txt"), b"work in progress").unwrap();
    child.kill().unwrap();
    child.wait().unwrap();

    assert!(
        work.join("unsaved.txt").exists(),
        "a killed session leaves its plaintext behind -- that is what recovery is for"
    );

    // The next session finds it and offers it back.
    let mut child = bin()
        .args(["interactive", "--idle-timeout", "0"])
        .env("XDG_RUNTIME_DIR", &runtime)
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::null())
        .spawn()
        .unwrap();
    child
        .stdin
        .take()
        .unwrap()
        .write_all(
            b"d
exit
",
        )
        .unwrap();
    let out = child.wait_with_output().unwrap();
    let stdout = String::from_utf8_lossy(&out.stdout);

    assert!(
        stdout.contains("did not exit cleanly"),
        "orphan not offered: {stdout}"
    );
    assert!(stdout.contains("discarded"), "{stdout}");
    assert!(!work.exists(), "discard must remove the plaintext");
}

/// The M11 claim, checked against the kernel rather than against our own report: a
/// running session's data key is pinned so it cannot be written to swap.
#[cfg(target_os = "linux")]
#[test]
fn a_running_session_pins_its_data_key() {
    let dir = tempfile::tempdir().unwrap();
    let (vault, keyfile) = make_keyfile_vault(dir.path(), "kv");
    let runtime = dir.path().join("runtime");
    std::fs::create_dir_all(&runtime).unwrap();

    let mut child = spawn_session(&runtime);
    let mut stdin = child.stdin.take().unwrap();
    stdin
        .write_all(
            format!(
                "open \"{}\" --keyfile \"{}\" --password-stdin\n{PASSWORD}\n",
                vault.display(),
                keyfile.display()
            )
            .as_bytes(),
        )
        .unwrap();

    let status_path = format!("/proc/{}/status", child.id());
    let deadline = std::time::Instant::now() + std::time::Duration::from_secs(60);
    let mut locked_kb = 0u64;
    while std::time::Instant::now() < deadline {
        if let Ok(status) = std::fs::read_to_string(&status_path) {
            locked_kb = status
                .lines()
                .find_map(|line| line.strip_prefix("VmLck:"))
                .and_then(|value| value.split_whitespace().next())
                .and_then(|value| value.parse().ok())
                .unwrap_or(0);
            if locked_kb > 0 {
                break;
            }
        }
        std::thread::sleep(std::time::Duration::from_millis(100));
    }

    stdin.write_all(b"exit\n").unwrap();
    drop(stdin);
    child.wait().unwrap();

    assert!(
        locked_kb > 0,
        "the kernel reports no locked memory in a session holding a data key"
    );
}
