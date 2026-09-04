//! End-to-end checks of the parts of the CLI that need no security key.
//!
//! `info` is deliberately touch-free (plan/02-crate-fidostorers.md), which makes it
//! the one command that can be tested against a real vault file in CI. Everything
//! else needs hardware and is covered by docs/M1-MANUAL-TESTING.md instead.

use std::process::Command;

use fidostorers::{Enrollment, Mode, Vault};
use zeroize::Zeroizing;

fn make_vault(path: &std::path::Path) {
    Vault::create(
        path,
        Mode::File,
        &Enrollment {
            factor: fidostorers::Factor::Fido2(fido_token::Credential {
                rp_id: "fidostorers.local".to_string(),
                credential_id: vec![0xAB, 0xCD, 0xEF],
                device_hint: None,
            }),
            rp_id: "fidostorers.local".to_string(),
            label: "primary".to_string(),
            salt: [3u8; 32],
            kek: Zeroizing::new([5u8; 32]),
        },
    )
    .unwrap();
}

#[test]
fn info_reports_a_vault_and_labels_it_unauthenticated() {
    let dir = tempfile::TempDir::new().unwrap();
    let path = dir.path().join("test.fido");
    make_vault(&path);

    let output = Command::new(env!("CARGO_BIN_EXE_fidostorers"))
        .arg("info")
        .arg(&path)
        .output()
        .unwrap();

    assert!(output.status.success(), "{output:?}");
    let stdout = String::from_utf8(output.stdout).unwrap();

    assert!(stdout.contains("UNAUTHENTICATED"), "{stdout}");
    assert!(stdout.contains("mode: file"), "{stdout}");
    assert!(stdout.contains("rp id: fidostorers.local"), "{stdout}");
    assert!(
        stdout.contains(&format!("format version: {}", fidostorers::FORMAT_VERSION)),
        "{stdout}"
    );
    // Since M8 a factor line is `<entry id>  <kind>  <label>`: an entry is named by
    // its own id rather than by a credential id it may not have.
    assert!(stdout.contains("fido2"), "{stdout}");
    assert!(stdout.contains("primary"), "{stdout}");
}

#[test]
fn info_on_a_non_vault_fails_with_a_clear_message() {
    let dir = tempfile::TempDir::new().unwrap();
    let path = dir.path().join("not.fido");
    std::fs::write(&path, b"just a file").unwrap();

    let output = Command::new(env!("CARGO_BIN_EXE_fidostorers"))
        .arg("info")
        .arg(&path)
        .output()
        .unwrap();

    assert!(!output.status.success());
    let stderr = String::from_utf8(output.stderr).unwrap();
    assert!(stderr.contains("not a fidostorers vault"), "{stderr}");
}

#[test]
fn init_refuses_to_overwrite_an_existing_vault() {
    // Guards the one destructive mistake the CLI could make without a touch:
    // clobbering a vault whose keys still exist. Checked before any hardware call,
    // so it is reachable in a hardware-free test.
    let dir = tempfile::TempDir::new().unwrap();
    let path = dir.path().join("test.fido");
    make_vault(&path);
    let before = std::fs::read(&path).unwrap();

    let output = Command::new(env!("CARGO_BIN_EXE_fidostorers"))
        .arg("init")
        .arg(&path)
        .args(["--mode", "file"])
        .output()
        .unwrap();

    assert!(!output.status.success());
    let stderr = String::from_utf8(output.stderr).unwrap();
    assert!(stderr.contains("already exists"), "{stderr}");
    assert_eq!(std::fs::read(&path).unwrap(), before, "vault was modified");
}
