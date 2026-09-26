#![cfg(unix)]

mod common;

use std::path::PathBuf;
use std::process::{Command, Stdio};

use uuid::Uuid;

use common::create_private_dir;

fn test_directory() -> PathBuf {
    let directory =
        std::env::temp_dir().join(format!("tegatad-approve-operator-{}", Uuid::new_v4()));
    std::fs::create_dir(&directory).expect("create test directory");
    directory
}

fn assert_refused_on_unix(approve_operator: bool) {
    let directory = test_directory();
    let state_dir = directory.join("state");
    create_private_dir(&state_dir);
    let config_path = directory.join("config.toml");
    let uid = unsafe { libc::geteuid() };
    std::fs::write(
        &config_path,
        format!(
            "state_dir = {:?}\naudit_log_path = {:?}\nsocket_path = {:?}\nallowed_uids = [{}]\napprove_operator = {}\n",
            state_dir,
            state_dir.join("audit.log"),
            directory.join("tegatad.sock"),
            uid,
            approve_operator,
        ),
    )
    .expect("write test config");

    let output = Command::new(env!("CARGO_BIN_EXE_tegatad"))
        .arg("--config")
        .arg(&config_path)
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::piped())
        .output()
        .expect("run tegatad");
    let stderr = String::from_utf8_lossy(&output.stderr);
    let socket_exists = directory.join("tegatad.sock").exists();
    let _ = std::fs::remove_dir_all(&directory);

    assert!(
        !output.status.success(),
        "daemon refused to start: {stderr}"
    );
    assert!(stderr.contains("approve_operator"), "stderr: {stderr}");
    assert!(
        stderr.contains("only supported on Windows"),
        "stderr: {stderr}"
    );
    assert!(!socket_exists, "no socket is bound");
}

/// Given: a Unix configuration that sets `approve_operator = true`
/// When: the daemon starts
/// Then: it exits unsuccessfully and explains that the option is Windows-only
#[test]
fn refuses_approve_operator_on_unix() {
    assert_refused_on_unix(true);
}

/// Given: a Unix configuration that sets `approve_operator = false` explicitly
/// When: the daemon starts
/// Then: it is refused the same way, because the key itself is Windows-only
#[test]
fn refuses_explicitly_disabled_approve_operator_on_unix() {
    assert_refused_on_unix(false);
}
