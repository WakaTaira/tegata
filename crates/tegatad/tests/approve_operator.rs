#![cfg(unix)]

use std::os::unix::fs::PermissionsExt;
use std::path::PathBuf;
use std::process::{Command, Stdio};

use uuid::Uuid;

fn test_directory() -> PathBuf {
    let directory =
        std::env::temp_dir().join(format!("tegatad-approve-operator-{}", Uuid::new_v4()));
    std::fs::create_dir(&directory).expect("create test directory");
    directory
}

/// Given: a Unix configuration that sets `approve_operator = true`
/// When: the daemon starts
/// Then: it exits unsuccessfully and explains that the option is Windows-only
#[test]
fn refuses_approve_operator_on_unix() {
    let directory = test_directory();
    let state_dir = directory.join("state");
    std::fs::create_dir(&state_dir).expect("create state directory");
    std::fs::set_permissions(&state_dir, std::fs::Permissions::from_mode(0o700))
        .expect("set state directory permissions");
    let config_path = directory.join("config.toml");
    let uid = unsafe { libc::geteuid() };
    std::fs::write(
        &config_path,
        format!(
            "state_dir = {:?}\naudit_log_path = {:?}\nsocket_path = {:?}\nallowed_uids = [{}]\napprove_operator = true\n",
            state_dir,
            state_dir.join("audit.log"),
            directory.join("tegatad.sock"),
            uid,
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
