#![cfg(unix)]

use std::io::{BufRead, BufReader, Write};
use std::os::unix::fs::{PermissionsExt, symlink};
use std::os::unix::net::UnixStream;
use std::path::{Path, PathBuf};
use std::process::{Command, Output, Stdio};
use std::thread::sleep;
use std::time::{Duration, Instant};

use uuid::Uuid;

fn test_directory(label: &str) -> PathBuf {
    let directory =
        std::env::temp_dir().join(format!("tegatad-state-dir-{label}-{}", Uuid::new_v4()));
    std::fs::create_dir(&directory).expect("create test directory");
    directory
}

fn write_config(directory: &Path, state_dir: &Path) -> PathBuf {
    let config_path = directory.join("config.toml");
    let socket_path = directory.join("tegatad.sock");
    let uid = unsafe { libc::geteuid() };
    let config = format!(
        "state_dir = {:?}\naudit_log_path = {:?}\nsocket_path = {:?}\nallowed_uids = [{}]\n",
        state_dir,
        state_dir.join("audit.log"),
        socket_path,
        uid,
    );
    std::fs::write(&config_path, config).expect("write test config");
    config_path
}

fn run_daemon(config_path: &Path) -> Output {
    Command::new(env!("CARGO_BIN_EXE_tegatad"))
        .arg("--config")
        .arg(config_path)
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::piped())
        .output()
        .expect("run tegatad")
}

#[test]
fn refuses_state_dir_without_private_mode() {
    let directory = test_directory("mode");
    let state_dir = directory.join("state");
    std::fs::create_dir(&state_dir).expect("create state directory");
    std::fs::set_permissions(&state_dir, std::fs::Permissions::from_mode(0o755))
        .expect("set state directory permissions");
    let config_path = write_config(&directory, &state_dir);

    let output = run_daemon(&config_path);
    let stderr = String::from_utf8_lossy(&output.stderr);
    let _ = std::fs::remove_dir_all(&directory);

    assert!(!output.status.success());
    assert!(stderr.contains("state_dir"));
    assert!(stderr.contains(state_dir.to_string_lossy().as_ref()));
    assert!(stderr.contains("0700"));
}

#[test]
fn refuses_state_dir_symlink() {
    let directory = test_directory("symlink");
    let state_dir = directory.join("state");
    let target = directory.join("target");
    std::fs::create_dir(&target).expect("create target directory");
    symlink(&target, &state_dir).expect("create state directory symlink");
    let config_path = write_config(&directory, &state_dir);

    let output = run_daemon(&config_path);
    let stderr = String::from_utf8_lossy(&output.stderr);
    let _ = std::fs::remove_dir_all(&directory);

    assert!(!output.status.success());
    assert!(stderr.contains("state_dir"));
    assert!(stderr.contains(state_dir.to_string_lossy().as_ref()));
    assert!(stderr.contains("symlink"));
}

#[test]
fn creates_missing_state_dir_with_private_mode() {
    let directory = test_directory("missing");
    let state_dir = directory.join("state");
    let config_path = write_config(&directory, &state_dir);
    let socket_path = directory.join("tegatad.sock");
    let mut child = Command::new(env!("CARGO_BIN_EXE_tegatad"))
        .arg("--config")
        .arg(&config_path)
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()
        .expect("spawn tegatad");

    wait_for_status(&socket_path);
    assert_eq!(
        std::fs::symlink_metadata(&state_dir)
            .expect("stat state directory")
            .permissions()
            .mode()
            & 0o777,
        0o700
    );
    let _ = child.kill();
    let _ = child.wait();
    let _ = std::fs::remove_dir_all(&directory);
}

fn wait_for_status(socket_path: &Path) {
    let deadline = Instant::now() + Duration::from_secs(5);
    while Instant::now() < deadline {
        if let Ok(mut stream) = UnixStream::connect(socket_path) {
            let request = r#"{"jsonrpc":"2.0","id":1,"method":"status","params":{}}"#;
            if writeln!(stream, "{request}").is_ok() {
                let mut response = String::new();
                if BufReader::new(stream).read_line(&mut response).is_ok()
                    && response.contains("\"result\"")
                {
                    return;
                }
            }
        }
        sleep(Duration::from_millis(25));
    }
    panic!("tegatad did not become ready");
}
