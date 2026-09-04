#![cfg(unix)]

use std::io::{BufRead, BufReader, Write};
use std::os::unix::net::UnixListener;
use std::path::{Path, PathBuf};
use std::process::{Command, Output, Stdio};
use std::thread;

use uuid::Uuid;

mod common;
use common::create_private_dir;

fn test_directory() -> PathBuf {
    let directory =
        std::env::temp_dir().join(format!("tegatad-executor-socket-{}", Uuid::new_v4()));
    std::fs::create_dir(&directory).expect("create test directory");
    directory
}

fn write_config(directory: &Path, executor_socket: &Path) -> PathBuf {
    let config_path = directory.join("config.toml");
    let state_dir = directory.join("state");
    create_private_dir(&state_dir);
    let daemon_socket = directory.join("tegatad.sock");
    let uid = unsafe { libc::geteuid() };
    let config = format!(
        "socket_path = {:?}\nstate_dir = {:?}\naudit_log_path = {:?}\nallowed_uids = [{}]\nexecutor_socket = {:?}\n",
        daemon_socket,
        state_dir,
        state_dir.join("audit.log"),
        uid,
        executor_socket,
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
fn refuses_executor_socket_running_as_the_daemons_user() {
    let directory = test_directory();
    let executor_socket = directory.join("executor.sock");
    let listener = UnixListener::bind(&executor_socket).expect("bind executor socket");
    let server = thread::spawn(move || {
        let (mut stream, _) = listener.accept().expect("accept executor connection");
        let mut request = String::new();
        BufReader::new(&mut stream)
            .read_line(&mut request)
            .expect("read hello request");
        assert_eq!(request, "{\"op\":\"hello\"}\n");
        let uid = unsafe { libc::geteuid() };
        writeln!(stream, "{{\"ok\":true,\"uid\":{uid},\"pid\":1}}").expect("write hello response");
    });
    let config_path = write_config(&directory, &executor_socket);

    let output = run_daemon(&config_path);
    server.join().expect("join executor server");
    let _ = std::fs::remove_dir_all(&directory);

    assert!(!output.status.success());
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(stderr.contains("executor must not run as the daemon's own user"));
}

#[test]
fn refuses_executor_socket_that_reports_not_ok() {
    let directory = test_directory();
    let executor_socket = directory.join("executor.sock");
    let listener = UnixListener::bind(&executor_socket).expect("bind executor socket");
    let server = thread::spawn(move || {
        let (mut stream, _) = listener.accept().expect("accept executor connection");
        let mut request = String::new();
        BufReader::new(&mut stream)
            .read_line(&mut request)
            .expect("read hello request");
        assert_eq!(request, "{\"op\":\"hello\"}\n");
        writeln!(stream, "{{\"ok\":false,\"uid\":null,\"pid\":1}}").expect("write hello response");
    });
    let config_path = write_config(&directory, &executor_socket);

    let output = run_daemon(&config_path);
    server.join().expect("join executor server");
    let _ = std::fs::remove_dir_all(&directory);

    assert!(!output.status.success());
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(stderr.contains("executor socket \"") && stderr.contains("executor reported ok=false"));
}

#[test]
fn refuses_executor_socket_running_as_root() {
    let directory = test_directory();
    let executor_socket = directory.join("executor.sock");
    let listener = UnixListener::bind(&executor_socket).expect("bind executor socket");
    let server = thread::spawn(move || {
        let (mut stream, _) = listener.accept().expect("accept executor connection");
        let mut request = String::new();
        BufReader::new(&mut stream)
            .read_line(&mut request)
            .expect("read hello request");
        assert_eq!(request, "{\"op\":\"hello\"}\n");
        writeln!(stream, "{{\"ok\":true,\"uid\":0,\"pid\":1}}").expect("write hello response");
    });
    let config_path = write_config(&directory, &executor_socket);

    let output = run_daemon(&config_path);
    server.join().expect("join executor server");
    let _ = std::fs::remove_dir_all(&directory);

    assert!(!output.status.success());
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(stderr.contains("executor must not run as root"));
}

#[test]
fn refuses_executor_socket_that_is_not_connectable() {
    let directory = test_directory();
    let executor_socket = directory.join("missing.sock");
    let config_path = write_config(&directory, &executor_socket);

    let output = run_daemon(&config_path);
    let _ = std::fs::remove_dir_all(&directory);

    assert!(!output.status.success());
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(stderr.contains("executor socket \"") && stderr.contains("is not connectable"));
}
