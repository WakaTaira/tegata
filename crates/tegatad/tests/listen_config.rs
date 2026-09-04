#![cfg(unix)]

use std::io::{BufRead, BufReader, Read, Write};
use std::net::{Shutdown, TcpStream};
use std::os::unix::net::UnixStream;
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};
use std::thread;
use std::time::{Duration, Instant};

use serde_json::{Value, json};
use sha2::{Digest, Sha256};
use uuid::Uuid;

mod common;
use common::create_private_dir;

struct Daemon {
    child: Child,
    directory: PathBuf,
    socket_path: PathBuf,
    tcp_port: u16,
    token: String,
}

impl Drop for Daemon {
    fn drop(&mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
        let _ = std::fs::remove_dir_all(&self.directory);
    }
}

fn start_daemon(max_pending_connections: Option<usize>) -> Daemon {
    let directory = std::env::temp_dir().join(format!("tegatad-listen-{}", Uuid::new_v4()));
    std::fs::create_dir(&directory).expect("create test directory");
    let state_dir = directory.join("state");
    create_private_dir(&state_dir);
    let socket_path = directory.join("tegatad.sock");
    let token = "listen-test-token";
    let token_hash = Sha256::digest(token.as_bytes())
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect::<String>();
    std::fs::write(state_dir.join("token_hash"), format!("{token_hash}\n"))
        .expect("write token hash");
    let tcp_listener = std::net::TcpListener::bind(("127.0.0.1", 0)).expect("reserve TCP port");
    let tcp_port = tcp_listener.local_addr().expect("read TCP port").port();
    drop(tcp_listener);
    let max_pending = max_pending_connections
        .map(|value| format!("max_pending_connections = {value}\n"))
        .unwrap_or_default();
    let config = format!(
        "state_dir = {:?}\naudit_log_path = {:?}\n{}\n[[listen]]\nkind = \"unix\"\npath = {:?}\nallowed_uids = [{}]\noperator_uids = [{}]\n\n[[listen]]\nkind = \"tcp\"\nbind = \"127.0.0.1\"\nport = {}\n",
        state_dir,
        state_dir.join("audit.log"),
        max_pending,
        socket_path,
        unsafe { libc::geteuid() },
        unsafe { libc::geteuid() },
        tcp_port,
    );
    let config_path = directory.join("config.toml");
    std::fs::write(&config_path, config).expect("write daemon config");
    let child = Command::new(env!("CARGO_BIN_EXE_tegatad"))
        .arg("--config")
        .arg(&config_path)
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()
        .expect("spawn tegatad");
    let daemon = Daemon {
        child,
        directory,
        socket_path,
        tcp_port,
        token: token.to_owned(),
    };
    wait_for_socket(&daemon.socket_path);
    daemon
}

fn wait_for_socket(socket_path: &Path) {
    let deadline = Instant::now() + Duration::from_secs(5);
    while Instant::now() < deadline {
        if let Ok(mut stream) = UnixStream::connect(socket_path) {
            let request = json!({"jsonrpc":"2.0","id":1,"method":"status","params":{}});
            if writeln!(stream, "{request}").is_ok() {
                let mut response = String::new();
                if BufReader::new(stream).read_line(&mut response).is_ok()
                    && response.contains("\"result\"")
                {
                    return;
                }
            }
        }
        thread::sleep(Duration::from_millis(25));
    }
    panic!("tegatad did not become ready");
}

fn read_line(stream: &mut TcpStream) -> String {
    let mut response = String::new();
    BufReader::new(stream.try_clone().expect("clone TCP stream"))
        .read_line(&mut response)
        .expect("read TCP line");
    response
}

fn tcp_rpc(stream: &mut TcpStream, token: &str) -> Value {
    writeln!(stream, "{}", json!({"v":1,"auth":token})).expect("write preamble");
    writeln!(
        stream,
        "{}",
        json!({"jsonrpc":"2.0","id":1,"method":"status","params":{}})
    )
    .expect("write status request");
    serde_json::from_str(&read_line(stream)).expect("parse TCP RPC response")
}

#[test]
fn listen_config_serves_unix_and_tcp_and_records_principals() {
    let daemon = start_daemon(None);
    let mut unix = UnixStream::connect(&daemon.socket_path).expect("connect UDS");
    writeln!(
        unix,
        "{}",
        json!({"jsonrpc":"2.0","id":1,"method":"status","params":{}})
    )
    .expect("write UDS status request");
    let mut unix_response = String::new();
    BufReader::new(unix)
        .read_line(&mut unix_response)
        .expect("read UDS status response");
    let unix_json: Value =
        serde_json::from_str(unix_response.trim()).expect("parse UDS status response");
    assert_eq!(unix_json["result"]["ok"], true);

    let mut tcp = TcpStream::connect(("127.0.0.1", daemon.tcp_port)).expect("connect TCP");
    let response = tcp_rpc(&mut tcp, &daemon.token);
    assert_eq!(response["result"]["ok"], true);

    let mut wrong = TcpStream::connect(("127.0.0.1", daemon.tcp_port)).expect("connect TCP");
    writeln!(wrong, "{}", json!({"v":1,"auth":"wrong-token"})).expect("write bad preamble");
    assert_eq!(
        read_line(&mut wrong).trim_end(),
        r#"{"ok":false,"error":"UNAUTHORIZED"}"#
    );
    let mut rest = Vec::new();
    wrong
        .set_read_timeout(Some(Duration::from_secs(1)))
        .expect("set read timeout");
    let _ = wrong.read_to_end(&mut rest);
    assert!(rest.is_empty());

    thread::sleep(Duration::from_millis(50));
    let audit =
        std::fs::read_to_string(daemon.directory.join("state/audit.log")).expect("read audit log");
    let records = audit
        .lines()
        .map(|line| serde_json::from_str::<Value>(line).expect("parse audit record"))
        .collect::<Vec<_>>();
    assert!(
        records
            .iter()
            .any(|record| { record["principal"] == format!("uid:{}", unsafe { libc::geteuid() }) })
    );
    assert!(records.iter().any(|record| {
        record["principal"] == "peer:legacy"
            && record["peer_id"] == "legacy"
            && record["peer_label"] == "legacy"
    }));
}

#[test]
fn listen_and_legacy_socket_key_are_mutually_exclusive() {
    let directory = std::env::temp_dir().join(format!("tegatad-listen-invalid-{}", Uuid::new_v4()));
    std::fs::create_dir(&directory).expect("create test directory");
    let config_path = directory.join("config.toml");
    std::fs::write(
        &config_path,
        format!(
            "state_dir = {:?}\naudit_log_path = {:?}\nsocket_path = {:?}\n\n[[listen]]\nkind = \"tcp\"\nbind = \"127.0.0.1\"\nport = 1\n",
            directory.join("state"),
            directory.join("audit.log"),
            directory.join("legacy.sock"),
        ),
    )
    .expect("write invalid config");
    let output = Command::new(env!("CARGO_BIN_EXE_tegatad"))
        .arg("--config")
        .arg(&config_path)
        .output()
        .expect("run tegatad");
    let _ = std::fs::remove_dir_all(directory);
    assert!(!output.status.success());
    assert!(String::from_utf8_lossy(&output.stderr).contains("listen cannot be combined"));
}

#[test]
fn unspecified_tcp_bind_is_rejected() {
    let directory = std::env::temp_dir().join(format!("tegatad-listen-invalid-{}", Uuid::new_v4()));
    std::fs::create_dir(&directory).expect("create test directory");
    let config_path = directory.join("config.toml");
    std::fs::write(
        &config_path,
        format!(
            "state_dir = {:?}\naudit_log_path = {:?}\n\n[[listen]]\nkind = \"tcp\"\nbind = \"0.0.0.0\"\nport = 1\n",
            directory.join("state"),
            directory.join("audit.log"),
        ),
    )
    .expect("write invalid config");
    let output = Command::new(env!("CARGO_BIN_EXE_tegatad"))
        .arg("--config")
        .arg(&config_path)
        .output()
        .expect("run tegatad");
    let _ = std::fs::remove_dir_all(directory);
    assert!(!output.status.success());
    assert!(String::from_utf8_lossy(&output.stderr).contains("unspecified address"));
}

#[test]
fn silent_tcp_connections_do_not_block_rpc_and_are_capped() {
    let daemon = start_daemon(Some(8));
    let mut silent = Vec::new();
    for _ in 0..7 {
        silent.push(
            TcpStream::connect(("127.0.0.1", daemon.tcp_port)).expect("connect silent TCP client"),
        );
    }
    let started = Instant::now();
    let mut rpc = TcpStream::connect(("127.0.0.1", daemon.tcp_port)).expect("connect RPC client");
    assert_eq!(tcp_rpc(&mut rpc, &daemon.token)["result"]["ok"], true);
    assert!(started.elapsed() < Duration::from_secs(2));

    silent.push(TcpStream::connect(("127.0.0.1", daemon.tcp_port)).expect("fill pending limit"));
    let mut rejected =
        TcpStream::connect(("127.0.0.1", daemon.tcp_port)).expect("connect capped client");
    rejected
        .set_read_timeout(Some(Duration::from_secs(1)))
        .expect("set read timeout");
    let started = Instant::now();
    let mut byte = [0_u8; 1];
    let result = rejected.read(&mut byte);
    assert!(started.elapsed() < Duration::from_secs(1));
    assert!(matches!(result, Ok(0) | Err(_)));

    for stream in silent {
        let _ = stream.shutdown(Shutdown::Both);
    }
}
