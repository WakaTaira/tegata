#![cfg(unix)]

use std::io::{BufRead, BufReader, Read, Write};
use std::os::unix::fs::PermissionsExt;
use std::os::unix::net::UnixStream;
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};
use std::thread;
use std::time::{Duration, Instant};

use serde_json::{Value, json};
use sha2::{Digest, Sha256};
use uuid::Uuid;

struct Daemon {
    child: Child,
    directory: PathBuf,
    state_dir: PathBuf,
    socket_path: PathBuf,
    tcp_port: u16,
}

impl Drop for Daemon {
    fn drop(&mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
        let _ = std::fs::remove_dir_all(&self.directory);
    }
}

fn start_daemon(legacy_token: &str) -> Daemon {
    start_daemon_with_existing_legacy(legacy_token, false)
}

fn start_daemon_with_existing_legacy(legacy_token: &str, existing_legacy: bool) -> Daemon {
    let directory = std::env::temp_dir().join(format!("tegatad-peers-{}", Uuid::new_v4()));
    std::fs::create_dir(&directory).expect("create test directory");
    let state_dir = directory.join("state");
    std::fs::create_dir(&state_dir).expect("create state directory");
    let socket_path = directory.join("tegatad.sock");
    let token_hash = Sha256::digest(legacy_token.as_bytes())
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect::<String>();
    std::fs::write(state_dir.join("token_hash"), format!("{token_hash}\n"))
        .expect("write legacy token hash");
    if existing_legacy {
        std::fs::write(
            state_dir.join("peers.json"),
            serde_json::to_vec(&vec![json!({
                "peer_id": "legacy",
                "label": "legacy",
                "token_sha256": token_hash,
                "issued_at": "unix:0",
                "revoked_at": null,
            })])
            .expect("serialize existing legacy peer"),
        )
        .expect("write existing peers");
    }
    let tcp_listener = std::net::TcpListener::bind(("127.0.0.1", 0)).expect("reserve TCP port");
    let tcp_port = tcp_listener.local_addr().expect("read TCP port").port();
    drop(tcp_listener);
    let config = format!(
        "state_dir = {:?}\naudit_log_path = {:?}\n\n[[listen]]\nkind = \"unix\"\npath = {:?}\nallowed_uids = [{}]\noperator_uids = [{}]\n\n[[listen]]\nkind = \"tcp\"\nbind = \"127.0.0.1\"\nport = {}\n",
        state_dir,
        state_dir.join("audit.log"),
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
        state_dir,
        socket_path,
        tcp_port,
    };
    wait_for_socket(&daemon.socket_path);
    daemon
}

fn wait_for_socket(socket_path: &Path) {
    let deadline = Instant::now() + Duration::from_secs(5);
    while Instant::now() < deadline {
        if let Ok(response) = call_unix(socket_path, "status", json!({}))
            && response.get("result").is_some()
        {
            return;
        }
        thread::sleep(Duration::from_millis(25));
    }
    panic!("tegatad did not become ready");
}

fn call_unix(socket_path: &Path, method: &str, params: Value) -> std::io::Result<Value> {
    let mut stream = UnixStream::connect(socket_path)?;
    let request = json!({
        "jsonrpc": "2.0",
        "id": 1,
        "method": method,
        "params": params,
    });
    writeln!(stream, "{request}")?;
    let mut line = String::new();
    BufReader::new(stream).read_line(&mut line)?;
    serde_json::from_str(&line)
        .map_err(|error| std::io::Error::new(std::io::ErrorKind::InvalidData, error))
}

fn start_daemon_with_unix_permissions(allowed_uids: &[u32], operator_uids: &[u32]) -> Daemon {
    let directory = std::env::temp_dir().join(format!("tegatad-peers-{}", Uuid::new_v4()));
    std::fs::create_dir(&directory).expect("create test directory");
    let state_dir = directory.join("state");
    std::fs::create_dir(&state_dir).expect("create state directory");
    let socket_path = directory.join("tegatad.sock");
    let allowed_uids = allowed_uids
        .iter()
        .map(u32::to_string)
        .collect::<Vec<_>>()
        .join(", ");
    let operator_uids = operator_uids
        .iter()
        .map(u32::to_string)
        .collect::<Vec<_>>()
        .join(", ");
    let config = format!(
        "state_dir = {:?}\naudit_log_path = {:?}\n\n[[listen]]\nkind = \"unix\"\npath = {:?}\nallowed_uids = [{}]\noperator_uids = [{}]\n",
        state_dir,
        state_dir.join("audit.log"),
        socket_path,
        allowed_uids,
        operator_uids,
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
        state_dir,
        socket_path,
        tcp_port: 0,
    };
    wait_for_connection(&daemon.socket_path);
    daemon
}

fn wait_for_connection(socket_path: &Path) {
    let deadline = Instant::now() + Duration::from_secs(5);
    while Instant::now() < deadline {
        if UnixStream::connect(socket_path).is_ok() {
            return;
        }
        thread::sleep(Duration::from_millis(25));
    }
    panic!("tegatad did not become ready");
}

#[test]
fn operator_uid_can_use_admin_rpc_but_not_normal_rpc() {
    let daemon = start_daemon_with_unix_permissions(&[], &[unsafe { libc::geteuid() }]);

    let issued = call_unix(
        &daemon.socket_path,
        "admin_peer_issue",
        json!({ "label": "ops" }),
    )
    .expect("issue peer");
    assert!(issued["result"]["peer_id"].is_string());
    assert!(issued["result"]["token"].is_string());

    for (method, params) in [
        ("status", json!({})),
        (
            "login",
            json!({
                "cred_id": "site",
                "target_url": "http://127.0.0.1",
            }),
        ),
    ] {
        let response = call_unix(&daemon.socket_path, method, params).expect("call RPC");
        assert_eq!(response["error"]["message"], "UNAUTHORIZED");
    }
}

fn tcp_exchange(daemon: &Daemon, token: &str, method: &str) -> Value {
    let mut stream =
        std::net::TcpStream::connect(("127.0.0.1", daemon.tcp_port)).expect("connect TCP");
    writeln!(stream, "{}", json!({ "v": 1, "auth": token })).expect("write preamble");
    writeln!(
        stream,
        "{}",
        json!({ "jsonrpc": "2.0", "id": 1, "method": method, "params": {} })
    )
    .expect("write RPC request");
    let mut line = String::new();
    BufReader::new(stream)
        .read_line(&mut line)
        .expect("read TCP response");
    serde_json::from_str(&line).expect("parse TCP response")
}

#[test]
fn named_peers_are_issued_revoked_listed_and_import_legacy_tokens() {
    let legacy_token = "legacy-peer-test-token";
    let daemon = start_daemon(legacy_token);

    let peers_path = daemon.state_dir.join("peers.json");
    let peers: Vec<Value> =
        serde_json::from_slice(&std::fs::read(&peers_path).expect("read peers.json"))
            .expect("parse peers.json");
    assert!(peers.iter().any(|peer| peer["peer_id"] == "legacy"));
    assert!(daemon.state_dir.join("token_hash.imported").exists());
    assert!(!daemon.state_dir.join("token_hash").exists());
    assert_eq!(
        std::fs::metadata(&peers_path)
            .expect("stat peers.json")
            .permissions()
            .mode()
            & 0o777,
        0o600
    );
    assert_eq!(
        tcp_exchange(&daemon, legacy_token, "status")["result"]["ok"],
        true
    );

    let issued = call_unix(
        &daemon.socket_path,
        "admin_peer_issue",
        json!({ "label": "ci" }),
    )
    .expect("issue peer");
    let peer_id = issued["result"]["peer_id"].as_str().expect("peer id");
    let token = issued["result"]["token"].as_str().expect("token");
    assert!(peer_id.starts_with("p_"));
    assert_eq!(tcp_exchange(&daemon, token, "status")["result"]["ok"], true);
    let audit =
        std::fs::read_to_string(daemon.state_dir.join("audit.log")).expect("read audit log");
    assert!(audit.lines().any(|line| {
        let record: Value = serde_json::from_str(line).expect("parse audit record");
        record["principal"] == format!("peer:{peer_id}") && record["peer_label"] == "ci"
    }));

    let revoked = call_unix(
        &daemon.socket_path,
        "admin_peer_revoke",
        json!({ "peer_id": peer_id }),
    )
    .expect("revoke peer");
    assert_eq!(revoked["result"]["ok"], true);
    let refused = tcp_exchange(&daemon, token, "status");
    assert_eq!(refused["error"], "UNAUTHORIZED");

    let listed = call_unix(&daemon.socket_path, "admin_peer_list", json!({})).expect("list peers");
    let entry = listed["result"]
        .as_array()
        .expect("peer list")
        .iter()
        .find(|peer| peer["peer_id"] == peer_id)
        .expect("revoked peer");
    assert_eq!(entry["label"], "ci");
    assert!(entry["revoked_at"].is_string());
    assert!(entry.get("token_sha256").is_none());

    let token_alias = call_unix(&daemon.socket_path, "admin_token_issue", json!({}))
        .expect("issue default token");
    let default_id = token_alias["result"]["peer_id"]
        .as_str()
        .expect("default peer id");
    assert!(token_alias["result"]["token"].is_string());
    let defaults =
        call_unix(&daemon.socket_path, "admin_peer_list", json!({})).expect("list default peer");
    assert!(
        defaults["result"]
            .as_array()
            .expect("peer list")
            .iter()
            .any(|peer| peer["peer_id"] == default_id && peer["label"] == "default")
    );
}

#[test]
fn revoked_peer_connections_are_rejected_after_authentication() {
    let daemon = start_daemon("legacy-peer-test-token");
    let issued = call_unix(
        &daemon.socket_path,
        "admin_peer_issue",
        json!({ "label": "persistent" }),
    )
    .expect("issue peer");
    let peer_id = issued["result"]["peer_id"].as_str().expect("peer id");
    let token = issued["result"]["token"].as_str().expect("peer token");
    let mut connection = BufReader::new(
        std::net::TcpStream::connect(("127.0.0.1", daemon.tcp_port)).expect("connect TCP"),
    );
    writeln!(connection.get_mut(), "{}", json!({ "v": 1, "auth": token })).expect("write preamble");
    writeln!(
        connection.get_mut(),
        "{}",
        json!({
            "jsonrpc": "2.0",
            "id": 1,
            "method": "status",
            "params": {},
        })
    )
    .expect("write initial request");
    let mut initial = String::new();
    connection
        .read_line(&mut initial)
        .expect("read initial response");
    assert_eq!(
        serde_json::from_str::<Value>(&initial).expect("parse initial response")["result"]["ok"],
        true
    );

    let revoked = call_unix(
        &daemon.socket_path,
        "admin_peer_revoke",
        json!({ "peer_id": peer_id }),
    )
    .expect("revoke peer");
    assert_eq!(revoked["result"]["ok"], true);
    writeln!(
        connection.get_mut(),
        "{}",
        json!({
            "jsonrpc": "2.0",
            "id": 2,
            "method": "status",
            "params": {},
        })
    )
    .expect("write request after revoke");
    let mut refused = String::new();
    connection
        .read_line(&mut refused)
        .expect("read refusal after revoke");
    assert_eq!(refused.trim_end(), r#"{"ok":false,"error":"UNAUTHORIZED"}"#);
    connection
        .get_mut()
        .set_read_timeout(Some(Duration::from_secs(1)))
        .expect("set read timeout");
    let mut rest = Vec::new();
    let _ = connection.read_to_end(&mut rest);
    assert!(rest.is_empty());
}

#[test]
fn legacy_hash_is_renamed_when_legacy_peer_already_exists() {
    let daemon = start_daemon_with_existing_legacy("legacy-peer-test-token", true);
    let peers: Vec<Value> = serde_json::from_slice(
        &std::fs::read(daemon.state_dir.join("peers.json")).expect("read peers.json"),
    )
    .expect("parse peers.json");
    assert_eq!(peers.len(), 1);
    assert!(daemon.state_dir.join("token_hash.imported").exists());
    assert!(!daemon.state_dir.join("token_hash").exists());
}
