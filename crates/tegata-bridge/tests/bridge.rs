#![cfg(unix)]

use std::fs;
use std::os::unix::fs::PermissionsExt;
use std::path::PathBuf;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::Duration;

use serde_json::Value;
use tegata_bridge::{BridgeConfig, run};
use tokio::io::{AsyncBufReadExt, AsyncReadExt, AsyncWriteExt, BufReader};
use tokio::net::{TcpListener, TcpStream, UnixStream};

static NEXT_ID: AtomicU64 = AtomicU64::new(0);

struct TestPaths {
    socket: PathBuf,
    token: PathBuf,
}

impl TestPaths {
    fn new() -> Self {
        let id = NEXT_ID.fetch_add(1, Ordering::Relaxed);
        let base = std::env::temp_dir().join(format!("tegata-bridge-{}-{id}", std::process::id()));
        Self {
            socket: base.with_extension("sock"),
            token: base.with_extension("token"),
        }
    }

    fn write_token(&self, mode: u32) {
        fs::write(&self.token, "test-token\n").expect("write token");
        fs::set_permissions(&self.token, fs::Permissions::from_mode(mode))
            .expect("set token permissions");
    }
}

impl Drop for TestPaths {
    fn drop(&mut self) {
        let _ = fs::remove_file(&self.socket);
        let _ = fs::remove_file(&self.token);
    }
}

async fn start_bridge(
    paths: &TestPaths,
    daemon_addr: String,
) -> tokio::task::JoinHandle<std::io::Result<()>> {
    let handle = tokio::spawn(run(BridgeConfig {
        socket_path: paths.socket.clone(),
        token_file: paths.token.clone(),
        daemon_addr,
    }));
    for _ in 0..100 {
        if paths.socket.exists() {
            return handle;
        }
        tokio::time::sleep(Duration::from_millis(5)).await;
    }
    panic!("bridge socket was not created");
}

async fn read_json_line<R: tokio::io::AsyncBufRead + Unpin>(reader: &mut R) -> Value {
    let mut line = String::new();
    reader.read_line(&mut line).await.expect("read JSON line");
    serde_json::from_str(line.trim_end()).expect("parse JSON line")
}

async fn read_tcp_line(stream: &mut TcpStream) -> Value {
    let mut bytes = Vec::new();
    loop {
        let mut byte = [0_u8; 1];
        stream.read_exact(&mut byte).await.expect("read TCP line");
        bytes.push(byte[0]);
        if byte[0] == b'\n' {
            return serde_json::from_slice(&bytes[..bytes.len() - 1]).expect("parse JSON line");
        }
    }
}

fn rpc_request(id: u64, method: &str, params: Value) -> String {
    format!(
        "{}\n",
        serde_json::json!({
            "jsonrpc": "2.0",
            "id": id,
            "method": method,
            "params": params,
        })
    )
}

#[tokio::test]
async fn rpc_round_trip_uses_the_authenticated_daemon_connection() {
    let paths = TestPaths::new();
    paths.write_token(0o600);
    let daemon = TcpListener::bind("127.0.0.1:0").await.expect("bind daemon");
    let daemon_addr = daemon.local_addr().expect("daemon address").to_string();
    let daemon_task = tokio::spawn(async move {
        let (mut stream, _) = daemon.accept().await.expect("accept daemon");
        let preamble = read_tcp_line(&mut stream).await;
        assert_eq!(
            preamble,
            serde_json::json!({ "v": 1, "auth": "test-token" })
        );
        let request = read_tcp_line(&mut stream).await;
        assert_eq!(request["method"], "status");
        stream
            .write_all(b"{\"jsonrpc\":\"2.0\",\"id\":1,\"result\":{\"ok\":true}}\n")
            .await
            .expect("write daemon response");
    });
    let bridge = start_bridge(&paths, daemon_addr).await;

    let mut client = UnixStream::connect(&paths.socket)
        .await
        .expect("connect bridge");
    client
        .write_all(rpc_request(1, "status", serde_json::json!({})).as_bytes())
        .await
        .expect("write request");
    let mut reader = BufReader::new(client);
    let response = read_json_line(&mut reader).await;
    assert_eq!(response["result"]["ok"], true);

    daemon_task.await.expect("daemon task");
    bridge.abort();
}

#[tokio::test]
async fn preamble_rejection_becomes_a_json_rpc_error() {
    let paths = TestPaths::new();
    paths.write_token(0o600);
    let daemon = TcpListener::bind("127.0.0.1:0").await.expect("bind daemon");
    let daemon_addr = daemon.local_addr().expect("daemon address").to_string();
    let daemon_task = tokio::spawn(async move {
        let (mut stream, _) = daemon.accept().await.expect("accept daemon");
        let _ = read_tcp_line(&mut stream).await;
        stream
            .write_all(b"{\"ok\":false,\"error\":\"UNAUTHORIZED\"}\n")
            .await
            .expect("write rejection");
    });
    let bridge = start_bridge(&paths, daemon_addr).await;

    let mut client = UnixStream::connect(&paths.socket)
        .await
        .expect("connect bridge");
    client
        .write_all(rpc_request(2, "status", serde_json::json!({})).as_bytes())
        .await
        .expect("write request");
    let mut reader = BufReader::new(client);
    let response = read_json_line(&mut reader).await;
    assert_eq!(response["error"]["message"], "UNAUTHORIZED");
    assert_eq!(response["id"], 2);

    daemon_task.await.expect("daemon task");
    bridge.abort();
}

#[tokio::test]
async fn an_unreachable_daemon_becomes_internal() {
    let paths = TestPaths::new();
    paths.write_token(0o600);
    let unused = TcpListener::bind("127.0.0.1:0").await.expect("bind port");
    let daemon_addr = unused.local_addr().expect("daemon address").to_string();
    drop(unused);
    let bridge = start_bridge(&paths, daemon_addr).await;

    let mut client = UnixStream::connect(&paths.socket)
        .await
        .expect("connect bridge");
    client
        .write_all(rpc_request(3, "status", serde_json::json!({})).as_bytes())
        .await
        .expect("write request");
    let mut reader = BufReader::new(client);
    let response = read_json_line(&mut reader).await;
    assert_eq!(response["error"]["message"], "INTERNAL");
    assert_eq!(response["id"], 3);

    bridge.abort();
}

#[tokio::test]
async fn bound_socket_has_private_permissions() {
    let paths = TestPaths::new();
    paths.write_token(0o600);
    let bridge = start_bridge(&paths, "127.0.0.1:1".to_owned()).await;

    let mode = fs::metadata(&paths.socket)
        .expect("socket metadata")
        .permissions()
        .mode()
        & 0o7777;
    assert_eq!(mode, 0o600);

    bridge.abort();
}

#[tokio::test]
async fn bridge_open_tunnel_invalid_params_becomes_internal() {
    let paths = TestPaths::new();
    paths.write_token(0o600);
    let bridge = start_bridge(&paths, "127.0.0.1:1".to_owned()).await;

    let mut client = UnixStream::connect(&paths.socket)
        .await
        .expect("connect bridge");
    client
        .write_all(
            rpc_request(
                6,
                "bridge_open_tunnel",
                serde_json::json!({ "port": "invalid" }),
            )
            .as_bytes(),
        )
        .await
        .expect("write tunnel request");
    let mut reader = BufReader::new(client);
    let response = read_json_line(&mut reader).await;
    assert_eq!(response["error"]["message"], "INTERNAL");

    bridge.abort();
}

#[tokio::test]
async fn bridge_open_tunnel_rejects_forbidden_tunnel() {
    let paths = TestPaths::new();
    paths.write_token(0o600);
    let daemon = TcpListener::bind("127.0.0.1:0").await.expect("bind daemon");
    let daemon_addr = daemon.local_addr().expect("daemon address").to_string();
    let daemon_task = tokio::spawn(async move {
        let (mut stream, _) = daemon.accept().await.expect("accept daemon");
        let preamble = read_tcp_line(&mut stream).await;
        assert_eq!(preamble["tunnel"]["session_id"], "session");
        assert_eq!(preamble["tunnel"]["port"], 80);
        stream
            .write_all(b"{\"ok\":false,\"error\":\"FORBIDDEN\"}\n")
            .await
            .expect("write rejection");
    });
    let bridge = start_bridge(&paths, daemon_addr).await;

    let mut client = UnixStream::connect(&paths.socket)
        .await
        .expect("connect bridge");
    client
        .write_all(
            rpc_request(
                5,
                "bridge_open_tunnel",
                serde_json::json!({ "session_id": "session", "port": 80 }),
            )
            .as_bytes(),
        )
        .await
        .expect("write tunnel request");
    let mut reader = BufReader::new(client);
    let response = read_json_line(&mut reader).await;
    assert_eq!(response["error"]["message"], "FORBIDDEN");
    assert!(response.get("result").is_none());

    daemon_task.await.expect("daemon task");
    bridge.abort();
}

#[tokio::test]
async fn a_token_file_without_private_permissions_rejects_startup() {
    let paths = TestPaths::new();
    paths.write_token(0o644);
    let result = run(BridgeConfig {
        socket_path: paths.socket.clone(),
        token_file: paths.token.clone(),
        daemon_addr: "127.0.0.1:1".to_owned(),
    })
    .await;
    let error = result.expect_err("insecure token file must reject startup");
    assert_eq!(error.kind(), std::io::ErrorKind::PermissionDenied);
    assert!(error.to_string().contains("0600"));
    assert!(!error.to_string().contains("test-token"));
}

#[tokio::test]
async fn bridge_open_tunnel_splices_bytes_after_tunnel_acceptance() {
    let paths = TestPaths::new();
    paths.write_token(0o600);
    let daemon = TcpListener::bind("127.0.0.1:0").await.expect("bind daemon");
    let daemon_addr = daemon.local_addr().expect("daemon address").to_string();
    let daemon_task = tokio::spawn(async move {
        let (mut stream, _) = daemon.accept().await.expect("accept daemon");
        let preamble = read_tcp_line(&mut stream).await;
        assert_eq!(preamble["v"], 1);
        assert_eq!(preamble["auth"], "test-token");
        assert_eq!(preamble["tunnel"]["session_id"], "session");
        assert_eq!(preamble["tunnel"]["port"], 9222);
        stream
            .write_all(b"{\"ok\":true}\n")
            .await
            .expect("accept tunnel");
        let (mut stream, _) = daemon.accept().await.expect("accept daemon");
        let preamble = read_tcp_line(&mut stream).await;
        assert_eq!(preamble["v"], 1);
        assert_eq!(preamble["auth"], "test-token");
        assert_eq!(preamble["tunnel"]["session_id"], "session");
        assert_eq!(preamble["tunnel"]["port"], 9222);
        stream
            .write_all(b"{\"ok\":true}\n")
            .await
            .expect("accept tunnel");
        let mut bytes = [0_u8; 4];
        stream
            .read_exact(&mut bytes)
            .await
            .expect("read tunnel bytes");
        stream.write_all(&bytes).await.expect("echo tunnel bytes");
    });
    let bridge = start_bridge(&paths, daemon_addr).await;

    let mut client = UnixStream::connect(&paths.socket)
        .await
        .expect("connect bridge");
    client
        .write_all(
            rpc_request(
                4,
                "bridge_open_tunnel",
                serde_json::json!({ "session_id": "session", "port": 9222 }),
            )
            .as_bytes(),
        )
        .await
        .expect("write tunnel request");
    let mut reader = BufReader::new(client);
    let response = read_json_line(&mut reader).await;
    let local_port = response["result"]["local_port"]
        .as_u64()
        .expect("local port") as u16;

    let mut tunnel = TcpStream::connect(("127.0.0.1", local_port))
        .await
        .expect("connect local tunnel");
    tunnel.write_all(b"ping").await.expect("write tunnel bytes");
    let mut bytes = [0_u8; 4];
    tunnel
        .read_exact(&mut bytes)
        .await
        .expect("read tunnel bytes");
    assert_eq!(&bytes, b"ping");

    daemon_task.await.expect("daemon task");
    bridge.abort();
}
