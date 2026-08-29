//! These tests drive the daemon over its UNIX domain socket transport, so they
//! only exist on UNIX targets.
#![cfg(unix)]

use std::path::PathBuf;
use std::process::{Child, Command, Stdio};
use std::thread::sleep;
use std::time::{Duration, Instant};

use serde_json::{Value, json};
use uuid::Uuid;

mod common;
use common::{rpc, try_rpc};

const USERNAME: &str = "integration-user-secret";
const PASSWORD: &str = "integration-password-secret";
const TOTP_SEED: &str = "invalid-base32-canary-$";

struct Daemon {
    child: Child,
    directory: PathBuf,
    socket_path: PathBuf,
}

impl Daemon {
    #[allow(clippy::zombie_processes)]
    fn start() -> Self {
        let directory = std::env::temp_dir().join(format!("tegatad-test-{}", Uuid::new_v4()));
        std::fs::create_dir(&directory).expect("create test directory");
        let state_dir = directory.join("state");
        std::fs::create_dir(&state_dir).expect("create state directory");
        let socket_path = directory.join("tegatad.sock");
        let config_path = directory.join("config.toml");
        let uid = unsafe { libc::geteuid() };
        let config = format!(
            "socket_path = {:?}\nstate_dir = {:?}\naudit_log_path = {:?}\nallowed_uids = [{}]\n\n[[providers]]\nnamespace = \"mock\"\ntype = \"mock\"\n\n[[providers.entries]]\nid = \"site\"\nname = \"Integration Site\"\nuri = \"http://127.0.0.1\"\nkind = \"login\"\nusername = {:?}\npassword = {:?}\ntotp_seed = {:?}\ntotp_exposable = true\n\n[[providers.entries]]\nid = \"site-no-totp\"\nname = \"Integration Site Without TOTP\"\nuri = \"http://127.0.0.1\"\nkind = \"login\"\nusername = {:?}\npassword = {:?}\n",
            socket_path,
            state_dir,
            state_dir.join("audit.log"),
            uid,
            USERNAME,
            PASSWORD,
            TOTP_SEED,
            USERNAME,
            PASSWORD,
        );
        std::fs::write(&config_path, config).expect("write test config");
        let mut child = Command::new(env!("CARGO_BIN_EXE_tegatad"))
            .arg("--config")
            .arg(config_path)
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .spawn()
            .expect("spawn tegatad");
        let deadline = Instant::now() + Duration::from_secs(5);
        loop {
            if socket_path.exists()
                && try_rpc(&socket_path, "status", json!({}))
                    .and_then(|response| response.get("result").cloned())
                    .is_some()
            {
                return Self {
                    child,
                    directory,
                    socket_path,
                };
            }
            if Instant::now() >= deadline {
                let _ = child.kill();
                let _ = child.wait();
                let _ = std::fs::remove_dir_all(&directory);
                panic!("tegatad did not become ready");
            }
            sleep(Duration::from_millis(20));
        }
    }
}

impl Drop for Daemon {
    fn drop(&mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
        let _ = std::fs::remove_dir_all(&self.directory);
    }
}

fn error_message(response: &Value, expected_code: &str) {
    assert_eq!(response["error"]["code"], json!(-32000));
    assert_eq!(response["error"]["message"], json!(expected_code));
    assert!(response.get("result").is_none());
}

#[test]
fn status_returns_ok() {
    let daemon = Daemon::start();
    let response = rpc(&daemon.socket_path, "status", json!({}));
    assert_eq!(response["result"], json!({ "ok": true }));
}

#[test]
fn catalog_projects_metadata_only() {
    let daemon = Daemon::start();
    let response = rpc(&daemon.socket_path, "list_credentials", json!({}));
    let items = response["result"].as_array().expect("catalog array");
    assert_eq!(items.len(), 2);
    for item in items {
        let mut keys = item
            .as_object()
            .unwrap()
            .keys()
            .cloned()
            .collect::<Vec<_>>();
        keys.sort();
        assert_eq!(keys, vec!["id", "kind", "name", "source", "status", "uri"]);
        assert!(!item.to_string().contains(PASSWORD));
        assert!(!item.to_string().contains(TOTP_SEED));
    }
}

#[test]
fn non_allowlisted_method_is_rejected() {
    let daemon = Daemon::start();
    let response = rpc(&daemon.socket_path, "resolve", json!({}));
    assert_eq!(response["error"]["code"], json!(-32601));
    assert_eq!(response["error"]["message"], json!("method not found"));
}

#[test]
fn totp_is_exposable_once_and_rate_limited() {
    let daemon = Daemon::start();
    let first = rpc(
        &daemon.socket_path,
        "get_totp",
        json!({ "cred_id": "mock:site" }),
    );
    assert!(first["result"]["code"].as_str().unwrap().len() == 6);
    assert!(
        first["result"]["code"]
            .as_str()
            .unwrap()
            .chars()
            .all(|c| c.is_ascii_digit())
    );
    assert!((1..=30).contains(&first["result"]["expires_in"].as_u64().unwrap()));
    assert!(!first.to_string().contains(TOTP_SEED));

    let second = rpc(
        &daemon.socket_path,
        "get_totp",
        json!({ "cred_id": "mock:site" }),
    );
    error_message(&second, "RATE_LIMITED");

    let refused = rpc(
        &daemon.socket_path,
        "get_totp",
        json!({ "cred_id": "mock:site-no-totp" }),
    );
    error_message(&refused, "TOTP_NOT_EXPOSABLE");
}

#[test]
fn lock_hides_metadata_and_blocks_login() {
    let daemon = Daemon::start();
    let locked = rpc(
        &daemon.socket_path,
        "lock_vault",
        json!({ "namespace": "mock" }),
    );
    assert_eq!(locked["result"], json!({ "ok": true }));
    let list = rpc(&daemon.socket_path, "list_credentials", json!({}));
    for item in list["result"].as_array().unwrap() {
        let mut keys = item
            .as_object()
            .unwrap()
            .keys()
            .cloned()
            .collect::<Vec<_>>();
        keys.sort();
        assert_eq!(keys, vec!["id", "name", "source", "status"]);
        assert_eq!(item["status"], json!("locked"));
    }
    let login = rpc(
        &daemon.socket_path,
        "login",
        json!({ "cred_id": "mock:site", "target_url": "http://127.0.0.1" }),
    );
    error_message(&login, "VAULT_LOCKED");
}

#[test]
fn unknown_login_credential_is_rejected() {
    let daemon = Daemon::start();
    let response = rpc(
        &daemon.socket_path,
        "login",
        json!({ "cred_id": "mock:missing", "target_url": "http://127.0.0.1" }),
    );
    error_message(&response, "INVALID_CREDENTIAL");
}
