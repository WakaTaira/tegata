//! These tests drive the daemon over its UNIX domain socket transport, so they
//! only exist on UNIX targets.
#![cfg(unix)]

use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};
use std::thread::sleep;
use std::time::{Duration, Instant};

use serde_json::{Value, json};
use uuid::Uuid;

mod common;
use common::{create_private_dir, rpc, try_rpc};

const USERNAME: &str = "integration-user-secret";
const PASSWORD: &str = "integration-password-secret";
const TOTP_SEED: &str = "invalid-base32-canary-$";

/// A fake executor that completes a login and then idles even after stdin
/// closes, imitating an executor whose browser keeps the event loop alive.
/// Only an explicit shutdown request or a signal can end it.
const IDLING_EXECUTOR: &str = r#"
const fs = require("node:fs");
const readline = require("node:readline");
fs.writeFileSync(__filename + ".pid", String(process.pid));
const rl = readline.createInterface({ input: process.stdin });
rl.on("line", (line) => {
  const request = JSON.parse(line);
  if (request.op === "login") {
    process.stdout.write(
      JSON.stringify({ id: request.id, ok: true, endpoint: "ws://127.0.0.1:38999/devtools/browser/test", target_id: "test-target" }) + "\n",
    );
  } else if (request.op === "lease") {
    process.stdout.write(JSON.stringify({ id: request.id, ok: true, target_id: "lease-target" }) + "\n");
  } else if (request.op === "release") {
    process.stdout.write(JSON.stringify({ id: request.id, ok: true }) + "\n");
  } else if (request.op === "shutdown") {
    process.stdout.write(JSON.stringify({ id: request.id, ok: true }) + "\n");
    process.exit(0);
  }
});
rl.on("close", () => { setInterval(() => {}, 1000); });
"#;

/// A fake executor that fails the login and then idles the same way.
const FAILING_EXECUTOR: &str = r#"
const fs = require("node:fs");
const readline = require("node:readline");
fs.writeFileSync(__filename + ".pid", String(process.pid));
const rl = readline.createInterface({ input: process.stdin });
rl.on("line", (line) => {
  const request = JSON.parse(line);
  if (request.op === "login") {
    process.stdout.write(JSON.stringify({ id: request.id, ok: false, error: "INVALID_CREDENTIAL" }) + "\n");
  } else if (request.op === "shutdown") {
    process.stdout.write(JSON.stringify({ id: request.id, ok: true }) + "\n");
    process.exit(0);
  }
});
rl.on("close", () => { setInterval(() => {}, 1000); });
"#;

const AUTHORIZE_SUCCESS_EXECUTOR: &str = r#"
const readline = require("node:readline");
const rl = readline.createInterface({ input: process.stdin });
rl.on("line", (line) => {
  const request = JSON.parse(line);
  if (request.op === "authorize_device") {
    process.stdout.write(JSON.stringify({ id: request.id, ok: true, endpoint: "ws://127.0.0.1:38999/devtools/browser/test" }) + "\n");
  } else if (request.op === "shutdown") {
    process.stdout.write(JSON.stringify({ id: request.id, ok: true }) + "\n");
    process.exit(0);
  }
});
"#;

const AUTHORIZE_REJECTED_EXECUTOR: &str = r#"
const readline = require("node:readline");
const rl = readline.createInterface({ input: process.stdin });
rl.on("line", (line) => {
  const request = JSON.parse(line);
  if (request.op === "authorize_device") {
    process.stdout.write(JSON.stringify({ id: request.id, ok: false, error: "DEVICE_CODE_REJECTED" }) + "\n");
  } else if (request.op === "shutdown") {
    process.stdout.write(JSON.stringify({ id: request.id, ok: true }) + "\n");
    process.exit(0);
  }
});
"#;

struct Daemon {
    child: Child,
    directory: PathBuf,
    socket_path: PathBuf,
}

impl Daemon {
    fn start() -> Self {
        Self::start_inner(None)
    }

    /// Starts the daemon with a fake node executor written into the test
    /// directory; the executor records its PID in `executor.js.pid`.
    fn start_with_executor(script: &str) -> Self {
        Self::start_inner_with_options(Some(script), None, None)
    }

    fn start_with_executor_and_approval(script: &str) -> Self {
        Self::start_inner_with_options(Some(script), Some(approve_once), None)
    }

    /// Starts the daemon with an `approve_cmd` that records the hook
    /// environment into `approval.env` and approves.
    fn start_with_executor_and_recording_approval(script: &str) -> Self {
        Self::start_inner_with_options(Some(script), Some(approve_and_record), None)
    }

    fn start_with_executor_and_ttl(script: &str, ttl_secs: u64) -> Self {
        Self::start_inner_with_options(Some(script), None, Some(ttl_secs))
    }

    #[allow(clippy::zombie_processes)]
    fn start_inner(executor_script: Option<&str>) -> Self {
        Self::start_inner_with_options(executor_script, None, None)
    }

    #[allow(clippy::zombie_processes)]
    fn start_inner_with_options(
        executor_script: Option<&str>,
        approve_cmd: Option<fn(&Path) -> String>,
        session_ttl_secs: Option<u64>,
    ) -> Self {
        let directory = std::env::temp_dir().join(format!("tegatad-test-{}", Uuid::new_v4()));
        std::fs::create_dir(&directory).expect("create test directory");
        let state_dir = directory.join("state");
        create_private_dir(&state_dir);
        let socket_path = directory.join("tegatad.sock");
        let config_path = directory.join("config.toml");
        let uid = unsafe { libc::geteuid() };
        let executor_line = executor_script
            .map(|script| {
                let script_path = directory.join("executor.js");
                std::fs::write(&script_path, script).expect("write executor script");
                format!("executor_entry = {script_path:?}\n")
            })
            .unwrap_or_default();
        let approval_line = approve_cmd
            .map(|approve_cmd| format!("approve_cmd = {:?}\n", approve_cmd(&directory)))
            .unwrap_or_default();
        let ttl_line = session_ttl_secs
            .map(|value| format!("session_ttl_secs = {value}\n"))
            .unwrap_or_default();
        let config = format!(
            "socket_path = {:?}\nstate_dir = {:?}\naudit_log_path = {:?}\nallowed_uids = [{}]\n{}{}{}\n[[providers]]\nnamespace = \"mock\"\ntype = \"mock\"\n\n[[providers.entries]]\nid = \"site\"\nname = \"Integration Site\"\nuri = \"http://127.0.0.1\"\nkind = \"login\"\nusername = {:?}\npassword = {:?}\ntotp_seed = {:?}\ntotp_exposable = true\n\n[[providers.entries]]\nid = \"site-no-totp\"\nname = \"Integration Site Without TOTP\"\nuri = \"http://127.0.0.1\"\nkind = \"login\"\nusername = {:?}\npassword = {:?}\n",
            socket_path,
            state_dir,
            state_dir.join("audit.log"),
            uid,
            executor_line,
            approval_line,
            ttl_line,
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

/// Approves the first request only.
fn approve_once(directory: &Path) -> String {
    let approval_path = directory.join("approval.once");
    format!("test ! -e {:?} && touch {:?}", approval_path, approval_path)
}

/// Approves every request after recording the hook environment.
fn approve_and_record(directory: &Path) -> String {
    let env_path = directory.join("approval.env");
    format!("env | grep '^TEGATA_' > {env_path:?}")
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
    assert_eq!(response["result"]["ok"], json!(true));
    assert_eq!(response["result"]["browsers"], json!(0));
    assert_eq!(response["result"]["leases"], json!(0));
}

#[test]
fn authorize_device_returns_only_ok_and_does_not_create_a_session() {
    let daemon = Daemon::start_with_executor(AUTHORIZE_SUCCESS_EXECUTOR);
    let response = rpc(
        &daemon.socket_path,
        "authorize_device",
        json!({
            "cred_id": "mock:site",
            "verification_url": "https://example.test/device",
            "user_code": "secret-device-code",
            "success_selector": "#device-ok"
        }),
    );
    assert_eq!(response["result"], json!({ "ok": true }));
    assert!(response["result"].get("endpoint").is_none());
    let status = rpc(&daemon.socket_path, "status", json!({}));
    assert_eq!(status["result"]["browsers"], json!(0));
    assert_eq!(status["result"]["leases"], json!(0));
}

#[test]
fn authorize_device_audit_uses_verification_url_without_query_or_spoofed_target() {
    let daemon = Daemon::start_with_executor(AUTHORIZE_SUCCESS_EXECUTOR);
    let response = rpc(
        &daemon.socket_path,
        "authorize_device",
        json!({
            "cred_id": "mock:site",
            "verification_url": "https://example.test/device?user_code=secret-device-code#fragment",
            "target_url": "https://attacker.test/forged",
            "user_code": "secret-device-code",
            "success_selector": "#device-ok"
        }),
    );
    assert_eq!(response["result"], json!({ "ok": true }));

    let audit = read_audit_log(&daemon, "authorize_device");
    let record = audit
        .lines()
        .map(|line| serde_json::from_str::<Value>(line).expect("parse audit record"))
        .find(|record| record["method"] == "authorize_device")
        .expect("authorize_device audit record");
    assert_eq!(record["target_url"], json!("https://example.test/device"));
    assert!(!audit.contains("secret-device-code"));
    assert!(!audit.contains("attacker.test"));
}

#[test]
fn authorize_device_audit_ignores_keys_the_method_does_not_accept() {
    let daemon = Daemon::start_with_executor(AUTHORIZE_SUCCESS_EXECUTOR);
    let response = rpc(
        &daemon.socket_path,
        "authorize_device",
        json!({
            "cred_id": "mock:site",
            "verification_url": "https://user:secret-userinfo@example.test/device",
            "user_code": "secret-device-code",
            "success_selector": "#device-ok",
            "session_id": "forged-session",
            "namespace": "forged-namespace"
        }),
    );
    assert_eq!(response["result"], json!({ "ok": true }));

    let audit = read_audit_log(&daemon, "authorize_device");
    let record = audit
        .lines()
        .map(|line| serde_json::from_str::<Value>(line).expect("parse audit record"))
        .find(|record| record["method"] == "authorize_device")
        .expect("authorize_device audit record");
    assert_eq!(record["cred_id"], json!("mock:site"));
    assert_eq!(record["target_url"], json!("https://example.test/device"));
    assert!(record["session_id"].is_null());
    assert_eq!(record["namespace"], json!("mock"));
    assert!(!audit.contains("forged-session"));
    assert!(!audit.contains("forged-namespace"));
    assert!(!audit.contains("secret-userinfo"));
}

#[test]
fn failed_login_audit_ignores_a_caller_supplied_session_id() {
    let daemon = Daemon::start_with_executor(FAILING_EXECUTOR);
    let response = rpc(
        &daemon.socket_path,
        "login",
        json!({
            "cred_id": "mock:site",
            "target_url": "http://127.0.0.1",
            "session_id": "forged-session",
            "namespace": "forged-namespace"
        }),
    );
    error_message(&response, "INVALID_CREDENTIAL");

    let audit = read_audit_log(&daemon, "login");
    let record = audit
        .lines()
        .map(|line| serde_json::from_str::<Value>(line).expect("parse audit record"))
        .find(|record| record["method"] == "login")
        .expect("login audit record");
    assert!(record["session_id"].is_null());
    assert_eq!(record["namespace"], json!("mock"));
    assert!(!audit.contains("forged-session"));
    assert!(!audit.contains("forged-namespace"));
}

#[test]
fn login_audit_derives_namespace_from_cred_id() {
    let daemon = Daemon::start_with_executor(FAILING_EXECUTOR);
    let response = rpc(
        &daemon.socket_path,
        "login",
        json!({
            "cred_id": "mock:site",
            "target_url": "http://127.0.0.1"
        }),
    );
    error_message(&response, "INVALID_CREDENTIAL");

    let audit = read_audit_log(&daemon, "login");
    let record = audit
        .lines()
        .map(|line| serde_json::from_str::<Value>(line).expect("parse audit record"))
        .find(|record| record["method"] == "login")
        .expect("login audit record");
    assert_eq!(record["namespace"], json!("mock"));
}

#[test]
fn authorize_device_approval_hook_receives_verification_url_without_query() {
    let daemon = Daemon::start_with_executor_and_recording_approval(AUTHORIZE_SUCCESS_EXECUTOR);
    let response = rpc(
        &daemon.socket_path,
        "authorize_device",
        json!({
            "cred_id": "mock:site",
            "verification_url": "https://user:secret-userinfo@example.test/device?user_code=secret-device-code#fragment",
            "user_code": "secret-device-code",
            "success_selector": "#device-ok"
        }),
    );
    assert_eq!(response["result"], json!({ "ok": true }));

    let env = std::fs::read_to_string(daemon.directory.join("approval.env"))
        .expect("read approval environment");
    assert!(
        env.lines()
            .any(|line| line == "TEGATA_TARGET_URL=https://example.test/device")
    );
    assert!(
        env.lines()
            .any(|line| line == "TEGATA_METHOD=authorize_device")
    );
    assert!(!env.contains("secret-device-code"));
    assert!(!env.contains("secret-userinfo"));
}

#[test]
fn authorize_device_propagates_device_code_rejected() {
    let daemon = Daemon::start_with_executor(AUTHORIZE_REJECTED_EXECUTOR);
    let response = rpc(
        &daemon.socket_path,
        "authorize_device",
        json!({
            "cred_id": "mock:site",
            "verification_url": "https://example.test/device",
            "user_code": "unissued-device-code",
            "success_selector": "#device-ok",
            "failure_selector": "#device-error"
        }),
    );
    error_message(&response, "DEVICE_CODE_REJECTED");
    let status = rpc(&daemon.socket_path, "status", json!({}));
    assert_eq!(status["result"]["browsers"], json!(0));
    assert_eq!(status["result"]["leases"], json!(0));
}

#[test]
fn shared_login_requires_approval_for_each_lease() {
    let daemon = Daemon::start_with_executor_and_approval(IDLING_EXECUTOR);
    let params = json!({ "cred_id": "mock:site", "target_url": "http://127.0.0.1" });
    let first = rpc(&daemon.socket_path, "login", params.clone());
    assert!(first["result"]["session_id"].is_string());

    let second = rpc(&daemon.socket_path, "login", params);
    error_message(&second, "APPROVAL_DENIED");

    let status = rpc(&daemon.socket_path, "status", json!({}));
    assert_eq!(status["result"]["leases"], json!(1));
}

#[test]
fn system_session_audits_have_system_principal() {
    let daemon = Daemon::start_with_executor_and_ttl(IDLING_EXECUTOR, 1);
    let login = rpc(
        &daemon.socket_path,
        "login",
        json!({ "cred_id": "mock:site", "target_url": "http://127.0.0.1" }),
    );
    assert!(login["result"]["session_id"].is_string());
    let deadline = Instant::now() + Duration::from_secs(8);
    let mut expired = false;
    while Instant::now() < deadline {
        let audit =
            std::fs::read_to_string(daemon.directory.join("state/audit.log")).unwrap_or_default();
        expired = audit.lines().any(|line| {
            let record: Value = serde_json::from_str(line).expect("parse audit record");
            record["method"] == "session_expired" && record["principal"] == "system"
        });
        if expired {
            break;
        }
        sleep(Duration::from_millis(50));
    }
    assert!(expired, "session_expired audit lacks system principal");
    drop(daemon);

    let daemon = Daemon::start_with_executor(IDLING_EXECUTOR);
    let login = rpc(
        &daemon.socket_path,
        "login",
        json!({ "cred_id": "mock:site", "target_url": "http://127.0.0.1" }),
    );
    let session_id = login["result"]["session_id"].clone();
    assert!(session_id.is_string());
    let locked = rpc(
        &daemon.socket_path,
        "lock_vault",
        json!({ "namespace": "mock" }),
    );
    assert_eq!(locked["result"]["ok"], true);
    let audit = read_audit_log(&daemon, "session_terminated");
    assert!(audit.lines().any(|line| {
        let record: Value = serde_json::from_str(line).expect("parse audit record");
        record["method"] == "session_terminated" && record["principal"] == "system"
    }));
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

fn executor_pid(daemon: &Daemon) -> libc::pid_t {
    let pid_path = daemon.directory.join("executor.js.pid");
    let deadline = Instant::now() + Duration::from_secs(5);
    loop {
        if let Ok(contents) = std::fs::read_to_string(&pid_path)
            && let Ok(pid) = contents.trim().parse()
        {
            return pid;
        }
        assert!(
            Instant::now() < deadline,
            "executor pid file did not appear"
        );
        sleep(Duration::from_millis(20));
    }
}

fn process_alive(pid: libc::pid_t) -> bool {
    unsafe { libc::kill(pid, 0) == 0 }
}

fn wait_for_death(pid: libc::pid_t, timeout: Duration) -> bool {
    let deadline = Instant::now() + timeout;
    while Instant::now() < deadline {
        if !process_alive(pid) {
            return true;
        }
        sleep(Duration::from_millis(20));
    }
    !process_alive(pid)
}

#[test]
fn login_failure_reaps_the_executor() {
    let daemon = Daemon::start_with_executor(FAILING_EXECUTOR);
    let response = rpc(
        &daemon.socket_path,
        "login",
        json!({ "cred_id": "mock:site", "target_url": "http://127.0.0.1" }),
    );
    error_message(&response, "INVALID_CREDENTIAL");
    let pid = executor_pid(&daemon);
    assert!(
        wait_for_death(pid, Duration::from_secs(5)),
        "executor survived a failed login"
    );
}

#[test]
fn sigterm_reaps_live_session_executors() {
    let mut daemon = Daemon::start_with_executor(IDLING_EXECUTOR);
    let response = rpc(
        &daemon.socket_path,
        "login",
        json!({ "cred_id": "mock:site", "target_url": "http://127.0.0.1" }),
    );
    assert!(
        response["result"]["session_id"].is_string(),
        "login should succeed: {response}"
    );
    let pid = executor_pid(&daemon);
    assert!(
        process_alive(pid),
        "executor should be running while the session is live"
    );
    unsafe { libc::kill(daemon.child.id() as libc::pid_t, libc::SIGTERM) };
    let deadline = Instant::now() + Duration::from_secs(5);
    loop {
        if daemon.child.try_wait().expect("poll daemon").is_some() {
            break;
        }
        assert!(
            Instant::now() < deadline,
            "daemon did not exit after SIGTERM"
        );
        sleep(Duration::from_millis(20));
    }
    assert!(
        wait_for_death(pid, Duration::from_secs(5)),
        "executor survived daemon shutdown"
    );
}

/// 指定 method の監査行が現れるまで短時間待ってから読む（ファイル I/O の遅延に対する保険）。
fn read_audit_log(daemon: &Daemon, method: &str) -> String {
    let path = daemon.directory.join("state/audit.log");
    let needle = format!("\"method\":\"{method}\"");
    let deadline = std::time::Instant::now() + std::time::Duration::from_secs(5);
    loop {
        let audit = std::fs::read_to_string(&path).unwrap_or_default();
        let complete = audit
            .lines()
            .any(|line| line.contains(&needle) && serde_json::from_str::<Value>(line).is_ok());
        if complete || std::time::Instant::now() >= deadline {
            return audit;
        }
        std::thread::sleep(std::time::Duration::from_millis(50));
    }
}

/// 監査行は RPC 応答より前にファイルへ書き終わっていなければならない。応答を受け取った
/// 直後に待たずに読み、その要求の行が必ず存在することを多数回の往復で確かめる。
#[test]
fn audit_record_is_on_disk_before_the_response_arrives() {
    let daemon = Daemon::start();
    let path = daemon.directory.join("state/audit.log");
    for attempt in 0..500 {
        let cred_id = format!("mock:missing-{attempt}");
        let response = rpc(
            &daemon.socket_path,
            "login",
            json!({ "cred_id": cred_id, "target_url": "http://127.0.0.1" }),
        );
        error_message(&response, "INVALID_CREDENTIAL");
        let audit = std::fs::read_to_string(&path).unwrap_or_default();
        let needle = format!("\"cred_id\":\"{cred_id}\"");
        assert!(
            audit
                .lines()
                .any(|line| line.contains(&needle) && serde_json::from_str::<Value>(line).is_ok()),
            "audit record for attempt {attempt} was not on disk when the response arrived"
        );
    }
}
