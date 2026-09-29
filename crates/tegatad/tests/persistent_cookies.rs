//! 資格ごとの永続 cookie（Issue #45）のデーモン側の振る舞いを、偽の executor で確かめる。
//! ブラウザを使わないため、executor とのプロトコル・保管・監査・管理コマンドを直接検証する。
//! UNIX ドメインソケット経由で RPC を送るため、UNIX でのみ実行する。
#![cfg(unix)]

use std::io::{BufRead, BufReader, Write};
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};
use std::thread::sleep;
use std::time::{Duration, Instant};

use serde_json::{Value, json};
use uuid::Uuid;

mod common;
use common::{create_private_dir, rpc, try_rpc};

/// login に保管対象の `device`（1 日）とセッション cookie の `sid` を返し、`export_cookies` にも応じる偽の executor。
/// 受け取った要求の op と `cookies` を `executor.js.requests` に 1 行ずつ記録する。
const COOKIE_EXECUTOR: &str = r#"
const fs = require("node:fs");
const readline = require("node:readline");
const log = __filename + ".requests";
const day = Date.now() / 1000 + 86400.5;
const jar = (tag) => [
  { name: "device", value: "device-canary-" + tag, domain: "127.0.0.1", path: "/", expires: day, httpOnly: true, secure: false, sameSite: "Lax" },
  { name: "sid", value: "sid-canary-" + tag, domain: "127.0.0.1", path: "/", expires: -1, httpOnly: true, secure: false, sameSite: "Lax" },
];
const reply = (id, body) => process.stdout.write(JSON.stringify({ id, ...body }) + "\n");
const rl = readline.createInterface({ input: process.stdin });
rl.on("line", (line) => {
  const request = JSON.parse(line);
  fs.appendFileSync(log, JSON.stringify({ op: request.op, cookies: request.cookies === undefined ? "absent" : request.cookies }) + "\n");
  if (request.op === "login") {
    reply(request.id, { ok: true, endpoint: "ws://127.0.0.1:38999/devtools/browser/test", target_id: "test-target", cookies: jar("login"), steps_skipped: Array.isArray(request.cookies) });
  } else if (request.op === "export_cookies") {
    reply(request.id, { ok: true, cookies: jar("export") });
  } else if (request.op === "lease") {
    reply(request.id, { ok: true, target_id: "lease-target" });
  } else if (request.op === "release") {
    reply(request.id, { ok: true });
  } else if (request.op === "shutdown") {
    reply(request.id, { ok: true });
    process.exit(0);
  }
});
"#;

/// cookie を知らない古い executor。login 応答に `cookies` が無く、`export_cookies` には応答しない。
const LEGACY_EXECUTOR: &str = r#"
const readline = require("node:readline");
const reply = (id, body) => process.stdout.write(JSON.stringify({ id, ...body }) + "\n");
const rl = readline.createInterface({ input: process.stdin });
rl.on("line", (line) => {
  const request = JSON.parse(line);
  if (request.op === "login") {
    reply(request.id, { ok: true, endpoint: "ws://127.0.0.1:38999/devtools/browser/test", target_id: "test-target" });
  } else if (request.op === "release") {
    reply(request.id, { ok: true });
  } else if (request.op === "shutdown") {
    reply(request.id, { ok: true });
    process.exit(0);
  }
});
"#;

const USERNAME: &str = "cookie-test-username-secret";
const PASSWORD: &str = "cookie-test-password-secret";

struct Daemon {
    child: Option<Child>,
    /// 最上位の表に追加する設定行。
    extra_config: String,
    directory: PathBuf,
    state_dir: PathBuf,
    socket_path: PathBuf,
    tcp_port: u16,
}

impl Daemon {
    fn start(persist_cookies: &[&str], executor: &str) -> Self {
        Self::start_with(persist_cookies, executor, "")
    }

    fn start_with(persist_cookies: &[&str], executor: &str, extra_config: &str) -> Self {
        let directory = std::env::temp_dir().join(format!("tegatad-cookies-{}", Uuid::new_v4()));
        std::fs::create_dir(&directory).expect("create test directory");
        let state_dir = directory.join("state");
        create_private_dir(&state_dir);
        std::fs::write(directory.join("executor.js"), executor).expect("write executor script");
        let tcp_listener = std::net::TcpListener::bind(("127.0.0.1", 0)).expect("reserve TCP port");
        let tcp_port = tcp_listener.local_addr().expect("read TCP port").port();
        drop(tcp_listener);
        let mut daemon = Self {
            child: None,
            extra_config: extra_config.to_owned(),
            socket_path: directory.join("tegatad.sock"),
            directory,
            state_dir,
            tcp_port,
        };
        daemon.launch(persist_cookies);
        daemon
    }

    /// 同じ state_dir のまま、`persist_cookies` を差し替えてデーモンを起動し直す。
    fn restart(&mut self, persist_cookies: &[&str]) {
        self.stop();
        let _ = std::fs::remove_file(&self.socket_path);
        self.launch(persist_cookies);
    }

    fn stop(&mut self) {
        if let Some(mut child) = self.child.take() {
            let _ = child.kill();
            let _ = child.wait();
        }
    }

    fn launch(&mut self, persist_cookies: &[&str]) {
        let uid = unsafe { libc::geteuid() };
        let entries = ["site", "site-b"]
            .iter()
            .map(|id| {
                format!(
                    "\n[[providers.entries]]\nid = \"{id}\"\nname = \"Cookie {id}\"\nuri = \"http://127.0.0.1\"\nkind = \"login\"\nusername = {USERNAME:?}\npassword = {PASSWORD:?}\n"
                )
            })
            .collect::<String>();
        let config = format!(
            "state_dir = {state_dir:?}\naudit_log_path = {audit:?}\nexecutor_entry = {executor:?}\n{extra}\n[[listen]]\nkind = \"unix\"\npath = {socket:?}\nallowed_uids = [{uid}]\noperator_uids = [{uid}]\n\n[[listen]]\nkind = \"tcp\"\nbind = \"127.0.0.1\"\nport = {port}\n\n[[providers]]\nnamespace = \"mock\"\ntype = \"mock\"\npersist_cookies = {persist}\n{entries}",
            state_dir = self.state_dir,
            audit = self.audit_path(),
            executor = self.directory.join("executor.js"),
            socket = self.socket_path,
            port = self.tcp_port,
            persist = serde_json::to_string(persist_cookies).expect("render persist_cookies"),
            extra = self.extra_config,
        );
        let config_path = self.directory.join("config.toml");
        std::fs::write(&config_path, config).expect("write test config");
        let stderr = std::fs::OpenOptions::new()
            .create(true)
            .append(true)
            .open(self.directory.join("stderr.log"))
            .expect("open stderr log");
        let child = Command::new(env!("CARGO_BIN_EXE_tegatad"))
            .arg("--config")
            .arg(config_path)
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(Stdio::from(stderr))
            .spawn()
            .expect("spawn tegatad");
        self.child = Some(child);
        let deadline = Instant::now() + Duration::from_secs(5);
        while Instant::now() < deadline {
            if try_rpc(&self.socket_path, "status", json!({}))
                .and_then(|response| response.get("result").cloned())
                .is_some()
            {
                return;
            }
            sleep(Duration::from_millis(20));
        }
        panic!(
            "tegatad did not become ready: {}",
            std::fs::read_to_string(self.directory.join("stderr.log")).unwrap_or_default()
        );
    }

    fn audit_path(&self) -> PathBuf {
        self.state_dir.join("audit.log")
    }

    fn audit_records(&self) -> Vec<Value> {
        std::fs::read_to_string(self.audit_path())
            .unwrap_or_default()
            .lines()
            .map(|line| serde_json::from_str(line).expect("parse audit record"))
            .collect()
    }

    fn record(&self, method: &str, session_id: &str) -> Value {
        self.audit_records()
            .into_iter()
            .find(|record| record["method"] == method && record["session_id"] == session_id)
            .unwrap_or_else(|| panic!("no {method} record for {session_id}"))
    }

    /// 偽の executor が受け取った要求（op と cookies）。
    fn executor_requests(&self) -> Vec<Value> {
        std::fs::read_to_string(self.directory.join("executor.js.requests"))
            .unwrap_or_default()
            .lines()
            .map(|line| serde_json::from_str(line).expect("parse executor request"))
            .collect()
    }

    fn store_dir(&self) -> PathBuf {
        self.state_dir.join("cookies")
    }

    fn store_files(&self) -> Vec<PathBuf> {
        match std::fs::read_dir(self.store_dir()) {
            Ok(entries) => entries
                .map(|entry| entry.expect("store entry").path())
                .collect(),
            Err(_) => Vec::new(),
        }
    }

    fn login(&self, cred_id: &str) -> (Value, String) {
        let response = rpc(
            &self.socket_path,
            "login",
            json!({ "cred_id": cred_id, "target_url": "http://127.0.0.1/login" }),
        );
        let session_id = response["result"]["session_id"]
            .as_str()
            .unwrap_or_else(|| panic!("login failed: {response}"))
            .to_owned();
        (response, session_id)
    }

    fn logout(&self, session_id: &str) -> Value {
        let response = rpc(
            &self.socket_path,
            "logout",
            json!({ "session_id": session_id }),
        );
        assert_eq!(response["result"], json!({ "ok": true }), "{response}");
        response
    }
}

impl Drop for Daemon {
    fn drop(&mut self) {
        self.stop();
        let _ = std::fs::remove_dir_all(&self.directory);
    }
}

fn cookies_forget_cli(socket_path: &Path, selector: &[&str]) -> std::process::Output {
    Command::new(env!("CARGO_BIN_EXE_tegatad"))
        .args(["cookies", "forget"])
        .args(selector)
        .arg("--socket")
        .arg(socket_path)
        .output()
        .expect("run tegatad cookies forget")
}

fn tcp_rpc(daemon: &Daemon, token: &str, method: &str, params: Value) -> Value {
    let mut stream =
        std::net::TcpStream::connect(("127.0.0.1", daemon.tcp_port)).expect("connect TCP");
    writeln!(stream, "{}", json!({ "v": 1, "auth": token })).expect("write preamble");
    writeln!(
        stream,
        "{}",
        json!({ "jsonrpc": "2.0", "id": 1, "method": method, "params": params })
    )
    .expect("write RPC request");
    let mut line = String::new();
    BufReader::new(stream)
        .read_line(&mut line)
        .expect("read TCP response");
    serde_json::from_str(&line).expect("parse TCP response")
}

#[test]
fn a_persisted_credential_restores_only_persistent_cookies_on_the_next_login() {
    let daemon = Daemon::start(&["site"], COOKIE_EXECUTOR);

    let (first_response, first) = daemon.login("mock:site");
    let first_record = daemon.record("login", &first);
    assert_eq!(first_record["cookies"], "none");
    assert_eq!(first_record["steps_skipped"], false);
    assert_eq!(
        daemon.store_files().len(),
        1,
        "the login cookies are stored"
    );

    let logout_response = daemon.logout(&first);
    let end = daemon.record("logout", &first);
    assert_eq!(end["cookies_saved"], true);
    let ops = daemon
        .executor_requests()
        .iter()
        .map(|request| request["op"].as_str().unwrap_or_default().to_owned())
        .collect::<Vec<_>>();
    let export = ops
        .iter()
        .position(|op| op == "export_cookies")
        .expect("export_cookies was sent");
    let shutdown = ops
        .iter()
        .position(|op| op == "shutdown")
        .expect("shutdown was sent");
    assert!(export < shutdown, "export precedes shutdown: {ops:?}");

    let (second_response, second) = daemon.login("mock:site");
    let second_record = daemon.record("login", &second);
    assert_eq!(second_record["cookies"], "restored");
    assert_eq!(second_record["steps_skipped"], true);
    let logins = daemon
        .executor_requests()
        .into_iter()
        .filter(|request| request["op"] == "login")
        .collect::<Vec<_>>();
    assert_eq!(logins[0]["cookies"], Value::Null);
    let restored = logins[1]["cookies"].as_array().expect("restored cookies");
    assert_eq!(restored.len(), 1, "session cookies are not carried over");
    assert_eq!(restored[0]["name"], "device");
    assert_eq!(restored[0]["value"], "device-canary-export");

    // cookie の値は RPC 応答・監査・stderr・保管ファイル名のいずれにも現れない。
    let audit = std::fs::read_to_string(daemon.audit_path()).expect("read audit log");
    let stderr = std::fs::read_to_string(daemon.directory.join("stderr.log")).unwrap_or_default();
    for surface in [
        first_response.to_string(),
        logout_response.to_string(),
        second_response.to_string(),
        audit,
        stderr,
    ] {
        assert!(!surface.contains("device-canary"), "{surface}");
        assert!(!surface.contains("sid-canary"), "{surface}");
    }
    for file in daemon.store_files() {
        let content = std::fs::read_to_string(&file).expect("read store file");
        assert!(!content.contains(USERNAME));
        assert!(!content.contains(PASSWORD));
        assert!(!content.contains("sid-canary"));
    }
}

#[test]
fn a_credential_outside_persist_cookies_behaves_as_before() {
    let daemon = Daemon::start(&["site-b"], COOKIE_EXECUTOR);

    let (_, session) = daemon.login("mock:site");
    daemon.logout(&session);
    let (_, again) = daemon.login("mock:site");

    for record in [
        daemon.record("login", &session),
        daemon.record("logout", &session),
        daemon.record("login", &again),
    ] {
        assert!(record.get("cookies").is_none(), "{record}");
        assert!(record.get("steps_skipped").is_none(), "{record}");
        assert!(record.get("cookies_saved").is_none(), "{record}");
    }
    let requests = daemon.executor_requests();
    assert!(
        requests
            .iter()
            .filter(|request| request["op"] == "login")
            .all(|request| request["cookies"].is_null())
    );
    assert!(
        requests
            .iter()
            .all(|request| request["op"] != "export_cookies")
    );
    assert!(daemon.store_files().is_empty());
}

#[test]
fn an_executor_without_cookie_support_still_logs_in_and_stores_nothing() {
    let daemon = Daemon::start(&["*"], LEGACY_EXECUTOR);

    let (_, session) = daemon.login("mock:site");
    let record = daemon.record("login", &session);
    assert_eq!(record["cookies"], "none");
    assert_eq!(record["steps_skipped"], false);

    daemon.logout(&session);
    assert_eq!(daemon.record("logout", &session)["cookies_saved"], false);
    assert!(daemon.store_files().is_empty());
}

#[test]
fn a_corrupt_store_file_is_discarded_and_replaced() {
    let daemon = Daemon::start(&["site"], COOKIE_EXECUTOR);
    let (_, first) = daemon.login("mock:site");
    daemon.logout(&first);
    let files = daemon.store_files();
    assert_eq!(files.len(), 1);
    std::fs::write(&files[0], "{ this is not json").expect("corrupt the store file");

    let (_, second) = daemon.login("mock:site");
    assert_eq!(daemon.record("login", &second)["cookies"], "none");
    let content = std::fs::read_to_string(&files[0]).expect("read replaced file");
    let document: Value = serde_json::from_str(&content).expect("replaced with valid JSON");
    assert_eq!(document["cred_id"], "mock:site");
    let stderr = std::fs::read_to_string(daemon.directory.join("stderr.log")).unwrap_or_default();
    assert!(stderr.contains("unreadable cookie file"), "{stderr}");
}

#[test]
fn operators_forget_cookies_and_other_peers_are_refused() {
    let daemon = Daemon::start(&["*"], COOKIE_EXECUTOR);
    for cred_id in ["mock:site", "mock:site-b"] {
        let (_, session) = daemon.login(cred_id);
        daemon.logout(&session);
    }
    assert_eq!(daemon.store_files().len(), 2);

    let issued = rpc(
        &daemon.socket_path,
        "admin_peer_issue",
        json!({ "label": "non-operator" }),
    );
    let token = issued["result"]["token"].as_str().expect("peer token");
    let refused = tcp_rpc(
        &daemon,
        token,
        "admin_cookies_forget",
        json!({ "all": true }),
    );
    assert_eq!(refused["error"]["message"], "ADMIN_REQUIRED", "{refused}");
    assert_eq!(daemon.store_files().len(), 2);

    let invalid = rpc(
        &daemon.socket_path,
        "admin_cookies_forget",
        json!({ "cred_id": "mock:site", "all": true }),
    );
    assert!(invalid.get("error").is_some(), "{invalid}");
    assert_eq!(daemon.store_files().len(), 2);

    let one = cookies_forget_cli(&daemon.socket_path, &["mock:site"]);
    assert!(
        one.status.success(),
        "{}",
        String::from_utf8_lossy(&one.stderr)
    );
    let result: Value = serde_json::from_slice(&one.stdout).expect("forget prints JSON");
    assert_eq!(result, json!({ "removed": 1 }));
    assert_eq!(daemon.store_files().len(), 1);
    let record = daemon
        .audit_records()
        .into_iter()
        .find(|record| record["method"] == "admin_cookies_forget" && record["outcome"] == "ok")
        .expect("forget audit record");
    assert_eq!(record["cred_id"], "mock:site");
    assert_eq!(record["removed"], 1);

    let all = cookies_forget_cli(&daemon.socket_path, &["--all"]);
    assert!(
        all.status.success(),
        "{}",
        String::from_utf8_lossy(&all.stderr)
    );
    let result: Value = serde_json::from_slice(&all.stdout).expect("forget prints JSON");
    assert_eq!(result, json!({ "removed": 1 }));
    assert!(daemon.store_files().is_empty());
    assert!(
        daemon
            .audit_records()
            .iter()
            .any(|record| record["method"] == "admin_cookies_forget" && record["all"] == true)
    );
}

#[test]
fn startup_removes_files_of_credentials_no_longer_persisted() {
    let mut daemon = Daemon::start(&["*"], COOKIE_EXECUTOR);
    for cred_id in ["mock:site", "mock:site-b"] {
        let (_, session) = daemon.login(cred_id);
        daemon.logout(&session);
    }
    assert_eq!(daemon.store_files().len(), 2);

    daemon.restart(&["site-b"]);
    assert_eq!(daemon.store_files().len(), 1);
    let (_, session) = daemon.login("mock:site-b");
    assert_eq!(daemon.record("login", &session)["cookies"], "restored");

    daemon.restart(&[]);
    assert!(daemon.store_files().is_empty());
}

#[test]
fn lock_vault_saves_the_cookies_of_the_sessions_it_ends_and_keeps_the_store() {
    let daemon = Daemon::start(&["site"], COOKIE_EXECUTOR);
    let (_, session) = daemon.login("mock:site");

    let locked = rpc(
        &daemon.socket_path,
        "lock_vault",
        json!({ "namespace": "mock" }),
    );
    assert_eq!(locked["result"], json!({ "ok": true }), "{locked}");

    let terminated = daemon.record("session_terminated", &session);
    assert_eq!(terminated["cookies_saved"], true);
    assert_eq!(daemon.store_files().len(), 1);
    assert!(
        daemon
            .executor_requests()
            .iter()
            .any(|request| request["op"] == "export_cookies")
    );
}

#[test]
fn an_expired_session_saves_its_cookies() {
    let daemon = Daemon::start_with(&["site"], COOKIE_EXECUTOR, "session_ttl_secs = 1\n");
    let (_, session) = daemon.login("mock:site");
    std::fs::remove_dir_all(daemon.store_dir()).expect("drop the login-time file");

    let deadline = Instant::now() + Duration::from_secs(10);
    let record = loop {
        if let Some(record) = daemon.audit_records().into_iter().find(|record| {
            record["method"] == "session_expired" && record["session_id"] == session.as_str()
        }) {
            break record;
        }
        assert!(Instant::now() < deadline, "the session did not expire");
        sleep(Duration::from_millis(100));
    };
    assert_eq!(record["cookies_saved"], true);
    assert_eq!(daemon.store_files().len(), 1);
}
