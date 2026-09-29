//! 注入プロキシ（`[[api_proxy]]` と `open_api_proxy`）のデーモン側を、偽 executor で検証する。
//! UNIX ドメインソケット経由で RPC を送るため、UNIX でのみ実行する。
#![cfg(unix)]

use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};
use std::thread::sleep;
use std::time::{Duration, Instant};

use serde_json::{Value, json};
use uuid::Uuid;

mod common;
use common::{create_private_dir, rpc, try_rpc};

const USERNAME: &str = "api-proxy-user-secret";
const PASSWORD: &str = "api-proxy-password-secret";
const UPSTREAM: &str = "http://127.0.0.1:9";
const PROXY_PORT: u16 = 38998;
const PATH_SECRET: &str = "fake-path-secret_A1";

/// 受けた要求を `executor.js.log` に 1 行ずつ記録する偽 executor。
/// 開始応答の直後と、停止・終了の応答の直前に id を持たないイベント行を書き、
/// デーモンがイベント行を応答と取り違えないことを確かめられるようにする。
/// stdin が閉じても待機を続けるが、親のデーモンが消えたら終了する（テストの後始末で孤児を残さないため、#47）。
const PROXY_EXECUTOR: &str = r#"
const fs = require("node:fs");
const readline = require("node:readline");
const parent = process.ppid;
const log = (value) => fs.appendFileSync(__filename + ".log", JSON.stringify(value) + "\n");
const event = (path, status) =>
  process.stdout.write(JSON.stringify({ event: "api_proxy_request", http_method: "GET", path, status }) + "\n");
const rl = readline.createInterface({ input: process.stdin });
rl.on("line", (line) => {
  const request = JSON.parse(line);
  log(request);
  if (request.op === "api_proxy_start") {
    process.stdout.write(JSON.stringify({ id: request.id, ok: true, port: 38998, secret: "fake-path-secret_A1" }) + "\n");
    event("/api/whoami", 200);
  } else if (request.op === "api_proxy_stop") {
    event("/api/late", 502);
    process.stdout.write(JSON.stringify({ id: request.id, ok: true }) + "\n");
  } else if (request.op === "shutdown") {
    event("/api/final", 404);
    process.stdout.write(JSON.stringify({ id: request.id, ok: true }) + "\n");
    process.exit(0);
  }
});
rl.on("close", () => { setInterval(() => { if (process.ppid !== parent) process.exit(0); }, 200); });
"#;

/// 開始応答の直後に、監査で整形されるべき path のイベント行を書く偽 executor。
/// 1 行目は path secret と同じ形の先頭 segment、2 行目は上限を超える長さの path を持つ。
const PATH_EVENT_EXECUTOR: &str = r#"
const readline = require("node:readline");
const event = (path, status) =>
  process.stdout.write(JSON.stringify({ event: "api_proxy_request", http_method: "GET", path, status }) + "\n");
const rl = readline.createInterface({ input: process.stdin });
rl.on("line", (line) => {
  const request = JSON.parse(line);
  if (request.op === "api_proxy_start") {
    process.stdout.write(JSON.stringify({ id: request.id, ok: true, port: 38998, secret: "fake-path-secret_A1" }) + "\n");
    event("/Ax7fQ2mN9pL3kR8sT1vW0y/api/whoami", 401);
    event("/" + "a".repeat(600), 200);
  } else {
    process.stdout.write(JSON.stringify({ id: request.id, ok: true }) + "\n");
    if (request.op === "shutdown") process.exit(0);
  }
});
"#;

/// 開始要求を失敗させる偽 executor。
const FAILING_PROXY_EXECUTOR: &str = r#"
const readline = require("node:readline");
const rl = readline.createInterface({ input: process.stdin });
rl.on("line", (line) => {
  const request = JSON.parse(line);
  if (request.op === "api_proxy_start") {
    process.stdout.write(JSON.stringify({ id: request.id, ok: false, error: "INTERNAL" }) + "\n");
  }
});
"#;

const OAUTH_PROXY_EXECUTOR: &str = r#"
const fs = require("node:fs");
const readline = require("node:readline");
const parent = process.ppid;
const log = (value) => fs.appendFileSync(__filename + ".log", JSON.stringify(value) + "\n");
const event = (action) =>
  process.stdout.write(JSON.stringify({ event: "oauth_token", action }) + "\n");
const rl = readline.createInterface({ input: process.stdin });
rl.on("line", (line) => {
  const request = JSON.parse(line);
  log(request);
  if (request.op === "api_proxy_start") {
    process.stdout.write(JSON.stringify({ id: request.id, ok: true, port: 38998, secret: "fake-path-secret_A1" }) + "\n");
    event("unknown");
    event("issued");
  } else if (request.op === "api_proxy_stop") {
    process.stdout.write(JSON.stringify({ id: request.id, ok: true }) + "\n");
    event("revoked");
  } else if (request.op === "shutdown") {
    process.stdout.write(JSON.stringify({ id: request.id, ok: true }) + "\n");
    process.exit(0);
  }
});
rl.on("close", () => { setInterval(() => { if (process.ppid !== parent) process.exit(0); }, 200); });
"#;

const OAUTH_FAILING_PROXY_EXECUTOR: &str = r#"
const readline = require("node:readline");
const rl = readline.createInterface({ input: process.stdin });
rl.on("line", (line) => {
  const request = JSON.parse(line);
  if (request.op === "api_proxy_start") {
    process.stdout.write(JSON.stringify({ id: request.id, ok: false, error: "OAUTH_GRANT_FAILED" }) + "\n");
  }
});
"#;

/// `api_proxy_stop` の応答を、デーモンの停止処理の待機（1 秒）より長く遅らせる OAuth の偽 executor。
/// 応答の直前に失効のイベント行を書き、executor が停止要求の中で行う revocation を模す。
const SLOW_REVOKING_OAUTH_PROXY_EXECUTOR: &str = r#"
const fs = require("node:fs");
const readline = require("node:readline");
const parent = process.ppid;
const log = (value) => fs.appendFileSync(__filename + ".log", JSON.stringify(value) + "\n");
const event = (action) =>
  process.stdout.write(JSON.stringify({ event: "oauth_token", action }) + "\n");
const rl = readline.createInterface({ input: process.stdin });
rl.on("line", (line) => {
  const request = JSON.parse(line);
  log(request);
  if (request.op === "api_proxy_start") {
    process.stdout.write(JSON.stringify({ id: request.id, ok: true, port: 38998, secret: "fake-path-secret_A1" }) + "\n");
    event("issued");
  } else if (request.op === "api_proxy_stop") {
    setTimeout(() => {
      event("revoked");
      process.stdout.write(JSON.stringify({ id: request.id, ok: true }) + "\n");
    }, 2000);
  } else if (request.op === "shutdown") {
    process.stdout.write(JSON.stringify({ id: request.id, ok: true }) + "\n");
    process.exit(0);
  }
});
rl.on("close", () => { setInterval(() => { if (process.ppid !== parent) process.exit(0); }, 200); });
"#;

struct Options<'a> {
    executor: &'a str,
    api_proxies: String,
    session_ttl_secs: Option<u64>,
    browser_max_lifetime_secs: Option<u64>,
    approve_cmd: Option<String>,
}

impl<'a> Options<'a> {
    fn new(executor: &'a str) -> Self {
        Self {
            executor,
            api_proxies: api_proxy_section("fx", UPSTREAM, None),
            session_ttl_secs: None,
            browser_max_lifetime_secs: None,
            approve_cmd: None,
        }
    }
}

fn api_proxy_section(name: &str, upstream: &str, value: Option<&str>) -> String {
    let value = value
        .map(|value| format!("value = {value:?}\n"))
        .unwrap_or_default();
    format!(
        "\n[[api_proxy]]\nname = {name:?}\ncred_id = \"mock:site\"\nupstream = {upstream:?}\n{value}"
    )
}

fn oauth_api_proxy_section(
    name: &str,
    upstream: &str,
    token_url: &str,
    login_cred_id: &str,
) -> String {
    format!(
        "\n[[api_proxy]]\nname = {name:?}\nupstream = {upstream:?}\nvalue = \"Bearer {{{{secret}}}}\"\n[api_proxy.oauth]\nclient_id = \"oauth-client\"\ndevice_authorization_url = \"https://oauth.example/device\"\ntoken_url = {token_url:?}\nlogin_cred_id = {login_cred_id:?}\nsuccess_selector = \"#success\"\n"
    )
}

struct Layout {
    directory: PathBuf,
    socket_path: PathBuf,
    config_path: PathBuf,
}

impl Layout {
    fn create(options: &Options<'_>) -> Self {
        let directory = std::env::temp_dir().join(format!("tegatad-api-proxy-{}", Uuid::new_v4()));
        std::fs::create_dir(&directory).expect("create test directory");
        let state_dir = directory.join("state");
        create_private_dir(&state_dir);
        let socket_path = directory.join("tegatad.sock");
        let config_path = directory.join("config.toml");
        let executor_path = directory.join("executor.js");
        std::fs::write(&executor_path, options.executor).expect("write executor script");
        let mut top = format!(
            "socket_path = {:?}\nstate_dir = {:?}\naudit_log_path = {:?}\nallowed_uids = [{}]\nexecutor_entry = {:?}\n",
            socket_path,
            state_dir,
            state_dir.join("audit.log"),
            unsafe { libc::geteuid() },
            executor_path,
        );
        if let Some(ttl) = options.session_ttl_secs {
            top.push_str(&format!("session_ttl_secs = {ttl}\n"));
        }
        if let Some(lifetime) = options.browser_max_lifetime_secs {
            top.push_str(&format!("browser_max_lifetime_secs = {lifetime}\n"));
        }
        if let Some(command) = &options.approve_cmd {
            top.push_str(&format!("approve_cmd = {command:?}\n"));
        }
        let config = format!(
            "{top}\n[[providers]]\nnamespace = \"mock\"\ntype = \"mock\"\n\n[[providers.entries]]\nid = \"site\"\nname = \"API Proxy Site\"\nuri = \"http://127.0.0.1\"\nkind = \"login\"\nusername = {USERNAME:?}\npassword = {PASSWORD:?}\n{}",
            options.api_proxies,
        );
        std::fs::write(&config_path, config).expect("write test config");
        Self {
            directory,
            socket_path,
            config_path,
        }
    }

    fn spawn(&self, stderr: Stdio) -> Child {
        Command::new(env!("CARGO_BIN_EXE_tegatad"))
            .arg("--config")
            .arg(&self.config_path)
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(stderr)
            .spawn()
            .expect("spawn tegatad")
    }
}

struct Daemon {
    child: Child,
    layout: Layout,
}

impl Daemon {
    #[allow(clippy::zombie_processes)]
    fn start(options: Options<'_>) -> Self {
        let layout = Layout::create(&options);
        let mut child = layout.spawn(Stdio::null());
        let deadline = Instant::now() + Duration::from_secs(5);
        loop {
            if layout.socket_path.exists()
                && try_rpc(&layout.socket_path, "status", json!({}))
                    .and_then(|response| response.get("result").cloned())
                    .is_some()
            {
                return Self { child, layout };
            }
            if Instant::now() >= deadline {
                let _ = child.kill();
                let _ = child.wait();
                let _ = std::fs::remove_dir_all(&layout.directory);
                panic!("tegatad did not become ready");
            }
            sleep(Duration::from_millis(20));
        }
    }

    fn socket(&self) -> &PathBuf {
        &self.layout.socket_path
    }

    fn audit_text(&self) -> String {
        std::fs::read_to_string(self.layout.directory.join("state/audit.log")).unwrap_or_default()
    }

    fn audit_records(&self) -> Vec<Value> {
        self.audit_text()
            .lines()
            .map(|line| serde_json::from_str(line).expect("parse audit record"))
            .collect()
    }

    fn executor_log(&self) -> Vec<Value> {
        read_executor_log(&self.layout.directory.join("executor.js.log"))
    }
}

impl Drop for Daemon {
    fn drop(&mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
        let _ = std::fs::remove_dir_all(&self.layout.directory);
    }
}

fn read_executor_log(path: &Path) -> Vec<Value> {
    std::fs::read_to_string(path)
        .unwrap_or_default()
        .lines()
        .map(|line| serde_json::from_str(line).expect("parse executor log"))
        .collect()
}

fn executor_ops(daemon: &Daemon) -> Vec<String> {
    daemon
        .executor_log()
        .iter()
        .filter_map(|request| request["op"].as_str().map(ToOwned::to_owned))
        .collect()
}

fn wait_for(description: &str, timeout: Duration, mut condition: impl FnMut() -> bool) {
    let deadline = Instant::now() + timeout;
    while Instant::now() < deadline {
        if condition() {
            return;
        }
        sleep(Duration::from_millis(50));
    }
    panic!("timed out waiting for {description}");
}

fn error_message(response: &Value, expected_code: &str) {
    assert_eq!(response["error"]["code"], json!(-32000));
    assert_eq!(response["error"]["message"], json!(expected_code));
    assert!(response.get("result").is_none());
}

fn open(daemon: &Daemon) -> String {
    let response = rpc(daemon.socket(), "open_api_proxy", json!({ "name": "fx" }));
    assert_eq!(
        response["result"]["base_url"],
        json!(format!("http://127.0.0.1:{PROXY_PORT}/{PATH_SECRET}")),
        "unexpected response: {response}"
    );
    response["result"]["session_id"]
        .as_str()
        .expect("session_id")
        .to_owned()
}

fn has_record(records: &[Value], method: &str, session_id: &str) -> bool {
    records
        .iter()
        .any(|record| record["method"] == method && record["session_id"] == session_id)
}

#[test]
fn open_api_proxy_injects_the_resolved_value_and_audits_requests() {
    let daemon = Daemon::start(Options::new(PROXY_EXECUTOR));
    let session_id = open(&daemon);

    let start = daemon
        .executor_log()
        .into_iter()
        .find(|request| request["op"] == "api_proxy_start")
        .expect("api_proxy_start request");
    assert_eq!(start["upstream"], json!(UPSTREAM));
    assert_eq!(start["header"], json!("Authorization"));
    assert_eq!(start["header_value"], json!(format!("Bearer {PASSWORD}")));

    let status = rpc(daemon.socket(), "status", json!({}));
    assert_eq!(status["result"]["leases"], json!(1));
    // プロキシはブラウザとして数えない。
    assert_eq!(status["result"]["browsers"], json!(0));

    wait_for(
        "api_proxy_request audit record",
        Duration::from_secs(5),
        || has_record(&daemon.audit_records(), "api_proxy_request", &session_id),
    );
    let records = daemon.audit_records();
    let opened = records
        .iter()
        .find(|record| record["method"] == "open_api_proxy")
        .expect("open_api_proxy audit record");
    assert_eq!(opened["target_url"], json!(UPSTREAM));
    assert_eq!(opened["cred_id"], json!("mock:site"));
    assert_eq!(opened["session_id"], json!(session_id));
    assert_eq!(opened["outcome"], json!("ok"));
    let request = records
        .iter()
        .find(|record| record["method"] == "api_proxy_request")
        .expect("api_proxy_request audit record");
    assert_eq!(request["proxy"], json!("fx"));
    assert_eq!(request["http_method"], json!("GET"));
    assert_eq!(request["path"], json!("/api/whoami"));
    assert_eq!(request["status"], json!(200));
    assert_eq!(request["outcome"], json!("ok"));
    assert_eq!(
        request["principal"],
        json!(format!("uid:{}", unsafe { libc::geteuid() }))
    );

    let audit = daemon.audit_text();
    assert!(!audit.contains(PASSWORD));
    assert!(!audit.contains(PATH_SECRET));
}

#[test]
fn logout_stops_the_proxy_without_confusing_event_lines_with_responses() {
    let daemon = Daemon::start(Options::new(PROXY_EXECUTOR));
    let session_id = open(&daemon);

    let logout = rpc(
        daemon.socket(),
        "logout",
        json!({ "session_id": session_id }),
    );
    assert_eq!(logout["result"]["ok"], json!(true));
    // イベント行が応答として照合されると executor は shutdown を受け取る前に停止させられる。
    assert_eq!(
        executor_ops(&daemon),
        ["api_proxy_start", "api_proxy_stop", "shutdown"]
    );
    let status = rpc(daemon.socket(), "status", json!({}));
    assert_eq!(status["result"]["leases"], json!(0));

    wait_for(
        "late api_proxy_request audit",
        Duration::from_secs(5),
        || {
            daemon
                .audit_records()
                .iter()
                .any(|record| record["method"] == "api_proxy_request" && record["status"] == 502)
        },
    );
    let unreachable = daemon
        .audit_records()
        .into_iter()
        .find(|record| record["method"] == "api_proxy_request" && record["status"] == 502)
        .expect("502 audit record");
    assert_eq!(unreachable["outcome"], json!("upstream_unreachable"));
    let again = rpc(
        daemon.socket(),
        "logout",
        json!({ "session_id": session_id }),
    );
    error_message(&again, "NOT_FOUND");
}

#[test]
fn lock_vault_terminates_the_proxy_session() {
    let daemon = Daemon::start(Options::new(PROXY_EXECUTOR));
    let session_id = open(&daemon);

    let locked = rpc(
        daemon.socket(),
        "lock_vault",
        json!({ "namespace": "mock" }),
    );
    assert_eq!(locked["result"]["ok"], json!(true));
    assert_eq!(
        executor_ops(&daemon),
        ["api_proxy_start", "api_proxy_stop", "shutdown"]
    );
    assert!(has_record(
        &daemon.audit_records(),
        "session_terminated",
        &session_id
    ));

    let reopened = rpc(daemon.socket(), "open_api_proxy", json!({ "name": "fx" }));
    error_message(&reopened, "VAULT_LOCKED");
}

#[test]
fn proxy_sessions_expire_with_the_session_ttl() {
    let mut options = Options::new(PROXY_EXECUTOR);
    options.session_ttl_secs = Some(1);
    let daemon = Daemon::start(options);
    let session_id = open(&daemon);

    wait_for(
        "session_expired audit record",
        Duration::from_secs(8),
        || has_record(&daemon.audit_records(), "session_expired", &session_id),
    );
    assert_eq!(
        executor_ops(&daemon),
        ["api_proxy_start", "api_proxy_stop", "shutdown"]
    );
}

#[test]
fn static_proxy_is_stopped_when_the_browser_lifetime_ends() {
    let mut options = Options::new(PROXY_EXECUTOR);
    options.browser_max_lifetime_secs = Some(1);
    let daemon = Daemon::start(options);
    let session_id = open(&daemon);

    wait_for(
        "session_expired audit record",
        Duration::from_secs(8),
        || has_record(&daemon.audit_records(), "session_expired", &session_id),
    );
    assert_eq!(
        executor_ops(&daemon),
        ["api_proxy_start", "api_proxy_stop", "shutdown"]
    );
}

#[test]
fn oauth_proxy_revocation_completes_when_the_browser_lifetime_ends() {
    let mut options = Options::new(SLOW_REVOKING_OAUTH_PROXY_EXECUTOR);
    options.api_proxies =
        oauth_api_proxy_section("fx", UPSTREAM, "https://oauth.example/token", "mock:site");
    options.browser_max_lifetime_secs = Some(1);
    let daemon = Daemon::start(options);
    let session_id = open(&daemon);

    wait_for(
        "session_expired audit record",
        Duration::from_secs(12),
        || has_record(&daemon.audit_records(), "session_expired", &session_id),
    );
    assert_eq!(
        executor_ops(&daemon),
        ["api_proxy_start", "api_proxy_stop", "shutdown"]
    );
    assert!(
        daemon.audit_records().iter().any(|record| {
            record["method"] == "api_proxy_oauth"
                && record["session_id"] == session_id
                && record["oauth_action"] == "revoked"
        }),
        "revocation was cut short: {}",
        daemon.audit_text()
    );
}

#[test]
fn open_api_proxy_audit_names_the_proxy_on_success_and_failure() {
    let daemon = Daemon::start(Options::new(PROXY_EXECUTOR));
    let session_id = open(&daemon);
    wait_for(
        "open_api_proxy audit record",
        Duration::from_secs(5),
        || has_record(&daemon.audit_records(), "open_api_proxy", &session_id),
    );
    let records = daemon.audit_records();
    let opened = records
        .iter()
        .find(|record| record["method"] == "open_api_proxy")
        .expect("open_api_proxy audit record");
    assert_eq!(opened["proxy"], json!("fx"));

    let mut options = Options::new(OAUTH_FAILING_PROXY_EXECUTOR);
    options.api_proxies =
        oauth_api_proxy_section("fx", UPSTREAM, "https://oauth.example/token", "mock:site");
    let failing = Daemon::start(options);
    let response = rpc(failing.socket(), "open_api_proxy", json!({ "name": "fx" }));
    error_message(&response, "OAUTH_GRANT_FAILED");
    wait_for(
        "failed open_api_proxy audit record",
        Duration::from_secs(5),
        || {
            failing.audit_records().iter().any(|record| {
                record["method"] == "open_api_proxy" && record["outcome"] == "OAUTH_GRANT_FAILED"
            })
        },
    );
    let failed = failing
        .audit_records()
        .into_iter()
        .find(|record| record["method"] == "open_api_proxy")
        .expect("failed open_api_proxy audit record");
    assert_eq!(failed["proxy"], json!("fx"));
}

#[test]
fn unknown_proxy_name_is_not_found() {
    let daemon = Daemon::start(Options::new(PROXY_EXECUTOR));
    let response = rpc(daemon.socket(), "open_api_proxy", json!({ "name": "nope" }));
    error_message(&response, "NOT_FOUND");
    assert!(executor_ops(&daemon).is_empty());
}

#[test]
fn executor_start_failure_is_internal_and_leaves_no_lease() {
    let daemon = Daemon::start(Options::new(FAILING_PROXY_EXECUTOR));
    let response = rpc(daemon.socket(), "open_api_proxy", json!({ "name": "fx" }));
    error_message(&response, "INTERNAL");
    let status = rpc(daemon.socket(), "status", json!({}));
    assert_eq!(status["result"]["leases"], json!(0));
}

#[test]
fn oauth_api_proxy_sends_oauth_wire_and_audits_token_events() {
    let mut options = Options::new(OAUTH_PROXY_EXECUTOR);
    options.api_proxies =
        oauth_api_proxy_section("fx", UPSTREAM, "https://oauth.example/token", "mock:site");
    let daemon = Daemon::start(options);
    let response = rpc(daemon.socket(), "open_api_proxy", json!({ "name": "fx" }));
    let session_id = response["result"]["session_id"]
        .as_str()
        .expect("session_id")
        .to_owned();

    let start = daemon
        .executor_log()
        .into_iter()
        .find(|request| request["op"] == "api_proxy_start")
        .expect("api_proxy_start request");
    assert!(start.get("header_value").is_none());
    assert_eq!(start["value_template"], json!("Bearer {{secret}}"));
    assert_eq!(start["oauth"]["client_id"], json!("oauth-client"));
    assert_eq!(
        start["oauth"]["device_authorization_url"],
        json!("https://oauth.example/device")
    );
    assert_eq!(
        start["oauth"]["token_url"],
        json!("https://oauth.example/token")
    );
    assert_eq!(start["oauth"]["login_url"], json!("http://127.0.0.1"));
    assert_eq!(start["oauth"]["secret"]["username"], json!(USERNAME));
    assert_eq!(start["oauth"]["secret"]["password"], json!(PASSWORD));
    assert!(start["oauth"]["secret"]["totp"].is_null());
    assert!(start["oauth"]["revocation_url"].is_null());
    assert!(start["oauth"]["scope"].is_null());
    assert!(start["oauth"]["steps"].is_null());
    assert!(start["oauth"]["failure_selector"].is_null());

    wait_for("issued oauth audit record", Duration::from_secs(5), || {
        daemon.audit_records().iter().any(|record| {
            record["method"] == "api_proxy_oauth"
                && record["session_id"] == session_id
                && record["oauth_action"] == "issued"
        })
    });
    let logout = rpc(
        daemon.socket(),
        "logout",
        json!({ "session_id": session_id }),
    );
    assert_eq!(logout["result"]["ok"], json!(true));
    wait_for("revoked oauth audit record", Duration::from_secs(5), || {
        daemon.audit_records().iter().any(|record| {
            record["method"] == "api_proxy_oauth"
                && record["oauth_action"] == "revoked"
                && record["principal"] == format!("uid:{}", unsafe { libc::geteuid() })
        })
    });
}

#[test]
fn oauth_api_proxy_propagates_grant_failure_and_keeps_no_lease() {
    let mut options = Options::new(OAUTH_FAILING_PROXY_EXECUTOR);
    options.api_proxies =
        oauth_api_proxy_section("fx", UPSTREAM, "https://oauth.example/token", "mock:site");
    let daemon = Daemon::start(options);
    let response = rpc(daemon.socket(), "open_api_proxy", json!({ "name": "fx" }));
    error_message(&response, "OAUTH_GRANT_FAILED");
    let status = rpc(daemon.socket(), "status", json!({}));
    assert_eq!(status["result"]["leases"], json!(0));
}

#[test]
fn audit_redacts_secret_shaped_segments_and_truncates_long_paths() {
    let daemon = Daemon::start(Options::new(PATH_EVENT_EXECUTOR));
    let response = rpc(daemon.socket(), "open_api_proxy", json!({ "name": "fx" }));
    assert!(response.get("result").is_some(), "{response}");

    wait_for(
        "two api_proxy_request records",
        Duration::from_secs(5),
        || {
            daemon
                .audit_records()
                .iter()
                .filter(|record| record["method"] == "api_proxy_request")
                .count()
                == 2
        },
    );
    let records = daemon.audit_records();
    let requests = records
        .iter()
        .filter(|record| record["method"] == "api_proxy_request")
        .collect::<Vec<_>>();
    assert_eq!(requests[0]["path"], json!("/[redacted]/api/whoami"));
    assert_eq!(requests[0]["outcome"], json!("upstream_error"));
    let long_path = requests[1]["path"].as_str().expect("path");
    assert_eq!(long_path.len(), 512);
    assert_eq!(requests[1]["outcome"], json!("ok"));
    assert!(!daemon.audit_text().contains("Ax7fQ2mN9pL3kR8sT1vW0y"));
}

#[test]
fn repeated_opens_are_rate_limited_per_proxy() {
    let daemon = Daemon::start(Options::new(PROXY_EXECUTOR));
    for _ in 0..3 {
        open(&daemon);
    }
    let limited = rpc(daemon.socket(), "open_api_proxy", json!({ "name": "fx" }));
    error_message(&limited, "RATE_LIMITED");
    assert_eq!(
        executor_ops(&daemon)
            .iter()
            .filter(|op| op.as_str() == "api_proxy_start")
            .count(),
        3
    );
}

#[test]
fn failed_starts_back_off() {
    let daemon = Daemon::start(Options::new(FAILING_PROXY_EXECUTOR));
    let first = rpc(daemon.socket(), "open_api_proxy", json!({ "name": "fx" }));
    error_message(&first, "INTERNAL");
    let second = rpc(daemon.socket(), "open_api_proxy", json!({ "name": "fx" }));
    error_message(&second, "RATE_LIMITED");
}

#[test]
fn approve_cmd_receives_the_upstream_and_can_deny() {
    let env_directory =
        std::env::temp_dir().join(format!("tegatad-api-proxy-env-{}", Uuid::new_v4()));
    std::fs::create_dir(&env_directory).expect("create env directory");
    let env_path = env_directory.join("approve.env");
    let mut options = Options::new(PROXY_EXECUTOR);
    options.approve_cmd = Some(format!("env > {}; exit 1", env_path.display()));
    let daemon = Daemon::start(options);

    let response = rpc(daemon.socket(), "open_api_proxy", json!({ "name": "fx" }));
    error_message(&response, "APPROVAL_DENIED");
    let env = std::fs::read_to_string(&env_path).expect("read approve env");
    let _ = std::fs::remove_dir_all(&env_directory);
    assert!(env.contains("TEGATA_METHOD=open_api_proxy"));
    assert!(env.contains(&format!("TEGATA_TARGET_URL={UPSTREAM}")));
    assert!(env.contains("TEGATA_CRED_ID=mock:site"));
    assert!(env.contains(&format!("TEGATA_PEER={}", unsafe { libc::geteuid() })));
    assert!(!env.contains(PASSWORD));
    assert!(executor_ops(&daemon).is_empty());
}

/// 設定を与えてデーモンを起動し、終了コードと stderr を返す。起動し続けた場合は None を返す。
fn run_until_exit(api_proxies: String) -> Option<(i32, String)> {
    let mut options = Options::new(PROXY_EXECUTOR);
    options.api_proxies = api_proxies;
    let layout = Layout::create(&options);
    let mut child = layout.spawn(Stdio::piped());
    let deadline = Instant::now() + Duration::from_secs(5);
    let result = loop {
        if let Some(status) = child.try_wait().expect("poll tegatad") {
            let mut stderr = String::new();
            std::io::Read::read_to_string(child.stderr.as_mut().expect("stderr pipe"), &mut stderr)
                .expect("read stderr");
            break Some((status.code().unwrap_or(-1), stderr));
        }
        if layout.socket_path.exists() || Instant::now() >= deadline {
            let _ = child.kill();
            let _ = child.wait();
            break None;
        }
        sleep(Duration::from_millis(20));
    };
    let _ = std::fs::remove_dir_all(&layout.directory);
    result
}

#[test]
fn invalid_api_proxy_configs_refuse_startup() {
    let cases = [
        (
            api_proxy_section("external", "http://example.com", None),
            "upstream",
        ),
        (
            api_proxy_section("spoof", "http://127.0.0.1@example.com", None),
            "upstream",
        ),
        (
            api_proxy_section("backslash", "http://example.com\\@127.0.0.1", None),
            "upstream",
        ),
        (
            api_proxy_section("ftp", "ftp://127.0.0.1", None),
            "upstream",
        ),
        (
            format!(
                "{}{}",
                api_proxy_section("dup", UPSTREAM, None),
                api_proxy_section("dup", "https://api.example.com", None)
            ),
            "more than once",
        ),
        (
            api_proxy_section("novalue", UPSTREAM, Some("Bearer static")),
            "{{secret}}",
        ),
        (
            api_proxy_section("", UPSTREAM, None),
            "name must not be empty",
        ),
        (
            api_proxy_section("nocolon", UPSTREAM, None).replace("mock:site", "mocksite"),
            "cred_id",
        ),
        (
            oauth_api_proxy_section(
                "external-token",
                UPSTREAM,
                "http://example.com/token",
                "mock:site",
            ),
            "token_url",
        ),
        (
            oauth_api_proxy_section(
                "bad-login-cred",
                UPSTREAM,
                "https://oauth.example/token",
                "mocksite",
            ),
            "login_cred_id",
        ),
        (
            api_proxy_section("no-cred", UPSTREAM, None).replace("cred_id = \"mock:site\"\n", ""),
            "exactly one of cred_id or oauth",
        ),
        (
            oauth_api_proxy_section(
                "both-credentials",
                UPSTREAM,
                "https://oauth.example/token",
                "mock:site",
            )
            .replace(
                "\nupstream = \"http://127.0.0.1:9\"",
                "\ncred_id = \"mock:site\"\nupstream = \"http://127.0.0.1:9\"",
            ),
            "mutually exclusive",
        ),
    ];
    for (section, reason) in cases {
        let (code, stderr) = run_until_exit(section.clone())
            .unwrap_or_else(|| panic!("daemon kept running: {section}"));
        assert_ne!(code, 0, "{section}");
        assert!(stderr.contains(reason), "{section}: {stderr}");
    }
}

#[test]
fn allowed_upstreams_are_accepted() {
    let proxies = [
        api_proxy_section("a", "https://api.example.com", None),
        api_proxy_section("b", "http://localhost:8080/v1", None),
        api_proxy_section("c", "http://[::1]:8080", None),
        api_proxy_section("d", "HTTP://127.0.0.1", Some("token {{secret}}")),
    ]
    .concat();
    let mut options = Options::new(PROXY_EXECUTOR);
    options.api_proxies = proxies;
    let daemon = Daemon::start(options);
    let response = rpc(daemon.socket(), "status", json!({}));
    assert_eq!(response["result"]["ok"], json!(true));
}
