//! stdio MCP サーバーの起動（`[[mcp_server]]` と `open_mcp_server`）のデーモン側を、偽 executor で検証する。
//! UNIX ドメインソケット経由で RPC を送るため、UNIX でのみ実行する。
#![cfg(unix)]

use std::path::PathBuf;
use std::process::{Child, Command, Stdio};
use std::thread::sleep;
use std::time::{Duration, Instant};

use serde_json::{Value, json};
use uuid::Uuid;

mod common;
use common::{create_private_dir, rpc, try_rpc};

const USERNAME: &str = "mcp-server-user-secret";
const PASSWORD: &str = "mcp-server-password-secret";
const TOTP_SEED: &str = "JBSWY3DPEHPK3PXP";
const COMMAND: &str = "/opt/fake/bin/fake-mcp-server";
const RELAY_PORT: u16 = 38999;
const STREAM_SECRET: &str = "fake-stream-secret_A1";

/// 受けた要求を `executor.js.log` に 1 行ずつ記録する偽 executor の雛形。
/// `__AFTER_START__` は開始応答の直後に実行する処理に置き換える。停止・終了の応答の直前には
/// id を持たないイベント行を書き、デーモンがイベント行を応答と取り違えないことを確かめられるようにする。
/// stdin が閉じても待機を続けるが、親のデーモンが消えたら終了する（テストの後始末で孤児を残さないため、#47）。
const MCP_EXECUTOR_TEMPLATE: &str = r#"
const fs = require("node:fs");
const readline = require("node:readline");
const parent = process.ppid;
const log = (value) => fs.appendFileSync(__filename + ".log", JSON.stringify(value) + "\n");
const event = (action, extra) =>
  process.stdout.write(JSON.stringify({ event: "mcp_server", action, ...extra }) + "\n");
const rl = readline.createInterface({ input: process.stdin });
rl.on("line", (line) => {
  const request = JSON.parse(line);
  log(request);
  if (request.op === "mcp_server_start") {
    process.stdout.write(JSON.stringify({ id: request.id, ok: true, port: 38999, stream_secret: "fake-stream-secret_A1" }) + "\n");
    __AFTER_START__
  } else if (request.op === "mcp_server_stop") {
    event("unknown_action", {});
    process.stdout.write(JSON.stringify({ id: request.id, ok: true }) + "\n");
  } else if (request.op === "shutdown") {
    process.stdout.write(JSON.stringify({ id: request.id, ok: true }) + "\n");
    process.exit(0);
  }
});
rl.on("close", () => { setInterval(() => { if (process.ppid !== parent) process.exit(0); }, 200); });
"#;

/// 開始要求を失敗させる偽 executor。
const FAILING_MCP_EXECUTOR: &str = r#"
const readline = require("node:readline");
const rl = readline.createInterface({ input: process.stdin });
rl.on("line", (line) => {
  const request = JSON.parse(line);
  if (request.op === "mcp_server_start") {
    process.stdout.write(JSON.stringify({ id: request.id, ok: false, error: "INTERNAL" }) + "\n");
  } else {
    process.stdout.write(JSON.stringify({ id: request.id, ok: true }) + "\n");
    if (request.op === "shutdown") process.exit(0);
  }
});
"#;

/// 開始後に接続の成立だけを知らせる偽 executor の本文を返す。
fn connecting_executor() -> String {
    MCP_EXECUTOR_TEMPLATE.replace("__AFTER_START__", r#"event("connected", {});"#)
}

/// 開始後に接続の成立を知らせ、少し後にサーバーの自発的な終了を知らせる偽 executor の本文を返す。
fn exiting_executor() -> String {
    MCP_EXECUTOR_TEMPLATE.replace(
        "__AFTER_START__",
        r#"event("connected", {}); setTimeout(() => event("exit", { exit_code: 3 }), 300);"#,
    )
}

/// 開始後に接続の成立を知らせ、少し後に行検査での漏洩の検出を知らせる偽 executor の本文を返す。
fn leaking_executor() -> String {
    MCP_EXECUTOR_TEMPLATE.replace(
        "__AFTER_START__",
        r#"event("connected", {}); setTimeout(() => event("leak", {}), 300);"#,
    )
}

struct Options {
    executor: String,
    mcp_servers: String,
    session_ttl_secs: Option<u64>,
    browser_max_lifetime_secs: Option<u64>,
    approve_cmd: Option<String>,
}

impl Options {
    fn new(executor: String) -> Self {
        Self {
            executor,
            mcp_servers: mcp_server_section("fx", COMMAND, "TOKEN = \"{{secret}}\"\n"),
            session_ttl_secs: None,
            browser_max_lifetime_secs: None,
            approve_cmd: None,
        }
    }
}

/// `[[mcp_server]]` の 1 項目を作る。`env` は `[mcp_server.env]` の本文である（空なら表を省く）。
fn mcp_server_section(name: &str, command: &str, env: &str) -> String {
    let env = if env.is_empty() {
        String::new()
    } else {
        format!("[mcp_server.env]\n{env}")
    };
    format!(
        "\n[[mcp_server]]\nname = {name:?}\ncred_id = \"mock:site\"\ncommand = {command:?}\nargs = [\"--stdio\", \"--verbose\"]\n{env}"
    )
}

struct Layout {
    directory: PathBuf,
    socket_path: PathBuf,
    config_path: PathBuf,
}

impl Layout {
    fn create(options: &Options) -> Self {
        let directory = std::env::temp_dir().join(format!("tegatad-mcp-server-{}", Uuid::new_v4()));
        std::fs::create_dir(&directory).expect("create test directory");
        let state_dir = directory.join("state");
        create_private_dir(&state_dir);
        let socket_path = directory.join("tegatad.sock");
        let config_path = directory.join("config.toml");
        let executor_path = directory.join("executor.js");
        std::fs::write(&executor_path, &options.executor).expect("write executor script");
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
            "{top}\n[[providers]]\nnamespace = \"mock\"\ntype = \"mock\"\n\n[[providers.entries]]\nid = \"site\"\nname = \"MCP Server Site\"\nuri = \"http://127.0.0.1\"\nkind = \"login\"\nusername = {USERNAME:?}\npassword = {PASSWORD:?}\ntotp_seed = {TOTP_SEED:?}\n{}",
            options.mcp_servers,
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
    fn start(options: Options) -> Self {
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
        std::fs::read_to_string(self.layout.directory.join("executor.js.log"))
            .unwrap_or_default()
            .lines()
            .map(|line| serde_json::from_str(line).expect("parse executor log"))
            .collect()
    }
}

impl Drop for Daemon {
    fn drop(&mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
        let _ = std::fs::remove_dir_all(&self.layout.directory);
    }
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
    let response = rpc(daemon.socket(), "open_mcp_server", json!({ "name": "fx" }));
    assert_eq!(
        response["result"]["port"],
        json!(RELAY_PORT),
        "unexpected response: {response}"
    );
    assert_eq!(response["result"]["stream_secret"], json!(STREAM_SECRET));
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

fn find_record(daemon: &Daemon, method: &str, action: &str) -> Value {
    daemon
        .audit_records()
        .into_iter()
        .find(|record| record["method"] == method && record["mcp_action"] == action)
        .unwrap_or_else(|| panic!("{method} {action} audit record: {}", daemon.audit_text()))
}

#[test]
fn open_mcp_server_sends_rendered_env_and_scan_and_audits_the_session() {
    let mut options = Options::new(connecting_executor());
    options.mcp_servers = mcp_server_section(
        "fx",
        COMMAND,
        "TOKEN = \"{{secret}}\"\nAUTH = \"Bearer {{secret}}\"\nUSER = \"{{username}}\"\nCODE = \"{{totp}}\"\nPLAIN = \"literal-value\"\nEMPTY = \"\"\n",
    );
    let daemon = Daemon::start(options);
    let session_id = open(&daemon);

    let start = daemon
        .executor_log()
        .into_iter()
        .find(|request| request["op"] == "mcp_server_start")
        .expect("mcp_server_start request");
    assert_eq!(start["id"], json!(1));
    assert_eq!(start["command"], json!(COMMAND));
    assert_eq!(start["args"], json!(["--stdio", "--verbose"]));
    let env = start["env"].as_object().expect("env object");
    assert_eq!(env["TOKEN"], json!(PASSWORD));
    assert_eq!(env["AUTH"], json!(format!("Bearer {PASSWORD}")));
    assert_eq!(env["USER"], json!(USERNAME));
    assert_eq!(env["PLAIN"], json!("literal-value"));
    assert_eq!(env["EMPTY"], json!(""));
    let code = env["CODE"].as_str().expect("totp value").to_owned();
    assert_eq!(code.len(), 6, "{code}");
    assert!(code.chars().all(|character| character.is_ascii_digit()));
    assert_eq!(env.len(), 6);
    let mut scan = start["scan"]
        .as_array()
        .expect("scan array")
        .iter()
        .map(|value| value.as_str().expect("scan string").to_owned())
        .collect::<Vec<_>>();
    scan.sort();
    // `{{username}}` のみを含む USER は漏洩検査の対象に入らない。
    let mut expected = vec![PASSWORD.to_owned(), format!("Bearer {PASSWORD}"), code];
    expected.sort();
    assert_eq!(scan, expected);

    let status = rpc(daemon.socket(), "status", json!({}));
    assert_eq!(status["result"]["leases"], json!(1));
    // MCP サーバーはブラウザとして数えない。
    assert_eq!(status["result"]["browsers"], json!(0));

    wait_for(
        "mcp_server connected audit record",
        Duration::from_secs(5),
        || has_record(&daemon.audit_records(), "mcp_server", &session_id),
    );
    let records = daemon.audit_records();
    let opened = records
        .iter()
        .find(|record| record["method"] == "open_mcp_server")
        .expect("open_mcp_server audit record");
    assert_eq!(opened["target_url"], json!("mcp:fx"));
    assert_eq!(opened["mcp_server"], json!("fx"));
    assert_eq!(opened["cred_id"], json!("mock:site"));
    assert_eq!(opened["namespace"], json!("mock"));
    assert_eq!(opened["session_id"], json!(session_id));
    assert_eq!(opened["outcome"], json!("ok"));
    let connected = find_record(&daemon, "mcp_server", "connected");
    assert_eq!(connected["session_id"], json!(session_id));
    assert_eq!(connected["mcp_server"], json!("fx"));
    assert_eq!(connected["cred_id"], json!("mock:site"));
    assert_eq!(connected["outcome"], json!("ok"));
    assert!(connected.get("exit_code").is_none());
    assert!(connected.get("proxy").is_none());
    assert_eq!(
        connected["principal"],
        json!(format!("uid:{}", unsafe { libc::geteuid() }))
    );

    let audit = daemon.audit_text();
    assert!(!audit.contains(PASSWORD));
    assert!(!audit.contains(USERNAME));
    assert!(!audit.contains(STREAM_SECRET));
}

/// `mcp_server_start` の `scan` を文字列の列として取り出す。
fn start_scan(daemon: &Daemon) -> Vec<String> {
    daemon
        .executor_log()
        .into_iter()
        .find(|request| request["op"] == "mcp_server_start")
        .expect("mcp_server_start request")["scan"]
        .as_array()
        .expect("scan array")
        .iter()
        .map(|value| value.as_str().expect("scan string").to_owned())
        .collect()
}

#[test]
fn username_only_env_values_are_not_scanned_but_values_with_the_secret_are() {
    let mut options = Options::new(connecting_executor());
    options.mcp_servers = mcp_server_section(
        "fx",
        COMMAND,
        "USER = \"{{username}}\"\nGREETING = \"hello {{username}}\"\nBASIC = \"{{username}}:{{secret}}\"\n",
    );
    let daemon = Daemon::start(options);
    open(&daemon);

    let scan = start_scan(&daemon);
    assert!(!scan.contains(&USERNAME.to_owned()), "{scan:?}");
    assert!(!scan.contains(&format!("hello {USERNAME}")), "{scan:?}");
    assert!(scan.contains(&format!("{USERNAME}:{PASSWORD}")), "{scan:?}");
    assert!(scan.contains(&PASSWORD.to_owned()), "{scan:?}");
    assert_eq!(scan.len(), 2, "{scan:?}");
}

#[test]
fn logout_stops_the_server_without_confusing_event_lines_with_responses() {
    let daemon = Daemon::start(Options::new(connecting_executor()));
    let session_id = open(&daemon);

    let logout = rpc(
        daemon.socket(),
        "logout",
        json!({ "session_id": session_id }),
    );
    assert_eq!(logout["result"]["ok"], json!(true));
    assert_eq!(
        executor_ops(&daemon),
        ["mcp_server_start", "mcp_server_stop", "shutdown"]
    );
    let status = rpc(daemon.socket(), "status", json!({}));
    assert_eq!(status["result"]["leases"], json!(0));
    let again = rpc(
        daemon.socket(),
        "logout",
        json!({ "session_id": session_id }),
    );
    error_message(&again, "NOT_FOUND");
}

#[test]
fn exit_event_ends_the_lease_and_is_audited() {
    let daemon = Daemon::start(Options::new(exiting_executor()));
    let session_id = open(&daemon);

    wait_for(
        "mcp_server_exit audit record",
        Duration::from_secs(8),
        || has_record(&daemon.audit_records(), "mcp_server_exit", &session_id),
    );
    let exit = find_record(&daemon, "mcp_server", "exit");
    assert_eq!(exit["session_id"], json!(session_id));
    assert_eq!(exit["mcp_server"], json!("fx"));
    assert_eq!(exit["exit_code"], json!(3));
    assert_eq!(exit["outcome"], json!("ok"));
    assert_eq!(
        executor_ops(&daemon),
        ["mcp_server_start", "mcp_server_stop", "shutdown"]
    );
    let status = rpc(daemon.socket(), "status", json!({}));
    assert_eq!(status["result"]["leases"], json!(0));
    let logout = rpc(
        daemon.socket(),
        "logout",
        json!({ "session_id": session_id }),
    );
    error_message(&logout, "NOT_FOUND");
}

#[test]
fn leak_event_ends_the_lease_and_is_audited() {
    let daemon = Daemon::start(Options::new(leaking_executor()));
    let session_id = open(&daemon);

    wait_for(
        "mcp_server_leak audit record",
        Duration::from_secs(8),
        || has_record(&daemon.audit_records(), "mcp_server_leak", &session_id),
    );
    let leak = find_record(&daemon, "mcp_server", "leak");
    assert_eq!(leak["session_id"], json!(session_id));
    assert_eq!(leak["mcp_server"], json!("fx"));
    assert_eq!(leak["outcome"], json!("leak"));
    assert!(leak.get("exit_code").is_none());
    assert_eq!(
        executor_ops(&daemon),
        ["mcp_server_start", "mcp_server_stop", "shutdown"]
    );
    let status = rpc(daemon.socket(), "status", json!({}));
    assert_eq!(status["result"]["leases"], json!(0));
    assert!(!daemon.audit_text().contains(PASSWORD));
}

#[test]
fn server_is_stopped_when_the_browser_lifetime_ends() {
    let mut options = Options::new(connecting_executor());
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
        ["mcp_server_start", "mcp_server_stop", "shutdown"]
    );
}

#[test]
fn server_sessions_expire_with_the_session_ttl() {
    let mut options = Options::new(connecting_executor());
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
        ["mcp_server_start", "mcp_server_stop", "shutdown"]
    );
}

#[test]
fn lock_vault_terminates_the_server_session() {
    let daemon = Daemon::start(Options::new(connecting_executor()));
    let session_id = open(&daemon);

    let locked = rpc(
        daemon.socket(),
        "lock_vault",
        json!({ "namespace": "mock" }),
    );
    assert_eq!(locked["result"]["ok"], json!(true));
    assert_eq!(
        executor_ops(&daemon),
        ["mcp_server_start", "mcp_server_stop", "shutdown"]
    );
    assert!(has_record(
        &daemon.audit_records(),
        "session_terminated",
        &session_id
    ));
    let reopened = rpc(daemon.socket(), "open_mcp_server", json!({ "name": "fx" }));
    error_message(&reopened, "VAULT_LOCKED");
}

#[test]
fn unknown_server_name_is_not_found() {
    let daemon = Daemon::start(Options::new(connecting_executor()));
    let response = rpc(
        daemon.socket(),
        "open_mcp_server",
        json!({ "name": "nope" }),
    );
    error_message(&response, "NOT_FOUND");
    assert!(executor_ops(&daemon).is_empty());
}

#[test]
fn failed_starts_are_internal_leave_no_lease_and_back_off() {
    let daemon = Daemon::start(Options::new(FAILING_MCP_EXECUTOR.to_owned()));
    let first = rpc(daemon.socket(), "open_mcp_server", json!({ "name": "fx" }));
    error_message(&first, "INTERNAL");
    let status = rpc(daemon.socket(), "status", json!({}));
    assert_eq!(status["result"]["leases"], json!(0));
    let second = rpc(daemon.socket(), "open_mcp_server", json!({ "name": "fx" }));
    error_message(&second, "RATE_LIMITED");
    let failed = daemon
        .audit_records()
        .into_iter()
        .find(|record| record["method"] == "open_mcp_server" && record["outcome"] == "INTERNAL")
        .expect("failed open_mcp_server audit record");
    assert_eq!(failed["mcp_server"], json!("fx"));
    assert_eq!(failed["target_url"], json!("mcp:fx"));
}

#[test]
fn approve_cmd_receives_the_server_target_and_can_deny() {
    let env_directory =
        std::env::temp_dir().join(format!("tegatad-mcp-server-env-{}", Uuid::new_v4()));
    std::fs::create_dir(&env_directory).expect("create env directory");
    let env_path = env_directory.join("approve.env");
    let mut options = Options::new(connecting_executor());
    options.approve_cmd = Some(format!("env > {}; exit 1", env_path.display()));
    let daemon = Daemon::start(options);

    let response = rpc(daemon.socket(), "open_mcp_server", json!({ "name": "fx" }));
    error_message(&response, "APPROVAL_DENIED");
    let env = std::fs::read_to_string(&env_path).expect("read approve env");
    let _ = std::fs::remove_dir_all(&env_directory);
    assert!(env.contains("TEGATA_METHOD=open_mcp_server"));
    assert!(env.contains("TEGATA_TARGET_URL=mcp:fx"));
    assert!(env.contains("TEGATA_CRED_ID=mock:site"));
    assert!(!env.contains(PASSWORD));
    assert!(executor_ops(&daemon).is_empty());
}

/// 設定を与えてデーモンを起動し、終了コードと stderr を返す。起動し続けた場合は None を返す。
fn run_until_exit(mcp_servers: String) -> Option<(i32, String)> {
    let mut options = Options::new(connecting_executor());
    options.mcp_servers = mcp_servers;
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
fn invalid_mcp_server_configs_refuse_startup() {
    let secret_env = "TOKEN = \"{{secret}}\"\n";
    let cases = [
        (
            format!(
                "{}{}",
                mcp_server_section("dup", COMMAND, secret_env),
                mcp_server_section("dup", "/usr/bin/other", secret_env)
            ),
            "more than once",
        ),
        (
            mcp_server_section("", COMMAND, secret_env),
            "name must not be empty",
        ),
        (
            mcp_server_section("relative", "node", secret_env),
            "absolute path",
        ),
        (
            mcp_server_section("dot-relative", "./bin/server", secret_env),
            "absolute path",
        ),
        (
            mcp_server_section("literal", COMMAND, "TOKEN = \"static\"\n"),
            "{{secret}}",
        ),
        (mcp_server_section("no-env", COMMAND, ""), "{{secret}}"),
        (
            mcp_server_section("nocolon", COMMAND, secret_env).replace("mock:site", "mocksite"),
            "cred_id",
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
fn every_placeholder_is_accepted_and_names_may_repeat_an_api_proxy() {
    let servers = [
        mcp_server_section("secret", COMMAND, "A = \"{{secret}}\"\n"),
        mcp_server_section("username", COMMAND, "A = \"{{username}}\"\n"),
        mcp_server_section("totp", COMMAND, "A = \"literal\"\nB = \"{{totp}}\"\n"),
        "\n[[api_proxy]]\nname = \"secret\"\ncred_id = \"mock:site\"\nupstream = \"https://api.example.com\"\n"
            .to_owned(),
    ]
    .concat();
    let mut options = Options::new(connecting_executor());
    options.mcp_servers = servers;
    let daemon = Daemon::start(options);
    let response = rpc(daemon.socket(), "status", json!({}));
    assert_eq!(response["result"]["ok"], json!(true));
}
