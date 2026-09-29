//! 段階ログイン（Issue #46）のデーモン側の振る舞いを、偽の executor で確かめる。
//! ブラウザを使わないため、executor とのプロトコル・台帳・期限・レート制限・監査を直接検証する。
//! UNIX ドメインソケット経由で RPC を送るため、UNIX でのみ実行する。
#![cfg(unix)]

use std::io::{BufRead, BufReader, Write};
use std::path::PathBuf;
use std::process::{Child, Command, Stdio};
use std::thread::sleep;
use std::time::{Duration, Instant};

use serde_json::{Value, json};
use uuid::Uuid;

mod common;
use common::{create_private_dir, rpc, try_rpc};

/// 段階ログインに応じる偽の executor。submit・click の selector で応答を切り替える。
/// `#verify` はハンドオフ、`#missing` は SELECTOR_NOT_FOUND、`#reject` は SNAPSHOT_REJECTED、
/// `#mismatch` は FILL_MISMATCH、`#vanish` は応答せずに切断する。`#echo-user` は username を
/// マスクせずに含むスナップショットを返す（executor の検査をすり抜けた場合の模擬）。
/// 受け取った要求の op・action・totp・secret のキー・cookies の数を `executor.js.requests` に記録する。
/// stdin が閉じられたら必ず終了する。
const STEPWISE_EXECUTOR: &str = r##"
const fs = require("node:fs");
const readline = require("node:readline");
const log = __filename + ".requests";
const endpoint = "ws://127.0.0.1:38999/devtools/browser/test";
const jar = [{ name: "device", value: "device-canary", domain: "127.0.0.1", path: "/", expires: Date.now() / 1000 + 86400.5, httpOnly: true, secure: false, sameSite: "Lax" }];
const snapshot = (page) => ({ url: "http://127.0.0.1/" + page, title: page, text: "Signed in as [username]", elements: [{ tag: "button", text: "Next", selector: "#next" }], settled: true });
const reply = (id, body) => process.stdout.write(JSON.stringify({ id, ...body }) + "\n");
let username = "";
const step = (request) => {
  const target = request.selector ?? (request.submit ? request.submit.click ?? request.submit.press_enter : undefined);
  if (request.action === "abort") return reply(request.id, { ok: true, state: "aborted" });
  if (target === "#missing") return reply(request.id, { ok: false, error: "SELECTOR_NOT_FOUND", step: 0 });
  if (target === "#reject") return reply(request.id, { ok: false, error: "SNAPSHOT_REJECTED" });
  if (target === "#mismatch") return reply(request.id, { ok: false, error: "FILL_MISMATCH", step: 1 });
  if (target === "#vanish") process.exit(0);
  if (target === "#echo-user") return reply(request.id, { ok: true, state: "pending", snapshot: { ...snapshot("echo"), text: "Signed in as " + username } });
  if (target === "#verify") return reply(request.id, { ok: true, state: "done", endpoint, target_id: "step-target", cookies: jar, steps_skipped: false });
  reply(request.id, { ok: true, state: "pending", snapshot: snapshot(request.action) });
};
const rl = readline.createInterface({ input: process.stdin });
rl.on("close", () => process.exit(0));
rl.on("line", (line) => {
  const request = JSON.parse(line);
  fs.appendFileSync(log, JSON.stringify({
    op: request.op,
    pid: process.pid,
    action: request.action,
    totp: request.totp,
    secret: request.secret ? Object.keys(request.secret).sort() : undefined,
    cookies: request.cookies === undefined ? "absent" : request.cookies === null ? null : request.cookies.length,
  }) + "\n");
  if (request.op === "login_begin") {
    username = request.secret.username;
    if (Array.isArray(request.cookies)) {
      reply(request.id, { ok: true, state: "done", endpoint, target_id: "begin-target", cookies: jar, steps_skipped: true });
    } else {
      reply(request.id, { ok: true, state: "pending", snapshot: snapshot("start") });
    }
  } else if (request.op === "login_step") {
    step(request);
  } else if (request.op === "login") {
    reply(request.id, { ok: true, endpoint, target_id: "login-target" });
  } else if (request.op === "export_cookies") {
    reply(request.id, { ok: true, cookies: jar });
  } else if (request.op === "lease") {
    reply(request.id, { ok: true, target_id: "lease-target" });
  } else if (request.op === "release") {
    reply(request.id, { ok: true });
  } else if (request.op === "shutdown") {
    reply(request.id, { ok: true });
    process.exit(0);
  }
});
"##;

const USERNAME: &str = "stepwise-test-username-secret";
const PASSWORD: &str = "stepwise-test-password-secret";
const TOTP_SEED: &str = "JBSWY3DPEHPK3PXP";

struct Daemon {
    child: Child,
    directory: PathBuf,
    state_dir: PathBuf,
    socket_path: PathBuf,
    tcp_port: u16,
}

impl Daemon {
    fn start() -> Self {
        Self::start_with("", &[])
    }

    fn start_with(extra_config: &str, persist_cookies: &[&str]) -> Self {
        let directory = std::env::temp_dir().join(format!("tegatad-stepwise-{}", Uuid::new_v4()));
        std::fs::create_dir(&directory).expect("create test directory");
        let state_dir = directory.join("state");
        create_private_dir(&state_dir);
        let executor = directory.join("executor.js");
        std::fs::write(&executor, STEPWISE_EXECUTOR).expect("write executor script");
        let tcp_listener = std::net::TcpListener::bind(("127.0.0.1", 0)).expect("reserve TCP port");
        let tcp_port = tcp_listener.local_addr().expect("read TCP port").port();
        drop(tcp_listener);
        let socket_path = directory.join("tegatad.sock");
        let uid = unsafe { libc::geteuid() };
        let config = format!(
            "state_dir = {state_dir:?}\naudit_log_path = {audit:?}\nexecutor_entry = {executor:?}\n{extra_config}\n[[listen]]\nkind = \"unix\"\npath = {socket_path:?}\nallowed_uids = [{uid}]\noperator_uids = [{uid}]\n\n[[listen]]\nkind = \"tcp\"\nbind = \"127.0.0.1\"\nport = {tcp_port}\n\n[[providers]]\nnamespace = \"mock\"\ntype = \"mock\"\npersist_cookies = {persist}\n\n[[providers.entries]]\nid = \"site\"\nname = \"Stepwise\"\nuri = \"http://127.0.0.1\"\nkind = \"login\"\nusername = {USERNAME:?}\npassword = {PASSWORD:?}\ntotp_seed = {TOTP_SEED:?}\n",
            audit = state_dir.join("audit.log"),
            persist = serde_json::to_string(persist_cookies).expect("render persist_cookies"),
        );
        let config_path = directory.join("config.toml");
        std::fs::write(&config_path, config).expect("write test config");
        let stderr =
            std::fs::File::create(directory.join("stderr.log")).expect("create stderr log");
        let child = Command::new(env!("CARGO_BIN_EXE_tegatad"))
            .arg("--config")
            .arg(config_path)
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(Stdio::from(stderr))
            .spawn()
            .expect("spawn tegatad");
        let daemon = Self {
            child,
            directory,
            state_dir,
            socket_path,
            tcp_port,
        };
        let deadline = Instant::now() + Duration::from_secs(5);
        while Instant::now() < deadline {
            if try_rpc(&daemon.socket_path, "status", json!({}))
                .and_then(|response| response.get("result").cloned())
                .is_some()
            {
                return daemon;
            }
            sleep(Duration::from_millis(20));
        }
        panic!("tegatad did not become ready: {}", daemon.stderr());
    }

    fn call(&self, method: &str, params: Value) -> Value {
        rpc(&self.socket_path, method, params)
    }

    fn begin(&self) -> Value {
        self.call(
            "login_begin",
            json!({
                "cred_id": "mock:site",
                "target_url": "http://127.0.0.1/login",
                "success_selector": "#signed-in",
            }),
        )
    }

    /// `login_begin` が pending を返すことを確かめ、login_id を返す。
    fn begin_pending(&self) -> String {
        let response = self.begin();
        let result = &response["result"];
        assert_eq!(result["state"], "pending", "{response}");
        result["login_id"]
            .as_str()
            .unwrap_or_else(|| panic!("no login_id: {response}"))
            .to_owned()
    }

    fn step(&self, login_id: &str, action: Value) -> Value {
        let mut params = action;
        params["login_id"] = json!(login_id);
        self.call("login_step", params)
    }

    fn status(&self) -> Value {
        self.call("status", json!({}))["result"].clone()
    }

    fn stderr(&self) -> String {
        std::fs::read_to_string(self.directory.join("stderr.log")).unwrap_or_default()
    }

    fn audit_text(&self) -> String {
        std::fs::read_to_string(self.state_dir.join("audit.log")).unwrap_or_default()
    }

    fn audit_records(&self) -> Vec<Value> {
        self.audit_text()
            .lines()
            .map(|line| serde_json::from_str(line).expect("parse audit record"))
            .collect()
    }

    fn records(&self, method: &str) -> Vec<Value> {
        self.audit_records()
            .into_iter()
            .filter(|record| record["method"] == method)
            .collect()
    }

    /// 条件を満たす監査行が現れるまで待つ。
    fn wait_for_record(&self, method: &str, login_id: &str) -> Value {
        let deadline = Instant::now() + Duration::from_secs(10);
        loop {
            if let Some(record) = self
                .records(method)
                .into_iter()
                .find(|record| record["login_id"] == login_id)
            {
                return record;
            }
            assert!(
                Instant::now() < deadline,
                "no {method} record for {login_id}"
            );
            sleep(Duration::from_millis(50));
        }
    }

    fn executor_requests(&self) -> Vec<Value> {
        std::fs::read_to_string(self.directory.join("executor.js.requests"))
            .unwrap_or_default()
            .lines()
            .map(|line| serde_json::from_str(line).expect("parse executor request"))
            .collect()
    }

    fn executor_ops(&self) -> Vec<String> {
        self.executor_requests()
            .iter()
            .map(|request| {
                let op = request["op"].as_str().unwrap_or_default();
                match request["action"].as_str() {
                    Some(action) => format!("{op}:{action}"),
                    None => op.to_owned(),
                }
            })
            .collect()
    }

    /// 偽の executor が `shutdown` を受け取るまで待つ。
    fn wait_for_shutdowns(&self, count: usize) {
        let deadline = Instant::now() + Duration::from_secs(10);
        while self
            .executor_ops()
            .iter()
            .filter(|op| op.as_str() == "shutdown")
            .count()
            < count
        {
            assert!(
                Instant::now() < deadline,
                "executor was not shut down: {:?}",
                self.executor_ops()
            );
            sleep(Duration::from_millis(50));
        }
    }

    fn store_files(&self) -> usize {
        std::fs::read_dir(self.state_dir.join("cookies"))
            .map(|entries| entries.count())
            .unwrap_or(0)
    }
}

impl Drop for Daemon {
    fn drop(&mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
        let _ = std::fs::remove_dir_all(&self.directory);
    }
}

fn click(selector: &str) -> Value {
    json!({ "action": "click", "selector": selector })
}

fn snapshot() -> Value {
    json!({ "action": "snapshot" })
}

fn fill_submit(values: &[&str], submit: &str) -> Value {
    let fills = values
        .iter()
        .enumerate()
        .map(|(index, value)| json!({ "selector": format!("#field{index}"), "value": value }))
        .collect::<Vec<_>>();
    json!({ "action": "fill_submit", "fills": fills, "submit": { "click": submit } })
}

fn error_message(response: &Value) -> &str {
    response["error"]["message"].as_str().unwrap_or_default()
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
fn a_stepwise_login_walks_to_a_handoff() {
    let daemon = Daemon::start();
    let begun = daemon.begin();
    let login_id = begun["result"]["login_id"]
        .as_str()
        .expect("login_id")
        .to_owned();
    assert_eq!(begun["result"]["snapshot"]["url"], "http://127.0.0.1/start");
    assert!(begun["result"].get("channel").is_none(), "{begun}");

    let clicked = daemon.step(&login_id, click("#next"));
    assert_eq!(clicked["result"]["state"], "pending", "{clicked}");
    assert_eq!(clicked["result"]["login_id"], login_id.as_str());
    let filled = daemon.step(
        &login_id,
        json!({ "action": "fill", "selector": "#user", "value": "{{username}}" }),
    );
    assert_eq!(filled["result"]["state"], "pending", "{filled}");
    let done = daemon.step(
        &login_id,
        fill_submit(&["{{password}}", "{{totp}}"], "#verify"),
    );
    let result = &done["result"];
    assert_eq!(result["state"], "done", "{done}");
    assert_eq!(result["target_id"], "step-target");
    assert_eq!(result["channel"]["kind"], "cdp");
    assert_eq!(
        result["channel"]["endpoint"],
        "ws://127.0.0.1:38999/devtools/browser/test"
    );
    let session_id = result["session_id"]
        .as_str()
        .expect("session_id")
        .to_owned();
    assert_eq!(daemon.status()["browsers"], 1);
    assert_eq!(daemon.status()["leases"], 1);

    // executor には username と password だけを渡し、TOTP コードは {{totp}} を含む fill_submit でのみ渡す。
    let requests = daemon.executor_requests();
    let begin = &requests[0];
    assert_eq!(begin["op"], "login_begin");
    assert_eq!(begin["secret"], json!(["password", "username"]));
    assert_eq!(begin["cookies"], Value::Null);
    let steps = requests
        .iter()
        .filter(|request| request["op"] == "login_step")
        .collect::<Vec<_>>();
    assert_eq!(steps.len(), 3);
    assert_eq!(steps[0]["totp"], Value::Null);
    assert_eq!(steps[1]["totp"], Value::Null);
    let code = steps[2]["totp"].as_str().expect("TOTP code");
    assert!(code.len() == 6 && code.chars().all(|c| c.is_ascii_digit()));

    // 監査: login_begin 行は stepwise と login_id を持ち、login_step 行は action の種別のみを持つ。
    let begin_record = &daemon.records("login_begin")[0];
    assert_eq!(begin_record["stepwise"], true);
    assert_eq!(begin_record["login_id"], login_id.as_str());
    assert_eq!(begin_record["cred_id"], "mock:site");
    assert_eq!(begin_record["target_url"], "http://127.0.0.1/login");
    let step_records = daemon.records("login_step");
    let actions = step_records
        .iter()
        .map(|record| record["action"].as_str().unwrap_or_default())
        .collect::<Vec<_>>();
    assert_eq!(actions, ["click", "fill", "fill_submit"]);
    assert!(
        step_records
            .iter()
            .all(|record| record["login_id"] == login_id.as_str() && record["outcome"] == "ok")
    );
    assert_eq!(step_records[2]["session_id"], session_id.as_str());
    let handoff = daemon.wait_for_record("stepwise_handoff", &login_id);
    assert_eq!(handoff["session_id"], session_id.as_str());
    let audit = daemon.audit_text();
    assert!(
        !audit.contains("#verify") && !audit.contains("#next"),
        "{audit}"
    );

    // 応答・監査・stderr に資格も TOTP コードも現れない。
    for surface in [
        begun.to_string(),
        clicked.to_string(),
        filled.to_string(),
        done.to_string(),
        audit,
        daemon.stderr(),
    ] {
        assert!(!surface.contains(USERNAME), "{surface}");
        assert!(!surface.contains(PASSWORD), "{surface}");
        assert!(!surface.contains(TOTP_SEED), "{surface}");
        assert!(!surface.contains(code), "{surface}");
    }

    // ハンドオフ後は login と同じセッションとして logout できる。
    let logout = daemon.call("logout", json!({ "session_id": session_id }));
    assert_eq!(logout["result"], json!({ "ok": true }), "{logout}");
    daemon.wait_for_shutdowns(1);
    assert_eq!(daemon.status()["browsers"], 0);
}

#[test]
fn a_login_id_is_bound_to_its_principal() {
    let daemon = Daemon::start();
    let login_id = daemon.begin_pending();
    let issued = daemon.call("admin_peer_issue", json!({ "label": "p2" }));
    let token = issued["result"]["token"].as_str().expect("peer token");

    let foreign = tcp_rpc(
        &daemon,
        token,
        "login_step",
        json!({ "login_id": login_id, "action": "snapshot" }),
    );
    assert_eq!(error_message(&foreign), "NOT_FOUND", "{foreign}");

    let own = daemon.step(&login_id, snapshot());
    assert_eq!(own["result"]["state"], "pending", "{own}");
    let steps = daemon
        .executor_ops()
        .into_iter()
        .filter(|op| op.starts_with("login_step"))
        .count();
    assert_eq!(steps, 1, "the foreign step never reached the executor");
}

#[test]
fn an_idle_stepwise_login_expires_once() {
    let daemon = Daemon::start_with("stepwise_idle_secs = 1\n", &[]);
    let login_id = daemon.begin_pending();
    sleep(Duration::from_millis(2500));

    let late = daemon.step(&login_id, snapshot());
    assert_eq!(error_message(&late), "NOT_FOUND", "{late}");
    daemon.wait_for_record("stepwise_expired", &login_id);
    daemon.wait_for_shutdowns(1);
    sleep(Duration::from_millis(1500));
    let expired = daemon
        .records("stepwise_expired")
        .into_iter()
        .filter(|record| record["login_id"] == login_id.as_str())
        .count();
    assert_eq!(expired, 1);
    assert!(
        !daemon
            .executor_ops()
            .iter()
            .any(|op| op.starts_with("login_step")),
        "the late step never reached the executor"
    );
}

#[test]
fn an_absolute_limit_ends_an_active_stepwise_login() {
    let daemon = Daemon::start_with("stepwise_idle_secs = 60\nstepwise_max_secs = 2\n", &[]);
    let login_id = daemon.begin_pending();
    let deadline = Instant::now() + Duration::from_secs(10);
    loop {
        let response = daemon.step(&login_id, snapshot());
        if error_message(&response) == "NOT_FOUND" {
            break;
        }
        assert_eq!(response["result"]["state"], "pending", "{response}");
        assert!(Instant::now() < deadline, "the login did not expire");
        sleep(Duration::from_millis(300));
    }
    daemon.wait_for_record("stepwise_expired", &login_id);
    daemon.wait_for_shutdowns(1);
}

#[test]
fn the_step_after_forty_is_rate_limited_and_ends_the_login() {
    let daemon = Daemon::start();
    let login_id = daemon.begin_pending();
    for index in 0..40 {
        let response = daemon.step(&login_id, snapshot());
        assert_eq!(
            response["result"]["state"], "pending",
            "step {index}: {response}"
        );
    }
    let over = daemon.step(&login_id, snapshot());
    assert_eq!(error_message(&over), "RATE_LIMITED", "{over}");
    let after = daemon.step(&login_id, snapshot());
    assert_eq!(error_message(&after), "NOT_FOUND", "{after}");
    let ended = daemon.wait_for_record("stepwise_terminated", &login_id);
    assert_eq!(ended["outcome"], "RATE_LIMITED");
    daemon.wait_for_shutdowns(1);
}

#[test]
fn invalid_step_params_get_the_invalid_params_error() {
    let daemon = Daemon::start();
    let login_id = daemon.begin_pending();
    let invalid = daemon.call("login", json!({}));
    assert!(invalid.get("error").is_some(), "{invalid}");

    for action in [
        json!({ "action": "fill", "selector": "#p", "value": "{{password}}" }),
        json!({ "action": "fill", "selector": "#p", "value": "{{totp}}" }),
        json!({ "action": "fill", "selector": "#p", "value": "literal" }),
        fill_submit(&["literal"], "#go"),
        fill_submit(&[], "#go"),
        fill_submit(&["{{username}}"; 4], "#go"),
        json!({ "action": "fill_submit", "fills": [{ "selector": "#p", "value": "{{password}}" }] }),
        json!({ "action": "type", "selector": "#p" }),
        json!({ "action": "click" }),
    ] {
        let response = daemon.step(&login_id, action.clone());
        assert!(response.get("result").is_none(), "{action}: {response}");
        assert_eq!(response["error"], invalid["error"], "{action}");
    }
    let begin_without_success = daemon.call(
        "login_begin",
        json!({ "cred_id": "mock:site", "target_url": "http://127.0.0.1/login" }),
    );
    assert_eq!(begin_without_success["error"], invalid["error"]);

    assert!(
        !daemon
            .executor_ops()
            .iter()
            .any(|op| op.starts_with("login_step")),
        "no invalid step reached the executor"
    );
    let still = daemon.step(&login_id, snapshot());
    assert_eq!(still["result"]["state"], "pending", "{still}");
}

#[test]
fn abort_ends_the_login_without_counting_a_failure() {
    let daemon = Daemon::start();
    let login_id = daemon.begin_pending();

    let aborted = daemon.step(&login_id, json!({ "action": "abort" }));
    assert_eq!(
        aborted["result"],
        json!({ "state": "aborted" }),
        "{aborted}"
    );
    let after = daemon.step(&login_id, snapshot());
    assert_eq!(error_message(&after), "NOT_FOUND", "{after}");
    let ops = daemon.executor_ops();
    assert_eq!(ops[1..], ["login_step:abort", "shutdown"], "{ops:?}");
    daemon.wait_for_record("stepwise_aborted", &login_id);

    // abort は失敗として数えないため、バックオフに掛からない。
    daemon.begin_pending();
}

#[test]
fn a_rejected_snapshot_ends_the_login_and_backs_off() {
    let daemon = Daemon::start();
    let login_id = daemon.begin_pending();

    let rejected = daemon.step(&login_id, fill_submit(&["{{password}}"], "#reject"));
    assert_eq!(error_message(&rejected), "SNAPSHOT_REJECTED", "{rejected}");
    let after = daemon.step(&login_id, snapshot());
    assert_eq!(error_message(&after), "NOT_FOUND", "{after}");
    let record = daemon.wait_for_record("stepwise_rejected", &login_id);
    assert_eq!(record["outcome"], "SNAPSHOT_REJECTED");
    daemon.wait_for_shutdowns(1);

    let again = daemon.begin();
    assert_eq!(error_message(&again), "RATE_LIMITED", "{again}");
}

#[test]
fn a_fill_mismatch_ends_the_login() {
    let daemon = Daemon::start();
    let login_id = daemon.begin_pending();

    let mismatch = daemon.step(&login_id, fill_submit(&["{{password}}"], "#mismatch"));
    assert_eq!(error_message(&mismatch), "FILL_MISMATCH", "{mismatch}");
    assert_eq!(mismatch["error"]["data"], json!({ "step": 1 }));
    let after = daemon.step(&login_id, snapshot());
    assert_eq!(error_message(&after), "NOT_FOUND", "{after}");
    daemon.wait_for_shutdowns(1);
}

#[test]
fn a_missing_selector_keeps_the_login_going() {
    let daemon = Daemon::start();
    let login_id = daemon.begin_pending();

    let missing = daemon.step(&login_id, click("#missing"));
    assert_eq!(error_message(&missing), "SELECTOR_NOT_FOUND", "{missing}");
    assert_eq!(missing["error"]["data"], json!({ "step": 0 }));
    let again = daemon.step(&login_id, snapshot());
    assert_eq!(again["result"]["state"], "pending", "{again}");
    let outcomes = daemon
        .records("login_step")
        .iter()
        .map(|record| record["outcome"].as_str().unwrap_or_default().to_owned())
        .collect::<Vec<_>>();
    assert_eq!(outcomes, ["SELECTOR_NOT_FOUND", "ok"]);
}

#[test]
fn a_disconnected_executor_ends_the_login() {
    let daemon = Daemon::start();
    let login_id = daemon.begin_pending();

    let vanished = daemon.step(&login_id, click("#vanish"));
    assert_eq!(error_message(&vanished), "INTERNAL", "{vanished}");
    let after = daemon.step(&login_id, snapshot());
    assert_eq!(error_message(&after), "NOT_FOUND", "{after}");
    let record = daemon.wait_for_record("stepwise_terminated", &login_id);
    assert_eq!(record["outcome"], "INTERNAL");
}

#[test]
fn lock_vault_ends_the_stepwise_logins_of_the_namespace() {
    let daemon = Daemon::start();
    let login_id = daemon.begin_pending();

    let locked = daemon.call("lock_vault", json!({ "namespace": "mock" }));
    assert_eq!(locked["result"], json!({ "ok": true }), "{locked}");
    let after = daemon.step(&login_id, snapshot());
    assert_eq!(error_message(&after), "NOT_FOUND", "{after}");
    let record = daemon.wait_for_record("stepwise_terminated", &login_id);
    assert_eq!(record["outcome"], "lock_vault");
    daemon.wait_for_shutdowns(1);
}

#[test]
fn a_stepwise_login_counts_once_against_the_rate_limit() {
    let daemon = Daemon::start();
    let login_id = daemon.begin_pending();
    for _ in 0..10 {
        let response = daemon.step(&login_id, snapshot());
        assert_eq!(response["result"]["state"], "pending", "{response}");
    }
    let done = daemon.step(&login_id, fill_submit(&["{{password}}"], "#verify"));
    let session_id = done["result"]["session_id"].as_str().expect("session_id");
    daemon.call("logout", json!({ "session_id": session_id }));

    daemon.begin_pending();
    daemon.begin_pending();
    let fourth = daemon.begin();
    assert_eq!(error_message(&fourth), "RATE_LIMITED", "{fourth}");
}

#[test]
fn restored_cookies_finish_login_begin_at_once() {
    let daemon = Daemon::start_with("", &["*"]);
    let login_id = daemon.begin_pending();
    let done = daemon.step(&login_id, fill_submit(&["{{password}}"], "#verify"));
    let session_id = done["result"]["session_id"].as_str().expect("session_id");
    assert_eq!(daemon.store_files(), 1, "the handoff stored the cookies");
    daemon.call("logout", json!({ "session_id": session_id }));
    daemon.wait_for_shutdowns(1);

    let again = daemon.begin();
    let result = &again["result"];
    assert_eq!(result["state"], "done", "{again}");
    assert!(result.get("snapshot").is_none(), "{again}");
    let session_id = result["session_id"].as_str().expect("session_id");
    let begins = daemon
        .executor_requests()
        .into_iter()
        .filter(|request| request["op"] == "login_begin")
        .collect::<Vec<_>>();
    assert_eq!(begins[1]["cookies"], 1, "the stored cookie was restored");

    let record = daemon
        .records("login_begin")
        .into_iter()
        .find(|record| record["session_id"] == session_id)
        .expect("login_begin record of the restored session");
    assert_eq!(record["cookies"], "restored");
    assert_eq!(record["steps_skipped"], true);
    assert_eq!(record["stepwise"], true);
    let first = &daemon.records("login_begin")[0];
    assert_eq!(first["cookies"], "none");
    assert!(!daemon.audit_text().contains("device-canary"));
}

#[test]
fn login_begin_joins_a_shared_session() {
    let daemon = Daemon::start();
    let login = daemon.call(
        "login",
        json!({ "cred_id": "mock:site", "target_url": "http://127.0.0.1/login" }),
    );
    assert!(login["result"]["session_id"].is_string(), "{login}");

    let joined = daemon.begin();
    let result = &joined["result"];
    assert_eq!(result["state"], "done", "{joined}");
    assert_eq!(result["target_id"], "lease-target");
    assert_eq!(daemon.status()["browsers"], 1);
    let record = daemon
        .records("login_begin")
        .into_iter()
        .next()
        .expect("login_begin record");
    assert_eq!(record["shared"], true);
    assert!(
        !daemon.executor_ops().iter().any(|op| op == "login_begin"),
        "no browser was started"
    );
}

#[test]
fn a_handoff_beside_a_shared_session_is_not_shared() {
    let daemon = Daemon::start();
    let login_id = daemon.begin_pending();
    let login = daemon.call(
        "login",
        json!({ "cred_id": "mock:site", "target_url": "http://127.0.0.1/login" }),
    );
    let shared_session = login["result"]["session_id"].as_str().expect("session_id");

    let done = daemon.step(&login_id, fill_submit(&["{{password}}"], "#verify"));
    assert_eq!(done["result"]["state"], "done", "{done}");
    assert_eq!(daemon.status()["browsers"], 2);

    // 共有セッションを閉じた後の login は、段階ログインのブラウザへ相乗りせずに新しく起動する。
    daemon.call("logout", json!({ "session_id": shared_session }));
    daemon.wait_for_shutdowns(1);
    let again = daemon.call(
        "login",
        json!({ "cred_id": "mock:site", "target_url": "http://127.0.0.1/login" }),
    );
    assert_eq!(again["result"]["target_id"], "login-target", "{again}");
    assert_eq!(daemon.status()["browsers"], 2);
}

#[test]
fn a_snapshot_caught_by_the_response_scan_ends_the_login() {
    let daemon = Daemon::start();
    let login_id = daemon.begin_pending();

    let leaked = daemon.step(&login_id, click("#echo-user"));
    assert_eq!(error_message(&leaked), "INTERNAL", "{leaked}");
    assert!(!leaked.to_string().contains(USERNAME), "{leaked}");
    let after = daemon.step(&login_id, snapshot());
    assert_eq!(error_message(&after), "NOT_FOUND", "{after}");
    let record = daemon.wait_for_record("stepwise_rejected", &login_id);
    assert_eq!(record["outcome"], "SNAPSHOT_REJECTED");
    daemon.wait_for_shutdowns(1);
    assert!(!daemon.audit_text().contains(USERNAME));

    // SNAPSHOT_REJECTED と同じく失敗として数えるため、直後の login_begin はバックオフに掛かる。
    let again = daemon.begin();
    assert_eq!(error_message(&again), "RATE_LIMITED", "{again}");
}

#[test]
fn revoking_a_peer_ends_its_stepwise_logins() {
    let daemon = Daemon::start();
    let own = daemon.begin_pending();
    let issued = daemon.call("admin_peer_issue", json!({ "label": "p2" }));
    let token = issued["result"]["token"].as_str().expect("peer token");
    let peer_id = issued["result"]["peer_id"].as_str().expect("peer_id");
    let begun = tcp_rpc(
        &daemon,
        token,
        "login_begin",
        json!({
            "cred_id": "mock:site",
            "target_url": "http://127.0.0.1/login",
            "success_selector": "#signed-in",
        }),
    );
    assert_eq!(begun["result"]["state"], "pending", "{begun}");
    let foreign = begun["result"]["login_id"].as_str().expect("login_id");

    let revoked = daemon.call("admin_peer_revoke", json!({ "peer_id": peer_id }));
    assert_eq!(revoked["result"], json!({ "ok": true }), "{revoked}");
    let record = daemon.wait_for_record("stepwise_terminated", foreign);
    assert_eq!(record["outcome"], "peer_revoked");
    daemon.wait_for_shutdowns(1);

    // 他の principal の段階ログインは続く。
    let still = daemon.step(&own, snapshot());
    assert_eq!(still["result"]["state"], "pending", "{still}");
    assert!(
        daemon
            .records("stepwise_terminated")
            .iter()
            .all(|record| record["login_id"] != own.as_str())
    );
}
