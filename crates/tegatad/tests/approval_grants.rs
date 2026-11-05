//! Verifies approval grants (`approval_grant_ttl_secs`) with a fake `approve_cmd` hook.
//! RPCs are sent over a UNIX domain socket, so these tests run on UNIX only.
#![cfg(unix)]

use std::path::PathBuf;
use std::process::{Child, Command, Stdio};
use std::thread::sleep;
use std::time::{Duration, Instant};

use serde_json::{Value, json};
use uuid::Uuid;

mod common;
use common::{create_private_dir, rpc, try_rpc};

const USERNAME: &str = "grant-user-secret";
const PASSWORD: &str = "grant-password-secret";
const TOTP_SEED: &str = "grant-totp-seed-canary";

/// Fake executor that succeeds for login and device authorization and also answers lease requests.
/// It lets a second login piggyback on the first login's browser.
const EXECUTOR: &str = r#"
const readline = require("node:readline");
const rl = readline.createInterface({ input: process.stdin });
rl.on("line", (line) => {
  const request = JSON.parse(line);
  if (answerStartupProbe(request)) return;
  if (request.op === "login") {
    process.stdout.write(
      JSON.stringify({ id: request.id, ok: true, endpoint: "ws://127.0.0.1:38999/devtools/browser/test", target_id: "test-target" }) + "\n",
    );
  } else if (request.op === "authorize_device") {
    process.stdout.write(JSON.stringify({ id: request.id, ok: true }) + "\n");
  } else if (request.op === "lease") {
    process.stdout.write(JSON.stringify({ id: request.id, ok: true, target_id: "lease-target" }) + "\n");
  } else if (request.op === "release") {
    process.stdout.write(JSON.stringify({ id: request.id, ok: true }) + "\n");
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
    /// Starts the daemon with a hook that appends one line to `hook.log` per call and denies while
    /// `hook.deny` exists.
    /// The hook holds its reply while `hook.hold` exists and
    /// appends the environment variables it received to `hook.env`.
    #[allow(clippy::zombie_processes)]
    fn start(grant_ttl_secs: Option<u64>) -> Self {
        let directory = std::env::temp_dir().join(format!("tegatad-grants-{}", Uuid::new_v4()));
        std::fs::create_dir(&directory).expect("create test directory");
        let state_dir = directory.join("state");
        create_private_dir(&state_dir);
        let socket_path = directory.join("tegatad.sock");
        let config_path = directory.join("config.toml");
        let script_path = directory.join("executor.js");
        std::fs::write(&script_path, common::fake_executor_source(EXECUTOR))
            .expect("write executor script");
        let hook = format!(
            "echo \"$TEGATA_APPROVAL_CODE $TEGATA_APPROVAL_GRANT_TTL_SECS $TEGATA_CRED_ID $TEGATA_METHOD\" >> {:?}; env >> {:?}; while test -e {:?}; do sleep 0.05; done; test ! -e {:?}",
            directory.join("hook.log"),
            directory.join("hook.env"),
            directory.join("hook.hold"),
            directory.join("hook.deny"),
        );
        let ttl_line = grant_ttl_secs
            .map(|value| format!("approval_grant_ttl_secs = {value}\n"))
            .unwrap_or_default();
        let entry = |id: &str| {
            format!(
                "[[providers.entries]]\nid = {id:?}\nname = {id:?}\nuri = \"http://127.0.0.1\"\nkind = \"login\"\nusername = {USERNAME:?}\npassword = {PASSWORD:?}\ntotp_seed = {TOTP_SEED:?}\n\n"
            )
        };
        let config = format!(
            "socket_path = {:?}\nstate_dir = {:?}\naudit_log_path = {:?}\nallowed_uids = [{}]\nexecutor_entry = {:?}\napprove_cmd = {:?}\n{}\n[[providers]]\nnamespace = \"mock\"\ntype = \"mock\"\n\n{}{}[[providers]]\nnamespace = \"other\"\ntype = \"mock\"\n\n{}[[providers]]\nnamespace = \"empty\"\ntype = \"mock\"\n",
            socket_path,
            state_dir,
            state_dir.join("audit.log"),
            unsafe { libc::geteuid() },
            script_path,
            hook,
            ttl_line,
            entry("site"),
            entry("second"),
            entry("site"),
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

    fn login(&self, cred_id: &str) -> Value {
        rpc(
            &self.socket_path,
            "login",
            json!({ "cred_id": cred_id, "target_url": "http://127.0.0.1" }),
        )
    }

    fn hook_calls(&self) -> Vec<String> {
        std::fs::read_to_string(self.directory.join("hook.log"))
            .unwrap_or_default()
            .lines()
            .map(ToOwned::to_owned)
            .collect()
    }

    fn set_deny(&self, deny: bool) {
        let path = self.directory.join("hook.deny");
        if deny {
            std::fs::write(path, "").expect("create deny file");
        } else {
            std::fs::remove_file(path).expect("remove deny file");
        }
    }

    /// Returns the audit lines for `method` in the order they were recorded.
    fn audit(&self, method: &str) -> Vec<Value> {
        std::fs::read_to_string(self.directory.join("state/audit.log"))
            .unwrap_or_default()
            .lines()
            .map(|line| serde_json::from_str::<Value>(line).expect("parse audit record"))
            .filter(|record| record["method"] == method)
            .collect()
    }
}

impl Drop for Daemon {
    fn drop(&mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
        let _ = std::fs::remove_dir_all(&self.directory);
    }
}

fn assert_error(response: &Value, code: &str) {
    assert_eq!(response["error"]["message"], json!(code), "{response}");
}

fn assert_session(response: &Value) {
    assert!(response["result"]["session_id"].is_string(), "{response}");
}

fn call_field(call: &str, index: usize) -> &str {
    call.split(' ').nth(index).expect("hook log field")
}

/// Given: `approve_cmd` is set and `approval_grant_ttl_secs` is not.
/// When: two logins are made with the same credential.
/// Then: the hook is called both times with a validity of 0, and no audit line has
/// `approval_grant`.
#[test]
fn without_a_grant_ttl_every_login_asks_the_hook() {
    let daemon = Daemon::start(None);
    assert_session(&daemon.login("mock:site"));
    assert_session(&daemon.login("mock:site"));

    let calls = daemon.hook_calls();
    assert_eq!(calls.len(), 2, "{calls:?}");
    assert!(calls.iter().all(|call| call_field(call, 1) == "0"));
    let audit = daemon.audit("login");
    assert_eq!(audit.len(), 2);
    assert!(
        audit
            .iter()
            .all(|record| record.get("approval_grant").is_none())
    );
}

/// Given: `approval_grant_ttl_secs = 60`.
/// When: the same principal logs in twice with the same credential.
/// Then: the hook is called only once, and the audit lines are `issued` followed by `reused`.
#[test]
fn a_grant_skips_the_hook_for_the_same_principal_and_credential() {
    let daemon = Daemon::start(Some(60));
    assert_session(&daemon.login("mock:site"));
    assert_session(&daemon.login("mock:site"));

    let calls = daemon.hook_calls();
    assert_eq!(calls.len(), 1, "{calls:?}");
    assert_eq!(call_field(&calls[0], 1), "60");
    let audit = daemon.audit("login");
    assert_eq!(audit.len(), 2);
    assert_eq!(audit[0]["approval_grant"], json!("issued"));
    assert_eq!(audit[1]["approval_grant"], json!("reused"));
}

/// Given: the grant validity is 1 second.
/// When: a second login is made after the grant expires.
/// Then: the hook is called again.
#[test]
fn an_expired_grant_asks_the_hook_again() {
    let daemon = Daemon::start(Some(1));
    assert_session(&daemon.login("mock:site"));
    sleep(Duration::from_millis(1500));
    assert_session(&daemon.login("mock:site"));

    assert_eq!(daemon.hook_calls().len(), 2);
    let audit = daemon.audit("login");
    assert_eq!(audit[1]["approval_grant"], json!("issued"));
}

/// Given: a grant exists for one credential.
/// When: a login is made with a different credential.
/// Then: the hook is called for that credential.
#[test]
fn a_grant_does_not_cover_another_credential() {
    let daemon = Daemon::start(Some(60));
    assert_session(&daemon.login("mock:site"));
    assert_session(&daemon.login("mock:second"));

    let calls = daemon.hook_calls();
    assert_eq!(calls.len(), 2, "{calls:?}");
    assert_eq!(call_field(&calls[1], 2), "mock:second");
}

/// Given: the hook denies the first time and allows afterwards.
/// When: two logins are made with the same credential.
/// Then: a denial creates no grant, so the second login asks for approval again.
#[test]
fn a_denial_creates_no_grant() {
    let daemon = Daemon::start(Some(60));
    daemon.set_deny(true);
    assert_error(&daemon.login("mock:site"), "APPROVAL_DENIED");
    daemon.set_deny(false);
    assert_session(&daemon.login("mock:site"));

    assert_eq!(daemon.hook_calls().len(), 2);
    let audit = daemon.audit("login");
    assert!(audit[0].get("approval_grant").is_none());
    assert_eq!(audit[1]["approval_grant"], json!("issued"));
}

/// Given: a grant exists from `login`.
/// When: `authorize_device` is made with the same credential.
/// Then: the grant is shared regardless of the method.
#[test]
fn authorize_device_reuses_a_login_grant() {
    let daemon = Daemon::start(Some(60));
    assert_session(&daemon.login("mock:site"));
    let response = rpc(
        &daemon.socket_path,
        "authorize_device",
        json!({
            "cred_id": "mock:site",
            "verification_url": "https://example.test/device",
            "user_code": "grant-device-code",
            "success_selector": "#device-ok"
        }),
    );
    assert_eq!(response["result"], json!({ "ok": true }), "{response}");

    assert_eq!(daemon.hook_calls().len(), 1);
    let audit = daemon.audit("authorize_device");
    assert_eq!(audit[0]["approval_grant"], json!("reused"));
}

/// Given: grants exist in two namespaces.
/// When: one namespace is locked with `lock_vault`.
/// Then: only the grants of that namespace are discarded.
#[test]
fn lock_vault_revokes_the_grants_of_its_namespace() {
    let daemon = Daemon::start(Some(60));
    assert_session(&daemon.login("mock:site"));
    assert_session(&daemon.login("other:site"));
    let locked = rpc(
        &daemon.socket_path,
        "lock_vault",
        json!({ "namespace": "mock" }),
    );
    assert_eq!(locked["result"]["ok"], true);

    assert_session(&daemon.login("other:site"));
    assert_eq!(daemon.hook_calls().len(), 2);
    daemon.login("mock:site");
    let calls = daemon.hook_calls();
    assert_eq!(calls.len(), 3, "{calls:?}");
    assert_eq!(call_field(&calls[2], 2), "mock:site");
}

/// Given: grants exist in two namespaces.
/// When: `lock_vault` is called without a namespace.
/// Then: all grants are discarded.
#[test]
fn lock_vault_without_a_namespace_revokes_every_grant() {
    let daemon = Daemon::start(Some(60));
    assert_session(&daemon.login("mock:site"));
    assert_session(&daemon.login("other:site"));
    let locked = rpc(&daemon.socket_path, "lock_vault", json!({}));
    assert_eq!(locked["result"]["ok"], true);

    daemon.login("mock:site");
    daemon.login("other:site");
    assert_eq!(daemon.hook_calls().len(), 4);
}

/// Given: the hook records the environment variables it receives.
/// When: approval is requested 5 times.
/// Then: each verification number is a 2-digit integer, they are not all the same value, and the
/// credential's secret is not passed to the hook.
#[test]
fn the_hook_receives_fresh_two_digit_codes_and_no_secrets() {
    let daemon = Daemon::start(Some(60));
    daemon.set_deny(true);
    for _ in 0..5 {
        assert_error(&daemon.login("mock:site"), "APPROVAL_DENIED");
    }

    let codes = daemon
        .hook_calls()
        .iter()
        .map(|call| call_field(call, 0).parse::<u8>().expect("numeric code"))
        .collect::<Vec<_>>();
    assert_eq!(codes.len(), 5);
    assert!(
        codes.iter().all(|code| (10..=99).contains(code)),
        "{codes:?}"
    );
    // The probability of 5 identical values in a row is 90^-4, so an accidental failure is
    // practically impossible.
    assert!(codes.iter().any(|code| *code != codes[0]), "{codes:?}");

    let env = std::fs::read_to_string(daemon.directory.join("hook.env")).expect("read hook env");
    for secret in [USERNAME, PASSWORD, TOTP_SEED] {
        assert!(!env.contains(secret), "hook env leaked {secret}");
    }
}

/// Given: the hook is holding its reply.
/// When: while it holds, the same namespace is locked with `lock_vault`, the approval is then
/// granted, and a login is made again.
/// Then: the grant is not revived after the lock, and the next login calls the hook again.
#[test]
fn a_lock_during_a_pending_approval_leaves_no_grant() {
    let daemon = Daemon::start(Some(60));
    let hold = daemon.directory.join("hook.hold");
    std::fs::write(&hold, "").expect("create hold file");
    let socket_path = daemon.socket_path.clone();
    let pending = std::thread::spawn(move || {
        rpc(
            &socket_path,
            "login",
            json!({ "cred_id": "mock:site", "target_url": "http://127.0.0.1" }),
        )
    });
    let deadline = Instant::now() + Duration::from_secs(10);
    while daemon.hook_calls().is_empty() {
        assert!(Instant::now() < deadline, "hook was not called");
        sleep(Duration::from_millis(20));
    }
    let locked = rpc(
        &daemon.socket_path,
        "lock_vault",
        json!({ "namespace": "mock" }),
    );
    assert_eq!(locked["result"]["ok"], true);
    std::fs::remove_file(&hold).expect("remove hold file");
    pending.join().expect("join pending login");

    let audit = daemon.audit("login");
    assert_eq!(audit.len(), 1);
    assert!(audit[0].get("approval_grant").is_none(), "{}", audit[0]);
    daemon.login("mock:site");
    let calls = daemon.hook_calls();
    assert_eq!(calls.len(), 2, "{calls:?}");
    assert_eq!(call_field(&calls[1], 2), "mock:site");
}

/// Given: a locked namespace has an empty listing.
/// When: two logins are made with a credential of that namespace.
/// Then: no grant is created for a credential whose existence cannot be confirmed, the hook is
/// called both times, and no audit line has
/// `approval_grant`.
#[test]
fn an_unconfirmed_credential_receives_no_grant() {
    let daemon = Daemon::start(Some(60));
    let locked = rpc(
        &daemon.socket_path,
        "lock_vault",
        json!({ "namespace": "empty" }),
    );
    assert_eq!(locked["result"]["ok"], true);

    assert!(daemon.login("empty:ghost").get("error").is_some());
    assert!(daemon.login("empty:ghost").get("error").is_some());

    let calls = daemon.hook_calls();
    assert_eq!(calls.len(), 2, "{calls:?}");
    let audit = daemon.audit("login");
    assert_eq!(audit.len(), 2);
    assert!(
        audit
            .iter()
            .all(|record| record.get("approval_grant").is_none())
    );
}

/// Given: an approval gate is configured.
/// When: `authorize_device` is made with a nonexistent credential.
/// Then: it is rejected with `INVALID_CREDENTIAL` before approval is requested, and the hook is not
/// called.
#[test]
fn authorize_device_rejects_an_unknown_credential_before_asking_the_hook() {
    let daemon = Daemon::start(Some(60));
    let response = rpc(
        &daemon.socket_path,
        "authorize_device",
        json!({
            "cred_id": "mock:missing",
            "verification_url": "https://example.test/device",
            "user_code": "grant-device-code",
            "success_selector": "#device-ok"
        }),
    );
    assert_error(&response, "INVALID_CREDENTIAL");

    assert!(daemon.hook_calls().is_empty());
    let audit = daemon.audit("authorize_device");
    assert_eq!(audit.len(), 1);
    assert!(audit[0].get("approval_grant").is_none(), "{}", audit[0]);
}
