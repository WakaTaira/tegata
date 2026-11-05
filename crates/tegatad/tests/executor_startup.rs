//! Verifies the executor check at startup in spawn mode (`executor_socket` unset).
//! Before listening, the daemon starts the executor once, sends `hello`, and then ends it with
//! `shutdown`.

#![cfg(unix)]

use std::path::PathBuf;
use std::process::{Command, Output, Stdio};

use uuid::Uuid;

mod common;
use common::{create_private_dir, wait_for_status};

const REASON: &str = "Full Chromium is required; a browser installed with --only-shell cannot be used (PLAYWRIGHT_BROWSERS_PATH=/nowhere)";

/// Template for a fake executor that records the op of each request and its own pid in
/// `executor.js.log` and answers hello with `__HELLO__`.
const RECORDING_EXECUTOR_TEMPLATE: &str = r#"
const fs = require("node:fs");
const readline = require("node:readline");
const log = (op) => fs.appendFileSync(__filename + ".log", JSON.stringify({ op, pid: process.pid }) + "\n");
const rl = readline.createInterface({ input: process.stdin });
rl.on("line", (line) => {
  const request = JSON.parse(line);
  log(request.op);
  if (request.op === "hello") {
    process.stdout.write(JSON.stringify({ ...__HELLO__, uid: process.getuid(), pid: process.pid }) + "\n");
  } else if (request.op === "shutdown") {
    process.stdout.write(JSON.stringify({ id: request.id, ok: true }) + "\n");
    process.exit(0);
  }
});
"#;

/// Fake executor that exits without answering hello.
const SILENT_EXECUTOR: &str = "process.exit(0);\n";

fn recording_executor(hello: &str) -> String {
    RECORDING_EXECUTOR_TEMPLATE.replace("__HELLO__", hello)
}

struct Layout {
    directory: PathBuf,
    config_path: PathBuf,
    socket_path: PathBuf,
}

impl Layout {
    fn new(executor_script: &str) -> Self {
        let directory =
            std::env::temp_dir().join(format!("tegatad-executor-startup-{}", Uuid::new_v4()));
        std::fs::create_dir(&directory).expect("create test directory");
        let state_dir = directory.join("state");
        create_private_dir(&state_dir);
        let executor = directory.join("executor.js");
        std::fs::write(&executor, executor_script).expect("write executor script");
        let socket_path = directory.join("tegatad.sock");
        let config_path = directory.join("config.toml");
        let config = format!(
            "socket_path = {:?}\nstate_dir = {:?}\naudit_log_path = {:?}\nallowed_uids = [{}]\nexecutor_entry = {:?}\n",
            socket_path,
            state_dir,
            state_dir.join("audit.log"),
            unsafe { libc::geteuid() },
            executor,
        );
        std::fs::write(&config_path, config).expect("write test config");
        Self {
            directory,
            config_path,
            socket_path,
        }
    }

    fn executor_log(&self) -> Vec<serde_json::Value> {
        std::fs::read_to_string(self.directory.join("executor.js.log"))
            .unwrap_or_default()
            .lines()
            .map(|line| serde_json::from_str(line).expect("parse executor log"))
            .collect()
    }

    fn run_to_exit(&self) -> Output {
        Command::new(env!("CARGO_BIN_EXE_tegatad"))
            .arg("--config")
            .arg(&self.config_path)
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(Stdio::piped())
            .output()
            .expect("run tegatad")
    }
}

impl Drop for Layout {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.directory);
    }
}

fn logged_ops(log: &[serde_json::Value]) -> Vec<&str> {
    log.iter()
        .filter_map(|record| record["op"].as_str())
        .collect()
}

fn process_is_alive(pid: i64) -> bool {
    unsafe { libc::kill(pid as libc::pid_t, 0) == 0 }
}

/// Given: a spawn-mode executor that answers hello with `ok: true`
/// When: the daemon is started
/// Then: the executor is started once before listening and sent hello and shutdown, and it has
/// exited
#[test]
fn checks_the_spawned_executor_once_and_shuts_it_down() {
    let layout = Layout::new(&recording_executor("{ ok: true }"));
    let mut child = Command::new(env!("CARGO_BIN_EXE_tegatad"))
        .arg("--config")
        .arg(&layout.config_path)
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()
        .expect("spawn tegatad");

    wait_for_status(&layout.socket_path);
    let log = layout.executor_log();
    let _ = child.kill();
    let _ = child.wait();

    assert_eq!(logged_ops(&log), ["hello", "shutdown"], "{log:?}");
    let pid = log[0]["pid"].as_i64().expect("executor pid");
    assert!(!process_is_alive(pid), "the startup executor still runs");
}

/// Given: a spawn-mode executor that answers hello with `ok: false` and a rejection reason
/// When: the daemon is started
/// Then: it exits non-zero, stderr contains the rejection reason, no socket is created, and the
/// executor is sent shutdown
#[test]
fn refuses_to_start_when_the_spawned_executor_reports_not_ok() {
    let hello = format!("{{ ok: false, reason: {REASON:?} }}");
    let layout = Layout::new(&recording_executor(&hello));

    let output = layout.run_to_exit();
    let stderr = String::from_utf8_lossy(&output.stderr);

    assert!(!output.status.success(), "{stderr}");
    assert!(stderr.contains("executor reported ok=false"), "{stderr}");
    assert!(stderr.contains(REASON), "{stderr}");
    assert!(!layout.socket_path.exists(), "no socket is bound");
    assert_eq!(logged_ops(&layout.executor_log()), ["hello", "shutdown"]);
}

/// Given: a spawn-mode executor that exits without answering hello
/// When: the daemon is started
/// Then: it exits non-zero and stderr indicates that the check failed
#[test]
fn refuses_to_start_when_the_spawned_executor_does_not_answer() {
    let layout = Layout::new(SILENT_EXECUTOR);

    let output = layout.run_to_exit();
    let stderr = String::from_utf8_lossy(&output.stderr);

    assert!(!output.status.success(), "{stderr}");
    assert!(stderr.contains("failed the startup check"), "{stderr}");
    assert!(!layout.socket_path.exists(), "no socket is bound");
}
