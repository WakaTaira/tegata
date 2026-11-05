// Each test binary pulls this in with `mod common;`, so unused helpers must not produce warnings in
// binaries that do not use them.
#![allow(dead_code)]

use std::io::{BufRead, BufReader, Write};
use std::os::unix::fs::PermissionsExt;
use std::os::unix::net::UnixStream;
use std::path::{Path, PathBuf};
use std::thread::sleep;
use std::time::{Duration, Instant};

use serde_json::{Value, json};

/// The daemon requires state_dir to be 0700, self-owned, and not a symlink, so tests create their
/// state dir with this helper.
pub(crate) fn create_private_dir(path: &Path) {
    std::fs::create_dir_all(path).expect("create state directory");
    std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o700))
        .expect("set state directory permissions");
}

pub(crate) fn rpc(socket_path: &PathBuf, method: &str, params: Value) -> Value {
    let mut stream = UnixStream::connect(socket_path).expect("connect to daemon");
    let request = json!({
        "jsonrpc": "2.0",
        "id": 1,
        "method": method,
        "params": params,
    });
    writeln!(stream, "{request}").expect("write RPC request");
    let mut response = String::new();
    BufReader::new(stream)
        .read_line(&mut response)
        .expect("read RPC response");
    serde_json::from_str(&response).expect("parse RPC response")
}

pub(crate) fn try_rpc(socket_path: &PathBuf, method: &str, params: Value) -> Option<Value> {
    let mut stream = UnixStream::connect(socket_path).ok()?;
    let request = json!({
        "jsonrpc": "2.0",
        "id": 1,
        "method": method,
        "params": params,
    });
    writeln!(stream, "{request}").ok()?;
    let mut response = String::new();
    BufReader::new(stream).read_line(&mut response).ok()?;
    serde_json::from_str(&response).ok()
}

/// JS placed before the body of a fake executor. In spawn mode the daemon starts the executor once
/// at startup,
/// sends `hello`, and then ends it with `shutdown`. Each fake executor calls
/// `answerStartupProbe(request)` at the top of its line handler and skips the rest of the handling
/// if it returns true.
/// This keeps the startup-check round trip out of the fake executor's own handling and records.
const STARTUP_PROBE_PRELUDE: &str = r#"
let startupProbeActive = false;
const answerStartupProbe = (request) => {
  if (request.op === "hello") {
    startupProbeActive = true;
    process.stdout.write(JSON.stringify({ ok: true, uid: process.getuid(), pid: process.pid }) + "\n");
    return true;
  }
  if (!startupProbeActive) return false;
  if (request.op === "shutdown") {
    process.stdout.write(JSON.stringify({ id: request.id, ok: true }) + "\n");
    process.exit(0);
  }
  return true;
};
"#;

/// Body of a fake executor that answers only the startup check. Used by tests that send no lease
/// requests, to avoid starting the real executor.
const PROBE_ONLY_EXECUTOR: &str = r#"
const readline = require("node:readline");
const rl = readline.createInterface({ input: process.stdin });
rl.on("line", (line) => {
  answerStartupProbe(JSON.parse(line));
});
"#;

/// Returns JS that prefixes the fake executor body with the preamble answering the startup check.
pub(crate) fn fake_executor_source(script: &str) -> String {
    format!("{STARTUP_PROBE_PRELUDE}{script}")
}

/// Writes a fake executor that answers only the startup check to `directory` and returns its path.
pub(crate) fn write_probe_only_executor(directory: &Path) -> PathBuf {
    let path = directory.join("probe-executor.js");
    std::fs::write(&path, fake_executor_source(PROBE_ONLY_EXECUTOR))
        .expect("write probe-only executor script");
    path
}

/// Waits up to 5 seconds until `status` returns a result.
pub(crate) fn wait_for_status(socket_path: &Path) {
    let deadline = Instant::now() + Duration::from_secs(5);
    while Instant::now() < deadline {
        if let Ok(mut stream) = UnixStream::connect(socket_path) {
            let request = r#"{"jsonrpc":"2.0","id":1,"method":"status","params":{}}"#;
            if writeln!(stream, "{request}").is_ok() {
                let mut response = String::new();
                if BufReader::new(stream).read_line(&mut response).is_ok()
                    && response.contains("\"result\"")
                {
                    return;
                }
            }
        }
        sleep(Duration::from_millis(25));
    }
    panic!("tegatad did not become ready");
}
