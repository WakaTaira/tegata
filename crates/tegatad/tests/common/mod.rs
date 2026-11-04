// 各テストバイナリが `mod common;` で取り込むため、使われないヘルパが出るバイナリでも警告にしない。
#![allow(dead_code)]

use std::io::{BufRead, BufReader, Write};
use std::os::unix::fs::PermissionsExt;
use std::os::unix::net::UnixStream;
use std::path::{Path, PathBuf};
use std::thread::sleep;
use std::time::{Duration, Instant};

use serde_json::{Value, json};

/// デーモンが state_dir に 0700・自己所有・非 symlink を要求するため、テストの state dir はこのヘルパで作成する。
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

/// 偽 executor の本文の前に置く JS。デーモンは spawn モードの起動時に executor を 1 回起動し、
/// `hello` を送ってから `shutdown` で終了させる。各偽 executor は行ハンドラの先頭で
/// `answerStartupProbe(request)` を呼び、真が返れば以降の処理を飛ばす。
/// これにより、起動時検査の往復を偽 executor の本体の処理と記録へ混ぜない。
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

/// 起動時検査にだけ答える偽 executor の本文。リース要求を受けないテストで、実際の executor を起動させないために用いる。
const PROBE_ONLY_EXECUTOR: &str = r#"
const readline = require("node:readline");
const rl = readline.createInterface({ input: process.stdin });
rl.on("line", (line) => {
  answerStartupProbe(JSON.parse(line));
});
"#;

/// 偽 executor の本文の前に、起動時検査へ答える前置きを付けた JS を返す。
pub(crate) fn fake_executor_source(script: &str) -> String {
    format!("{STARTUP_PROBE_PRELUDE}{script}")
}

/// 起動時検査にだけ答える偽 executor を `directory` に書き、そのパスを返す。
pub(crate) fn write_probe_only_executor(directory: &Path) -> PathBuf {
    let path = directory.join("probe-executor.js");
    std::fs::write(&path, fake_executor_source(PROBE_ONLY_EXECUTOR))
        .expect("write probe-only executor script");
    path
}

/// `status` に結果が返るまで最大 5 秒待つ。
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
