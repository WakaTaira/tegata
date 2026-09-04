// 各テストバイナリが `mod common;` で取り込むため、使われないヘルパが出るバイナリでも警告にしない。
#![allow(dead_code)]

use std::io::{BufRead, BufReader, Write};
use std::os::unix::fs::PermissionsExt;
use std::os::unix::net::UnixStream;
use std::path::{Path, PathBuf};

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
