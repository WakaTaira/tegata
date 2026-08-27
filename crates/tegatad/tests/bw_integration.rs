use std::io::{BufRead, BufReader, Write};
use std::net::{TcpListener, TcpStream};
use std::os::unix::fs::PermissionsExt;
use std::os::unix::net::UnixStream;
use std::path::PathBuf;
use std::process::{Child, Command, Stdio};
use std::thread::sleep;
use std::time::{Duration, Instant};

use serde_json::{Value, json};
use uuid::Uuid;

struct ProcessGuard {
    child: Child,
}

impl Drop for ProcessGuard {
    fn drop(&mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
    }
}

struct TestStack {
    _vaultwarden: ProcessGuard,
    _tegatad: ProcessGuard,
    directory: PathBuf,
    socket_path: PathBuf,
}

impl TestStack {
    fn start() -> Self {
        let directory = std::env::temp_dir().join(format!("tegata-bw-test-{}", Uuid::new_v4()));
        std::fs::create_dir_all(&directory).expect("create test directory");
        let port = TcpListener::bind("127.0.0.1:0")
            .expect("reserve vaultwarden port")
            .local_addr()
            .expect("read vaultwarden port")
            .port();
        let data_dir = directory.join("vw-data");
        let vaultwarden = Command::new("vaultwarden")
            .env("ROCKET_PORT", port.to_string())
            .env("SIGNUPS_ALLOWED", "true")
            .env("WEB_VAULT_ENABLED", "false")
            .env("DATA_FOLDER", &data_dir)
            .env("DOMAIN", format!("http://127.0.0.1:{port}"))
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .spawn()
            .expect("spawn vaultwarden");
        let vaultwarden = ProcessGuard { child: vaultwarden };
        wait_for_port(port);

        let email = "acceptance@test.local";
        let password = format!("LEAK_CANARY_bw_{}", Uuid::new_v4().simple());
        let items = json!([
            {
                "name": "Canary TOTP",
                "uri": "http://127.0.0.1/login",
                "username": format!("LEAK_CANARY_bw_{}", Uuid::new_v4().simple()),
                "password": password,
                "totp_seed": format!("LEAK_CANARY_bw_{}", Uuid::new_v4().simple()),
            },
            {
                "name": "Canary Password",
                "uri": "http://127.0.0.1/password",
                "username": format!("LEAK_CANARY_bw_{}", Uuid::new_v4().simple()),
                "password": format!("LEAK_CANARY_bw_{}", Uuid::new_v4().simple()),
            },
        ]);
        let provisioner = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
            .join("../../packages/provision-test-vault/dist/index.js");
        assert!(
            provisioner.exists(),
            "{} is missing; run `npm run build -w @tegata/provision-test-vault` first",
            provisioner.display()
        );
        let mut provision = Command::new("node")
            .arg(&provisioner)
            .args([
                "--server",
                &format!("http://127.0.0.1:{port}"),
                "--email",
                email,
                "--password",
                &password,
            ])
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::null())
            .spawn()
            .expect("spawn provision-test-vault");
        provision
            .stdin
            .take()
            .expect("open provision stdin")
            .write_all(items.to_string().as_bytes())
            .expect("write provision items");
        let output = provision.wait_with_output().expect("wait for provisioner");
        assert!(output.status.success(), "provision-test-vault failed");
        assert_eq!(
            serde_json::from_slice::<Value>(&output.stdout).expect("parse provision result"),
            json!({ "ok": true, "created": 2 })
        );

        let askpass_path = directory.join("master-pass");
        std::fs::write(&askpass_path, format!("{password}\n")).expect("write askpass file");
        std::fs::set_permissions(&askpass_path, std::fs::Permissions::from_mode(0o600))
            .expect("set askpass permissions");
        let state_dir = directory.join("state");
        std::fs::create_dir_all(&state_dir).expect("create daemon state directory");
        let socket_path = directory.join("tegatad.sock");
        let config_path = directory.join("config.toml");
        let uid = unsafe { libc::geteuid() };
        let config = format!(
            "socket_path = {:?}\nstate_dir = {:?}\naudit_log_path = {:?}\nallowed_uids = [{}]\n\n[[providers]]\nnamespace = \"vw\"\ntype = \"bitwarden-cli\"\nserver_url = \"http://127.0.0.1:{port}\"\nemail = \"{email}\"\naskpass_cmd = \"cat {}\"\ntotp_exposable = [\"Canary TOTP\"]\n",
            socket_path,
            state_dir,
            state_dir.join("audit.log"),
            uid,
            askpass_path.display(),
        );
        std::fs::write(&config_path, config).expect("write daemon config");
        let daemon = Command::new(env!("CARGO_BIN_EXE_tegatad"))
            .arg("--config")
            .arg(&config_path)
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .spawn()
            .expect("spawn tegatad");
        let stack = Self {
            _vaultwarden: vaultwarden,
            _tegatad: ProcessGuard { child: daemon },
            directory,
            socket_path,
        };
        wait_for_daemon(&stack.socket_path);
        stack
    }
}

impl Drop for TestStack {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.directory);
    }
}

fn wait_for_port(port: u16) {
    let deadline = Instant::now() + Duration::from_secs(30);
    while Instant::now() < deadline {
        if TcpStream::connect(("127.0.0.1", port)).is_ok() {
            return;
        }
        sleep(Duration::from_millis(100));
    }
    panic!("vaultwarden did not become ready within 30 seconds");
}

fn wait_for_daemon(socket_path: &PathBuf) {
    let deadline = Instant::now() + Duration::from_secs(10);
    while Instant::now() < deadline {
        if try_rpc(socket_path, "status", json!({})).is_some() {
            return;
        }
        sleep(Duration::from_millis(20));
    }
    panic!("tegatad did not become ready");
}

fn rpc(socket_path: &PathBuf, method: &str, params: Value) -> Value {
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

fn try_rpc(socket_path: &PathBuf, method: &str, params: Value) -> Option<Value> {
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

#[ignore]
#[test]
fn bitwarden_cli_provider_round_trip() {
    let stack = TestStack::start();
    let list = rpc(&stack.socket_path, "list_credentials", json!({}));
    let items = list["result"].as_array().expect("credential list");
    assert_eq!(items.len(), 2);
    assert!(items.iter().any(|item| item["name"] == "Canary TOTP"));
    assert!(items.iter().any(|item| item["name"] == "Canary Password"));
    assert!(!list.to_string().contains("LEAK_CANARY_bw_"));

    let totp = rpc(
        &stack.socket_path,
        "get_totp",
        json!({ "cred_id": items.iter().find(|item| item["name"] == "Canary TOTP").unwrap()["id"] }),
    );
    let code = totp["result"]["code"].as_str().expect("TOTP code");
    assert_eq!(code.len(), 6);
    assert!(code.chars().all(|character| character.is_ascii_digit()));

    let locked = rpc(
        &stack.socket_path,
        "lock_vault",
        json!({ "namespace": "vw" }),
    );
    assert_eq!(locked["result"], json!({ "ok": true }));
    let list = rpc(&stack.socket_path, "list_credentials", json!({}));
    for item in list["result"].as_array().expect("locked credential list") {
        let mut keys = item
            .as_object()
            .expect("credential object")
            .keys()
            .cloned()
            .collect::<Vec<_>>();
        keys.sort();
        assert_eq!(keys, vec!["id", "name", "source", "status"]);
        assert_eq!(item["status"], "locked");
    }
}
