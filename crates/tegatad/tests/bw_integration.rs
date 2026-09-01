//! These tests drive the daemon over its UNIX domain socket transport, so they
//! only exist on UNIX targets.
#![cfg(unix)]

use std::io::Write;
use std::net::{TcpListener, TcpStream};
use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};
use std::thread::sleep;
use std::time::{Duration, Instant};

use serde_json::{Value, json};
use uuid::Uuid;

mod common;
use common::{rpc, try_rpc};

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
        let tls = TlsMaterial::generate(&directory);
        let server_url = format!("https://127.0.0.1:{port}");
        let vaultwarden = Command::new("vaultwarden")
            .env("ROCKET_PORT", port.to_string())
            .env("ROCKET_TLS", tls.rocket_config())
            .env("SIGNUPS_ALLOWED", "true")
            .env("WEB_VAULT_ENABLED", "false")
            .env("DATA_FOLDER", &data_dir)
            .env("DOMAIN", &server_url)
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
                &server_url,
                "--email",
                email,
                "--password",
                &password,
            ])
            .env("NODE_EXTRA_CA_CERTS", &tls.certificate)
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
            "socket_path = {:?}\nstate_dir = {:?}\naudit_log_path = {:?}\nallowed_uids = [{}]\n\n[[providers]]\nnamespace = \"vw\"\ntype = \"bitwarden-cli\"\nserver_url = \"{server_url}\"\nemail = \"{email}\"\naskpass_cmd = \"cat {}\"\ntotp_exposable = [\"Canary TOTP\"]\n",
            socket_path,
            state_dir,
            state_dir.join("audit.log"),
            uid,
            askpass_path.display(),
        );
        std::fs::write(&config_path, config).expect("write daemon config");
        // The daemon passes its environment on to bw, which is how bw trusts the vault.
        let daemon = Command::new(env!("CARGO_BIN_EXE_tegatad"))
            .arg("--config")
            .arg(&config_path)
            .env("NODE_EXTRA_CA_CERTS", &tls.certificate)
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

/// A throwaway self-signed certificate for the test vault. bw refuses plain-http
/// servers since 2025.10, so the vault has to speak TLS; bw and the provisioning
/// tool are node programs and trust the certificate through NODE_EXTRA_CA_CERTS.
struct TlsMaterial {
    certificate: PathBuf,
    key: PathBuf,
}

impl TlsMaterial {
    fn generate(directory: &Path) -> Self {
        let certificate = directory.join("vw-cert.pem");
        let key = directory.join("vw-key.pem");
        let status = Command::new("openssl")
            .args([
                "req",
                "-x509",
                "-newkey",
                "rsa:2048",
                "-nodes",
                "-days",
                "2",
                "-subj",
                "/CN=127.0.0.1",
                "-addext",
                "subjectAltName=IP:127.0.0.1",
            ])
            .arg("-keyout")
            .arg(&key)
            .arg("-out")
            .arg(&certificate)
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .status()
            .expect("spawn openssl");
        assert!(
            status.success(),
            "openssl could not mint the test certificate"
        );
        Self { certificate, key }
    }

    /// The value Rocket reads from `ROCKET_TLS`.
    fn rocket_config(&self) -> String {
        format!(
            "{{certs=\"{}\",key=\"{}\"}}",
            self.certificate.display(),
            self.key.display()
        )
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

/// Every `lock_vault` followed by a resolve runs the full unlock ceremony again:
/// `bw unlock`, the `bw status` verification and `bw sync`. bw before 2025.12.1
/// lost its session-key persistence race in roughly a third of these.
#[ignore]
#[test]
fn bitwarden_cli_provider_survives_repeated_unlock_ceremonies() {
    let stack = TestStack::start();
    let list = rpc(&stack.socket_path, "list_credentials", json!({}));
    let totp_id = list["result"]
        .as_array()
        .expect("credential list")
        .iter()
        .find(|item| item["name"] == "Canary TOTP")
        .expect("Canary TOTP item")["id"]
        .clone();
    for ceremony in 1..=8 {
        let locked = rpc(
            &stack.socket_path,
            "lock_vault",
            json!({ "namespace": "vw" }),
        );
        assert_eq!(
            locked["result"],
            json!({ "ok": true }),
            "ceremony {ceremony}"
        );
        // Resolving the item is what unlocks the vault again. The TOTP rate limit
        // applies after the ceremony, so a RATE_LIMITED answer still proves it ran.
        let totp = rpc(
            &stack.socket_path,
            "get_totp",
            json!({ "cred_id": totp_id }),
        );
        assert!(
            totp["result"]["code"].is_string() || totp["error"]["message"] == "RATE_LIMITED",
            "ceremony {ceremony}: unexpected get_totp answer {totp}"
        );
        let list = rpc(&stack.socket_path, "list_credentials", json!({}));
        let items = list["result"].as_array().expect("credential list");
        assert_eq!(items.len(), 2, "ceremony {ceremony}");
        assert!(
            items.iter().all(|item| item["status"] == "unlocked"),
            "ceremony {ceremony}: vault still locked after the ceremony: {list}"
        );
    }
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
