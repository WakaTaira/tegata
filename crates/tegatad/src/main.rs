#[cfg(windows)]
mod dpapi;
mod peers;
mod provider;
mod secure_fs;
mod sessions;
mod transport;
#[cfg(windows)]
mod windows_cli;
#[cfg(windows)]
mod windows_service;

use std::collections::HashMap;
use std::fmt;
use std::io;
use std::path::{Path, PathBuf};
use std::sync::atomic::Ordering;
use std::sync::{Arc, atomic::AtomicBool};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use clap::Parser;
use leakscan::scan_bytes;
use serde::ser::SerializeMap;
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
#[cfg(unix)]
use tegata_core::wire::{ExecutorHelloRequest, ExecutorHelloResponse};
use tegata_core::wire::{
    ExecutorLeaseRequest, ExecutorLoginRequest, ExecutorReleaseRequest, ExecutorResponse,
    ExecutorSecret, LoginParams, RpcError, RpcRequest, RpcResponse,
};
use tegata_core::{Secret, totp};
use tokio::io::{AsyncBufReadExt, AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt, BufReader};
use tokio::process::{Child, Command};
use tokio::sync::{Mutex, mpsc};
use tokio::task::JoinSet;
use tokio::time::{Instant, interval, sleep, timeout};
use uuid::Uuid;

#[cfg(windows)]
use tegata_core::wire::AdminSealParams;
#[cfg(windows)]
use zeroize::Zeroize;

#[cfg(feature = "mock-provider")]
use crate::provider::StaticProvider;
use crate::provider::{
    BitwardenCliConfig, BitwardenCliProvider, CredentialProvider, FileProvider, FileProviderConfig,
    ResolvedCredential,
};
#[cfg(unix)]
use crate::provider::{PassProvider, PassProviderConfig};
use crate::transport::{
    Accepted, CdpPortResolver, ListenConfig, PeerIdentity, PlatformConfig, PlatformTransport,
    Transport,
};

const JSON_RPC_VERSION: &str = "2.0";
const METHOD_NOT_FOUND: i32 = -32601;
const CLASSIFICATION_ERROR: i32 = -32000;
const EXECUTOR_TIMEOUT: Duration = Duration::from_secs(90);
const EXECUTOR_OPERATION_TIMEOUT: Duration = Duration::from_secs(1);
const EXECUTOR_SHUTDOWN_TIMEOUT: Duration = Duration::from_secs(1);
const EXECUTOR_LEASE_READY_DELAY: Duration = Duration::from_millis(100);
const PASSWORD_FILE_DIR: &str = ".bw-passwords";

type ReadySender = Arc<std::sync::Mutex<Option<std::sync::mpsc::SyncSender<Result<(), String>>>>>;

#[derive(Debug, Deserialize)]
struct Config {
    state_dir: String,
    audit_log_path: String,
    audit_log_max_bytes: Option<u64>,
    approve_cmd: Option<String>,
    approve_timeout_secs: Option<u64>,
    executor_entry: Option<String>,
    #[cfg(unix)]
    executor_socket: Option<String>,
    session_ttl_secs: Option<u64>,
    #[cfg(windows)]
    #[serde(default = "default_unlock_mode")]
    unlock_mode: UnlockMode,
    #[serde(default)]
    providers: Vec<ProviderConfig>,
    #[serde(default)]
    listen: Option<Vec<ListenConfig>>,
    #[serde(default = "default_max_pending_connections")]
    max_pending_connections: usize,
    /// Keys of the platform transport, read from the same top level table.
    /// Which keys those are depends on the target, so the transport module
    /// owns them.
    #[serde(flatten)]
    transport: PlatformConfig,
}

fn default_max_pending_connections() -> usize {
    8
}

fn normalize_listeners(config_text: &str, config: &Config) -> Result<Vec<ListenConfig>, io::Error> {
    let document: toml::Value = toml::from_str(config_text).map_err(|error| {
        io::Error::new(
            io::ErrorKind::InvalidData,
            format!("could not parse config: {error}"),
        )
    })?;
    let legacy_keys = [
        #[cfg(unix)]
        "socket_path",
        #[cfg(unix)]
        "allowed_uids",
        #[cfg(windows)]
        "pipe_name",
        #[cfg(windows)]
        "tcp_port",
        #[cfg(windows)]
        "tcp_bind",
        #[cfg(windows)]
        "allowed_sids",
        #[cfg(windows)]
        "operator_sid",
    ];
    if config.listen.is_some() && legacy_keys.iter().any(|key| document.get(*key).is_some()) {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "listen cannot be combined with legacy transport keys",
        ));
    }
    if let Some(listeners) = &config.listen {
        if listeners.is_empty() {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "listen must contain at least one listener",
            ));
        }
        return Ok(listeners.clone());
    }
    #[cfg(unix)]
    {
        let path = config.transport.socket_path.clone().ok_or_else(|| {
            io::Error::new(io::ErrorKind::InvalidInput, "socket_path is required")
        })?;
        let allowed_uids = config.transport.allowed_uids.clone().ok_or_else(|| {
            io::Error::new(io::ErrorKind::InvalidInput, "allowed_uids is required")
        })?;
        Ok(vec![ListenConfig::Unix {
            path,
            allowed_uids,
            operator_uids: Vec::new(),
        }])
    }
    #[cfg(windows)]
    {
        let mut listeners = vec![ListenConfig::Pipe {
            name: config.transport.pipe_name.clone(),
            allowed_sids: config.transport.allowed_sids.clone(),
            operator_sid: config.transport.operator_sid.clone(),
        }];
        if config.transport.tcp_port != 0 {
            listeners.push(ListenConfig::Tcp {
                bind: config.transport.tcp_bind.clone(),
                port: config.transport.tcp_port,
            });
        }
        return Ok(listeners);
    }
}

#[cfg(windows)]
#[derive(Clone, Copy, Debug, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "lowercase")]
enum UnlockMode {
    Sealed,
    Askpass,
}

#[cfg(windows)]
fn default_unlock_mode() -> UnlockMode {
    UnlockMode::Sealed
}

#[derive(Debug, Deserialize)]
struct ProviderConfig {
    namespace: String,
    #[serde(flatten)]
    kind: ProviderConfigKind,
}

#[derive(Debug, Deserialize)]
#[serde(tag = "type", rename_all = "kebab-case")]
enum ProviderConfigKind {
    #[cfg(feature = "mock-provider")]
    Mock {
        #[serde(default)]
        entries: Vec<EntryConfig>,
    },
    BitwardenCli {
        server_url: String,
        email: String,
        askpass_cmd: String,
        #[serde(default)]
        totp_exposable: Vec<String>,
        session_ttl_secs: Option<u64>,
    },
    AgeFile {
        entries_path: PathBuf,
        identity_path: PathBuf,
        session_ttl_secs: Option<u64>,
    },
    Pass {
        store_dir: PathBuf,
        gnupghome: Option<PathBuf>,
        #[serde(default)]
        pass_bin: Option<PathBuf>,
        #[serde(default)]
        totp_exposable: Vec<String>,
        session_ttl_secs: Option<u64>,
    },
}

#[derive(Debug, Deserialize)]
struct EntryConfig {
    id: String,
    name: String,
    uri: String,
    kind: String,
    username: String,
    password: String,
    totp_seed: Option<String>,
    totp_exposable: Option<bool>,
}

struct Provider {
    namespace: String,
    provider: Arc<Mutex<dyn CredentialProvider + Send>>,
}

enum ExecutorHandle {
    Spawned(Child),
    #[cfg(unix)]
    Socket {
        reader: Arc<Mutex<tokio::net::unix::OwnedReadHalf>>,
        writer: tokio::net::unix::OwnedWriteHalf,
    },
}

enum ExecutorReader {
    Spawned(tokio::process::ChildStdout),
    #[cfg(unix)]
    Socket(Arc<Mutex<tokio::net::unix::OwnedReadHalf>>),
}

pub(crate) struct ExecutorConnection {
    executor: Mutex<ExecutorHandle>,
    responses: Mutex<mpsc::UnboundedReceiver<io::Result<String>>>,
    operation: Mutex<()>,
}

struct DaemonState {
    providers: Vec<Provider>,
    browsers: HashMap<String, sessions::Browser>,
    shared_browsers: HashMap<sessions::BrowserKey, String>,
    start_controls: HashMap<sessions::BrowserKey, Arc<Mutex<sessions::StartControl>>>,
    last_totp: HashMap<String, Instant>,
    registry: Arc<Mutex<Vec<String>>>,
    audit_log_path: PathBuf,
    audit_log_max_bytes: Option<u64>,
    audit_rotated: AtomicBool,
    audit_lock: Arc<Mutex<()>>,
    executor_entry: PathBuf,
    executor_socket: Option<PathBuf>,
    node_path: PathBuf,
    browsers_path: Option<PathBuf>,
    cdp_ports: Arc<std::sync::RwLock<HashMap<String, (String, u16)>>>,
    session_ttl: Duration,
    provider_ttls: HashMap<String, Duration>,
    #[cfg(unix)]
    approve_cmd: Option<String>,
    #[cfg(unix)]
    approve_timeout: Duration,
    peers: peers::SharedPeerStore,
    #[cfg(windows)]
    sealed_blob_path: PathBuf,
}

type SharedState = Arc<Mutex<DaemonState>>;

// Keep in sync with packages/tegata-mcp/src/index.ts and tests/acceptance/support/harness.ts.
#[derive(Clone, Copy)]
enum ErrorCode {
    InvalidCredential,
    MfaRequired,
    SelectorNotFound,
    VaultLocked,
    RateLimited,
    TotpNotExposable,
    ApprovalDenied,
    ApprovalTimeout,
    Internal,
    NotFound,
    #[cfg(windows)]
    Unauthorized,
    AdminRequired,
    #[cfg(windows)]
    AdminSealUnavailable,
}

impl ErrorCode {
    fn as_str(self) -> &'static str {
        match self {
            Self::InvalidCredential => "INVALID_CREDENTIAL",
            Self::MfaRequired => "MFA_REQUIRED",
            Self::SelectorNotFound => "SELECTOR_NOT_FOUND",
            Self::VaultLocked => "VAULT_LOCKED",
            Self::RateLimited => "RATE_LIMITED",
            Self::TotpNotExposable => "TOTP_NOT_EXPOSABLE",
            Self::ApprovalDenied => "APPROVAL_DENIED",
            Self::ApprovalTimeout => "APPROVAL_TIMEOUT",
            Self::Internal => "INTERNAL",
            Self::NotFound => "NOT_FOUND",
            #[cfg(windows)]
            Self::Unauthorized => "UNAUTHORIZED",
            Self::AdminRequired => "ADMIN_REQUIRED",
            #[cfg(windows)]
            Self::AdminSealUnavailable => "ADMIN_SEAL_UNAVAILABLE",
        }
    }
}

enum AuditPeer<'a> {
    Peer(&'a PeerIdentity),
    System,
}

impl Serialize for AuditPeer<'_> {
    fn serialize<S: serde::Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        match self {
            Self::Peer(peer) => peer.serialize(serializer),
            Self::System => {
                let mut map = serializer.serialize_map(Some(1))?;
                map.serialize_entry("peer_system", &true)?;
                map.end()
            }
        }
    }
}

#[derive(Serialize)]
struct AuditRecord<'a> {
    ts: String,
    #[serde(flatten)]
    peer: AuditPeer<'a>,
    method: String,
    cred_id: Option<String>,
    target_url: Option<String>,
    session_id: Option<String>,
    namespace: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    shared: Option<bool>,
    outcome: String,
}

#[derive(Clone)]
struct AuditFields {
    cred_id: Option<String>,
    target_url: Option<String>,
    session_id: Option<String>,
    namespace: Option<String>,
    shared: Option<bool>,
}

#[derive(Deserialize)]
struct LoginRequestParams {
    #[serde(flatten)]
    login: LoginParams,
    #[serde(default)]
    exclusive: bool,
}

struct HandledRequest {
    response: RpcResponse,
    outcome: String,
    audit_shared: Option<bool>,
}

impl HandledRequest {
    fn with_audit_shared(mut self, shared: bool) -> Self {
        self.audit_shared = Some(shared);
        self
    }
}

#[derive(Parser)]
struct Args {
    #[arg(long)]
    config: Option<PathBuf>,
    #[cfg(windows)]
    #[arg(long)]
    foreground: bool,
    #[cfg(windows)]
    #[command(subcommand)]
    command: Option<windows_cli::WindowsCommand>,
    #[cfg(unix)]
    #[command(subcommand)]
    command: Option<UnixCommand>,
}

#[cfg(unix)]
#[derive(clap::Subcommand)]
enum UnixCommand {
    Peer {
        #[command(subcommand)]
        command: UnixPeerCommand,
    },
    Token {
        #[command(subcommand)]
        command: UnixTokenCommand,
    },
}

#[cfg(unix)]
#[derive(clap::Subcommand)]
enum UnixPeerCommand {
    Issue {
        #[arg(long)]
        label: String,
        #[arg(long, default_value = "/run/tegata/tegatad.sock")]
        socket: PathBuf,
    },
    Revoke {
        peer_id: String,
        #[arg(long, default_value = "/run/tegata/tegatad.sock")]
        socket: PathBuf,
    },
    List {
        #[arg(long, default_value = "/run/tegata/tegatad.sock")]
        socket: PathBuf,
    },
}

#[cfg(unix)]
#[derive(clap::Subcommand)]
enum UnixTokenCommand {
    Issue {
        #[arg(long, default_value = "/run/tegata/tegatad.sock")]
        socket: PathBuf,
    },
}

fn main() {
    if let Err(error) = run() {
        eprintln!("tegatad: {error}");
        std::process::exit(1);
    }
}

fn run() -> Result<(), Box<dyn std::error::Error>> {
    let args = Args::parse();
    #[cfg(windows)]
    {
        if let Some(command) = args.command {
            return match command {
                windows_cli::WindowsCommand::Status { pipe } => {
                    windows_cli::run_windows_cli(&pipe, "status", json!({}))
                }
                windows_cli::WindowsCommand::Token { command } => match command {
                    windows_cli::TokenCommand::Issue { pipe } => {
                        windows_cli::run_windows_cli(&pipe, "admin_token_issue", json!({}))
                    }
                },
                windows_cli::WindowsCommand::Peer { command } => match command {
                    windows_cli::PeerCommand::Issue { label, pipe } => {
                        windows_cli::run_windows_cli(
                            &pipe,
                            "admin_peer_issue",
                            json!({ "label": label }),
                        )
                    }
                    windows_cli::PeerCommand::Revoke { peer_id, pipe } => {
                        windows_cli::run_windows_cli(
                            &pipe,
                            "admin_peer_revoke",
                            json!({ "peer_id": peer_id }),
                        )
                    }
                    windows_cli::PeerCommand::List { pipe } => {
                        windows_cli::run_windows_cli(&pipe, "admin_peer_list", json!({}))
                    }
                },
                windows_cli::WindowsCommand::Seal { pipe } => {
                    let mut password = windows_cli::read_master_password()?;
                    let result = windows_cli::run_windows_cli(
                        &pipe,
                        "admin_seal",
                        json!({
                            "master_password": password.as_str(),
                        }),
                    );
                    password.zeroize();
                    result
                }
                windows_cli::WindowsCommand::Service { command } => match command {
                    windows_service::ServiceCommand::Install { config } => {
                        windows_service::install_service(&config)
                    }
                    windows_service::ServiceCommand::Uninstall { name } => {
                        windows_service::uninstall_service(&name)
                    }
                },
            };
        }
        let config = args.config.ok_or("--config is required")?;
        let foreground = args.foreground;
        if foreground {
            return run_daemon_runtime(&config, true, None);
        }
        windows_service::START().map_err(Into::into)
    }

    #[cfg(unix)]
    {
        if let Some(command) = args.command {
            return run_unix_command(command);
        }
        let config = args.config.ok_or("--config is required")?;
        run_daemon_runtime(&config, false, None)
    }
}

#[cfg(unix)]
fn run_unix_command(command: UnixCommand) -> Result<(), Box<dyn std::error::Error>> {
    match command {
        UnixCommand::Peer { command } => match command {
            UnixPeerCommand::Issue { label, socket } => {
                let response =
                    call_unix_rpc(&socket, "admin_peer_issue", json!({ "label": label }))?;
                let result = response
                    .get("result")
                    .ok_or("admin_peer_issue returned no result")?;
                let token = result
                    .get("token")
                    .and_then(Value::as_str)
                    .ok_or("admin_peer_issue returned no token")?;
                let peer_id = result
                    .get("peer_id")
                    .and_then(Value::as_str)
                    .ok_or("admin_peer_issue returned no peer_id")?;
                println!("{token}");
                eprintln!("{peer_id}");
            }
            UnixPeerCommand::Revoke { peer_id, socket } => {
                let _ = call_unix_rpc(&socket, "admin_peer_revoke", json!({ "peer_id": peer_id }))?;
            }
            UnixPeerCommand::List { socket } => {
                let response = call_unix_rpc(&socket, "admin_peer_list", json!({}))?;
                let result = response
                    .get("result")
                    .ok_or("admin_peer_list returned no result")?;
                println!("{}", serde_json::to_string(result)?);
            }
        },
        UnixCommand::Token { command } => match command {
            UnixTokenCommand::Issue { socket } => {
                let response = call_unix_rpc(&socket, "admin_token_issue", json!({}))?;
                let token = response
                    .get("result")
                    .and_then(|result| result.get("token"))
                    .and_then(Value::as_str)
                    .ok_or("admin_token_issue returned no token")?;
                println!("{token}");
            }
        },
    }
    Ok(())
}

#[cfg(unix)]
fn call_unix_rpc(socket_path: &Path, method: &str, params: Value) -> io::Result<Value> {
    use std::io::{BufRead, BufReader, Write};
    use std::os::unix::net::UnixStream;

    let mut stream = UnixStream::connect(socket_path)?;
    let request = json!({
        "jsonrpc": JSON_RPC_VERSION,
        "id": 1,
        "method": method,
        "params": params,
    });
    writeln!(stream, "{request}")?;
    let mut response = String::new();
    BufReader::new(stream).read_line(&mut response)?;
    let response: Value = serde_json::from_str(&response)
        .map_err(|error| io::Error::new(io::ErrorKind::InvalidData, error))?;
    if let Some(message) = response
        .get("error")
        .and_then(|error| error.get("message"))
        .and_then(Value::as_str)
    {
        return Err(io::Error::other(message.to_owned()));
    }
    Ok(response)
}

fn run_daemon_runtime(
    config_path: &Path,
    ready: bool,
    stop: Option<tokio::sync::oneshot::Receiver<()>>,
) -> Result<(), Box<dyn std::error::Error>> {
    tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()?
        .block_on(run_daemon(config_path, ready, stop, None))
}

async fn run_daemon(
    config_path: &Path,
    ready: bool,
    stop: Option<tokio::sync::oneshot::Receiver<()>>,
    ready_sender: Option<ReadySender>,
) -> Result<(), Box<dyn std::error::Error>> {
    let config_text = tokio::fs::read_to_string(config_path).await?;
    let config: Config = toml::from_str(&config_text)?;
    let listeners = normalize_listeners(&config_text, &config)?;
    remove_legacy_password_dir(Path::new(&config.state_dir)).await;
    #[cfg(windows)]
    if config.approve_cmd.is_some() {
        return Err("approve_cmd is only supported on Unix".into());
    }
    #[cfg(unix)]
    if let Some(path) = config.executor_socket.as_deref() {
        let uid = validate_executor_socket(path).await?;
        eprintln!("executor: socket {path} (uid {uid})");
    } else {
        eprintln!("executor: spawned by the daemon (browser is not isolated)");
    }
    #[cfg(windows)]
    if let Some(message) = config.providers.iter().find_map(|provider| {
        let ProviderConfigKind::Pass {
            store_dir,
            gnupghome,
            pass_bin,
            totp_exposable,
            session_ttl_secs,
        } = &provider.kind
        else {
            return None;
        };
        Some(format!(
            "pass provider is only supported on Unix (namespace={}, store_dir={}, gnupghome={:?}, pass_bin={:?}, totp_exposable={:?}, session_ttl_secs={:?})",
            provider.namespace,
            store_dir.display(),
            gnupghome,
            pass_bin,
            totp_exposable,
            session_ttl_secs,
        ))
    }) {
        return Err(message.into());
    }
    #[cfg(windows)]
    if config
        .providers
        .iter()
        .any(|provider| matches!(&provider.kind, ProviderConfigKind::AgeFile { .. }))
    {
        return Err("the age-file provider is not supported on Windows: the browser shares the service account and could read the identity file (see docs/security.md)".into());
    }
    #[cfg(windows)]
    eprintln!("executor: spawned by the daemon (browser is not isolated)");
    #[cfg(windows)]
    let _ = config.approve_timeout_secs;
    #[cfg(windows)]
    let (token_hash_path, _sealed_blob_path) = resolve_windows_paths(&config);
    #[cfg(unix)]
    let token_hash_path = PathBuf::from(&config.state_dir).join("token_hash");
    let max_pending_connections = config.max_pending_connections;
    tokio::fs::create_dir_all(&config.state_dir).await?;
    let peers_path = PathBuf::from(&config.state_dir).join("peers.json");
    let peers = peers::PeerStore::load_or_import(&peers_path, &token_hash_path)?;
    let state = Arc::new(Mutex::new(build_state(config, peers.clone())?));
    let cdp_ports = state.lock().await.cdp_ports.clone();
    let resolver: CdpPortResolver = Arc::new(move |session_id, peer| {
        cdp_ports.read().ok().and_then(|ports| {
            ports
                .get(session_id)
                .filter(|(principal, _)| principal == &peer.principal())
                .map(|(_, port)| *port)
        })
    });
    let transport = PlatformTransport::bind(
        &listeners,
        &token_hash_path,
        resolver,
        peers::authenticator(&peers),
        max_pending_connections,
    )
    .await?;
    if let Some(sender) = ready_sender
        && let Some(sender) = sender.lock().expect("service ready lock").take()
    {
        let _ = sender.send(Ok(()));
    }
    spawn_session_reaper(state.clone());
    spawn_provider_expiry_reaper(state.clone());
    if ready {
        let ready_line = r#"{"ready":true}"#;
        println!("{}", ready_line);
        std::io::Write::flush(&mut std::io::stdout())?;
    }
    serve_transport(transport, state, stop).await
}

async fn serve_transport(
    transport: PlatformTransport,
    state: SharedState,
    stop: Option<tokio::sync::oneshot::Receiver<()>>,
) -> Result<(), Box<dyn std::error::Error>> {
    let result = accept_connections(transport, state.clone(), stop).await;
    // The daemon is exiting — on a stop request, a termination signal, or a
    // transport failure. Reap every live executor before returning so
    // interrupted sessions do not leave orphaned browser processes behind.
    terminate_browsers(&state, drain_browsers(&state, None).await).await;
    result
}

#[cfg(unix)]
async fn validate_executor_socket(path: &str) -> Result<u32, io::Error> {
    use tokio::net::UnixStream;

    let mut stream = timeout(Duration::from_secs(10), UnixStream::connect(path))
        .await
        .map_err(|error| executor_socket_error(path, error))?
        .map_err(|error| executor_socket_error(path, error))?;
    let request = serde_json::to_vec(&ExecutorHelloRequest { op: "hello" })
        .map_err(|error| executor_socket_error(path, error))?;
    stream
        .write_all(&[request.as_slice(), b"\n"].concat())
        .await
        .map_err(|error| executor_socket_error(path, error))?;
    stream
        .flush()
        .await
        .map_err(|error| executor_socket_error(path, error))?;
    let mut reader = BufReader::new(stream);
    let mut response_line = String::new();
    timeout(
        Duration::from_secs(10),
        reader.read_line(&mut response_line),
    )
    .await
    .map_err(|error| executor_socket_error(path, error))?
    .map_err(|error| executor_socket_error(path, error))?;
    if response_line.is_empty() {
        return Err(executor_socket_error(path, "empty response"));
    }
    let response: ExecutorHelloResponse =
        serde_json::from_str(&response_line).map_err(|error| executor_socket_error(path, error))?;
    if !response.ok {
        return Err(executor_socket_error(path, "executor reported ok=false"));
    }
    if response.uid == Some(0) {
        return Err(io::Error::other("executor must not run as root"));
    }
    let Some(uid) = response.uid else {
        return Err(io::Error::other(
            "executor must not run as the daemon's own user",
        ));
    };
    if uid == unsafe { libc::geteuid() } {
        return Err(io::Error::other(
            "executor must not run as the daemon's own user",
        ));
    }
    Ok(uid)
}

async fn remove_legacy_password_dir(state_dir: &Path) {
    let password_dir = state_dir.join(PASSWORD_FILE_DIR);
    match tokio::fs::remove_dir_all(&password_dir).await {
        Ok(()) => {
            eprintln!(
                "removed legacy password directory {}",
                password_dir.display()
            );
        }
        Err(error) if error.kind() == io::ErrorKind::NotFound => {}
        Err(error) => eprintln!(
            "failed to remove legacy password directory {}: {error}",
            password_dir.display()
        ),
    }
}

#[cfg(unix)]
fn executor_socket_error(path: &str, error: impl fmt::Display) -> io::Error {
    io::Error::other(format!(
        "executor socket \"{path}\" is not connectable: {error}"
    ))
}

async fn accept_connections(
    mut transport: PlatformTransport,
    state: SharedState,
    mut stop: Option<tokio::sync::oneshot::Receiver<()>>,
) -> Result<(), Box<dyn std::error::Error>> {
    #[cfg(unix)]
    let (mut sigterm, mut sigint) = {
        use tokio::signal::unix::{SignalKind, signal};
        (
            signal(SignalKind::terminate())?,
            signal(SignalKind::interrupt())?,
        )
    };
    loop {
        let stopped = async {
            match stop.as_mut() {
                Some(stop) => {
                    let _ = stop.await;
                }
                None => std::future::pending::<()>().await,
            }
        };
        #[cfg(unix)]
        tokio::select! {
            result = transport.accept() => process_accepted(result?, state.clone()).await?,
            _ = stopped => break,
            _ = sigterm.recv() => break,
            _ = sigint.recv() => break,
        }
        #[cfg(windows)]
        tokio::select! {
            result = transport.accept() => process_accepted(result?, state.clone()).await?,
            _ = stopped => break,
        }
    }
    Ok(())
}

async fn process_accepted<S>(
    accepted: Accepted<S>,
    state: SharedState,
) -> Result<(), Box<dyn std::error::Error>>
where
    S: AsyncRead + AsyncWrite + Send + Unpin + 'static,
{
    if let Accepted::Rpc {
        peer,
        stream,
        operator_uids,
    } = accepted
    {
        tokio::spawn(async move {
            serve_connection(stream, peer, operator_uids, state).await;
        });
    }
    Ok(())
}

fn provider_ttl_secs(kind: &ProviderConfigKind) -> Option<u64> {
    match kind {
        #[cfg(feature = "mock-provider")]
        ProviderConfigKind::Mock { .. } => None,
        ProviderConfigKind::BitwardenCli {
            session_ttl_secs, ..
        }
        | ProviderConfigKind::AgeFile {
            session_ttl_secs, ..
        } => *session_ttl_secs,
        #[cfg(unix)]
        ProviderConfigKind::Pass {
            session_ttl_secs, ..
        } => *session_ttl_secs,
        #[cfg(windows)]
        ProviderConfigKind::Pass { .. } => None,
    }
}

fn build_state(config: Config, peers: peers::SharedPeerStore) -> Result<DaemonState, io::Error> {
    #[cfg(windows)]
    let (_, sealed_blob_path) = resolve_windows_paths(&config);
    #[cfg(windows)]
    let unlock_mode = config.unlock_mode;
    #[cfg(feature = "mock-provider")]
    let mut registry = Vec::new();
    #[cfg(not(feature = "mock-provider"))]
    let registry = Vec::new();
    let audit_log_path = PathBuf::from(&config.audit_log_path);
    let audit_log_max_bytes = config.audit_log_max_bytes;
    #[cfg(unix)]
    let approve_cmd = config.approve_cmd.clone();
    #[cfg(unix)]
    let approve_timeout = Duration::from_secs(config.approve_timeout_secs.unwrap_or(60));
    let executor_entry = resolve_executor_entry(&config);
    #[cfg(unix)]
    let executor_socket = config.executor_socket.as_deref().map(PathBuf::from);
    #[cfg(windows)]
    let executor_socket = None;
    let node_path = resolve_node_path(&config);
    let browsers_path = resolve_browsers_path(&config);
    let bw_path = resolve_bw_path(&config);
    let session_ttl = Duration::from_secs(config.session_ttl_secs.unwrap_or(300));
    let state_dir = PathBuf::from(&config.state_dir);
    let mut provider_ttls = HashMap::new();
    let providers = config
        .providers
        .into_iter()
        .map(|provider| -> Result<Provider, io::Error> {
            let namespace = provider.namespace;
            if let Some(ttl) = provider_ttl_secs(&provider.kind) {
                provider_ttls.insert(namespace.clone(), Duration::from_secs(ttl));
            }
            let provider: Arc<Mutex<dyn CredentialProvider + Send>> = match provider.kind {
                #[cfg(feature = "mock-provider")]
                ProviderConfigKind::Mock { entries } => Arc::new(Mutex::new(
                    StaticProvider::from_config(entries, &mut registry),
                )),
                ProviderConfigKind::BitwardenCli {
                    server_url,
                    email,
                    askpass_cmd,
                    totp_exposable,
                    session_ttl_secs,
                } => Arc::new(Mutex::new(BitwardenCliProvider::new(BitwardenCliConfig {
                    server_url,
                    email,
                    askpass_cmd,
                    appdata_dir: state_dir.join(format!("bw-{}", safe_path_component(&namespace))),
                    bw_path: bw_path.clone(),
                    totp_exposable,
                    session_ttl: Duration::from_secs(
                        session_ttl_secs.unwrap_or(session_ttl.as_secs()),
                    ),
                    #[cfg(windows)]
                    unlock_mode,
                    #[cfg(windows)]
                    sealed_blob_path: sealed_blob_path.clone(),
                }))),
                ProviderConfigKind::AgeFile {
                    entries_path,
                    identity_path,
                    session_ttl_secs,
                } => Arc::new(Mutex::new(FileProvider::new(FileProviderConfig {
                    entries_path,
                    identity_path,
                    session_ttl: Duration::from_secs(
                        session_ttl_secs.unwrap_or(session_ttl.as_secs()),
                    ),
                })?)),
                #[cfg(unix)]
                ProviderConfigKind::Pass {
                    store_dir,
                    gnupghome,
                    pass_bin,
                    totp_exposable,
                    session_ttl_secs,
                } => Arc::new(Mutex::new(PassProvider::new(PassProviderConfig {
                    store_dir,
                    gnupghome,
                    pass_bin,
                    totp_exposable,
                    session_ttl: Duration::from_secs(
                        session_ttl_secs.unwrap_or(session_ttl.as_secs()),
                    ),
                }))),
                #[cfg(windows)]
                ProviderConfigKind::Pass { .. } => unreachable!("pass provider was rejected above"),
            };
            Ok(Provider {
                namespace,
                provider,
            })
        })
        .collect::<Result<Vec<_>, _>>()?;
    Ok(DaemonState {
        providers,
        browsers: HashMap::new(),
        shared_browsers: HashMap::new(),
        start_controls: HashMap::new(),
        last_totp: HashMap::new(),
        registry: Arc::new(Mutex::new(registry)),
        audit_log_path,
        audit_log_max_bytes,
        audit_rotated: AtomicBool::new(false),
        audit_lock: Arc::new(Mutex::new(())),
        executor_entry,
        executor_socket,
        node_path,
        browsers_path,
        cdp_ports: Arc::new(std::sync::RwLock::new(HashMap::new())),
        session_ttl,
        provider_ttls,
        #[cfg(unix)]
        approve_cmd,
        #[cfg(unix)]
        approve_timeout,
        peers,
        #[cfg(windows)]
        sealed_blob_path,
    })
}

fn safe_path_component(value: &str) -> String {
    value
        .chars()
        .map(|character| {
            if character.is_ascii_alphanumeric() || character == '-' || character == '_' {
                character
            } else {
                '_'
            }
        })
        .collect()
}

/// Resolves the executor entry from configuration, then `TEGATA_EXECUTOR_ENTRY`,
/// and finally `current_exe()/../../../packages/tegata-executor/dist/index.js`.
fn resolve_executor_entry(config: &Config) -> PathBuf {
    if let Some(entry) = config.executor_entry.as_deref() {
        return PathBuf::from(entry);
    }
    if let Ok(entry) = std::env::var("TEGATA_EXECUTOR_ENTRY")
        && !entry.is_empty()
    {
        return PathBuf::from(entry);
    }
    std::env::current_exe()
        .unwrap_or_else(|_| PathBuf::from("tegatad"))
        .join("../../../packages/tegata-executor/dist/index.js")
}

fn resolve_node_path(config: &Config) -> PathBuf {
    #[cfg(windows)]
    {
        config
            .transport
            .node_path
            .as_deref()
            .map(PathBuf::from)
            .unwrap_or_else(|| PathBuf::from("node"))
    }
    #[cfg(not(windows))]
    {
        let _ = config;
        PathBuf::from("node")
    }
}

fn resolve_browsers_path(config: &Config) -> Option<PathBuf> {
    #[cfg(windows)]
    {
        config.transport.browsers_path.as_deref().map(PathBuf::from)
    }
    #[cfg(not(windows))]
    {
        let _ = config;
        None
    }
}

fn resolve_bw_path(config: &Config) -> Option<PathBuf> {
    #[cfg(windows)]
    {
        config.transport.bw_path.as_deref().map(PathBuf::from)
    }
    #[cfg(not(windows))]
    {
        let _ = config;
        None
    }
}

#[cfg(windows)]
fn resolve_windows_paths(config: &Config) -> (PathBuf, PathBuf) {
    let state_dir = Path::new(&config.state_dir);
    let token_hash_path = config
        .transport
        .token_hash_path
        .as_deref()
        .map(PathBuf::from)
        .unwrap_or_else(|| state_dir.join("token_hash"));
    let sealed_blob_path = config
        .transport
        .sealed_blob_path
        .as_deref()
        .map(PathBuf::from)
        .unwrap_or_else(|| state_dir.join("sealed.blob"));
    (token_hash_path, sealed_blob_path)
}

fn spawn_session_reaper(state: SharedState) {
    tokio::spawn(async move {
        let mut ticker = interval(Duration::from_secs(1));
        loop {
            ticker.tick().await;
            let expired = {
                let mut daemon = state.lock().await;
                let now = Instant::now();
                let mut expired = Vec::new();
                let browser_ids = daemon.browsers.keys().cloned().collect::<Vec<_>>();
                for browser_id in browser_ids {
                    let mut removed_ids = Vec::new();
                    {
                        let Some(browser) = daemon.browsers.get_mut(&browser_id) else {
                            continue;
                        };
                        let lease_ids = browser
                            .leases
                            .iter()
                            .filter_map(|(id, lease)| {
                                (lease.expires_at <= now).then_some(id.clone())
                            })
                            .collect::<Vec<_>>();
                        for session_id in lease_ids {
                            let Some(lease) = browser.leases.remove(&session_id) else {
                                continue;
                            };
                            removed_ids.push(session_id.clone());
                            expired.push((
                                session_id,
                                lease,
                                browser.executor.clone(),
                                browser.key.namespace.clone(),
                                browser.leases.is_empty(),
                            ));
                        }
                    }
                    if let Ok(mut ports) = daemon.cdp_ports.write() {
                        for session_id in removed_ids {
                            ports.remove(&session_id);
                        }
                    }
                }
                let empty_browsers = daemon
                    .browsers
                    .iter()
                    .filter_map(|(id, browser)| browser.leases.is_empty().then_some(id.clone()))
                    .collect::<Vec<_>>();
                for browser_id in empty_browsers {
                    if let Some(browser) = daemon.browsers.remove(&browser_id)
                        && !browser.exclusive
                    {
                        daemon.shared_browsers.remove(&browser.key);
                    }
                }
                expired
            };
            for (session_id, lease, executor, namespace, shutdown) in expired {
                let release_failed = executor_release(&executor, lease.target_id).await.is_err();
                if shutdown || release_failed {
                    shutdown_executor(executor).await;
                }
                let daemon = state.lock().await;
                if let Err(error) = append_audit(
                    &daemon,
                    AuditPeer::System,
                    "session_expired".to_owned(),
                    AuditFields {
                        cred_id: None,
                        target_url: None,
                        session_id: Some(session_id),
                        namespace: Some(namespace),
                        shared: None,
                    },
                    "ok".to_owned(),
                )
                .await
                {
                    eprintln!("tegatad: audit append failed: {error}");
                }
            }
        }
    });
}

fn spawn_provider_expiry_reaper(state: SharedState) {
    tokio::spawn(async move {
        let mut ticker = interval(Duration::from_secs(1));
        loop {
            ticker.tick().await;
            let providers = {
                let daemon = state.lock().await;
                daemon
                    .providers
                    .iter()
                    .map(|provider| (provider.namespace.clone(), provider.provider.clone()))
                    .collect::<Vec<_>>()
            };
            for (namespace, provider) in providers {
                let mut provider = provider.lock().await;
                let _ = provider.expire().await;
                let autolocked = provider.take_autolock_event();
                drop(provider);
                if autolocked {
                    audit_provider_autolock(&state, namespace).await;
                }
            }
        }
    });
}

async fn audit_provider_autolock(state: &SharedState, namespace: String) {
    let daemon = state.lock().await;
    if let Err(error) = append_audit(
        &daemon,
        AuditPeer::System,
        "vault_autolocked".to_owned(),
        AuditFields {
            cred_id: None,
            target_url: None,
            session_id: None,
            namespace: Some(namespace),
            shared: None,
        },
        "ok".to_owned(),
    )
    .await
    {
        eprintln!("tegatad: audit append failed: {error}");
    }
}

async fn serve_connection<S>(
    stream: S,
    peer: PeerIdentity,
    operator_uids: Vec<u32>,
    state: SharedState,
) where
    S: AsyncRead + AsyncWrite + Send + Unpin,
{
    let (read_half, mut write_half) = tokio::io::split(stream);
    let mut lines = BufReader::new(read_half).lines();
    while let Ok(Some(line)) = lines.next_line().await {
        let parsed = serde_json::from_str::<RpcRequest>(&line);
        let (request, response, outcome, fields) = match parsed {
            Ok(request) => {
                let fields = audit_fields(&request.params);
                let handled = handle_request(&request, state.clone(), &peer, &operator_uids).await;
                let mut fields = fields;
                if request.method == "login"
                    && handled.outcome == "ok"
                    && let Some(result) = handled.response.result.as_ref()
                {
                    fields.session_id = result
                        .get("session_id")
                        .and_then(Value::as_str)
                        .map(ToOwned::to_owned);
                    fields.shared = handled.audit_shared;
                }
                (Some(request), handled.response, handled.outcome, fields)
            }
            Err(_) => (
                None,
                error_response(Value::Null, ErrorCode::Internal),
                ErrorCode::Internal.as_str().to_owned(),
                AuditFields {
                    cred_id: None,
                    target_url: None,
                    session_id: None,
                    namespace: None,
                    shared: None,
                },
            ),
        };
        let method = request
            .as_ref()
            .map(|request| request.method.clone())
            .unwrap_or_default();
        if write_response(
            &mut write_half,
            &response,
            &state,
            &peer,
            method,
            fields,
            outcome,
        )
        .await
        .is_err()
        {
            break;
        }
    }
}

async fn write_response<W: AsyncWrite + Unpin>(
    writer: &mut W,
    response: &RpcResponse,
    state: &SharedState,
    peer: &PeerIdentity,
    method: String,
    fields: AuditFields,
    outcome: String,
) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    let daemon = state.lock().await;
    let mut response_bytes = serde_json::to_vec(response)?;
    let registry = daemon.registry.lock().await;
    let leaked = scan_bytes(&response_bytes, registry.as_slice());
    drop(registry);
    let final_outcome = if leaked.is_empty() {
        outcome
    } else {
        if let Err(error) = append_audit(
            &daemon,
            AuditPeer::Peer(peer),
            method.clone(),
            fields.clone(),
            ErrorCode::Internal.as_str().to_owned(),
        )
        .await
        {
            eprintln!("tegatad: audit append failed: {error}");
        }
        response_bytes =
            serde_json::to_vec(&error_response(response.id.clone(), ErrorCode::Internal))?;
        ErrorCode::Internal.as_str().to_owned()
    };
    if leaked.is_empty()
        && let Err(error) = append_audit(
            &daemon,
            AuditPeer::Peer(peer),
            method,
            fields,
            final_outcome,
        )
        .await
    {
        eprintln!("tegatad: audit append failed: {error}");
    }
    drop(daemon);
    response_bytes.push(b'\n');
    writer.write_all(&response_bytes).await?;
    writer.flush().await?;
    Ok(())
}

#[derive(Debug)]
enum AppendAuditError {
    Open(io::Error),
    Serialize(serde_json::Error),
    Write(io::Error),
}

impl fmt::Display for AppendAuditError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Open(error) => write!(formatter, "could not open audit log: {error}"),
            Self::Serialize(error) => {
                write!(formatter, "could not serialize audit record: {error}")
            }
            Self::Write(error) => write!(formatter, "could not write audit log: {error}"),
        }
    }
}

impl std::error::Error for AppendAuditError {}

async fn append_audit(
    state: &DaemonState,
    peer: AuditPeer<'_>,
    method: String,
    fields: AuditFields,
    outcome: String,
) -> Result<(), AppendAuditError> {
    let _guard = state.audit_lock.lock().await;
    let record = AuditRecord {
        ts: SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map(|duration| format!("unix:{}", duration.as_secs()))
            .unwrap_or_else(|_| "unix:0".to_owned()),
        peer,
        method,
        cred_id: fields.cred_id,
        target_url: fields.target_url,
        session_id: fields.session_id,
        namespace: fields.namespace,
        shared: fields.shared,
        outcome,
    };
    let mut bytes = serde_json::to_vec(&record).map_err(AppendAuditError::Serialize)?;
    bytes.push(b'\n');
    let current_size = match tokio::fs::metadata(&state.audit_log_path).await {
        Ok(metadata) => metadata.len(),
        Err(error) if error.kind() == io::ErrorKind::NotFound => 0,
        Err(error) => return Err(AppendAuditError::Open(error)),
    };
    if let Some(max_bytes) = state.audit_log_max_bytes
        && !state.audit_rotated.load(Ordering::Relaxed)
        && (current_size > max_bytes || current_size.saturating_add(bytes.len() as u64) > max_bytes)
        && current_size > 0
    {
        let rotated_path = PathBuf::from(format!("{}.1", state.audit_log_path.display()));
        match tokio::fs::remove_file(&rotated_path).await {
            Ok(()) => {}
            Err(error) if error.kind() == io::ErrorKind::NotFound => {}
            Err(error) => return Err(AppendAuditError::Open(error)),
        }
        tokio::fs::rename(&state.audit_log_path, rotated_path)
            .await
            .map_err(AppendAuditError::Open)?;
        state.audit_rotated.store(true, Ordering::Relaxed);
    }
    let mut file = match secure_fs::create_private_file(&state.audit_log_path).await {
        Ok(file) => {
            drop(file);
            tokio::fs::OpenOptions::new()
                .append(true)
                .open(&state.audit_log_path)
                .await
        }
        Err(error) if error.kind() == io::ErrorKind::AlreadyExists => {
            tokio::fs::OpenOptions::new()
                .append(true)
                .open(&state.audit_log_path)
                .await
        }
        Err(error) => Err(error),
    }
    .map_err(AppendAuditError::Open)?;
    file.write_all(&bytes)
        .await
        .map_err(AppendAuditError::Write)
}

async fn handle_request(
    request: &RpcRequest,
    state: SharedState,
    peer: &PeerIdentity,
    operator_uids: &[u32],
) -> HandledRequest {
    if request.jsonrpc != JSON_RPC_VERSION {
        return classified(request.id.clone(), ErrorCode::Internal);
    }
    if request.method.starts_with("admin_") {
        if !peer.allows_admin_rpc(operator_uids) {
            return classified(request.id.clone(), ErrorCode::AdminRequired);
        }
        return match request.method.as_str() {
            "admin_peer_issue" => admin_peer_issue(request, state).await,
            "admin_peer_revoke" => admin_peer_revoke(request, state).await,
            "admin_peer_list" => admin_peer_list(request, state).await,
            "admin_token_issue" => admin_token_issue(request, state).await,
            #[cfg(windows)]
            "admin_seal" => admin_seal(request, state).await,
            _ => classified(request.id.clone(), ErrorCode::Internal),
        };
    }
    #[cfg(windows)]
    if !peer.allows_normal_rpc() {
        return classified(request.id.clone(), ErrorCode::Unauthorized);
    }
    match request.method.as_str() {
        "status" => status(request, state).await,
        "list_credentials" => list_credentials(request, state).await,
        "login" => login(request, state, peer).await,
        "logout" => logout(request, state, peer).await,
        "get_totp" => get_totp(request, state).await,
        "lock_vault" => lock_vault(request, state).await,
        _ => HandledRequest {
            response: RpcResponse {
                jsonrpc: JSON_RPC_VERSION,
                id: request.id.clone(),
                result: None,
                error: Some(RpcError {
                    code: METHOD_NOT_FOUND,
                    message: "method not found".to_owned(),
                }),
            },
            outcome: "method_not_found".to_owned(),
            audit_shared: None,
        },
    }
}

async fn admin_token_issue(request: &RpcRequest, state: SharedState) -> HandledRequest {
    issue_peer_with_label(request, state, "default".to_owned()).await
}

#[derive(Deserialize)]
struct AdminPeerIssueParams {
    label: String,
}

#[derive(Deserialize)]
struct AdminPeerRevokeParams {
    peer_id: String,
}

async fn issue_peer_with_label(
    request: &RpcRequest,
    state: SharedState,
    label: String,
) -> HandledRequest {
    if label.is_empty() {
        return classified(request.id.clone(), ErrorCode::Internal);
    }
    let peers = state.lock().await.peers.clone();
    let issued = match peers::issue(&peers, &label) {
        Ok(issued) => issued,
        Err(_) => return classified(request.id.clone(), ErrorCode::Internal),
    };
    success(
        request.id.clone(),
        json!({ "peer_id": issued.peer_id, "token": issued.token }),
    )
}

async fn admin_peer_issue(request: &RpcRequest, state: SharedState) -> HandledRequest {
    let params = match parse_params::<AdminPeerIssueParams>(&request.params) {
        Ok(params) => params,
        Err(error) => return classified(request.id.clone(), error),
    };
    if params.label.is_empty() {
        return classified(request.id.clone(), ErrorCode::Internal);
    }
    issue_peer_with_label(request, state, params.label).await
}

async fn admin_peer_revoke(request: &RpcRequest, state: SharedState) -> HandledRequest {
    let params = match parse_params::<AdminPeerRevokeParams>(&request.params) {
        Ok(params) => params,
        Err(error) => return classified(request.id.clone(), error),
    };
    let peers = state.lock().await.peers.clone();
    match peers::revoke(&peers, &params.peer_id) {
        Ok(true) => {
            terminate_peer_leases(state, &params.peer_id).await;
            success(request.id.clone(), json!({ "ok": true }))
        }
        Ok(false) => classified(request.id.clone(), ErrorCode::NotFound),
        Err(_) => classified(request.id.clone(), ErrorCode::Internal),
    }
}

async fn admin_peer_list(request: &RpcRequest, state: SharedState) -> HandledRequest {
    let peers = state.lock().await.peers.clone();
    let peers = match peers::list(&peers) {
        Ok(peers) => peers,
        Err(_) => return classified(request.id.clone(), ErrorCode::Internal),
    };
    success(
        request.id.clone(),
        json!(
            peers
                .into_iter()
                .map(|peer| json!({
                    "peer_id": peer.peer_id,
                    "label": peer.label,
                    "issued_at": peer.issued_at,
                    "revoked_at": peer.revoked_at,
                }))
                .collect::<Vec<_>>()
        ),
    )
}

#[cfg(windows)]
async fn admin_seal(request: &RpcRequest, state: SharedState) -> HandledRequest {
    let mut params: AdminSealParams = match parse_params(&request.params) {
        Ok(params) => params,
        Err(error) => return classified(request.id.clone(), error),
    };
    let path = state.lock().await.sealed_blob_path.clone();
    // The serde-owned RPC line and Value clones may retain copies of the password beyond this handler.
    let mut master_password = std::mem::take(&mut params.master_password);
    let result = seal_master_password(&mut master_password, &path);
    master_password.zeroize();
    match result {
        Ok(()) => success(request.id.clone(), json!({ "ok": true })),
        Err(error) => classified(request.id.clone(), error),
    }
}

#[cfg(windows)]
fn seal_master_password(
    master_password: &mut String,
    sealed_blob_path: &Path,
) -> Result<(), ErrorCode> {
    dpapi::seal(master_password, sealed_blob_path).map_err(|_| ErrorCode::AdminSealUnavailable)
}

async fn list_credentials(request: &RpcRequest, state: SharedState) -> HandledRequest {
    let namespace = match optional_namespace(&request.params) {
        Ok(namespace) => namespace,
        Err(error) => return classified(request.id.clone(), error),
    };
    let providers = {
        let daemon = state.lock().await;
        daemon
            .providers
            .iter()
            .filter(|provider| {
                namespace
                    .as_deref()
                    .is_none_or(|requested| requested == provider.namespace)
            })
            .map(|provider| (provider.namespace.clone(), provider.provider.clone()))
            .collect::<Vec<_>>()
    };
    let mut result = Vec::new();
    for (provider_namespace, provider) in providers {
        let (refs_result, locked, autolocked) = {
            let mut provider = provider.lock().await;
            let refs_result = provider.list_refs().await;
            let autolocked = provider.take_autolock_event();
            (refs_result, provider.locked(), autolocked)
        };
        if autolocked {
            audit_provider_autolock(&state, provider_namespace.clone()).await;
        }
        let refs = match refs_result {
            Ok(refs) => refs,
            Err(error) => return classified(request.id.clone(), error),
        };
        for credential in refs {
            let id = format!("{provider_namespace}:{}", credential.id);
            if locked {
                result.push(json!({
                    "id": id,
                    "name": credential.name,
                    "source": provider_namespace,
                    "status": "locked",
                }));
            } else {
                result.push(json!({
                    "id": id,
                    "name": credential.name,
                    "uri": credential.uri.unwrap_or_default(),
                    "kind": credential.kind.unwrap_or_default(),
                    "source": provider_namespace,
                    "status": "unlocked",
                }));
            }
        }
    }
    success(request.id.clone(), Value::Array(result))
}

async fn status(request: &RpcRequest, state: SharedState) -> HandledRequest {
    let daemon = state.lock().await;
    let leases = daemon
        .browsers
        .values()
        .map(|browser| browser.leases.len())
        .sum::<usize>();
    success(
        request.id.clone(),
        json!({ "ok": true, "browsers": daemon.browsers.len(), "leases": leases }),
    )
}

async fn join_browser(
    state: &SharedState,
    key: &sessions::BrowserKey,
    principal: &str,
) -> Option<Result<Value, ErrorCode>> {
    let (browser_id, executor, endpoint, ttl) = {
        let daemon = state.lock().await;
        let browser_id = daemon.shared_browsers.get(key)?.clone();
        let browser = daemon.browsers.get(&browser_id)?;
        (
            browser_id,
            browser.executor.clone(),
            browser.endpoint.clone(),
            daemon
                .provider_ttls
                .get(&key.namespace)
                .copied()
                .unwrap_or(daemon.session_ttl),
        )
    };
    let target_id = match executor_lease(&executor).await {
        Ok(target_id) => target_id,
        Err(error) => return Some(Err(error)),
    };
    // Executor は lease 応答後も CDP guard の target 初期化を継続するため、直後の release との競合を避けます。
    sleep(EXECUTOR_LEASE_READY_DELAY).await;
    let session_id = Uuid::new_v4().to_string();
    let lease = sessions::Lease {
        principal: principal.to_owned(),
        expires_at: Instant::now() + ttl,
        target_id: target_id.clone(),
    };
    let mut daemon = state.lock().await;
    let Some(cdp_port) = daemon
        .browsers
        .get(&browser_id)
        .map(|browser| browser.cdp_port)
    else {
        drop(daemon);
        let _ = executor_release(&executor, target_id).await;
        return None;
    };
    daemon
        .browsers
        .get_mut(&browser_id)
        .expect("browser checked above")
        .leases
        .insert(session_id.clone(), lease);
    if let Ok(mut ports) = daemon.cdp_ports.write() {
        ports.insert(session_id.clone(), (principal.to_owned(), cdp_port));
    }
    Some(Ok(json!({
        "session_id": session_id,
        "target_id": target_id,
        "channel": { "kind": "cdp", "endpoint": endpoint },
    })))
}

async fn login(request: &RpcRequest, state: SharedState, peer: &PeerIdentity) -> HandledRequest {
    let request_params = match parse_params::<LoginRequestParams>(&request.params) {
        Ok(params) => params,
        Err(error) => return classified(request.id.clone(), error),
    };
    let params = request_params.login;
    let Some((namespace, _)) = params.cred_id.split_once(':') else {
        return classified(request.id.clone(), ErrorCode::InvalidCredential);
    };
    let namespace = namespace.to_owned();
    let principal = peer.principal();
    let key = sessions::BrowserKey::new(principal.clone(), namespace, params.cred_id.clone());
    if !request_params.exclusive
        && let Some(result) = join_browser(&state, &key, &principal).await
    {
        return match result {
            Ok(result) => success(request.id.clone(), result).with_audit_shared(true),
            Err(error) => classified(request.id.clone(), error),
        };
    }
    let start_gate = {
        let mut daemon = state.lock().await;
        daemon
            .start_controls
            .entry(key.clone())
            .or_insert_with(|| Arc::new(Mutex::new(sessions::StartControl::new())))
            .clone()
    };
    let mut start_guard = start_gate.lock().await;
    if !request_params.exclusive
        && let Some(result) = join_browser(&state, &key, &principal).await
    {
        return match result {
            Ok(result) => success(request.id.clone(), result).with_audit_shared(true),
            Err(error) => classified(request.id.clone(), error),
        };
    }
    {
        let now = Instant::now();
        start_guard.prune_attempts(now);
        if start_guard.attempts.len() >= 3 || start_guard.retry_at.is_some_and(|retry| retry > now)
        {
            return classified(request.id.clone(), ErrorCode::RateLimited);
        }
    }
    #[cfg(unix)]
    if state.lock().await.approve_cmd.is_some() {
        let credential_state = match credential_state(&state, &params.cred_id).await {
            Ok(Some(locked)) => locked,
            Ok(None) => return classified(request.id.clone(), ErrorCode::InvalidCredential),
            Err(error) => return classified(request.id.clone(), error),
        };
        if credential_state {
            return classified(request.id.clone(), ErrorCode::VaultLocked);
        }
        if let Err(error) = approve_login(&state, &params, peer).await {
            return classified(request.id.clone(), error);
        }
    }
    let (credential, executor_entry, executor_socket, node_path, browsers_path, ttl) = {
        let credential = match resolve_credential(&state, &params.cred_id).await {
            Ok(Some(credential)) => credential,
            Ok(None) => return classified(request.id.clone(), ErrorCode::InvalidCredential),
            Err(error) => return classified(request.id.clone(), error),
        };
        if credential.locked {
            return classified(request.id.clone(), ErrorCode::VaultLocked);
        }
        let daemon = state.lock().await;
        (
            credential,
            daemon.executor_entry.clone(),
            daemon.executor_socket.clone(),
            daemon.node_path.clone(),
            daemon.browsers_path.clone(),
            daemon
                .provider_ttls
                .get(&key.namespace)
                .copied()
                .unwrap_or(daemon.session_ttl),
        )
    };
    {
        start_guard.prune_attempts(Instant::now());
        start_guard.attempts.push(Instant::now());
    }
    let (endpoint, target_id, mut executor) = match start_executor(
        &executor_entry,
        executor_socket.as_deref(),
        &node_path,
        browsers_path.as_deref(),
        &params,
        &credential,
    )
    .await
    {
        Ok(result) => {
            start_guard.consecutive_failures = 0;
            start_guard.retry_at = None;
            result
        }
        Err(error) => {
            start_guard.consecutive_failures += 1;
            let delay = match start_guard.consecutive_failures {
                1 => 2,
                2 => 5,
                _ => 15,
            };
            start_guard.retry_at = Some(Instant::now() + Duration::from_secs(delay));
            return classified(request.id.clone(), error);
        }
    };
    let session_id = Uuid::new_v4().to_string();
    let reader = executor
        .take_reader()
        .ok_or_else(|| io::Error::other("executor stdout or socket reader is unavailable"));
    let reader = match reader {
        Ok(reader) => reader,
        Err(_) => {
            stop_child(executor).await;
            return classified(request.id.clone(), ErrorCode::Internal);
        }
    };
    let Some(cdp_port) = cdp_port_from_endpoint(&endpoint) else {
        stop_child(executor).await;
        return classified(request.id.clone(), ErrorCode::Internal);
    };
    let (response_sender, response_receiver) = mpsc::unbounded_channel();
    let connection = Arc::new(ExecutorConnection {
        executor: Mutex::new(executor),
        responses: Mutex::new(response_receiver),
        operation: Mutex::new(()),
    });
    let browser_id = Uuid::new_v4().to_string();
    let response_target_id = target_id.clone();
    let browser = sessions::Browser {
        key: key.clone(),
        executor: connection.clone(),
        cdp_port,
        endpoint: endpoint.clone(),
        leases: HashMap::from([(
            session_id.clone(),
            sessions::Lease {
                principal: principal.clone(),
                expires_at: Instant::now() + ttl,
                target_id,
            },
        )]),
        exclusive: request_params.exclusive,
    };
    let cdp_ports = state.lock().await.cdp_ports.clone();
    if let Ok(mut ports) = cdp_ports.write() {
        ports.insert(session_id.clone(), (principal, cdp_port));
    } else {
        shutdown_executor(connection).await;
        return classified(request.id.clone(), ErrorCode::Internal);
    }
    let mut daemon = state.lock().await;
    daemon.browsers.insert(browser_id.clone(), browser);
    if !request_params.exclusive {
        daemon.shared_browsers.insert(key, browser_id.clone());
    }
    drop(daemon);
    spawn_executor_reaper(state.clone(), browser_id, reader, response_sender);
    success(
        request.id.clone(),
        json!({
            "session_id": session_id,
            "target_id": response_target_id,
            "channel": { "kind": "cdp", "endpoint": endpoint },
        }),
    )
    .with_audit_shared(false)
}

#[cfg(unix)]
async fn credential_state(state: &SharedState, cred_id: &str) -> Result<Option<bool>, ErrorCode> {
    let Some((namespace, entry_id)) = cred_id.split_once(':') else {
        return Ok(None);
    };
    let provider = {
        let daemon = state.lock().await;
        let Some(provider) = daemon
            .providers
            .iter()
            .find(|provider| provider.namespace == namespace)
        else {
            return Ok(None);
        };
        provider.provider.clone()
    };
    let mut provider = provider.lock().await;
    let refs_result = provider.list_refs().await;
    let autolocked = provider.take_autolock_event();
    let locked = provider.locked();
    drop(provider);
    if autolocked {
        audit_provider_autolock(state, namespace.to_owned()).await;
    }
    let refs = refs_result?;
    if refs.iter().any(|credential| credential.id == entry_id) {
        return Ok(Some(false));
    }
    if locked && refs.is_empty() {
        return Ok(Some(false));
    }
    Ok(None)
}

#[cfg(unix)]
async fn approve_login(
    state: &SharedState,
    params: &LoginParams,
    peer: &PeerIdentity,
) -> Result<(), ErrorCode> {
    let (approve_cmd, approve_timeout) = {
        let daemon = state.lock().await;
        (daemon.approve_cmd.clone(), daemon.approve_timeout)
    };
    let Some(approve_cmd) = approve_cmd else {
        return Ok(());
    };
    let peer_uid = match peer {
        PeerIdentity::Uid(uid) => uid.to_string(),
        _ => peer.principal(),
    };
    let mut command = Command::new("sh");
    command
        .args(["-c", approve_cmd.as_str()])
        .env("TEGATA_CRED_ID", &params.cred_id)
        .env("TEGATA_TARGET_URL", &params.target_url)
        .env("TEGATA_PEER", peer_uid)
        .stdin(std::process::Stdio::null())
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::null());
    use std::os::unix::process::CommandExt;
    command.as_std_mut().process_group(0);
    let mut child = command.spawn().map_err(|_| ErrorCode::Internal)?;
    match timeout(approve_timeout, child.wait()).await {
        Ok(Ok(status)) if status.success() => Ok(()),
        Ok(Ok(_)) => Err(ErrorCode::ApprovalDenied),
        Ok(Err(_)) => Err(ErrorCode::Internal),
        Err(_) => {
            kill_process_group(&child);
            let _ = child.wait().await;
            Err(ErrorCode::ApprovalTimeout)
        }
    }
}

async fn logout(request: &RpcRequest, state: SharedState, peer: &PeerIdentity) -> HandledRequest {
    let session_id = match required_string_param(&request.params, "session_id") {
        Ok(session_id) => session_id,
        Err(error) => return classified(request.id.clone(), error),
    };
    let principal = peer.principal();
    let removed = {
        let mut daemon = state.lock().await;
        let browser_id = daemon.browsers.iter().find_map(|(id, browser)| {
            browser
                .leases
                .get(&session_id)
                .filter(|lease| lease.principal == principal)
                .map(|_| id.clone())
        });
        let Some(browser_id) = browser_id else {
            return classified(request.id.clone(), ErrorCode::NotFound);
        };
        let (lease, executor, empty, namespace) = {
            let browser = daemon
                .browsers
                .get_mut(&browser_id)
                .expect("browser exists");
            let lease = browser.leases.remove(&session_id).expect("lease exists");
            let executor = browser.executor.clone();
            let empty = browser.leases.is_empty();
            let namespace = browser.key.namespace.clone();
            (lease, executor, empty, namespace)
        };
        if empty {
            let browser = daemon.browsers.remove(&browser_id).expect("browser exists");
            if !browser.exclusive {
                daemon.shared_browsers.remove(&browser.key);
            }
        }
        let _ = daemon
            .cdp_ports
            .write()
            .map(|mut ports| ports.remove(&session_id));
        Some((lease, executor, empty, namespace))
    };
    if let Some((lease, executor, empty, _)) = removed {
        let release_failed = executor_release(&executor, lease.target_id).await.is_err();
        if empty || release_failed {
            shutdown_executor(executor).await;
        }
    }
    success(request.id.clone(), json!({ "ok": true }))
}

async fn get_totp(request: &RpcRequest, state: SharedState) -> HandledRequest {
    let cred_id = match required_string_param(&request.params, "cred_id") {
        Ok(cred_id) => cred_id,
        Err(error) => return classified(request.id.clone(), error),
    };
    let credential = match resolve_credential(&state, &cred_id).await {
        Ok(Some(credential)) => credential,
        Ok(None) => return classified(request.id.clone(), ErrorCode::TotpNotExposable),
        Err(error) => return classified(request.id.clone(), error),
    };
    if credential.locked {
        return classified(request.id.clone(), ErrorCode::VaultLocked);
    }
    let Some(seed) = credential.totp_seed else {
        return classified(request.id.clone(), ErrorCode::TotpNotExposable);
    };
    if !credential.totp_exposable {
        return classified(request.id.clone(), ErrorCode::TotpNotExposable);
    }
    let mut daemon = state.lock().await;
    if daemon
        .last_totp
        .get(&cred_id)
        .is_some_and(|last| last.elapsed() < Duration::from_secs(30))
    {
        return classified(request.id.clone(), ErrorCode::RateLimited);
    }
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|duration| duration.as_secs())
        .unwrap_or(0);
    let (code, expires_in) = totp(seed.as_str(), now);
    daemon.last_totp.insert(cred_id, Instant::now());
    success(
        request.id.clone(),
        json!({ "code": code, "expires_in": expires_in }),
    )
}

async fn lock_vault(request: &RpcRequest, state: SharedState) -> HandledRequest {
    let namespace = match optional_namespace(&request.params) {
        Ok(namespace) => namespace,
        Err(error) => return classified(request.id.clone(), error),
    };
    let providers = {
        let daemon = state.lock().await;
        daemon
            .providers
            .iter()
            .filter(|provider| {
                namespace
                    .as_deref()
                    .is_none_or(|requested| requested == provider.namespace)
            })
            .map(|provider| provider.provider.clone())
            .collect::<Vec<_>>()
    };
    for provider in providers {
        let mut provider = provider.lock().await;
        if let Err(error) = provider.lock().await {
            return classified(request.id.clone(), error);
        }
    }
    let browsers = drain_browsers(&state, namespace.as_deref()).await;
    terminate_browsers(&state, browsers).await;
    success(request.id.clone(), json!({ "ok": true }))
}

async fn drain_browsers(state: &SharedState, namespace: Option<&str>) -> Vec<sessions::Browser> {
    let mut daemon = state.lock().await;
    let browser_ids = daemon
        .browsers
        .iter()
        .filter_map(|(browser_id, browser)| {
            namespace
                .is_none_or(|requested| requested == browser.key.namespace)
                .then_some(browser_id.clone())
        })
        .collect::<Vec<_>>();
    let mut browsers = Vec::new();
    for browser_id in browser_ids {
        let Some(browser) = daemon.browsers.remove(&browser_id) else {
            continue;
        };
        {
            if !browser.exclusive {
                daemon.shared_browsers.remove(&browser.key);
            }
            let session_ids = browser.leases.keys().cloned().collect::<Vec<_>>();
            if let Ok(mut ports) = daemon.cdp_ports.write() {
                for session_id in session_ids {
                    ports.remove(&session_id);
                }
            }
        }
        browsers.push(browser);
    }
    browsers
}

async fn terminate_browsers(state: &SharedState, browsers: Vec<sessions::Browser>) {
    let mut tasks = JoinSet::new();
    for browser in browsers {
        let state = state.clone();
        tasks.spawn(async move { terminate_browser(&state, browser).await });
    }
    while tasks.join_next().await.is_some() {}
}

async fn terminate_browser(state: &SharedState, browser: sessions::Browser) {
    let namespace = browser.key.namespace.clone();
    let leases = browser.leases.into_iter().collect::<Vec<_>>();
    for (_, lease) in &leases {
        if executor_release(&browser.executor, lease.target_id.clone())
            .await
            .is_err()
        {
            break;
        }
    }
    shutdown_executor(browser.executor).await;
    for (session_id, _) in leases {
        audit_system_session(state, "session_terminated", session_id, namespace.clone()).await;
    }
}

async fn terminate_peer_leases(state: SharedState, peer_id: &str) {
    let principal = format!("peer:{peer_id}");
    let removed = {
        let mut daemon = state.lock().await;
        let browser_ids = daemon.browsers.keys().cloned().collect::<Vec<_>>();
        let mut removed = Vec::new();
        for browser_id in browser_ids {
            let Some(browser) = daemon.browsers.get_mut(&browser_id) else {
                continue;
            };
            let session_ids = browser
                .leases
                .iter()
                .filter_map(|(id, lease)| (lease.principal == principal).then_some(id.clone()))
                .collect::<Vec<_>>();
            for session_id in session_ids {
                let lease = browser.leases.remove(&session_id).expect("lease exists");
                removed.push((
                    session_id,
                    lease,
                    browser.executor.clone(),
                    browser.key.namespace.clone(),
                    browser.leases.is_empty(),
                ));
            }
        }
        let empty = daemon
            .browsers
            .iter()
            .filter_map(|(id, browser)| browser.leases.is_empty().then_some(id.clone()))
            .collect::<Vec<_>>();
        for browser_id in empty {
            if let Some(browser) = daemon.browsers.remove(&browser_id)
                && !browser.exclusive
            {
                daemon.shared_browsers.remove(&browser.key);
            }
        }
        for (session_id, _, _, _, _) in &removed {
            let _ = daemon
                .cdp_ports
                .write()
                .map(|mut ports| ports.remove(session_id));
        }
        removed
    };
    for (session_id, lease, executor, namespace, shutdown) in removed {
        let _ = executor_release(&executor, lease.target_id).await;
        if shutdown {
            shutdown_executor(executor).await;
        }
        let daemon = state.lock().await;
        if let Err(error) = append_audit(
            &daemon,
            AuditPeer::System,
            "session_terminated".to_owned(),
            AuditFields {
                cred_id: None,
                target_url: None,
                session_id: Some(session_id),
                namespace: Some(namespace),
                shared: None,
            },
            "ok".to_owned(),
        )
        .await
        {
            eprintln!("tegatad: audit append failed: {error}");
        }
    }
}

async fn audit_system_session(
    state: &SharedState,
    method: &str,
    session_id: String,
    namespace: String,
) {
    let daemon = state.lock().await;
    if let Err(error) = append_audit(
        &daemon,
        AuditPeer::System,
        method.to_owned(),
        AuditFields {
            cred_id: None,
            target_url: None,
            session_id: Some(session_id),
            namespace: Some(namespace),
            shared: None,
        },
        "ok".to_owned(),
    )
    .await
    {
        eprintln!("tegatad: audit append failed: {error}");
    }
}

async fn resolve_credential(
    state: &SharedState,
    cred_id: &str,
) -> Result<Option<ResolvedCredential>, ErrorCode> {
    let Some((namespace, entry_id)) = cred_id.split_once(':') else {
        return Ok(None);
    };
    let provider = {
        let daemon = state.lock().await;
        let Some(provider) = daemon
            .providers
            .iter()
            .find(|provider| provider.namespace == namespace)
        else {
            return Ok(None);
        };
        provider.provider.clone()
    };
    let mut provider = provider.lock().await;
    let credential_result = provider.resolve(entry_id).await;
    let autolocked = provider.take_autolock_event();
    drop(provider);
    if autolocked {
        audit_provider_autolock(state, namespace.to_owned()).await;
    }
    let credential = credential_result?;
    let Some(credential) = credential else {
        return Ok(None);
    };
    if !credential.secrets_preregistered {
        let daemon = state.lock().await;
        let mut registry = daemon.registry.lock().await;
        register_secret(&mut registry, &credential.username);
        register_secret(&mut registry, &credential.password);
        if let Some(seed) = &credential.totp_seed {
            register_secret(&mut registry, seed);
        }
        drop(registry);
        drop(daemon);
    }
    Ok(Some(credential))
}

fn register_secret(registry: &mut Vec<String>, secret: &Secret) {
    if !registry
        .iter()
        .any(|registered| registered == secret.as_str())
    {
        registry.push(secret.as_str().to_owned());
    }
}

impl ExecutorHandle {
    async fn write_line(&mut self, line: &[u8]) -> io::Result<()> {
        match self {
            Self::Spawned(child) => {
                let stdin = child
                    .stdin
                    .as_mut()
                    .ok_or_else(|| io::Error::other("executor stdin is unavailable"))?;
                stdin.write_all(line).await?;
                stdin.flush().await
            }
            #[cfg(unix)]
            Self::Socket { writer, .. } => {
                writer.write_all(line).await?;
                writer.flush().await
            }
        }
    }

    async fn read_line(&mut self) -> io::Result<String> {
        match self {
            Self::Spawned(child) => {
                let mut stdout = child
                    .stdout
                    .take()
                    .ok_or_else(|| io::Error::other("executor stdout is unavailable"))?;
                let result = read_executor_line(&mut stdout).await;
                child.stdout = Some(stdout);
                result
            }
            #[cfg(unix)]
            Self::Socket { reader, .. } => {
                let mut reader = reader.lock().await;
                read_executor_line(&mut *reader).await
            }
        }
    }

    fn take_reader(&mut self) -> Option<ExecutorReader> {
        match self {
            Self::Spawned(child) => child.stdout.take().map(ExecutorReader::Spawned),
            #[cfg(unix)]
            Self::Socket { reader, .. } => Some(ExecutorReader::Socket(reader.clone())),
        }
    }
}

async fn read_executor_line<R: AsyncRead + Unpin>(reader: &mut R) -> io::Result<String> {
    let mut line = Vec::new();
    loop {
        let mut byte = [0; 1];
        if reader.read(&mut byte).await? == 0 {
            break;
        }
        line.push(byte[0]);
        if byte[0] == b'\n' {
            break;
        }
    }
    String::from_utf8(line).map_err(|error| io::Error::new(io::ErrorKind::InvalidData, error))
}

async fn start_executor(
    entry: &Path,
    executor_socket: Option<&Path>,
    node_path: &Path,
    browsers_path: Option<&Path>,
    params: &LoginParams,
    credential: &ResolvedCredential,
) -> Result<(String, String, ExecutorHandle), ErrorCode> {
    #[cfg(not(windows))]
    let _ = browsers_path;
    #[cfg(windows)]
    let _ = executor_socket;
    let mut command = Command::new(node_path);
    command
        .arg(entry)
        .stdin(std::process::Stdio::piped())
        .stdout(std::process::Stdio::piped())
        .stderr(std::process::Stdio::null())
        // Safety net: if the handle is dropped without an explicit shutdown
        // (a cancelled login task, runtime teardown), kill the executor
        // rather than leaking it.
        .kill_on_drop(true);
    #[cfg(windows)]
    if let Some(browsers_path) = browsers_path {
        command.env("PLAYWRIGHT_BROWSERS_PATH", browsers_path);
    }
    #[cfg(unix)]
    let mut executor = if let Some(socket) = executor_socket {
        let stream = timeout(EXECUTOR_TIMEOUT, tokio::net::UnixStream::connect(socket))
            .await
            .map_err(|_| ErrorCode::Internal)?
            .map_err(|_| ErrorCode::Internal)?;
        let (reader, writer) = stream.into_split();
        ExecutorHandle::Socket {
            reader: Arc::new(Mutex::new(reader)),
            writer,
        }
    } else {
        ExecutorHandle::Spawned(command.spawn().map_err(|_| ErrorCode::Internal)?)
    };
    #[cfg(windows)]
    let mut executor = ExecutorHandle::Spawned(command.spawn().map_err(|_| ErrorCode::Internal)?);
    let result = async {
        let totp = credential.totp_seed.as_ref().map(|seed| {
            let now = SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .map(|duration| duration.as_secs())
                .unwrap_or(0);
            tegata_core::totp(seed.as_str(), now).0
        });
        let request = ExecutorLoginRequest {
            op: "login",
            target_url: params.target_url.clone(),
            steps: params.steps.clone(),
            success_selector: params.success_selector.clone(),
            failure_selector: params.failure_selector.clone(),
            secret: ExecutorSecret {
                username: credential.username.as_str().to_owned(),
                password: credential.password.as_str().to_owned(),
                totp,
            },
        };
        let mut line = serde_json::to_vec(&request).map_err(|_| ErrorCode::Internal)?;
        line.push(b'\n');
        executor
            .write_line(&line)
            .await
            .map_err(|_| ErrorCode::Internal)?;
        let response_line = timeout(EXECUTOR_TIMEOUT, executor.read_line())
            .await
            .map_err(|_| ErrorCode::Internal)?
            .map_err(|_| ErrorCode::Internal)?;
        if response_line.is_empty() {
            return Err(ErrorCode::Internal);
        }
        let response: ExecutorResponse =
            serde_json::from_str(&response_line).map_err(|_| ErrorCode::Internal)?;
        if response.ok {
            let endpoint = response.endpoint.ok_or(ErrorCode::Internal)?;
            let target_id = response.target_id.ok_or(ErrorCode::Internal)?;
            Ok((endpoint, target_id))
        } else {
            Err(response
                .error
                .as_deref()
                .map(parse_error_code)
                .unwrap_or(ErrorCode::Internal))
        }
    }
    .await;
    match result {
        Ok((endpoint, target_id)) => Ok((endpoint, target_id, executor)),
        Err(error) => {
            stop_child(executor).await;
            Err(error)
        }
    }
}

fn cdp_port_from_endpoint(endpoint: &str) -> Option<u16> {
    let authority = endpoint.split_once("://")?.1.split('/').next()?;
    let port = authority.rsplit_once(':')?.1.parse().ok()?;
    (port != 0).then_some(port)
}

fn parse_error_code(value: &str) -> ErrorCode {
    match value {
        "INVALID_CREDENTIAL" => ErrorCode::InvalidCredential,
        "MFA_REQUIRED" => ErrorCode::MfaRequired,
        "SELECTOR_NOT_FOUND" => ErrorCode::SelectorNotFound,
        "VAULT_LOCKED" => ErrorCode::VaultLocked,
        "RATE_LIMITED" => ErrorCode::RateLimited,
        "TOTP_NOT_EXPOSABLE" => ErrorCode::TotpNotExposable,
        "APPROVAL_DENIED" => ErrorCode::ApprovalDenied,
        "APPROVAL_TIMEOUT" => ErrorCode::ApprovalTimeout,
        "INTERNAL" => ErrorCode::Internal,
        "NOT_FOUND" => ErrorCode::NotFound,
        _ => ErrorCode::Internal,
    }
}

async fn executor_request(
    connection: &Arc<ExecutorConnection>,
    mut request: Vec<u8>,
) -> Result<Value, ErrorCode> {
    let _operation = timeout(EXECUTOR_OPERATION_TIMEOUT, connection.operation.lock())
        .await
        .map_err(|_| ErrorCode::Internal)?;
    request.push(b'\n');
    let mut executor = timeout(EXECUTOR_OPERATION_TIMEOUT, connection.executor.lock())
        .await
        .map_err(|_| ErrorCode::Internal)?;
    timeout(EXECUTOR_OPERATION_TIMEOUT, executor.write_line(&request))
        .await
        .map_err(|_| ErrorCode::Internal)?
        .map_err(|_| ErrorCode::Internal)?;
    drop(executor);
    let mut responses = timeout(EXECUTOR_OPERATION_TIMEOUT, connection.responses.lock())
        .await
        .map_err(|_| ErrorCode::Internal)?;
    let response = timeout(EXECUTOR_OPERATION_TIMEOUT, responses.recv())
        .await
        .map_err(|_| ErrorCode::Internal)?
        .ok_or(ErrorCode::Internal)?
        .map_err(|_| ErrorCode::Internal)?;
    serde_json::from_str(&response).map_err(|_| ErrorCode::Internal)
}

async fn executor_lease(connection: &Arc<ExecutorConnection>) -> Result<String, ErrorCode> {
    let request = serde_json::to_vec(&ExecutorLeaseRequest { op: "lease" })
        .map_err(|_| ErrorCode::Internal)?;
    let response = executor_request(connection, request).await?;
    let response: tegata_core::wire::ExecutorLeaseResponse =
        serde_json::from_value(response).map_err(|_| ErrorCode::Internal)?;
    if response.ok {
        response.target_id.ok_or(ErrorCode::Internal)
    } else {
        Err(response
            .error
            .as_deref()
            .map(parse_error_code)
            .unwrap_or(ErrorCode::Internal))
    }
}

async fn executor_release(
    connection: &Arc<ExecutorConnection>,
    target_id: String,
) -> Result<(), ErrorCode> {
    let request = serde_json::to_vec(&ExecutorReleaseRequest {
        op: "release",
        target_id,
    })
    .map_err(|_| ErrorCode::Internal)?;
    let response = executor_request(connection, request).await?;
    let response: tegata_core::wire::ExecutorLeaseResponse =
        serde_json::from_value(response).map_err(|_| ErrorCode::Internal)?;
    response.ok.then_some(()).ok_or_else(|| {
        response
            .error
            .as_deref()
            .map(parse_error_code)
            .unwrap_or(ErrorCode::Internal)
    })
}

async fn shutdown_executor(connection: Arc<ExecutorConnection>) {
    let Ok(_operation) = timeout(EXECUTOR_SHUTDOWN_TIMEOUT, connection.operation.lock()).await
    else {
        kill_executor(&connection).await;
        return;
    };
    let Ok(mut executor) = timeout(EXECUTOR_SHUTDOWN_TIMEOUT, connection.executor.lock()).await
    else {
        kill_executor(&connection).await;
        return;
    };
    let write_result = timeout(
        EXECUTOR_SHUTDOWN_TIMEOUT,
        executor.write_line(b"{\"op\":\"shutdown\"}\n"),
    )
    .await;
    if !matches!(write_result, Ok(Ok(()))) {
        kill_executor_handle(&mut executor).await;
        return;
    }
    if wait_or_kill_executor(&mut executor).await {
        return;
    }
    #[cfg(unix)]
    {
        drop(executor);
        let Ok(mut responses) =
            timeout(EXECUTOR_SHUTDOWN_TIMEOUT, connection.responses.lock()).await
        else {
            return;
        };
        let _ = timeout(EXECUTOR_SHUTDOWN_TIMEOUT, async {
            while responses.recv().await.is_some() {}
        })
        .await;
    }
}

async fn wait_or_kill_executor(executor: &mut ExecutorHandle) -> bool {
    match executor {
        ExecutorHandle::Spawned(child) => {
            if timeout(EXECUTOR_SHUTDOWN_TIMEOUT, child.wait())
                .await
                .is_err()
            {
                let _ = child.start_kill();
                let _ = timeout(EXECUTOR_SHUTDOWN_TIMEOUT, child.wait()).await;
            }
            true
        }
        #[cfg(unix)]
        ExecutorHandle::Socket { .. } => false,
    }
}

async fn kill_executor(connection: &Arc<ExecutorConnection>) {
    let Ok(mut executor) = timeout(EXECUTOR_SHUTDOWN_TIMEOUT, connection.executor.lock()).await
    else {
        return;
    };
    kill_executor_handle(&mut executor).await;
}

async fn kill_executor_handle(executor: &mut ExecutorHandle) {
    match executor {
        ExecutorHandle::Spawned(child) => {
            let _ = child.start_kill();
            let _ = timeout(EXECUTOR_SHUTDOWN_TIMEOUT, child.wait()).await;
        }
        #[cfg(unix)]
        ExecutorHandle::Socket { writer, .. } => {
            let _ = timeout(EXECUTOR_SHUTDOWN_TIMEOUT, writer.shutdown()).await;
        }
    }
}

async fn stop_child(mut executor: ExecutorHandle) {
    match &mut executor {
        ExecutorHandle::Spawned(child) => {
            let _ = child.start_kill();
            let _ = child.wait().await;
        }
        #[cfg(unix)]
        ExecutorHandle::Socket { writer, .. } => {
            let _ = writer.shutdown().await;
        }
    }
}

fn spawn_executor_reaper(
    state: SharedState,
    browser_id: String,
    mut reader: ExecutorReader,
    sender: mpsc::UnboundedSender<io::Result<String>>,
) {
    tokio::spawn(async move {
        loop {
            let result = match &mut reader {
                ExecutorReader::Spawned(stdout) => read_executor_line(stdout).await,
                #[cfg(unix)]
                ExecutorReader::Socket(reader) => {
                    let mut reader = reader.lock().await;
                    read_executor_line(&mut *reader).await
                }
            };
            match result {
                Ok(line) if !line.is_empty() => {
                    if sender.send(Ok(line)).is_err() {
                        return;
                    }
                }
                Ok(_) | Err(_) => {
                    let _ = sender.send(Err(io::Error::new(
                        io::ErrorKind::UnexpectedEof,
                        "executor disconnected",
                    )));
                    break;
                }
            }
        }
        let browser = {
            let mut daemon = state.lock().await;
            let browser = daemon.browsers.remove(&browser_id);
            if let Some(browser) = &browser {
                if !browser.exclusive {
                    daemon.shared_browsers.remove(&browser.key);
                }
                let session_ids = browser.leases.keys().cloned().collect::<Vec<_>>();
                if let Ok(mut ports) = daemon.cdp_ports.write() {
                    for session_id in session_ids {
                        ports.remove(&session_id);
                    }
                }
            }
            browser
        };
        let Some(browser) = browser else {
            return;
        };
        for (session_id, _) in browser.leases {
            audit_system_session(
                &state,
                "session_terminated",
                session_id,
                browser.key.namespace.clone(),
            )
            .await;
        }
    });
}

#[cfg(unix)]
fn kill_process_group(child: &Child) {
    if let Some(pid) = child.id() {
        unsafe {
            libc::kill(-(pid as libc::pid_t), libc::SIGKILL);
        }
    }
}

fn parse_params<T: for<'de> Deserialize<'de>>(params: &Value) -> Result<T, ErrorCode> {
    let params = if params.is_null() {
        Value::Object(serde_json::Map::new())
    } else {
        params.clone()
    };
    serde_json::from_value(params).map_err(|_| ErrorCode::Internal)
}

fn required_string_param(params: &Value, key: &str) -> Result<String, ErrorCode> {
    params
        .get(key)
        .and_then(Value::as_str)
        .map(ToOwned::to_owned)
        .ok_or(ErrorCode::Internal)
}

fn optional_namespace(params: &Value) -> Result<Option<String>, ErrorCode> {
    if params.is_null() {
        return Ok(None);
    }
    match params.get("namespace") {
        None | Some(Value::Null) => Ok(None),
        Some(Value::String(namespace)) => Ok(Some(namespace.clone())),
        Some(_) => Err(ErrorCode::Internal),
    }
}

fn audit_fields(params: &Value) -> AuditFields {
    AuditFields {
        cred_id: params
            .get("cred_id")
            .and_then(Value::as_str)
            .map(ToOwned::to_owned),
        target_url: params
            .get("target_url")
            .and_then(Value::as_str)
            .map(ToOwned::to_owned),
        session_id: params
            .get("session_id")
            .and_then(Value::as_str)
            .map(ToOwned::to_owned),
        namespace: params
            .get("namespace")
            .and_then(Value::as_str)
            .map(ToOwned::to_owned),
        shared: None,
    }
}

fn success(id: Value, result: Value) -> HandledRequest {
    HandledRequest {
        response: RpcResponse {
            jsonrpc: JSON_RPC_VERSION,
            id,
            result: Some(result),
            error: None,
        },
        outcome: "ok".to_owned(),
        audit_shared: None,
    }
}

fn classified(id: Value, error: ErrorCode) -> HandledRequest {
    HandledRequest {
        response: error_response(id, error),
        outcome: error.as_str().to_owned(),
        audit_shared: None,
    }
}

fn error_response(id: Value, error: ErrorCode) -> RpcResponse {
    RpcResponse {
        jsonrpc: JSON_RPC_VERSION,
        id,
        result: None,
        error: Some(RpcError {
            code: CLASSIFICATION_ERROR,
            message: error.as_str().to_owned(),
        }),
    }
}

#[cfg(all(test, unix))]
mod tests {
    use super::{AuditPeer, AuditRecord, PeerIdentity};

    #[test]
    fn audit_record_names_the_peer_by_its_transport_identity() {
        let peer = PeerIdentity::Uid(1000);
        let record = AuditRecord {
            ts: "unix:1".to_owned(),
            peer: AuditPeer::Peer(&peer),
            method: "status".to_owned(),
            cred_id: None,
            target_url: None,
            session_id: None,
            namespace: None,
            shared: None,
            outcome: "ok".to_owned(),
        };
        assert_eq!(
            serde_json::to_string(&record).expect("serialize audit record"),
            r#"{"ts":"unix:1","peer_uid":1000,"principal":"uid:1000","method":"status","cred_id":null,"target_url":null,"session_id":null,"namespace":null,"outcome":"ok"}"#
        );
    }
}

#[cfg(all(test, windows))]
mod windows_config_tests {
    use super::Config;

    #[test]
    fn minimal_windows_daemon_config_is_backward_compatible() {
        let config: Config = toml::from_str(
            r#"
pipe_name = "tegatad-test"
tcp_port = 0
state_dir = "C:\\Temp\\tegata\\state"
audit_log_path = "C:\\Temp\\tegata\\state\\audit.log"
allowed_sids = ["S-1-5-21-1"]

[[providers]]
namespace = "vault"
type = "bitwarden-cli"
server_url = "http://127.0.0.1:8087"
email = "test@example.com"
askpass_cmd = "echo password"
"#,
        )
        .expect("parse minimal Windows daemon config");

        assert_eq!(config.providers.len(), 1);
        assert!(config.transport.operator_sid.is_none());
        assert!(config.transport.token_hash_path.is_none());
        assert!(config.transport.sealed_blob_path.is_none());
        assert_eq!(config.unlock_mode, super::UnlockMode::Sealed);
        assert!(config.transport.browsers_path.is_none());
        assert!(config.transport.bw_path.is_none());
        assert!(config.transport.node_path.is_none());

        let config: Config = toml::from_str(
            r#"
pipe_name = "tegatad-test"
tcp_port = 0
state_dir = "C:\\Temp\\tegata\\state"
audit_log_path = "C:\\Temp\\tegata\\state\\audit.log"
allowed_sids = []
"#,
        )
        .expect("parse renderer config without providers");
        assert!(config.providers.is_empty());
    }
}
