use std::collections::HashMap;
use std::os::fd::AsRawFd;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use clap::Parser;
use leakscan::scan_bytes;
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use tegata_core::{Secret, totp};
use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};
use tokio::net::{UnixListener, UnixStream};
use tokio::process::{Child, Command};
use tokio::sync::Mutex;
use tokio::time::{Instant, interval, timeout};
use uuid::Uuid;

const JSON_RPC_VERSION: &str = "2.0";
const METHOD_NOT_FOUND: i32 = -32601;
const CLASSIFICATION_ERROR: i32 = -32000;
const EXECUTOR_TIMEOUT: Duration = Duration::from_secs(90);

#[derive(Debug, Deserialize)]
struct Config {
    socket_path: String,
    state_dir: String,
    audit_log_path: String,
    allowed_uids: Vec<u32>,
    executor_entry: Option<String>,
    session_ttl_secs: Option<u64>,
    providers: Vec<ProviderConfig>,
}

#[derive(Debug, Deserialize)]
struct ProviderConfig {
    namespace: String,
    #[serde(rename = "type")]
    provider_type: String,
    #[serde(default)]
    entries: Vec<EntryConfig>,
    server_url: Option<String>,
    email: Option<String>,
    askpass_cmd: Option<String>,
    #[serde(default)]
    totp_exposable: Vec<String>,
    session_ttl_secs: Option<u64>,
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
    provider_type: String,
    entries: Vec<Entry>,
    locked: bool,
    bitwarden: Option<Arc<Mutex<BitwardenCliProvider>>>,
}

struct Entry {
    id: String,
    name: String,
    uri: String,
    kind: String,
    username: Secret,
    password: Secret,
    totp_seed: Option<Secret>,
    totp_exposable: bool,
}

struct ResolvedCredential {
    provider_type: String,
    locked: bool,
    username: Secret,
    password: Secret,
    totp_seed: Option<Secret>,
    totp_exposable: bool,
}

struct BitwardenCliProvider {
    server_url: String,
    email: String,
    askpass_cmd: String,
    appdata_dir: PathBuf,
    totp_exposable: Vec<String>,
    session_ttl: Duration,
    session: Option<Secret>,
    unlocked_at: Option<Instant>,
    locked: bool,
    catalog: Vec<BitwardenCatalogItem>,
}

struct BitwardenCatalogItem {
    id: String,
    name: String,
}

#[derive(Debug, Deserialize)]
struct BitwardenItem {
    id: String,
    name: String,
    login: Option<BitwardenLogin>,
}

#[derive(Debug, Deserialize)]
struct BitwardenLogin {
    #[serde(default)]
    uris: Vec<BitwardenUri>,
    username: Option<String>,
    password: Option<String>,
    totp: Option<String>,
}

#[derive(Debug, Deserialize)]
struct BitwardenUri {
    uri: Option<String>,
}

impl BitwardenCliProvider {
    async fn run_bw(
        &self,
        args: &[String],
        session: Option<&Secret>,
        password: Option<&Secret>,
    ) -> Result<Vec<u8>, ()> {
        tokio::fs::create_dir_all(&self.appdata_dir)
            .await
            .map_err(|_| ())?;
        let mut command = Command::new("bw");
        command
            .args(args)
            .env("BW_APPDATA_DIR", &self.appdata_dir)
            .env("BITWARDENCLI_APPDATA_DIR", &self.appdata_dir)
            .env_remove("BW_PASSWORD")
            .env_remove("BW_SESSION")
            .stdout(std::process::Stdio::piped())
            .stderr(std::process::Stdio::null());
        if let Some(session) = session {
            command.env("BW_SESSION", session.as_str());
        }
        if let Some(password) = password {
            command.env("BW_PASSWORD", password.as_str());
        }
        let output = command.output().await.map_err(|_| ())?;
        if !output.status.success() {
            return Err(());
        }
        Ok(output.stdout)
    }

    async fn run_askpass(&self) -> Result<Secret, ErrorCode> {
        tokio::fs::create_dir_all(&self.appdata_dir)
            .await
            .map_err(|_| ErrorCode::Internal)?;
        let output = Command::new("sh")
            .args(["-c", self.askpass_cmd.as_str()])
            .env("BW_APPDATA_DIR", &self.appdata_dir)
            .env("BITWARDENCLI_APPDATA_DIR", &self.appdata_dir)
            .env_remove("BW_PASSWORD")
            .env_remove("BW_SESSION")
            .stdout(std::process::Stdio::piped())
            .stderr(std::process::Stdio::null())
            .output()
            .await
            .map_err(|_| ErrorCode::Internal)?;
        if !output.status.success() {
            return Err(ErrorCode::Internal);
        }
        let first_line = String::from_utf8(output.stdout)
            .ok()
            .and_then(|value| value.lines().next().map(ToOwned::to_owned))
            .map(|value| value.trim_end_matches('\r').to_owned())
            .filter(|value| !value.is_empty())
            .ok_or(ErrorCode::Internal)?;
        Ok(Secret::new(first_line))
    }

    async fn ensure_session(&mut self) -> Result<(), ErrorCode> {
        if self.locked {
            return Err(ErrorCode::VaultLocked);
        }
        if let (Some(_session), Some(unlocked_at)) = (&self.session, self.unlocked_at) {
            if unlocked_at.elapsed() < self.session_ttl {
                return Ok(());
            }
            let _ = self.lock_session().await;
            self.locked = true;
            return Err(ErrorCode::VaultLocked);
        }

        let password = self.run_askpass().await?;
        self.run_bw(
            &[
                "config".to_owned(),
                "server".to_owned(),
                self.server_url.clone(),
            ],
            None,
            None,
        )
        .await
        .map_err(|_| ErrorCode::Internal)?;
        let logged_in = self
            .run_bw(&["login".to_owned(), "--check".to_owned()], None, None)
            .await
            .is_ok();
        let login_args = if logged_in {
            vec![
                "unlock".to_owned(),
                "--raw".to_owned(),
                "--passwordenv".to_owned(),
                "BW_PASSWORD".to_owned(),
            ]
        } else {
            vec![
                "login".to_owned(),
                self.email.clone(),
                "--raw".to_owned(),
                "--passwordenv".to_owned(),
                "BW_PASSWORD".to_owned(),
            ]
        };
        let session = self
            .run_bw(&login_args, None, Some(&password))
            .await
            .map_err(|_| ErrorCode::Internal)?;
        drop(password);
        let session = String::from_utf8(session)
            .ok()
            .and_then(|value| value.lines().next().map(ToOwned::to_owned))
            .map(|value| value.trim_end_matches('\r').to_owned())
            .filter(|value| !value.is_empty())
            .ok_or(ErrorCode::Internal)?;
        self.session = Some(Secret::new(session));
        self.unlocked_at = Some(Instant::now());
        Ok(())
    }

    async fn lock_session(&mut self) -> Result<(), ErrorCode> {
        let result = if let Some(session) = self.session.as_ref() {
            self.run_bw(&["lock".to_owned()], Some(session), None)
                .await
                .map(|_| ())
                .map_err(|_| ErrorCode::Internal)
        } else {
            Ok(())
        };
        self.session = None;
        self.unlocked_at = None;
        result
    }

    async fn expire_session(&mut self) {
        if self.locked {
            return;
        }
        if self
            .unlocked_at
            .is_some_and(|unlocked_at| unlocked_at.elapsed() >= self.session_ttl)
        {
            let _ = self.lock_session().await;
            self.locked = true;
        }
    }

    async fn list_items(&mut self) -> Result<Vec<BitwardenItem>, ErrorCode> {
        self.ensure_session().await?;
        let output = self
            .run_bw(
                &["list".to_owned(), "items".to_owned()],
                self.session.as_ref(),
                None,
            )
            .await
            .map_err(|_| ErrorCode::Internal)?;
        serde_json::from_slice(&output).map_err(|_| ErrorCode::Internal)
    }

    async fn get_item(&mut self, item_id: &str) -> Result<BitwardenItem, ErrorCode> {
        self.ensure_session().await?;
        let output = self
            .run_bw(
                &["get".to_owned(), "item".to_owned(), item_id.to_owned()],
                self.session.as_ref(),
                None,
            )
            .await
            .map_err(|_| ErrorCode::InvalidCredential)?;
        serde_json::from_slice(&output).map_err(|_| ErrorCode::InvalidCredential)
    }

    async fn resolve(&mut self, item_id: &str) -> Result<ResolvedCredential, ErrorCode> {
        let item = self.get_item(item_id).await?;
        let login = item.login.ok_or(ErrorCode::InvalidCredential)?;
        if !self.catalog.iter().any(|cached| cached.id == item.id) {
            self.catalog.push(BitwardenCatalogItem {
                id: item.id.clone(),
                name: item.name.clone(),
            });
        }
        let expose_totp = self.totp_exposable.iter().any(|name| name == &item.name);
        Ok(ResolvedCredential {
            provider_type: "bitwarden-cli".to_owned(),
            locked: self.locked,
            username: Secret::new(login.username.unwrap_or_default()),
            password: Secret::new(login.password.unwrap_or_default()),
            totp_seed: expose_totp.then_some(login.totp).flatten().map(Secret::new),
            totp_exposable: expose_totp,
        })
    }
}

struct Session {
    child: Child,
    expires_at: Instant,
}

struct DaemonState {
    providers: Vec<Provider>,
    sessions: HashMap<String, Session>,
    last_totp: HashMap<String, Instant>,
    registry: Arc<Vec<String>>,
    audit_log_path: PathBuf,
    audit_lock: Arc<Mutex<()>>,
    executor_entry: PathBuf,
    session_ttl: Duration,
}

type SharedState = Arc<Mutex<DaemonState>>;

#[derive(Clone, Copy)]
enum ErrorCode {
    InvalidCredential,
    MfaRequired,
    SelectorNotFound,
    VaultLocked,
    RateLimited,
    TotpNotExposable,
    Internal,
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
            Self::Internal => "INTERNAL",
        }
    }
}

#[derive(Debug, Deserialize)]
struct RpcRequest {
    jsonrpc: String,
    id: Value,
    method: String,
    #[serde(default)]
    params: Value,
}

#[derive(Serialize)]
struct RpcResponse {
    jsonrpc: &'static str,
    id: Value,
    #[serde(skip_serializing_if = "Option::is_none")]
    result: Option<Value>,
    #[serde(skip_serializing_if = "Option::is_none")]
    error: Option<RpcError>,
}

#[derive(Serialize)]
struct RpcError {
    code: i32,
    message: String,
}

#[derive(Deserialize)]
struct LoginParams {
    cred_id: String,
    target_url: String,
    steps: Option<Vec<LoginStep>>,
    success_selector: Option<String>,
    failure_selector: Option<String>,
}

#[derive(Clone, Deserialize, Serialize)]
struct LoginStep {
    action: String,
    selector: String,
    value: Option<String>,
}

#[derive(Serialize)]
struct ExecutorLoginRequest {
    op: &'static str,
    target_url: String,
    steps: Option<Vec<LoginStep>>,
    success_selector: Option<String>,
    failure_selector: Option<String>,
    secret: ExecutorSecret,
}

#[derive(Serialize)]
struct ExecutorSecret {
    username: String,
    password: String,
    totp: Option<String>,
}

#[derive(Deserialize)]
struct ExecutorResponse {
    ok: bool,
    endpoint: Option<String>,
    error: Option<String>,
}

#[derive(Serialize)]
struct AuditRecord {
    ts: String,
    peer_uid: u32,
    method: String,
    cred_id: Option<String>,
    target_url: Option<String>,
    outcome: String,
}

struct AuditFields {
    cred_id: Option<String>,
    target_url: Option<String>,
}

struct HandledRequest {
    response: RpcResponse,
    outcome: String,
}

#[derive(Parser)]
struct Args {
    #[arg(long)]
    config: PathBuf,
}

#[tokio::main]
async fn main() {
    if let Err(error) = run().await {
        eprintln!("tegatad: {error}");
        std::process::exit(1);
    }
}

async fn run() -> Result<(), Box<dyn std::error::Error>> {
    let args = Args::parse();
    let config_text = tokio::fs::read_to_string(&args.config).await?;
    let config: Config = toml::from_str(&config_text)?;
    let socket_path = PathBuf::from(&config.socket_path);
    if socket_path.exists() {
        tokio::fs::remove_file(&socket_path).await?;
    }
    tokio::fs::create_dir_all(&config.state_dir).await?;
    if let Some(parent) = socket_path.parent() {
        tokio::fs::create_dir_all(parent).await?;
    }
    let listener = UnixListener::bind(&socket_path)?;
    let allowed_uids = Arc::new(config.allowed_uids.clone());
    let state = Arc::new(Mutex::new(build_state(config)));
    spawn_session_reaper(state.clone());
    spawn_bitwarden_session_reaper(state.clone());

    loop {
        let (stream, _) = listener.accept().await?;
        let peer_uid = match peer_uid(&stream) {
            Ok(uid) => uid,
            Err(_) => continue,
        };
        if !allowed_uids.contains(&peer_uid) {
            continue;
        }
        let state = state.clone();
        tokio::spawn(async move {
            serve_connection(stream, peer_uid, state).await;
        });
    }
}

fn build_state(config: Config) -> DaemonState {
    let mut registry = Vec::new();
    let audit_log_path = PathBuf::from(&config.audit_log_path);
    let executor_entry = resolve_executor_entry(&config);
    let session_ttl = Duration::from_secs(config.session_ttl_secs.unwrap_or(300));
    let state_dir = PathBuf::from(&config.state_dir);
    let providers = config
        .providers
        .into_iter()
        .map(|provider| {
            let namespace = provider.namespace;
            let provider_type = provider.provider_type;
            let bitwarden = if provider_type == "bitwarden-cli" {
                match (provider.server_url, provider.email, provider.askpass_cmd) {
                    (Some(server_url), Some(email), Some(askpass_cmd)) => {
                        Some(Arc::new(Mutex::new(BitwardenCliProvider {
                            appdata_dir: state_dir
                                .join(format!("bw-{}", safe_path_component(&namespace))),
                            server_url,
                            email,
                            askpass_cmd,
                            totp_exposable: provider.totp_exposable,
                            session_ttl: Duration::from_secs(
                                provider.session_ttl_secs.unwrap_or(session_ttl.as_secs()),
                            ),
                            session: None,
                            unlocked_at: None,
                            locked: false,
                            catalog: Vec::new(),
                        })))
                    }
                    _ => None,
                }
            } else {
                None
            };
            Provider {
                namespace,
                provider_type,
                entries: provider
                    .entries
                    .into_iter()
                    .map(|entry| {
                        registry.push(entry.username.clone());
                        registry.push(entry.password.clone());
                        if let Some(seed) = &entry.totp_seed {
                            registry.push(seed.clone());
                        }
                        Entry {
                            id: entry.id,
                            name: entry.name,
                            uri: entry.uri,
                            kind: entry.kind,
                            username: Secret::new(entry.username),
                            password: Secret::new(entry.password),
                            totp_seed: entry.totp_seed.map(Secret::new),
                            totp_exposable: entry.totp_exposable.unwrap_or(false),
                        }
                    })
                    .collect(),
                locked: false,
                bitwarden,
            }
        })
        .collect();
    DaemonState {
        providers,
        sessions: HashMap::new(),
        last_totp: HashMap::new(),
        registry: Arc::new(registry),
        audit_log_path,
        audit_lock: Arc::new(Mutex::new(())),
        executor_entry,
        session_ttl,
    }
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

fn spawn_session_reaper(state: SharedState) {
    tokio::spawn(async move {
        let mut ticker = interval(Duration::from_secs(1));
        loop {
            ticker.tick().await;
            let expired = {
                let mut daemon = state.lock().await;
                let now = Instant::now();
                let ids: Vec<String> = daemon
                    .sessions
                    .iter()
                    .filter_map(|(id, session)| (session.expires_at <= now).then_some(id.clone()))
                    .collect();
                ids.into_iter()
                    .filter_map(|id| daemon.sessions.remove(&id))
                    .collect::<Vec<_>>()
            };
            for session in expired {
                stop_child(session.child).await;
            }
        }
    });
}

fn spawn_bitwarden_session_reaper(state: SharedState) {
    tokio::spawn(async move {
        let mut ticker = interval(Duration::from_secs(1));
        loop {
            ticker.tick().await;
            let providers = {
                let daemon = state.lock().await;
                daemon
                    .providers
                    .iter()
                    .filter_map(|provider| provider.bitwarden.clone())
                    .collect::<Vec<_>>()
            };
            for provider in providers {
                provider.lock().await.expire_session().await;
            }
        }
    });
}

async fn serve_connection(stream: UnixStream, peer_uid: u32, state: SharedState) {
    let (read_half, mut write_half) = stream.into_split();
    let mut lines = BufReader::new(read_half).lines();
    while let Ok(Some(line)) = lines.next_line().await {
        let parsed = serde_json::from_str::<RpcRequest>(&line);
        let (request, response, outcome, fields) = match parsed {
            Ok(request) => {
                let fields = audit_fields(&request.params);
                let handled = handle_request(&request, state.clone()).await;
                (Some(request), handled.response, handled.outcome, fields)
            }
            Err(_) => (
                None,
                error_response(Value::Null, ErrorCode::Internal),
                ErrorCode::Internal.as_str().to_owned(),
                AuditFields {
                    cred_id: None,
                    target_url: None,
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
            peer_uid,
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

async fn write_response(
    writer: &mut tokio::net::unix::OwnedWriteHalf,
    response: &RpcResponse,
    state: &SharedState,
    peer_uid: u32,
    method: String,
    fields: AuditFields,
    outcome: String,
) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    let daemon = state.lock().await;
    let mut response_bytes = serde_json::to_vec(response)?;
    let leaked = scan_bytes(&response_bytes, daemon.registry.as_slice());
    let final_outcome = if leaked.is_empty() {
        outcome
    } else {
        append_audit(
            &daemon,
            peer_uid,
            method.clone(),
            fields.cred_id.clone(),
            fields.target_url.clone(),
            ErrorCode::Internal.as_str().to_owned(),
        )
        .await;
        response_bytes =
            serde_json::to_vec(&error_response(response.id.clone(), ErrorCode::Internal))?;
        ErrorCode::Internal.as_str().to_owned()
    };
    if leaked.is_empty() {
        append_audit(
            &daemon,
            peer_uid,
            method,
            fields.cred_id,
            fields.target_url,
            final_outcome,
        )
        .await;
    }
    drop(daemon);
    response_bytes.push(b'\n');
    writer.write_all(&response_bytes).await?;
    writer.flush().await?;
    Ok(())
}

async fn append_audit(
    state: &DaemonState,
    peer_uid: u32,
    method: String,
    cred_id: Option<String>,
    target_url: Option<String>,
    outcome: String,
) {
    let _guard = state.audit_lock.lock().await;
    let record = AuditRecord {
        ts: SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map(|duration| format!("unix:{}", duration.as_secs()))
            .unwrap_or_else(|_| "unix:0".to_owned()),
        peer_uid,
        method,
        cred_id,
        target_url,
        outcome,
    };
    let Ok(mut file) = tokio::fs::OpenOptions::new()
        .create(true)
        .append(true)
        .open(&state.audit_log_path)
        .await
    else {
        return;
    };
    let Ok(mut bytes) = serde_json::to_vec(&record) else {
        return;
    };
    bytes.push(b'\n');
    let _ = file.write_all(&bytes).await;
}

async fn handle_request(request: &RpcRequest, state: SharedState) -> HandledRequest {
    if request.jsonrpc != JSON_RPC_VERSION {
        return classified(request.id.clone(), ErrorCode::Internal);
    }
    match request.method.as_str() {
        "status" => success(request.id.clone(), json!({ "ok": true })),
        "list_credentials" => list_credentials(request, state).await,
        "login" => login(request, state).await,
        "logout" => logout(request, state).await,
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
        },
    }
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
            .map(|provider| {
                let entries = provider
                    .entries
                    .iter()
                    .map(|entry| {
                        (
                            entry.id.clone(),
                            entry.name.clone(),
                            entry.uri.clone(),
                            entry.kind.clone(),
                        )
                    })
                    .collect::<Vec<_>>();
                (
                    provider.namespace.clone(),
                    provider.provider_type.clone(),
                    provider.locked,
                    entries,
                    provider.bitwarden.clone(),
                )
            })
            .collect::<Vec<_>>()
    };
    let mut result = Vec::new();
    for (provider_namespace, provider_type, locked, entries, bitwarden) in providers {
        if provider_type == "mock" {
            for (entry_id, entry_name, entry_uri, entry_kind) in entries {
                let id = format!("{provider_namespace}:{entry_id}");
                if locked {
                    result.push(json!({
                        "id": id,
                        "name": entry_name,
                        "source": provider_namespace,
                        "status": "locked",
                    }));
                } else {
                    result.push(json!({
                        "id": id,
                        "name": entry_name,
                        "uri": entry_uri,
                        "kind": entry_kind,
                        "source": provider_namespace,
                        "status": "unlocked",
                    }));
                }
            }
        } else if provider_type == "bitwarden-cli" {
            let Some(bitwarden) = bitwarden else {
                return classified(request.id.clone(), ErrorCode::Internal);
            };
            let mut client = bitwarden.lock().await;
            if client.locked {
                for item in &client.catalog {
                    result.push(json!({
                        "id": format!("{provider_namespace}:{}", item.id),
                        "name": item.name,
                        "source": provider_namespace,
                        "status": "locked",
                    }));
                }
                continue;
            }
            let items = match client.list_items().await {
                Ok(items) => items,
                Err(error) => return classified(request.id.clone(), error),
            };
            client.catalog = items
                .iter()
                .filter_map(|item| {
                    item.login.as_ref()?;
                    Some(BitwardenCatalogItem {
                        id: item.id.clone(),
                        name: item.name.clone(),
                    })
                })
                .collect();
            for item in items {
                let Some(login) = item.login else {
                    continue;
                };
                let uri = login
                    .uris
                    .first()
                    .and_then(|uri| uri.uri.clone())
                    .unwrap_or_default();
                result.push(json!({
                    "id": format!("{provider_namespace}:{}", item.id),
                    "name": item.name,
                    "uri": uri,
                    "kind": "login",
                    "source": provider_namespace,
                    "status": "unlocked",
                }));
            }
        }
    }
    success(request.id.clone(), Value::Array(result))
}

async fn login(request: &RpcRequest, state: SharedState) -> HandledRequest {
    let params = match parse_params::<LoginParams>(&request.params) {
        Ok(params) => params,
        Err(error) => return classified(request.id.clone(), error),
    };
    let (credential, executor_entry, ttl) = {
        let credential = match resolve_credential(&state, &params.cred_id).await {
            Ok(Some(credential)) => credential,
            Ok(None) => return classified(request.id.clone(), ErrorCode::InvalidCredential),
            Err(error) => return classified(request.id.clone(), error),
        };
        if credential.locked {
            return classified(request.id.clone(), ErrorCode::VaultLocked);
        }
        if credential.provider_type != "mock" && credential.provider_type != "bitwarden-cli" {
            return classified(request.id.clone(), ErrorCode::Internal);
        }
        let daemon = state.lock().await;
        (
            credential,
            daemon.executor_entry.clone(),
            daemon.session_ttl,
        )
    };
    let (endpoint, session_id, child) =
        match start_executor(&executor_entry, &params, &credential).await {
            Ok(result) => result,
            Err(error) => return classified(request.id.clone(), error),
        };
    state.lock().await.sessions.insert(
        session_id.clone(),
        Session {
            child,
            expires_at: Instant::now() + ttl,
        },
    );
    success(
        request.id.clone(),
        json!({
            "session_id": session_id,
            "channel": { "kind": "cdp", "endpoint": endpoint },
        }),
    )
}

async fn logout(request: &RpcRequest, state: SharedState) -> HandledRequest {
    let session_id = match required_string_param(&request.params, "session_id") {
        Ok(session_id) => session_id,
        Err(error) => return classified(request.id.clone(), error),
    };
    let session = state.lock().await.sessions.remove(&session_id);
    if let Some(session) = session {
        shutdown_child(session.child).await;
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
    if credential.provider_type != "mock" && credential.provider_type != "bitwarden-cli" {
        return classified(request.id.clone(), ErrorCode::Internal);
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
    let bitwarden = {
        let mut daemon = state.lock().await;
        let mut bitwarden = Vec::new();
        for provider in &mut daemon.providers {
            if namespace
                .as_deref()
                .is_none_or(|requested| requested == provider.namespace)
            {
                if provider.provider_type == "mock" {
                    provider.locked = true;
                } else if provider.provider_type == "bitwarden-cli" {
                    if let Some(client) = &provider.bitwarden {
                        bitwarden.push(client.clone());
                    } else {
                        return classified(request.id.clone(), ErrorCode::Internal);
                    }
                }
            }
        }
        bitwarden
    };
    for provider in bitwarden {
        let mut provider = provider.lock().await;
        if let Err(error) = provider.lock_session().await {
            return classified(request.id.clone(), error);
        }
        provider.locked = true;
    }
    success(request.id.clone(), json!({ "ok": true }))
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
        if provider.provider_type == "bitwarden-cli" {
            (provider.provider_type.clone(), provider.bitwarden.clone())
        } else {
            let Some(entry) = provider.entries.iter().find(|entry| entry.id == entry_id) else {
                return Ok(None);
            };
            return Ok(Some(ResolvedCredential {
                provider_type: provider.provider_type.clone(),
                locked: provider.locked,
                username: Secret::new(entry.username.as_str()),
                password: Secret::new(entry.password.as_str()),
                totp_seed: entry
                    .totp_seed
                    .as_ref()
                    .map(|seed| Secret::new(seed.as_str())),
                totp_exposable: entry.totp_exposable,
            }));
        }
    };
    let (provider_type, Some(bitwarden)) = provider else {
        return Err(ErrorCode::Internal);
    };
    if provider_type != "bitwarden-cli" {
        return Ok(None);
    }
    let mut bitwarden = bitwarden.lock().await;
    Ok(Some(bitwarden.resolve(entry_id).await?))
}

async fn start_executor(
    entry: &Path,
    params: &LoginParams,
    credential: &ResolvedCredential,
) -> Result<(String, String, Child), ErrorCode> {
    let mut child = Command::new("node")
        .arg(entry)
        .stdin(std::process::Stdio::piped())
        .stdout(std::process::Stdio::piped())
        .stderr(std::process::Stdio::null())
        .spawn()
        .map_err(|_| ErrorCode::Internal)?;
    let result = async {
        let stdout = child.stdout.take().ok_or(ErrorCode::Internal)?;
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
        let stdin = child.stdin.as_mut().ok_or(ErrorCode::Internal)?;
        stdin
            .write_all(&line)
            .await
            .map_err(|_| ErrorCode::Internal)?;
        stdin.flush().await.map_err(|_| ErrorCode::Internal)?;
        let mut reader = BufReader::new(stdout);
        let mut response_line = String::new();
        timeout(EXECUTOR_TIMEOUT, reader.read_line(&mut response_line))
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
            Ok((endpoint, Uuid::new_v4().to_string()))
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
        Ok((endpoint, session_id)) => Ok((endpoint, session_id, child)),
        Err(error) => {
            stop_child(child).await;
            Err(error)
        }
    }
}

fn parse_error_code(value: &str) -> ErrorCode {
    match value {
        "INVALID_CREDENTIAL" => ErrorCode::InvalidCredential,
        "MFA_REQUIRED" => ErrorCode::MfaRequired,
        "SELECTOR_NOT_FOUND" => ErrorCode::SelectorNotFound,
        "VAULT_LOCKED" => ErrorCode::VaultLocked,
        "RATE_LIMITED" => ErrorCode::RateLimited,
        "TOTP_NOT_EXPOSABLE" => ErrorCode::TotpNotExposable,
        "INTERNAL" => ErrorCode::Internal,
        _ => ErrorCode::Internal,
    }
}

async fn shutdown_child(mut child: Child) {
    if let Some(stdin) = child.stdin.as_mut() {
        let mut line = b"{\"op\":\"shutdown\"}\n".to_vec();
        let _ = stdin.write_all(&line).await;
        let _ = stdin.flush().await;
        line.fill(0);
    }
    if timeout(Duration::from_secs(1), child.wait()).await.is_err() {
        let _ = child.start_kill();
        let _ = child.wait().await;
    }
}

async fn stop_child(mut child: Child) {
    let _ = child.start_kill();
    let _ = child.wait().await;
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
    }
}

fn classified(id: Value, error: ErrorCode) -> HandledRequest {
    HandledRequest {
        response: error_response(id, error),
        outcome: error.as_str().to_owned(),
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

fn peer_uid(stream: &UnixStream) -> Result<u32, std::io::Error> {
    let fd = stream.as_raw_fd();
    let mut credentials = libc::ucred {
        pid: 0,
        uid: 0,
        gid: 0,
    };
    let mut length = std::mem::size_of::<libc::ucred>() as libc::socklen_t;
    let result = unsafe {
        libc::getsockopt(
            fd,
            libc::SOL_SOCKET,
            libc::SO_PEERCRED,
            (&mut credentials as *mut libc::ucred).cast(),
            &mut length,
        )
    };
    if result == -1 {
        return Err(std::io::Error::last_os_error());
    }
    Ok(credentials.uid)
}
