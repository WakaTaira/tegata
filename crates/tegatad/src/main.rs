#[cfg(any(windows, test))]
mod approvals;
mod cookie_store;
#[cfg(windows)]
mod dpapi;
mod grants;
#[cfg_attr(not(windows), allow(dead_code))]
mod interop;
mod peers;
mod provider;
mod secure_fs;
mod sessions;
mod stepwise;
mod transport;
#[cfg(windows)]
mod windows_cli;
#[cfg(windows)]
mod windows_service;

use std::collections::{BTreeMap, HashMap, HashSet};
use std::fmt;
use std::io;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, AtomicUsize, Ordering};
use std::sync::{Arc, atomic::AtomicBool};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use clap::Parser;
use leakscan::scan_bytes;
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use tegata_core::wire::{
    AuthorizeDeviceParams, ExecutorApiProxyOAuth, ExecutorApiProxyOAuthSecret,
    ExecutorApiProxyOAuthTokenEvent, ExecutorApiProxyRequestEvent, ExecutorApiProxyStartRequest,
    ExecutorApiProxyStartResponse, ExecutorAuthorizeDeviceRequest, ExecutorLeaseRequest,
    ExecutorLoginRequest, ExecutorMcpServerEvent, ExecutorMcpServerStartRequest,
    ExecutorMcpServerStartResponse, ExecutorReleaseRequest, ExecutorResponse, ExecutorSecret,
    ExecutorServiceStopRequest, LoginParams, OpenApiProxyParams, OpenMcpServerParams, RpcError,
    RpcRequest, RpcResponse,
};
use tegata_core::wire::{ExecutorHelloRequest, ExecutorHelloResponse};
use tegata_core::{Secret, totp};
use tokio::io::{AsyncBufReadExt, AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt, BufReader};
use tokio::process::{Child, Command};
use tokio::sync::{Mutex, mpsc};
use tokio::task::JoinSet;
use tokio::time::{Instant, interval, timeout};
use uuid::Uuid;
use zeroize::{Zeroize, Zeroizing};

#[cfg(windows)]
use tegata_core::wire::AdminSealParams;

#[cfg(feature = "mock-provider")]
use crate::provider::StaticProvider;
use crate::provider::{
    BitwardenCliConfig, BitwardenCliProvider, CredentialProvider, CredentialRef, FileProvider,
    FileProviderConfig, ResolvedCredential,
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
const EXECUTOR_OPERATION_TIMEOUT: Duration = Duration::from_secs(5);
/// Upper bound on waiting for the `api_proxy_stop` response. The executor's revocation limit of 5
/// seconds
/// (`REVOCATION_TIMEOUT_MS` in packages/tegata-executor/src/oauth.ts) plus a margin.
/// Keep the two in sync when changing either.
const API_PROXY_STOP_TIMEOUT: Duration = Duration::from_secs(8);
/// Upper bound on waiting for the `mcp_server_stop` response. The executor moves to SIGKILL 2
/// seconds after SIGTERM,
/// so this is that wait plus the cleanup, with a margin.
const MCP_SERVER_STOP_TIMEOUT: Duration = Duration::from_secs(5);
const EXECUTOR_SHUTDOWN_TIMEOUT: Duration = Duration::from_secs(1);
const PASSWORD_FILE_DIR: &str = ".bw-passwords";

struct RpcContext {
    id: u64,
    method: String,
}

tokio::task_local! {
    static RPC_CONTEXT: RpcContext;
    static STARTUP_CONTEXT: ();
}

static NEXT_RPC_ID: AtomicU64 = AtomicU64::new(1);

pub(crate) fn current_rpc_id() -> Option<u64> {
    RPC_CONTEXT.try_with(|context| context.id).ok()
}

/// Returns the value recorded as `rpc_id` in a diagnostic line. Inside an RPC it is a sequence
/// number, in startup processing it is `"startup"`,
/// and in other background tasks outside an RPC, such as the reaper, it is `"background"`.
pub(crate) fn current_diagnostic_rpc_id() -> Value {
    match current_rpc_id() {
        Some(rpc_id) => json!(rpc_id),
        None if STARTUP_CONTEXT.try_with(|()| ()).is_ok() => json!("startup"),
        None => json!("background"),
    }
}

pub(crate) fn current_rpc_method() -> Option<String> {
    RPC_CONTEXT.try_with(|context| context.method.clone()).ok()
}

type ReadySender = Arc<std::sync::Mutex<Option<std::sync::mpsc::SyncSender<Result<(), String>>>>>;

#[derive(Debug, Deserialize)]
struct Config {
    state_dir: String,
    audit_log_path: String,
    audit_log_max_bytes: Option<u64>,
    approve_cmd: Option<String>,
    approve_timeout_secs: Option<u64>,
    approve_operator: Option<bool>,
    #[serde(default)]
    approval_grant_ttl_secs: u64,
    executor_entry: Option<String>,
    #[cfg(unix)]
    executor_socket: Option<String>,
    session_ttl_secs: Option<u64>,
    #[serde(default = "default_browser_max_lifetime_secs")]
    browser_max_lifetime_secs: u64,
    #[serde(default = "default_stepwise_idle_secs")]
    stepwise_idle_secs: u64,
    #[serde(default = "default_stepwise_max_secs")]
    stepwise_max_secs: u64,
    #[cfg(windows)]
    #[serde(default = "default_unlock_mode")]
    unlock_mode: UnlockMode,
    #[serde(default)]
    providers: Vec<ProviderConfig>,
    #[serde(default)]
    listen: Option<Vec<ListenConfig>>,
    #[serde(default = "default_max_pending_connections")]
    max_pending_connections: usize,
    #[serde(default)]
    api_proxy: Vec<ApiProxyConfig>,
    #[serde(default)]
    mcp_server: Vec<McpServerConfig>,
    /// Keys of the platform transport, read from the same top level table.
    /// Which keys those are depends on the target, so the transport module
    /// owns them.
    #[serde(flatten)]
    transport: PlatformConfig,
}

fn default_max_pending_connections() -> usize {
    8
}

fn default_browser_max_lifetime_secs() -> u64 {
    3600
}

fn default_stepwise_idle_secs() -> u64 {
    stepwise::DEFAULT_IDLE_SECS
}

fn default_stepwise_max_secs() -> u64 {
    stepwise::DEFAULT_MAX_SECS
}

/// One `[[api_proxy]]` entry. The agent only selects by `name`; the upstream and the injected
/// header are fixed by the configuration.
#[derive(Clone, Debug, Deserialize)]
struct ApiProxyConfig {
    name: String,
    cred_id: Option<String>,
    upstream: String,
    #[serde(default = "default_api_proxy_header")]
    header: String,
    #[serde(default = "default_api_proxy_value")]
    value: String,
    oauth: Option<ApiProxyOAuthConfig>,
}

/// Settings of `[api_proxy.oauth]`. The injected value is built from the token the executor obtains
/// through the device-code grant.
/// `login_cred_id` is the credential used for the browser login on the authorization screen, and is
/// also the subject of approval.
#[derive(Clone, Debug, Deserialize)]
struct ApiProxyOAuthConfig {
    client_id: String,
    device_authorization_url: String,
    token_url: String,
    revocation_url: Option<String>,
    scope: Option<String>,
    login_cred_id: String,
    steps: Option<Vec<tegata_core::wire::LoginStep>>,
    success_selector: String,
    failure_selector: Option<String>,
}

/// Specification of the injected value carried in `api_proxy_start`.
///
/// A static credential has only `header_value`; OAuth has only the pair of `value_template` and
/// `oauth`.
/// The two are mutually exclusive: it never has both, and never has neither.
struct ApiProxyStartOptions {
    value_template: Option<String>,
    header_value: Option<Zeroizing<String>>,
    oauth: Option<ExecutorApiProxyOAuth>,
}

const API_PROXY_SECRET_PLACEHOLDER: &str = "{{secret}}";

fn default_api_proxy_header() -> String {
    "Authorization".to_owned()
}

fn default_api_proxy_value() -> String {
    format!("Bearer {API_PROXY_SECRET_PLACEHOLDER}")
}

fn api_proxy_cred_id(proxy: &ApiProxyConfig) -> Option<&str> {
    proxy.cred_id.as_deref().or_else(|| {
        proxy
            .oauth
            .as_ref()
            .map(|oauth| oauth.login_cred_id.as_str())
    })
}

/// Detects a misconfigured `[[api_proxy]]` whose startup must be refused.
fn validate_api_proxies(proxies: &[ApiProxyConfig]) -> Result<(), String> {
    let mut names = HashSet::new();
    for proxy in proxies {
        if proxy.name.is_empty() {
            return Err("api_proxy name must not be empty".to_owned());
        }
        if !names.insert(proxy.name.as_str()) {
            return Err(format!(
                "api_proxy \"{}\" is defined more than once",
                proxy.name
            ));
        }
        if proxy.cred_id.is_some() == proxy.oauth.is_some() {
            let reason = if proxy.cred_id.is_some() {
                "cred_id and oauth are mutually exclusive"
            } else {
                "exactly one of cred_id or oauth is required"
            };
            return Err(format!("api_proxy \"{}\": {reason}", proxy.name));
        }
        if let Some(cred_id) = &proxy.cred_id
            && cred_id.split_once(':').is_none()
        {
            return Err(format!(
                "api_proxy \"{}\": cred_id must be <namespace>:<entry id>",
                proxy.name
            ));
        }
        if !api_proxy_upstream_allowed(&proxy.upstream) {
            return Err(format!(
                "api_proxy \"{}\": upstream must be https:// or http:// on a loopback host (127.0.0.1, ::1, localhost)",
                proxy.name
            ));
        }
        if let Some(oauth) = &proxy.oauth {
            validate_api_proxy_oauth(&proxy.name, oauth)?;
        }
        if !proxy.value.contains(API_PROXY_SECRET_PLACEHOLDER) {
            return Err(format!(
                "api_proxy \"{}\": value must contain {API_PROXY_SECRET_PLACEHOLDER}",
                proxy.name
            ));
        }
    }
    Ok(())
}

/// Detects a misconfigured `[api_proxy.oauth]` whose startup must be refused. `name` is the proxy
/// name put in the error.
fn validate_api_proxy_oauth(name: &str, oauth: &ApiProxyOAuthConfig) -> Result<(), String> {
    if oauth.login_cred_id.split_once(':').is_none() {
        return Err(format!(
            "api_proxy \"{name}\": login_cred_id must be <namespace>:<entry id>"
        ));
    }
    for (field, url) in [
        (
            "device_authorization_url",
            Some(oauth.device_authorization_url.as_str()),
        ),
        ("token_url", Some(oauth.token_url.as_str())),
        ("revocation_url", oauth.revocation_url.as_deref()),
    ] {
        if let Some(url) = url
            && !api_proxy_upstream_allowed(url)
        {
            return Err(format!(
                "api_proxy \"{name}\": {field} must be https:// or http:// on a loopback host (127.0.0.1, ::1, localhost)"
            ));
        }
    }
    if !valid_authorize_steps(oauth.steps.as_deref()) {
        return Err(format!(
            "api_proxy \"{name}\": oauth steps contain an unsupported action or value"
        ));
    }
    Ok(())
}

/// One `[[mcp_server]]` entry. The agent only selects by `name`; the command, arguments, and
/// environment variables are fixed by the configuration.
#[derive(Clone, Debug, Deserialize)]
struct McpServerConfig {
    name: String,
    cred_id: String,
    command: String,
    #[serde(default)]
    args: Vec<String>,
    #[serde(default)]
    env: BTreeMap<String, String>,
}

/// Placeholders substituted in the values of `[mcp_server.env]`. `{{secret}}` is the password and
/// `{{totp}}` is the current TOTP.
const MCP_SECRET_PLACEHOLDER: &str = API_PROXY_SECRET_PLACEHOLDER;
const MCP_USERNAME_PLACEHOLDER: &str = "{{username}}";
const MCP_TOTP_PLACEHOLDER: &str = "{{totp}}";
const MCP_PLACEHOLDERS: [&str; 3] = [
    MCP_SECRET_PLACEHOLDER,
    MCP_USERNAME_PLACEHOLDER,
    MCP_TOTP_PLACEHOLDER,
];

fn contains_mcp_placeholder(template: &str) -> bool {
    MCP_PLACEHOLDERS
        .iter()
        .any(|placeholder| template.contains(placeholder))
}

/// Detects a misconfigured `[[mcp_server]]` whose startup must be refused. Its namespace is
/// separate from `[[api_proxy]]`.
fn validate_mcp_servers(servers: &[McpServerConfig]) -> Result<(), String> {
    let mut names = HashSet::new();
    for server in servers {
        if server.name.is_empty() {
            return Err("mcp_server name must not be empty".to_owned());
        }
        if !names.insert(server.name.as_str()) {
            return Err(format!(
                "mcp_server \"{}\" is defined more than once",
                server.name
            ));
        }
        if server.cred_id.split_once(':').is_none() {
            return Err(format!(
                "mcp_server \"{}\": cred_id must be <namespace>:<entry id>",
                server.name
            ));
        }
        if !Path::new(&server.command).is_absolute() {
            return Err(format!(
                "mcp_server \"{}\": command must be an absolute path",
                server.name
            ));
        }
        if mcp_server_contains_nul(server) {
            return Err(format!(
                "mcp_server \"{}\": command, args, and env must not contain NUL",
                server.name
            ));
        }
        if server
            .env
            .keys()
            .any(|key| key.is_empty() || key.contains('='))
        {
            return Err(format!(
                "mcp_server \"{}\": env names must not be empty or contain '='",
                server.name
            ));
        }
        if !server
            .env
            .values()
            .any(|template| contains_mcp_placeholder(template))
        {
            return Err(format!(
                "mcp_server \"{}\": env must contain at least one of {}",
                server.name,
                MCP_PLACEHOLDERS.join(", ")
            ));
        }
    }
    Ok(())
}

/// Checks whether any of the command, the args, or the name or value of an env entry contains a
/// NUL.
/// The executor cannot start a child process with an argument or environment variable containing
/// NUL and refuses it at runtime, so this is checked ahead of time at startup.
fn mcp_server_contains_nul(server: &McpServerConfig) -> bool {
    std::iter::once(&server.command)
        .chain(&server.args)
        .chain(server.env.iter().flat_map(|(key, value)| [key, value]))
        .any(|value| value.contains('\0'))
}

/// Checks whether the upstream is `https://`, or `http://` on a loopback host.
///
/// Values containing characters that the executor (WHATWG URL) may interpret differently (control
/// characters, whitespace, backslashes),
/// or a port that cannot be interpreted, are uniformly rejected to avoid a misjudgment.
fn api_proxy_upstream_allowed(upstream: &str) -> bool {
    if upstream
        .chars()
        .any(|character| character.is_control() || character.is_whitespace() || character == '\\')
    {
        return false;
    }
    let Some((scheme, authority, _)) = split_authority(upstream) else {
        return false;
    };
    let host_port = authority
        .rsplit_once('@')
        .map_or(authority, |(_, host_port)| host_port);
    let (host, port) = match host_port.strip_prefix('[') {
        Some(bracketed) => match bracketed.split_once(']') {
            Some((host, "")) => (host, None),
            Some((host, tail)) => match tail.strip_prefix(':') {
                Some(port) => (host, Some(port)),
                None => return false,
            },
            None => return false,
        },
        None => match host_port.split_once(':') {
            Some((host, port)) => (host, Some(port)),
            None => (host_port, None),
        },
    };
    if host.is_empty()
        || port.is_some_and(|port| {
            !port.is_empty()
                && (!port.chars().all(|character| character.is_ascii_digit())
                    || port.parse::<u16>().is_err())
        })
    {
        return false;
    }
    if scheme.eq_ignore_ascii_case("https") {
        return true;
    }
    scheme.eq_ignore_ascii_case("http")
        && (host == "127.0.0.1" || host == "::1" || host.eq_ignore_ascii_case("localhost"))
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
    /// Backend id of the credential whose cookies are persisted. `"*"` stands for every
    /// credential of that provider. Common to all provider kinds.
    #[serde(default)]
    persist_cookies: Vec<String>,
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
    next_id: AtomicU64,
}

struct DaemonState {
    providers: Vec<Provider>,
    browsers: HashMap<String, sessions::Browser>,
    shared_browsers: HashMap<sessions::BrowserKey, String>,
    start_controls: HashMap<sessions::StartKey, Arc<Mutex<sessions::StartControl>>>,
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
    ports: Arc<std::sync::RwLock<HashMap<String, (String, u16)>>>,
    session_ttl: Duration,
    browser_max_lifetime: Duration,
    #[cfg(unix)]
    approve_cmd: Option<String>,
    approve_timeout: Duration,
    #[cfg(windows)]
    approve_operator: bool,
    #[cfg(windows)]
    approvals: approvals::ApprovalQueue,
    approval_grants: grants::ApprovalGrants,
    peers: peers::SharedPeerStore,
    api_proxies: HashMap<String, ApiProxyConfig>,
    mcp_servers: HashMap<String, McpServerConfig>,
    cookie_store: Arc<cookie_store::CookieStore>,
    /// Ledger of stepwise logins before the handoff.
    stepwise: stepwise::Ledger,
    /// Indicates that the daemon has entered shutdown processing (left `accept_connections`).
    /// Used so that a `pending` stepwise login registered after shutdown processing began ends
    /// itself right after registration.
    shutting_down: bool,
    #[cfg(windows)]
    sealed_blob_path: PathBuf,
}

type SharedState = Arc<Mutex<DaemonState>>;

// Keep in sync with packages/tegata-mcp/src/index.ts and tests/acceptance/support/harness.ts.
#[derive(Clone, Copy)]
enum ErrorCode {
    OAuthGrantFailed,
    InvalidCredential,
    MfaRequired,
    SelectorNotFound,
    FillMismatch,
    FillTargetRefused,
    SnapshotRejected,
    DeviceCodeRejected,
    LoginResultTimeout,
    VaultLocked,
    RateLimited,
    TotpNotExposable,
    ApprovalDenied,
    ApprovalTimeout,
    ProviderUnavailable,
    Internal,
    NotFound,
    Unauthorized,
    AdminRequired,
    #[cfg(windows)]
    AdminSealUnavailable,
}

impl ErrorCode {
    fn as_str(self) -> &'static str {
        match self {
            Self::OAuthGrantFailed => "OAUTH_GRANT_FAILED",
            Self::InvalidCredential => "INVALID_CREDENTIAL",
            Self::MfaRequired => "MFA_REQUIRED",
            Self::SelectorNotFound => "SELECTOR_NOT_FOUND",
            Self::FillMismatch => "FILL_MISMATCH",
            Self::FillTargetRefused => "FILL_TARGET_REFUSED",
            Self::SnapshotRejected => "SNAPSHOT_REJECTED",
            Self::DeviceCodeRejected => "DEVICE_CODE_REJECTED",
            Self::LoginResultTimeout => "LOGIN_RESULT_TIMEOUT",
            Self::VaultLocked => "VAULT_LOCKED",
            Self::RateLimited => "RATE_LIMITED",
            Self::TotpNotExposable => "TOTP_NOT_EXPOSABLE",
            Self::ApprovalDenied => "APPROVAL_DENIED",
            Self::ApprovalTimeout => "APPROVAL_TIMEOUT",
            Self::ProviderUnavailable => "PROVIDER_UNAVAILABLE",
            Self::Internal => "INTERNAL",
            Self::NotFound => "NOT_FOUND",
            Self::Unauthorized => "UNAUTHORIZED",
            Self::AdminRequired => "ADMIN_REQUIRED",
            #[cfg(windows)]
            Self::AdminSealUnavailable => "ADMIN_SEAL_UNAVAILABLE",
        }
    }
}

#[derive(Clone, Copy)]
struct ExecutorFailure {
    code: ErrorCode,
    step: Option<usize>,
}

impl From<ErrorCode> for ExecutorFailure {
    fn from(code: ErrorCode) -> Self {
        Self { code, step: None }
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
            Self::System => PeerIdentity::System.serialize(serializer),
        }
    }
}

#[derive(Serialize)]
struct AuditRecord<'a> {
    ts: String,
    #[serde(flatten)]
    peer: AuditPeer<'a>,
    method: String,
    #[serde(flatten)]
    fields: AuditFields,
    outcome: String,
}

/// Audit line fields. Those from `proxy` onward have values only in the lines of injection proxies
/// and MCP servers, and are omitted in other lines.
#[derive(Clone, Default, Serialize)]
struct AuditFields {
    cred_id: Option<String>,
    target_url: Option<String>,
    session_id: Option<String>,
    namespace: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    shared: Option<bool>,
    #[serde(skip_serializing_if = "Option::is_none")]
    approval_id: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    approval_allow: Option<bool>,
    #[serde(skip_serializing_if = "Option::is_none")]
    approval_grant: Option<grants::ApprovalGrant>,
    #[serde(skip_serializing_if = "Option::is_none")]
    proxy: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    http_method: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    path: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    status: Option<u16>,
    #[serde(skip_serializing_if = "Option::is_none")]
    oauth_action: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    mcp_server: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    mcp_action: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    exit_code: Option<i64>,
    /// In the login line of a persisted credential, whether the stored cookies were restored
    /// (`"restored"` / `"none"`).
    #[serde(skip_serializing_if = "Option::is_none")]
    cookies: Option<&'static str>,
    #[serde(skip_serializing_if = "Option::is_none")]
    steps_skipped: Option<bool>,
    /// In the line where the browser of a persisted credential ended, whether the cookies could
    /// be stored.
    #[serde(skip_serializing_if = "Option::is_none")]
    cookies_saved: Option<bool>,
    /// In the `admin_cookies_forget` line, the number of files deleted and whether everything
    /// was deleted.
    #[serde(skip_serializing_if = "Option::is_none")]
    removed: Option<usize>,
    #[serde(skip_serializing_if = "Option::is_none")]
    all: Option<bool>,
    /// In the lines of a stepwise login (`login_begin`, `login_step`, and the termination
    /// line), the ID of that stepwise login.
    #[serde(skip_serializing_if = "Option::is_none")]
    login_id: Option<String>,
    /// In the `login_step` line, the kind name of the action. The selector and the values are
    /// not recorded.
    #[serde(skip_serializing_if = "Option::is_none")]
    action: Option<String>,
    /// That the line concerns a stepwise login.
    #[serde(skip_serializing_if = "Option::is_none")]
    stepwise: Option<bool>,
}

/// Cookie persistence audit fields recorded in the login line and the session termination line.
/// They have values only for a persisted credential.
#[derive(Clone, Copy, Default)]
struct CookieAudit {
    cookies: Option<&'static str>,
    steps_skipped: Option<bool>,
    cookies_saved: Option<bool>,
}

impl CookieAudit {
    fn login(restored: bool, steps_skipped: bool) -> Self {
        Self {
            cookies: Some(if restored { "restored" } else { "none" }),
            steps_skipped: Some(steps_skipped),
            cookies_saved: None,
        }
    }

    fn session_end(cookies_saved: Option<bool>) -> Self {
        Self {
            cookies_saved,
            ..Self::default()
        }
    }

    fn apply(self, fields: &mut AuditFields) {
        fields.cookies = self.cookies.or(fields.cookies);
        fields.steps_skipped = self.steps_skipped.or(fields.steps_skipped);
        fields.cookies_saved = self.cookies_saved.or(fields.cookies_saved);
    }
}

#[derive(Deserialize)]
struct LoginRequestParams {
    #[serde(flatten)]
    login: LoginParams,
    #[serde(default)]
    exclusive: bool,
}

struct CredentialMetadata {
    uri: Option<String>,
}

struct HandledRequest {
    response: RpcResponse,
    outcome: String,
    audit_shared: Option<bool>,
    audit_approval: Option<(String, bool)>,
    audit_approval_grant: Option<grants::ApprovalGrant>,
    /// Audit fields determined by the handler. When `Some`, they are recorded in place of the
    /// fields derived from params.
    audit_fields: Option<AuditFields>,
    /// Cookie persistence audit fields. Recorded on top of the audit fields above.
    audit_cookies: Option<CookieAudit>,
}

impl HandledRequest {
    fn with_audit_shared(mut self, shared: bool) -> Self {
        self.audit_shared = Some(shared);
        self
    }

    #[cfg(windows)]
    fn with_audit_approval(mut self, approval_id: String, allow: bool) -> Self {
        self.audit_approval = Some((approval_id, allow));
        self
    }

    fn with_audit_fields(mut self, fields: AuditFields) -> Self {
        self.audit_fields = Some(fields);
        self
    }

    fn with_audit_approval_grant(mut self, grant: Option<grants::ApprovalGrant>) -> Self {
        self.audit_approval_grant = grant;
        self
    }

    fn with_audit_cookies(mut self, cookies: Option<CookieAudit>) -> Self {
        self.audit_cookies = cookies;
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
    Cookies {
        #[command(subcommand)]
        command: UnixCookiesCommand,
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

#[cfg(unix)]
#[derive(clap::Subcommand)]
enum UnixCookiesCommand {
    /// Delete the stored cookies of one credential (every principal) or of all credentials.
    Forget {
        #[arg(required_unless_present = "all", conflicts_with = "all")]
        cred_id: Option<String>,
        #[arg(long)]
        all: bool,
        #[arg(long, default_value = "/run/tegata/tegatad.sock")]
        socket: PathBuf,
    },
}

/// Builds the params of `admin_cookies_forget` from the CLI arguments of `cookies forget`.
/// clap guarantees that exactly one of cred_id and `--all` is given.
fn cookies_forget_params(cred_id: Option<String>, all: bool) -> Value {
    match cred_id {
        Some(cred_id) => json!({ "cred_id": cred_id }),
        None => json!({ "all": all }),
    }
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
                windows_cli::WindowsCommand::Approval { command } => {
                    let (pipe, id, allow) = match command {
                        windows_cli::ApprovalCommand::List { pipe } => {
                            return windows_cli::run_windows_cli(
                                &pipe,
                                "admin_approval_list",
                                json!({}),
                            );
                        }
                        windows_cli::ApprovalCommand::Allow { id, pipe } => (pipe, id, true),
                        windows_cli::ApprovalCommand::Deny { id, pipe } => (pipe, id, false),
                    };
                    windows_cli::run_windows_cli(
                        &pipe,
                        "admin_approval_decide",
                        json!({ "id": id, "allow": allow }),
                    )
                }
                windows_cli::WindowsCommand::Cookies { command } => match command {
                    windows_cli::CookiesCommand::Forget { cred_id, all, pipe } => {
                        windows_cli::run_windows_cli(
                            &pipe,
                            "admin_cookies_forget",
                            cookies_forget_params(cred_id, all),
                        )
                    }
                },
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
        UnixCommand::Cookies { command } => match command {
            UnixCookiesCommand::Forget {
                cred_id,
                all,
                socket,
            } => {
                let response = call_unix_rpc(
                    &socket,
                    "admin_cookies_forget",
                    cookies_forget_params(cred_id, all),
                )?;
                let result = response
                    .get("result")
                    .ok_or("admin_cookies_forget returned no result")?;
                println!("{}", serde_json::to_string(result)?);
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
    if config.browser_max_lifetime_secs == 0 {
        return Err("browser_max_lifetime_secs must be at least 1".into());
    }
    if config.stepwise_idle_secs == 0 {
        return Err("stepwise_idle_secs must be at least 1".into());
    }
    if config.stepwise_max_secs == 0 {
        return Err("stepwise_max_secs must be at least 1".into());
    }
    let listeners = normalize_listeners(&config_text, &config)?;
    validate_api_proxies(&config.api_proxy)?;
    validate_mcp_servers(&config.mcp_server)?;
    #[cfg(unix)]
    if let Some(path) = config.executor_socket.as_deref() {
        let uid = validate_executor_socket(path).await?;
        eprintln!("executor: socket {path} (uid {uid})");
    } else {
        eprintln!("executor: spawned by the daemon (browser is not isolated)");
        validate_spawned_executor(&config).await?;
    }
    #[cfg(unix)]
    secure_fs::ensure_private_dir(Path::new(&config.state_dir))?;
    remove_legacy_password_dir(Path::new(&config.state_dir)).await;
    #[cfg(windows)]
    if config.approve_cmd.is_some() {
        return Err("approve_cmd is only supported on Unix".into());
    }
    #[cfg(unix)]
    if config.approve_operator.is_some() {
        return Err("approve_operator is only supported on Windows".into());
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
    validate_spawned_executor(&config).await?;
    #[cfg(windows)]
    let (token_hash_path, _sealed_blob_path) = resolve_windows_paths(&config);
    #[cfg(unix)]
    let token_hash_path = PathBuf::from(&config.state_dir).join("token_hash");
    let max_pending_connections = config.max_pending_connections;
    let pending_connections = Arc::new(AtomicUsize::new(0));
    #[cfg(windows)]
    tokio::fs::create_dir_all(&config.state_dir).await?;
    let peers_path = PathBuf::from(&config.state_dir).join("peers.json");
    let peers = peers::PeerStore::load_or_import(&peers_path, &token_hash_path)?;
    let state = Arc::new(Mutex::new(build_state(config, peers.clone()).await?));
    let ports = state.lock().await.ports.clone();
    let resolver: CdpPortResolver = Arc::new(move |session_id, peer| {
        ports.read().ok().and_then(|ports| {
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
        pending_connections,
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
    stepwise::spawn_reaper(state.clone());
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
    // The flag is set immediately before the sweep so that it reliably picks up the `pending`
    // of a stepwise login registered before the sweep.
    // A `pending` registered after the sweep is picked up by the self-termination check right
    // after registration (`stepwise::register_pending`).
    state.lock().await.shutting_down = true;
    terminate_browsers(&state, drain_browsers(&state, None).await).await;
    stepwise::terminate(&state, None, stepwise::EndReason::Shutdown).await;
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
        return Err(executor_socket_error(path, executor_refusal(&response)));
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

/// Returns the explanation used when the executor refuses hello. If the executor attached a reason,
/// it is included as is.
fn executor_refusal(response: &ExecutorHelloResponse) -> String {
    match response.reason.as_deref() {
        Some(reason) => format!("executor reported ok=false: {reason}"),
        None => "executor reported ok=false".to_owned(),
    }
}

/// Starts the spawn-mode executor once in the same way as at lease time, and checks the startup
/// prerequisites.
///
/// A missing prerequisite such as the full Chromium is stopped at startup rather than at every
/// lease, so this runs before listen.
/// Regardless of whether the response succeeds, the executor is terminated with `shutdown`.
async fn validate_spawned_executor(config: &Config) -> Result<(), io::Error> {
    let entry = resolve_executor_entry(config);
    let node_path = resolve_node_path(config);
    let browsers_path = resolve_browsers_path(config);
    let mut executor = connect_executor(&entry, None, &node_path, browsers_path.as_deref())
        .await
        .map_err(|error| {
            spawned_executor_error(
                &entry,
                format!(
                    "the executor could not be started with node \"{}\": {error}",
                    node_path.display()
                ),
            )
        })?;
    let response = request_executor_hello(&mut executor).await;
    shutdown_executor_handle(&mut executor, 1).await;
    let response = response.map_err(|error| spawned_executor_error(&entry, error))?;
    if !response.ok {
        return Err(spawned_executor_error(&entry, executor_refusal(&response)));
    }
    Ok(())
}

/// Sends one `hello` line to a started executor and interprets the response. If it exits without
/// responding, that is a failure.
async fn request_executor_hello(
    executor: &mut ExecutorHandle,
) -> Result<ExecutorHelloResponse, String> {
    let mut request = serde_json::to_vec(&ExecutorHelloRequest { op: "hello" })
        .map_err(|error| error.to_string())?;
    request.push(b'\n');
    executor
        .write_line(&request)
        .await
        .map_err(|error| error.to_string())?;
    let response_line = timeout(EXECUTOR_TIMEOUT, executor.read_line())
        .await
        .map_err(|_| "no response to hello".to_owned())?
        .map_err(|error| error.to_string())?;
    if response_line.is_empty() {
        return Err("the executor exited without answering hello".to_owned());
    }
    serde_json::from_str(&response_line).map_err(|error| error.to_string())
}

fn spawned_executor_error(entry: &Path, error: impl fmt::Display) -> io::Error {
    io::Error::other(format!(
        "executor \"{}\" failed the startup check: {error}",
        entry.display()
    ))
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
    let (peer, stream, allowed_uids, operator_uids) = match accepted {
        Accepted::Rpc {
            peer,
            stream,
            operator_uids,
        } => (peer, stream, Vec::new(), operator_uids),
        #[cfg(unix)]
        Accepted::UnixRpc {
            peer,
            stream,
            allowed_uids,
            operator_uids,
        } => (peer, stream, allowed_uids, operator_uids),
        Accepted::Consumed => return Ok(()),
    };
    tokio::spawn(async move {
        serve_connection(stream, peer, allowed_uids, operator_uids, state).await;
    });
    Ok(())
}

async fn build_state(
    config: Config,
    peers: peers::SharedPeerStore,
) -> Result<DaemonState, io::Error> {
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
    let approve_timeout = Duration::from_secs(config.approve_timeout_secs.unwrap_or(60));
    #[cfg(windows)]
    let approve_operator = config.approve_operator.unwrap_or(false);
    let approval_grant_ttl = Duration::from_secs(config.approval_grant_ttl_secs);
    let executor_entry = resolve_executor_entry(&config);
    #[cfg(unix)]
    let executor_socket = config.executor_socket.as_deref().map(PathBuf::from);
    #[cfg(windows)]
    let executor_socket = None;
    let node_path = resolve_node_path(&config);
    let browsers_path = resolve_browsers_path(&config);
    let bw_path = resolve_bw_path(&config);
    let session_ttl = Duration::from_secs(config.session_ttl_secs.unwrap_or(300));
    let browser_max_lifetime = Duration::from_secs(config.browser_max_lifetime_secs);
    let stepwise = stepwise::Ledger::new(
        Duration::from_secs(config.stepwise_idle_secs),
        Duration::from_secs(config.stepwise_max_secs),
    );
    let state_dir = PathBuf::from(&config.state_dir);
    let api_proxies = config
        .api_proxy
        .iter()
        .map(|proxy| (proxy.name.clone(), proxy.clone()))
        .collect();
    let mcp_servers = config
        .mcp_server
        .iter()
        .map(|server| (server.name.clone(), server.clone()))
        .collect();
    let mut providers = Vec::new();
    let mut cookie_policy = cookie_store::CookiePolicy::default();
    let mut version_logged = false;
    for provider in config.providers {
        let namespace = provider.namespace;
        cookie_policy.insert(namespace.clone(), provider.persist_cookies);
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
            } => {
                let provider = BitwardenCliProvider::new(BitwardenCliConfig {
                    namespace: namespace.clone(),
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
                });
                if !version_logged {
                    STARTUP_CONTEXT.scope((), provider.log_version()).await;
                    version_logged = true;
                }
                Arc::new(Mutex::new(provider))
            }
            ProviderConfigKind::AgeFile {
                entries_path,
                identity_path,
                session_ttl_secs,
            } => Arc::new(Mutex::new(FileProvider::new(FileProviderConfig {
                entries_path,
                identity_path,
                session_ttl: Duration::from_secs(session_ttl_secs.unwrap_or(session_ttl.as_secs())),
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
                session_ttl: Duration::from_secs(session_ttl_secs.unwrap_or(session_ttl.as_secs())),
            }))),
            #[cfg(windows)]
            ProviderConfigKind::Pass { .. } => unreachable!("pass provider was rejected above"),
        };
        providers.push(Provider {
            namespace,
            provider,
        });
    }
    let cookie_store = cookie_store::CookieStore::new(&state_dir, cookie_policy);
    cookie_store.prepare()?;
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
        ports: Arc::new(std::sync::RwLock::new(HashMap::new())),
        session_ttl,
        browser_max_lifetime,
        #[cfg(unix)]
        approve_cmd,
        approve_timeout,
        #[cfg(windows)]
        approve_operator,
        #[cfg(windows)]
        approvals: approvals::ApprovalQueue::new(),
        approval_grants: grants::ApprovalGrants::new(approval_grant_ttl),
        peers,
        api_proxies,
        mcp_servers,
        cookie_store: Arc::new(cookie_store),
        stepwise,
        shutting_down: false,
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

fn lease_expiry(now: Instant, ttl: Duration, deadline: Instant) -> Instant {
    (now + ttl).min(deadline)
}

fn take_browser_locked(daemon: &mut DaemonState, browser_id: &str) -> Option<sessions::Browser> {
    let browser = daemon.browsers.remove(browser_id)?;
    if !browser.exclusive {
        daemon.shared_browsers.remove(&browser.key);
    }
    if let Ok(mut ports) = daemon.ports.write() {
        for session_id in browser.leases.keys() {
            ports.remove(session_id);
        }
    }
    Some(browser)
}

async fn expire_browser_at_deadline(state: &SharedState, browser_id: &str) {
    let browser = {
        let mut daemon = state.lock().await;
        let expired = daemon
            .browsers
            .get(browser_id)
            .is_some_and(|browser| browser.deadline <= Instant::now());
        if expired {
            take_browser_locked(&mut daemon, browser_id)
        } else {
            None
        }
    };
    if let Some(browser) = browser {
        terminate_browser(state, browser, "session_expired", false).await;
    }
}

fn spawn_session_reaper(state: SharedState) {
    tokio::spawn(async move {
        let mut ticker = interval(Duration::from_secs(1));
        loop {
            ticker.tick().await;
            let (deadline_expired, expired) = {
                let mut daemon = state.lock().await;
                let now = Instant::now();
                let mut deadline_expired = Vec::new();
                let mut expired = Vec::new();
                let browser_ids = daemon.browsers.keys().cloned().collect::<Vec<_>>();
                for browser_id in browser_ids {
                    if daemon
                        .browsers
                        .get(&browser_id)
                        .is_some_and(|browser| browser.deadline <= now)
                    {
                        if let Some(browser) = take_browser_locked(&mut daemon, &browser_id) {
                            deadline_expired.push(browser);
                        }
                        continue;
                    }
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
                                browser.key.clone(),
                                browser.leases.is_empty(),
                                browser.persist_cookies,
                            ));
                        }
                    }
                    if let Ok(mut ports) = daemon.ports.write() {
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
                (deadline_expired, expired)
            };
            for browser in deadline_expired {
                let state = state.clone();
                tokio::spawn(async move {
                    terminate_browser(&state, browser, "session_expired", false).await;
                });
            }
            for (session_id, lease, executor, key, shutdown, persist_cookies) in expired {
                // Expiry of the last lease closes the browser, so the cookies are
                // written out before closing the tab.
                let cookies_saved = if shutdown && persist_cookies {
                    Some(export_browser_cookies(&state, &key, &executor).await)
                } else {
                    None
                };
                let release_failed = release_lease(&executor, &lease.target).await.is_err();
                if shutdown || release_failed {
                    shutdown_executor(executor).await;
                }
                let daemon = state.lock().await;
                if let Err(error) = append_audit(
                    &daemon,
                    AuditPeer::System,
                    "session_expired".to_owned(),
                    AuditFields {
                        session_id: Some(session_id),
                        namespace: Some(key.namespace),
                        cookies_saved,
                        ..AuditFields::default()
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
            namespace: Some(namespace),
            ..AuditFields::default()
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
    allowed_uids: Vec<u32>,
    operator_uids: Vec<u32>,
    state: SharedState,
) where
    S: AsyncRead + AsyncWrite + Send + Unpin,
{
    let (read_half, mut write_half) = tokio::io::split(stream);
    let mut lines = BufReader::new(read_half).lines();
    while let Ok(Some(line)) = lines.next_line().await {
        if let PeerIdentity::Peer { peer_id, .. } = &peer {
            let peer_store = state.lock().await.peers.clone();
            if !peers::is_active(&peer_store, peer_id) {
                let _ = write_half
                    .write_all(b"{\"ok\":false,\"error\":\"UNAUTHORIZED\"}\n")
                    .await;
                let _ = write_half.flush().await;
                break;
            }
        }
        let parsed = serde_json::from_str::<RpcRequest>(&line);
        let rpc_id = NEXT_RPC_ID.fetch_add(1, Ordering::Relaxed);
        let (request, response, outcome, fields) = match parsed {
            Ok(request) => {
                let fields = audit_fields(&request.method, &request.params);
                let handled = RPC_CONTEXT
                    .scope(
                        RpcContext {
                            id: rpc_id,
                            method: request.method.clone(),
                        },
                        handle_request(
                            &request,
                            state.clone(),
                            &peer,
                            &allowed_uids,
                            &operator_uids,
                        ),
                    )
                    .await;
                let mut fields = fields;
                if matches!(
                    request.method.as_str(),
                    "login" | "login_begin" | "login_step"
                ) && handled.outcome == "ok"
                    && let Some(result) = handled.response.result.as_ref()
                {
                    fields.session_id = result
                        .get("session_id")
                        .and_then(Value::as_str)
                        .map(ToOwned::to_owned);
                    fields.shared = handled.audit_shared;
                    // The line that started a stepwise login carries the
                    // login_id to associate it with the later login_step lines.
                    if request.method == "login_begin" {
                        fields.login_id = result
                            .get("login_id")
                            .and_then(Value::as_str)
                            .map(ToOwned::to_owned);
                    }
                }
                if let Some(handler_fields) = handled.audit_fields {
                    fields = handler_fields;
                }
                if let Some((approval_id, allow)) = handled.audit_approval {
                    fields.approval_id = Some(approval_id);
                    fields.approval_allow = Some(allow);
                }
                if let Some(grant) = handled.audit_approval_grant {
                    fields.approval_grant = Some(grant);
                }
                if let Some(cookies) = handled.audit_cookies {
                    cookies.apply(&mut fields);
                }
                (Some(request), handled.response, handled.outcome, fields)
            }
            Err(_) => (
                None,
                error_response(Value::Null, ErrorCode::Internal),
                ErrorCode::Internal.as_str().to_owned(),
                AuditFields::default(),
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
    // To avoid letting a stepwise login continue on a page containing a secret, the stepwise
    // login of a replaced pending response is terminated.
    let leaked_login_id = (!leaked.is_empty())
        .then(|| stepwise::pending_login_id(&method, response.result.as_ref()))
        .flatten();
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
    if let Some(login_id) = leaked_login_id {
        stepwise::end_leaked(state, &login_id, peer).await;
    }
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
        fields,
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
        .map_err(AppendAuditError::Write)?;
    // The tokio File returns completion once the write has been handed to a background blocking
    // task.
    // Without waiting for the write to complete with flush, a response can arrive before the
    // audit line appears in the file.
    file.flush().await.map_err(AppendAuditError::Write)
}

async fn handle_request(
    request: &RpcRequest,
    state: SharedState,
    peer: &PeerIdentity,
    allowed_uids: &[u32],
    operator_uids: &[u32],
) -> HandledRequest {
    if request.jsonrpc != JSON_RPC_VERSION {
        return classified(request.id.clone(), ErrorCode::Internal);
    }
    if request.method.starts_with("admin_") {
        if !peer.allows_admin_rpc(operator_uids) {
            if let PeerIdentity::Sid {
                origin,
                elevated,
                administrator,
                ..
            } = peer
            {
                eprintln!(
                    "tegatad: admin rpc refused: peer origin {} (elevated={elevated}, administrator={administrator})",
                    origin.as_str()
                );
            }
            return classified(request.id.clone(), ErrorCode::AdminRequired);
        }
        return match request.method.as_str() {
            "admin_peer_issue" => admin_peer_issue(request, state).await,
            "admin_peer_revoke" => admin_peer_revoke(request, state).await,
            "admin_peer_list" => admin_peer_list(request, state).await,
            "admin_token_issue" => admin_token_issue(request, state).await,
            "admin_cookies_forget" => admin_cookies_forget(request, state).await,
            #[cfg(windows)]
            "admin_seal" => admin_seal(request, state).await,
            #[cfg(windows)]
            "admin_approval_list" => admin_approval_list(request, state).await,
            #[cfg(windows)]
            "admin_approval_decide" => admin_approval_decide(request, state).await,
            _ => classified(request.id.clone(), ErrorCode::Internal),
        };
    }
    if !peer.allows_normal_rpc(allowed_uids) {
        return classified(request.id.clone(), ErrorCode::Unauthorized);
    }
    match request.method.as_str() {
        "status" => status(request, state).await,
        "list_credentials" => list_credentials(request, state).await,
        "login" => login(request, state, peer).await,
        "login_begin" => stepwise::login_begin(request, state, peer).await,
        "login_step" => stepwise::login_step(request, state, peer).await,
        "authorize_device" => authorize_device(request, state, peer).await,
        "open_api_proxy" => open_service::<ApiProxyConfig>(request, state, peer).await,
        "open_mcp_server" => open_service::<McpServerConfig>(request, state, peer).await,
        "disconnect" => disconnect(request, state, peer).await,
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
                    data: None,
                }),
            },
            outcome: "method_not_found".to_owned(),
            audit_shared: None,
            audit_approval: None,
            audit_approval_grant: None,
            audit_fields: None,
            audit_cookies: None,
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

#[derive(Deserialize)]
struct AdminCookiesForgetParams {
    cred_id: Option<String>,
    #[serde(default)]
    all: bool,
}

/// Deletes the stored cookies. With `cred_id` it deletes them for all principals of that
/// credential, and with `all` it deletes everything.
/// A running session is not terminated, so its cookies are saved again when that session ends.
async fn admin_cookies_forget(request: &RpcRequest, state: SharedState) -> HandledRequest {
    let params = match parse_params::<AdminCookiesForgetParams>(&request.params) {
        Ok(params) => params,
        Err(error) => return classified(request.id.clone(), error),
    };
    let audit = AuditFields {
        cred_id: params.cred_id.clone(),
        all: params.all.then_some(true),
        ..AuditFields::default()
    };
    let target = match (params.cred_id.as_deref(), params.all) {
        (Some(cred_id), false) => cookie_store::ForgetTarget::Credential(cred_id),
        (None, true) => cookie_store::ForgetTarget::All,
        _ => return classified(request.id.clone(), ErrorCode::Internal).with_audit_fields(audit),
    };
    let store = state.lock().await.cookie_store.clone();
    match store.forget(target) {
        Ok(removed) => success(request.id.clone(), json!({ "removed": removed }))
            .with_audit_fields(AuditFields {
                removed: Some(removed),
                ..audit
            }),
        Err(error) => {
            eprintln!("tegatad: cookie store: forget failed: {error}");
            classified(request.id.clone(), ErrorCode::Internal).with_audit_fields(audit)
        }
    }
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
#[derive(Deserialize)]
struct AdminApprovalDecideParams {
    id: String,
    allow: bool,
}

#[cfg(windows)]
async fn admin_approval_list(request: &RpcRequest, state: SharedState) -> HandledRequest {
    let queue = state.lock().await.approvals.clone();
    let pending = queue
        .list()
        .into_iter()
        .map(|pending| {
            json!({
                "id": pending.id,
                "method": pending.method,
                "cred_id": pending.cred_id,
                "target_url": pending.target_url,
                "principal": pending.principal,
                "age_secs": pending.age_secs,
            })
        })
        .collect::<Vec<_>>();
    success(request.id.clone(), json!({ "pending": pending }))
}

#[cfg(windows)]
async fn admin_approval_decide(request: &RpcRequest, state: SharedState) -> HandledRequest {
    let params = match parse_params::<AdminApprovalDecideParams>(&request.params) {
        Ok(params) => params,
        Err(error) => return classified(request.id.clone(), error),
    };
    let queue = state.lock().await.approvals.clone();
    let handled = match queue.decide(&params.id, params.allow) {
        Ok(()) => success(request.id.clone(), json!({ "ok": true })),
        Err(approvals::NotFound) => classified(request.id.clone(), ErrorCode::NotFound),
    };
    // The content of the decision is recorded in the audit fields so that which pending request
    // was answered, and how, can be traced in the audit.
    handled.with_audit_approval(params.id, params.allow)
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
    // `browsers` counts only browsers, excluding injection proxies and MCP servers. `leases`
    // counts all leases.
    let browsers = daemon
        .browsers
        .values()
        .filter(|browser| !browser.is_service())
        .count();
    success(
        request.id.clone(),
        json!({ "ok": true, "browsers": browsers, "leases": leases }),
    )
}

async fn join_browser(
    state: &SharedState,
    key: &sessions::BrowserKey,
    principal: &str,
) -> Option<Result<Value, ErrorCode>> {
    let (browser_id, executor, endpoint, ttl, deadline_expired) = {
        let daemon = state.lock().await;
        let browser_id = daemon.shared_browsers.get(key)?.clone();
        let browser = daemon.browsers.get(&browser_id)?;
        let now = Instant::now();
        (
            browser_id,
            browser.executor.clone(),
            browser.endpoint.clone(),
            daemon.session_ttl,
            browser.deadline <= now,
        )
    };
    if deadline_expired {
        expire_browser_at_deadline(state, &browser_id).await;
        return None;
    }
    let target_id = match executor_lease(&executor).await {
        Ok(target_id) => target_id,
        Err(error) => {
            let active = {
                let daemon = state.lock().await;
                daemon
                    .browsers
                    .get(&browser_id)
                    .is_some_and(|browser| browser.deadline > Instant::now())
            };
            if !active {
                expire_browser_at_deadline(state, &browser_id).await;
                return None;
            }
            return Some(Err(error));
        }
    };
    let session_id = Uuid::new_v4().to_string();
    let (joined, expired_browser) = {
        let mut daemon = state.lock().await;
        let now = Instant::now();
        let browser_expired = daemon
            .browsers
            .get(&browser_id)
            .is_some_and(|browser| browser.deadline <= now);
        if browser_expired {
            (false, take_browser_locked(&mut daemon, &browser_id))
        } else if let Some(port) = daemon.browsers.get(&browser_id).map(|browser| browser.port) {
            let deadline = daemon
                .browsers
                .get(&browser_id)
                .expect("browser exists")
                .deadline;
            let lease = sessions::Lease {
                principal: principal.to_owned(),
                expires_at: lease_expiry(now, ttl, deadline),
                target: sessions::LeaseTarget::Tab(target_id.clone()),
            };
            daemon
                .browsers
                .get_mut(&browser_id)
                .expect("browser checked above")
                .leases
                .insert(session_id.clone(), lease);
            if let Ok(mut ports) = daemon.ports.write() {
                ports.insert(session_id.clone(), (principal.to_owned(), port));
            }
            (true, None)
        } else {
            (false, None)
        }
    };
    if let Some(browser) = expired_browser {
        let _ = executor_release(&executor, target_id).await;
        terminate_browser(state, browser, "session_expired", false).await;
        return None;
    }
    if !joined {
        let _ = executor_release(&executor, target_id).await;
        return None;
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
    let grant =
        match gate_on_approval(&state, &params.cred_id, &params.target_url, "login", peer).await {
            Ok(grant) => grant,
            Err(error) => return classified(request.id.clone(), error),
        };
    start_login(
        request,
        state,
        key,
        principal,
        params,
        request_params.exclusive,
    )
    .await
    .with_audit_approval_grant(grant)
}

/// For a `login` that passed the approval gate, piggybacks on an existing browser or starts a new
/// one.
async fn start_login(
    request: &RpcRequest,
    state: SharedState,
    key: sessions::BrowserKey,
    principal: String,
    params: LoginParams,
    exclusive: bool,
) -> HandledRequest {
    let start_gate = start_control(&state, sessions::StartKey::Browser(key.clone())).await;
    let mut start_guard = start_gate.lock().await;
    if !exclusive && let Some(result) = join_browser(&state, &key, &principal).await {
        return match result {
            Ok(result) => success(request.id.clone(), result).with_audit_shared(true),
            Err(error) => classified(request.id.clone(), error),
        };
    }
    if start_guard.is_limited(Instant::now()) {
        return classified(request.id.clone(), ErrorCode::RateLimited);
    }
    let credential = match resolve_unlocked_credential(&state, &params.cred_id).await {
        Ok(credential) => credential,
        Err(error) => return classified(request.id.clone(), error),
    };
    let (executor_entry, executor_socket, node_path, browsers_path, cookie_store) = {
        let daemon = state.lock().await;
        (
            daemon.executor_entry.clone(),
            daemon.executor_socket.clone(),
            daemon.node_path.clone(),
            daemon.browsers_path.clone(),
            daemon.cookie_store.clone(),
        )
    };
    // Read the stored cookies only after passing the approval gate and the unlock check.
    let persist_cookies = cookie_store.persists(&params.cred_id);
    let restored_cookies = persist_cookies
        .then(|| cookie_store.load(&key, cookie_store::unix_now()))
        .flatten();
    start_guard.record_attempt(Instant::now());
    let browser_started_at = Instant::now();
    let started = match start_executor(
        &executor_entry,
        executor_socket.as_deref(),
        &node_path,
        browsers_path.as_deref(),
        &params,
        &credential,
        restored_cookies.as_deref(),
    )
    .await
    {
        Ok(result) => {
            start_guard.record_success();
            result
        }
        Err(error) => {
            start_guard.record_failure(Instant::now());
            return classified_with_step(request.id.clone(), error.code, error.step);
        }
    };
    let ExecutorLoginStarted {
        endpoint,
        target_id,
        executor,
        cookies: returned_cookies,
        steps_skipped,
    } = started;
    let registration = BrowserRegistration {
        key: key.clone(),
        principal,
        exclusive,
        persist_cookies,
        endpoint,
        target_id,
        executor,
        next_id: 2,
        browser_started_at,
    };
    let result = match register_login_browser(&state, registration).await {
        Ok(result) => result,
        Err(error) => return classified(request.id.clone(), error),
    };
    let cookie_audit = persist_cookies.then(|| {
        if let Some(cookies) = returned_cookies.as_ref() {
            save_cookies(&cookie_store, &key, cookies);
        }
        CookieAudit::login(restored_cookies.is_some(), steps_skipped)
    });
    success(request.id.clone(), result)
        .with_audit_shared(false)
        .with_audit_cookies(cookie_audit)
}

/// Values for registering an executor that finished login as a browser holding one lease.
struct BrowserRegistration {
    key: sessions::BrowserKey,
    principal: String,
    exclusive: bool,
    persist_cookies: bool,
    endpoint: String,
    target_id: String,
    executor: ExecutorHandle,
    /// Id of the next request to send to the executor. It must not overlap any id used so far.
    next_id: u64,
    browser_started_at: Instant,
}

/// Registers an executor that finished login in the ledger as a browser, and starts a reaper that
/// reads its responses.
/// The return value is the success response of `login` (`session_id`, `target_id`, `channel`).
/// If it cannot be registered, the executor is stopped and `INTERNAL` is returned.
async fn register_login_browser(
    state: &SharedState,
    registration: BrowserRegistration,
) -> Result<Value, ErrorCode> {
    let BrowserRegistration {
        key,
        principal,
        exclusive,
        persist_cookies,
        endpoint,
        target_id,
        mut executor,
        next_id,
        browser_started_at,
    } = registration;
    let (ttl, browser_max_lifetime) = {
        let daemon = state.lock().await;
        (daemon.session_ttl, daemon.browser_max_lifetime)
    };
    let deadline = browser_started_at + browser_max_lifetime;
    let session_id = Uuid::new_v4().to_string();
    let reader = executor
        .take_reader()
        .ok_or_else(|| io::Error::other("executor stdout or socket reader is unavailable"));
    let reader = match reader {
        Ok(reader) => reader,
        Err(_) => {
            stop_child(executor).await;
            return Err(ErrorCode::Internal);
        }
    };
    let Some(port) = cdp_port_from_endpoint(&endpoint) else {
        stop_child(executor).await;
        return Err(ErrorCode::Internal);
    };
    let (response_sender, response_receiver) = mpsc::unbounded_channel();
    let connection = Arc::new(ExecutorConnection {
        executor: Mutex::new(executor),
        responses: Mutex::new(response_receiver),
        operation: Mutex::new(()),
        next_id: AtomicU64::new(next_id),
    });
    let browser_id = Uuid::new_v4().to_string();
    let response_target_id = target_id.clone();
    let now = Instant::now();
    let browser = sessions::Browser {
        key: key.clone(),
        executor: connection.clone(),
        port,
        endpoint: endpoint.clone(),
        deadline,
        leases: HashMap::from([(
            session_id.clone(),
            sessions::Lease {
                principal: principal.clone(),
                expires_at: lease_expiry(now, ttl, deadline),
                target: sessions::LeaseTarget::Tab(target_id),
            },
        )]),
        exclusive,
        persist_cookies,
    };
    let ports = state.lock().await.ports.clone();
    if let Ok(mut ports) = ports.write() {
        ports.insert(session_id.clone(), (principal, port));
    } else {
        shutdown_executor(connection).await;
        return Err(ErrorCode::Internal);
    }
    let mut daemon = state.lock().await;
    daemon.browsers.insert(browser_id.clone(), browser);
    if !exclusive {
        daemon.shared_browsers.insert(key, browser_id.clone());
    }
    drop(daemon);
    spawn_executor_reaper(state.clone(), browser_id, reader, response_sender, None);
    Ok(json!({
        "session_id": session_id,
        "target_id": response_target_id,
        "channel": { "kind": "cdp", "endpoint": endpoint },
    }))
}

/// Takes out the startup control for each key, creating it if absent.
async fn start_control(
    state: &SharedState,
    key: sessions::StartKey,
) -> Arc<Mutex<sessions::StartControl>> {
    state
        .lock()
        .await
        .start_controls
        .entry(key)
        .or_insert_with(|| Arc::new(Mutex::new(sessions::StartControl::new())))
        .clone()
}

/// When the approval gate is configured, checks the existence and lock state of the credential and
/// then asks for approval.
/// A locked credential is rejected before approval is requested. The handling of grants follows
/// `approve_with_grant`.
/// For a credential whose existence could not be confirmed, approval alone is requested, without
/// consulting or recording a grant.
async fn gate_on_approval(
    state: &SharedState,
    cred_id: &str,
    target_url: &str,
    method: &str,
    peer: &PeerIdentity,
) -> Result<Option<grants::ApprovalGrant>, ErrorCode> {
    if !approval_required(&*state.lock().await) {
        return Ok(None);
    }
    let credential = match credential_state(state, cred_id).await? {
        Some(credential) => credential,
        None => return Err(ErrorCode::InvalidCredential),
    };
    if credential.locked {
        return Err(ErrorCode::VaultLocked);
    }
    if !credential.confirmed {
        request_approval(state, cred_id, target_url, method, peer).await?;
        return Ok(None);
    }
    approve_with_grant(state, cred_id, target_url, method, peer).await
}

/// If a valid grant exists for (principal, cred_id), passes without asking for approval; otherwise
/// asks for approval.
/// The grant is recorded only when approval is given. Returns `None` in a configuration where the
/// grant validity period is 0.
async fn approve_with_grant(
    state: &SharedState,
    cred_id: &str,
    target_url: &str,
    method: &str,
    peer: &PeerIdentity,
) -> Result<Option<grants::ApprovalGrant>, ErrorCode> {
    let principal = peer.principal();
    let observed = {
        let mut daemon = state.lock().await;
        if daemon
            .approval_grants
            .reuse(&principal, cred_id, Instant::now())
        {
            return Ok(Some(grants::ApprovalGrant::Reused));
        }
        daemon.approval_grants.generation()
    };
    request_approval(state, cred_id, target_url, method, peer).await?;
    // If lock_vault discarded the grant while waiting for approval, this approval applies only
    // to the current request
    // and is not recorded as a grant.
    let issued = state.lock().await.approval_grants.issue(
        principal,
        cred_id.to_owned(),
        Instant::now(),
        observed,
    );
    Ok(issued.then_some(grants::ApprovalGrant::Issued))
}

/// Resolves the credential, yielding `INVALID_CREDENTIAL` if it does not exist and `VAULT_LOCKED`
/// if it is locked.
async fn resolve_unlocked_credential(
    state: &SharedState,
    cred_id: &str,
) -> Result<ResolvedCredential, ErrorCode> {
    let credential = resolve_credential(state, cred_id)
        .await?
        .ok_or(ErrorCode::InvalidCredential)?;
    if credential.locked {
        return Err(ErrorCode::VaultLocked);
    }
    Ok(credential)
}

/// Checks whether the credential provider of the namespace is locked. If the provider is not found,
/// it is not treated as locked.
/// It can be called more cheaply than `resolve_unlocked_credential` because it does not resolve a
/// credential.
async fn namespace_locked(state: &SharedState, namespace: &str) -> bool {
    let provider = {
        let daemon = state.lock().await;
        daemon
            .providers
            .iter()
            .find(|provider| provider.namespace == namespace)
            .map(|provider| provider.provider.clone())
    };
    let Some(provider) = provider else {
        return false;
    };
    provider.lock().await.locked()
}

async fn authorize_device(
    request: &RpcRequest,
    state: SharedState,
    peer: &PeerIdentity,
) -> HandledRequest {
    let params = match parse_params::<AuthorizeDeviceParams>(&request.params) {
        Ok(params) => params,
        Err(error) => return classified(request.id.clone(), error),
    };
    let verification_origin = match http_origin(&params.verification_url) {
        Some(origin) => origin,
        None => return classified(request.id.clone(), ErrorCode::Internal),
    };
    if !valid_authorize_steps(params.steps.as_deref()) {
        return classified(request.id.clone(), ErrorCode::Internal);
    }
    let Some((namespace, _)) = params.cred_id.split_once(':') else {
        return classified(request.id.clone(), ErrorCode::InvalidCredential);
    };
    let key = sessions::BrowserKey::new(
        peer.principal(),
        namespace.to_owned(),
        params.cred_id.clone(),
    );
    let metadata = match credential_metadata(&state, &params.cred_id).await {
        Ok(Some(metadata)) => metadata,
        Ok(None) => return classified(request.id.clone(), ErrorCode::InvalidCredential),
        Err(error) => return classified(request.id.clone(), error),
    };
    let login_url = metadata
        .uri
        .filter(|uri| !uri.is_empty())
        .unwrap_or(verification_origin);
    let grant = if approval_required(&*state.lock().await) {
        match approve_authorize_device(&state, &params, peer).await {
            Ok(grant) => grant,
            Err(error) => return classified(request.id.clone(), error),
        }
    } else {
        None
    };
    let credential = match resolve_unlocked_credential(&state, &params.cred_id).await {
        Ok(credential) => credential,
        Err(error) => {
            return classified(request.id.clone(), error).with_audit_approval_grant(grant);
        }
    };
    // Read the stored cookies only after passing the approval gate and the unlock check.
    let login_cookies = LoginCookies::load(&state, key).await;
    let restored_cookies = login_cookies.as_ref().and_then(LoginCookies::wire_cookies);
    let (executor_entry, executor_socket, node_path, browsers_path) = {
        let daemon = state.lock().await;
        (
            daemon.executor_entry.clone(),
            daemon.executor_socket.clone(),
            daemon.node_path.clone(),
            daemon.browsers_path.clone(),
        )
    };
    match authorize_device_with_executor(
        &executor_entry,
        executor_socket.as_deref(),
        &node_path,
        browsers_path.as_deref(),
        || authorize_device_request(&params, login_url, &credential, restored_cookies),
    )
    .await
    {
        Ok(returned) => success(request.id.clone(), json!({ "ok": true }))
            .with_audit_cookies(login_cookies.map(|cookies| cookies.finish(returned))),
        Err(error) => classified_with_step(request.id.clone(), error.code, error.step),
    }
    .with_audit_approval_grant(grant)
}

/// Starts a configured service on a dedicated executor connection and registers it as an exclusive
/// lease.
///
/// The audit fields are determined from the values of the configuration looked up by name, not from
/// values the agent attached to params.
async fn open_service<S: HostedService>(
    request: &RpcRequest,
    state: SharedState,
    peer: &PeerIdentity,
) -> HandledRequest {
    let params = match parse_params::<S::Params>(&request.params) {
        Ok(params) => params,
        Err(error) => return classified(request.id.clone(), error),
    };
    let Some(service) = S::lookup(&*state.lock().await, &S::requested_name(&params)) else {
        return classified(request.id.clone(), ErrorCode::NotFound);
    };
    let Some(cred_id) = service.cred_id().map(ToOwned::to_owned) else {
        return classified(request.id.clone(), ErrorCode::InvalidCredential);
    };
    let target_url = service.target_url();
    let mut fields = AuditFields {
        cred_id: Some(cred_id.clone()),
        target_url: Some(target_url.clone()),
        namespace: cred_id
            .split_once(':')
            .map(|(namespace, _)| namespace.to_owned()),
        ..S::KIND.named_audit_fields(service.name().to_owned())
    };
    let Some((namespace, _)) = cred_id.split_once(':') else {
        return classified(request.id.clone(), ErrorCode::InvalidCredential)
            .with_audit_fields(fields);
    };
    let namespace = namespace.to_owned();
    let grant =
        match gate_on_approval(&state, &cred_id, &target_url, S::KIND.open_method(), peer).await {
            Ok(grant) => grant,
            Err(error) => return classified(request.id.clone(), error).with_audit_fields(fields),
        };
    match start_service_session(&state, peer, service, cred_id, namespace).await {
        Ok((session_id, port, secret, cookie_audit)) => {
            fields.session_id = Some(session_id.clone());
            success(
                request.id.clone(),
                S::open_result(&session_id, port, &secret),
            )
            .with_audit_fields(fields)
            .with_audit_cookies(cookie_audit)
        }
        Err(error) => classified(request.id.clone(), error).with_audit_fields(fields),
    }
    .with_audit_approval_grant(grant)
}

/// Starts a service that passed the approval gate through the startup control, registers the lease,
/// and
/// returns `(session_id, port, secret, cookie persistence audit fields)`.
/// `cred_id` and `namespace` are values already split from the approval subject.
async fn start_service_session<S: HostedService>(
    state: &SharedState,
    peer: &PeerIdentity,
    service: S,
    cred_id: String,
    namespace: String,
) -> Result<(String, u16, String, Option<CookieAudit>), ErrorCode> {
    let start_gate = start_control(
        state,
        S::KIND.start_key(peer.principal(), service.name().to_owned()),
    )
    .await;
    let mut start_guard = start_gate.lock().await;
    if start_guard.is_limited(Instant::now()) {
        return Err(ErrorCode::RateLimited);
    }
    let credential = resolve_unlocked_credential(state, &cred_id).await?;
    // Read the stored cookies only after passing the approval gate and the unlock check.
    let login_cookies = if service.logs_in_browser() {
        let key = sessions::BrowserKey::new(peer.principal(), namespace.clone(), cred_id.clone());
        LoginCookies::load(state, key).await
    } else {
        None
    };
    let settings = service_launch_settings(state).await;
    let launch = service.build_launch(
        &credential,
        login_cookies.as_ref().and_then(LoginCookies::wire_cookies),
    )?;
    drop(credential);
    start_guard.record_attempt(Instant::now());
    let started_at = Instant::now();
    let started = match service.start_executor(&settings, launch).await {
        Ok(result) => {
            start_guard.record_success();
            result
        }
        Err(error) => {
            start_guard.record_failure(Instant::now());
            return Err(error);
        }
    };
    let deadline = started_at + settings.browser_max_lifetime;
    drop(start_guard);
    let ServiceStarted {
        port,
        secret,
        executor,
        returned_cookies,
    } = started;
    let session_id = register_service_lease(
        state,
        peer,
        executor,
        ServiceLease {
            kind: S::KIND,
            name: service.name().to_owned(),
            cred_id,
            namespace,
            port,
            ttl: settings.session_ttl,
            deadline,
        },
    )
    .await?;
    let cookie_audit = login_cookies.map(|cookies| cookies.finish(returned_cookies));
    Ok((session_id, port, secret, cookie_audit))
}

/// The executor of a started service, and the values extracted from its success response.
struct ServiceStarted {
    port: u16,
    secret: String,
    executor: ExecutorHandle,
    /// Cookie persistence values for a startup that involves a browser login. The default for
    /// other startups.
    returned_cookies: ReturnedCookies,
}

/// Settings of a service that occupies one executor connection. Provides the parts of
/// `open_service` and `start_service_session`
/// that differ by service kind (how the configuration is looked up, the approval subject, the
/// startup request, and the shape of the response).
trait HostedService: Clone {
    const KIND: ServiceKind;
    /// RPC parameters. The agent selects only by the name in the configuration.
    type Params: for<'de> Deserialize<'de>;
    /// Startup value passed to the executor after the credential is resolved. Contains the
    /// resolved secret.
    type Launch;

    fn requested_name(params: &Self::Params) -> String;
    fn lookup(daemon: &DaemonState, name: &str) -> Option<Self>;
    fn name(&self) -> &str;
    /// Credential subject to approval and resolution. `None` when it is not determined by the
    /// configuration.
    fn cred_id(&self) -> Option<&str>;
    /// Subject recorded in approval and audit.
    fn target_url(&self) -> String;
    /// Whether the startup performs a browser login with the credential. If true, the stored
    /// cookies are used for that login.
    fn logs_in_browser(&self) -> bool;
    /// `cookies` are the stored cookies restored before the browser login.
    fn build_launch(
        &self,
        credential: &ResolvedCredential,
        cookies: Option<Vec<Value>>,
    ) -> Result<Self::Launch, ErrorCode>;
    /// Opens one executor connection and starts the service.
    async fn start_executor(
        &self,
        settings: &ServiceLaunchSettings,
        launch: Self::Launch,
    ) -> Result<ServiceStarted, ErrorCode>;
    /// RPC result when startup succeeds.
    fn open_result(session_id: &str, port: u16, secret: &str) -> Value;
}

impl HostedService for ApiProxyConfig {
    const KIND: ServiceKind = ServiceKind::ApiProxy;
    type Params = OpenApiProxyParams;
    type Launch = ApiProxyStartOptions;

    fn requested_name(params: &Self::Params) -> String {
        params.name.clone()
    }

    fn lookup(daemon: &DaemonState, name: &str) -> Option<Self> {
        daemon.api_proxies.get(name).cloned()
    }

    fn name(&self) -> &str {
        &self.name
    }

    fn cred_id(&self) -> Option<&str> {
        api_proxy_cred_id(self)
    }

    fn target_url(&self) -> String {
        self.upstream.clone()
    }

    fn logs_in_browser(&self) -> bool {
        self.oauth.is_some()
    }

    fn build_launch(
        &self,
        credential: &ResolvedCredential,
        cookies: Option<Vec<Value>>,
    ) -> Result<Self::Launch, ErrorCode> {
        if let Some(oauth) = &self.oauth {
            return build_oauth_start(&self.value, oauth, credential, cookies);
        }
        Ok(ApiProxyStartOptions {
            value_template: None,
            header_value: Some(Zeroizing::new(
                self.value
                    .replace(API_PROXY_SECRET_PLACEHOLDER, credential.password.as_str()),
            )),
            oauth: None,
        })
    }

    async fn start_executor(
        &self,
        settings: &ServiceLaunchSettings,
        launch: Self::Launch,
    ) -> Result<ServiceStarted, ErrorCode> {
        start_api_proxy_executor(settings, self, launch).await
    }

    fn open_result(session_id: &str, port: u16, secret: &str) -> Value {
        json!({ "session_id": session_id, "base_url": format!("http://127.0.0.1:{port}/{secret}") })
    }
}

impl HostedService for McpServerConfig {
    const KIND: ServiceKind = ServiceKind::McpServer;
    type Params = OpenMcpServerParams;
    type Launch = McpServerLaunch;

    fn requested_name(params: &Self::Params) -> String {
        params.name.clone()
    }

    fn lookup(daemon: &DaemonState, name: &str) -> Option<Self> {
        daemon.mcp_servers.get(name).cloned()
    }

    fn name(&self) -> &str {
        &self.name
    }

    fn cred_id(&self) -> Option<&str> {
        Some(&self.cred_id)
    }

    fn target_url(&self) -> String {
        format!("mcp:{}", self.name)
    }

    fn logs_in_browser(&self) -> bool {
        false
    }

    fn build_launch(
        &self,
        credential: &ResolvedCredential,
        _cookies: Option<Vec<Value>>,
    ) -> Result<Self::Launch, ErrorCode> {
        build_mcp_server_launch(&self.env, credential)
    }

    async fn start_executor(
        &self,
        settings: &ServiceLaunchSettings,
        launch: Self::Launch,
    ) -> Result<ServiceStarted, ErrorCode> {
        let (port, secret, executor) = start_mcp_server_executor(settings, self, launch).await?;
        Ok(ServiceStarted {
            port,
            secret,
            executor,
            returned_cookies: ReturnedCookies::default(),
        })
    }

    fn open_result(session_id: &str, port: u16, secret: &str) -> Value {
        json!({ "session_id": session_id, "port": port, "stream_secret": secret })
    }
}

/// Kind of service that occupies one executor connection. Determines how the lease release request
/// and the event lines are handled.
#[derive(Clone, Copy)]
enum ServiceKind {
    ApiProxy,
    McpServer,
}

impl ServiceKind {
    fn lease_target(self) -> sessions::LeaseTarget {
        match self {
            Self::ApiProxy => sessions::LeaseTarget::ApiProxy,
            Self::McpServer => sessions::LeaseTarget::McpServer,
        }
    }

    /// RPC name that opens the service. Passed to the approval gate.
    fn open_method(self) -> &'static str {
        match self {
            Self::ApiProxy => "open_api_proxy",
            Self::McpServer => "open_mcp_server",
        }
    }

    fn start_key(self, principal: String, name: String) -> sessions::StartKey {
        match self {
            Self::ApiProxy => sessions::StartKey::ApiProxy { principal, name },
            Self::McpServer => sessions::StartKey::McpServer { principal, name },
        }
    }

    /// Returns the name in the configuration, put in the audit field that matches the kind
    /// (`proxy` or `mcp_server`).
    fn named_audit_fields(self, name: String) -> AuditFields {
        let name = Some(name);
        let (proxy, mcp_server) = match self {
            Self::ApiProxy => (name, None),
            Self::McpServer => (None, name),
        };
        AuditFields {
            proxy,
            mcp_server,
            ..AuditFields::default()
        }
    }

    /// The op of the stop request and the upper bound on waiting for its response.
    fn stop_request(self) -> (&'static str, Duration) {
        match self {
            Self::ApiProxy => ("api_proxy_stop", API_PROXY_STOP_TIMEOUT),
            Self::McpServer => ("mcp_server_stop", MCP_SERVER_STOP_TIMEOUT),
        }
    }
}

/// Values for registering a started service as a lease. `name` is the name in the configuration.
struct ServiceLease {
    kind: ServiceKind,
    name: String,
    cred_id: String,
    namespace: String,
    port: u16,
    ttl: Duration,
    deadline: Instant,
}

/// Registers the executor connection of a started service as one exclusive lease and starts reading
/// event lines.
/// If it cannot be registered, the executor is stopped. Returns the issued session_id.
async fn register_service_lease(
    state: &SharedState,
    peer: &PeerIdentity,
    mut executor: ExecutorHandle,
    lease: ServiceLease,
) -> Result<String, ErrorCode> {
    let ServiceLease {
        kind,
        name,
        cred_id,
        namespace,
        port,
        ttl,
        deadline,
    } = lease;
    let principal = peer.principal();
    let Some(reader) = executor.take_reader() else {
        stop_child(executor).await;
        return Err(ErrorCode::Internal);
    };
    let (response_sender, response_receiver) = mpsc::unbounded_channel();
    let connection = Arc::new(ExecutorConnection {
        executor: Mutex::new(executor),
        responses: Mutex::new(response_receiver),
        operation: Mutex::new(()),
        next_id: AtomicU64::new(2),
    });
    let session_id = Uuid::new_v4().to_string();
    let now = Instant::now();
    // A service is not shared, so it is not registered in shared_browsers. The endpoint is a
    // value used only for
    // CDP piggybacking, so it is left empty so that no path secret or the like remains.
    let browser = sessions::Browser {
        key: sessions::BrowserKey::new(principal.clone(), namespace.clone(), cred_id.clone()),
        executor: connection.clone(),
        port,
        endpoint: String::new(),
        deadline,
        leases: HashMap::from([(
            session_id.clone(),
            sessions::Lease {
                principal: principal.clone(),
                expires_at: lease_expiry(now, ttl, deadline),
                target: kind.lease_target(),
            },
        )]),
        exclusive: true,
        persist_cookies: false,
    };
    let ports = state.lock().await.ports.clone();
    if let Ok(mut ports) = ports.write() {
        ports.insert(session_id.clone(), (principal, port));
    } else {
        shutdown_executor(connection).await;
        return Err(ErrorCode::Internal);
    }
    let browser_id = Uuid::new_v4().to_string();
    state
        .lock()
        .await
        .browsers
        .insert(browser_id.clone(), browser);
    spawn_executor_reaper(
        state.clone(),
        browser_id.clone(),
        reader,
        response_sender,
        Some(ServiceEventContext {
            kind,
            browser_id,
            session_id: session_id.clone(),
            namespace,
            name,
            cred_id,
            peer: peer.clone(),
        }),
    );
    Ok(session_id)
}

/// Settings of the executor startup route used to start a service, and of the lease lifetime.
struct ServiceLaunchSettings {
    executor_entry: PathBuf,
    executor_socket: Option<PathBuf>,
    node_path: PathBuf,
    browsers_path: Option<PathBuf>,
    session_ttl: Duration,
    browser_max_lifetime: Duration,
}

async fn service_launch_settings(state: &SharedState) -> ServiceLaunchSettings {
    let daemon = state.lock().await;
    ServiceLaunchSettings {
        executor_entry: daemon.executor_entry.clone(),
        executor_socket: daemon.executor_socket.clone(),
        node_path: daemon.node_path.clone(),
        browsers_path: daemon.browsers_path.clone(),
        session_ttl: daemon.session_ttl,
        browser_max_lifetime: daemon.browser_max_lifetime,
    }
}

/// Environment variables and the leak scan target strings carried in `mcp_server_start`. Both
/// contain resolved secrets, so
/// they are held in `Zeroizing` and `Debug` is not derived.
struct McpServerLaunch {
    env: BTreeMap<String, Zeroizing<String>>,
    scan: Vec<Zeroizing<String>>,
}

/// Replaces the placeholders in `[mcp_server.env]` with the credential's values and builds the leak
/// scan target strings.
///
/// The scan targets are the password and the substituted values of the entries that contained
/// `{{secret}}` or `{{totp}}`
/// (excluding empty strings and removing duplicates). Values containing only `{{username}}` are not
/// targets.
/// If the configuration uses `{{totp}}` and the credential has no TOTP seed, the result is
/// `INTERNAL`.
fn build_mcp_server_launch(
    templates: &BTreeMap<String, String>,
    credential: &ResolvedCredential,
) -> Result<McpServerLaunch, ErrorCode> {
    let totp = if templates
        .values()
        .any(|template| template.contains(MCP_TOTP_PLACEHOLDER))
    {
        Some(Zeroizing::new(
            current_totp(credential).ok_or(ErrorCode::Internal)?,
        ))
    } else {
        None
    };
    let mut values = vec![
        McpPlaceholderValue {
            placeholder: MCP_SECRET_PLACEHOLDER,
            value: credential.password.as_str(),
            scanned: true,
        },
        McpPlaceholderValue {
            placeholder: MCP_USERNAME_PLACEHOLDER,
            value: credential.username.as_str(),
            scanned: false,
        },
    ];
    if let Some(totp) = &totp {
        values.push(McpPlaceholderValue {
            placeholder: MCP_TOTP_PLACEHOLDER,
            value: totp.as_str(),
            scanned: true,
        });
    }
    let mut scan = Vec::new();
    push_scan_value(&mut scan, credential.password.as_str());
    let mut env = BTreeMap::new();
    for (key, template) in templates {
        let (value, scanned) = render_mcp_env_value(template, &values);
        if scanned {
            push_scan_value(&mut scan, value.as_str());
        }
        env.insert(key.clone(), value);
    }
    Ok(McpServerLaunch { env, scan })
}

/// Adds to the leak scan target strings, excluding empty strings and values already present.
fn push_scan_value(scan: &mut Vec<Zeroizing<String>>, value: &str) {
    if !value.is_empty() && !scan.iter().any(|existing| existing.as_str() == value) {
        scan.push(Zeroizing::new(value.to_owned()));
    }
}

/// One kind of placeholder and the value that replaces it. `scanned` indicates whether a value
/// containing it is a leak scan target.
struct McpPlaceholderValue<'a> {
    placeholder: &'static str,
    value: &'a str,
    scanned: bool,
}

/// Scans the template once from the start and substitutes the placeholders, returning
/// whether at least one `scanned` placeholder was substituted.
///
/// The substituted values are not scanned again, so placeholder-shaped strings contained in the
/// credential's values are not expanded.
/// The capacity for the upper bound is reserved first so that no fragment of the secret remains in
/// freed memory through reallocation during substitution.
fn render_mcp_env_value(
    template: &str,
    values: &[McpPlaceholderValue<'_>],
) -> (Zeroizing<String>, bool) {
    let longest = values
        .iter()
        .map(|entry| entry.value.len())
        .max()
        .unwrap_or(0);
    let occurrences = template.matches("{{").count();
    let mut rendered = Zeroizing::new(String::with_capacity(
        template.len() + occurrences.saturating_mul(longest),
    ));
    let mut scanned = false;
    let mut rest = template;
    while let Some(character) = rest.chars().next() {
        if let Some(entry) = values
            .iter()
            .find(|entry| rest.starts_with(entry.placeholder))
        {
            rendered.push_str(entry.value);
            rest = &rest[entry.placeholder.len()..];
            scanned |= entry.scanned;
        } else {
            rendered.push(character);
            rest = &rest[character.len_utf8()..];
        }
    }
    (rendered, scanned)
}

/// Builds the values carried in `api_proxy_start` for an OAuth injection proxy.
/// The login URL prefers the credential's URI, and falls back to the origin of the device
/// authorization endpoint if it is absent or empty.
/// `cookies` are the stored cookies restored before the browser login.
fn build_oauth_start(
    value_template: &str,
    oauth: &ApiProxyOAuthConfig,
    credential: &ResolvedCredential,
    cookies: Option<Vec<Value>>,
) -> Result<ApiProxyStartOptions, ErrorCode> {
    let login_url = credential
        .uri
        .clone()
        .filter(|uri| !uri.is_empty())
        .or_else(|| http_origin(&oauth.device_authorization_url))
        .ok_or(ErrorCode::Internal)?;
    let oauth = ExecutorApiProxyOAuth {
        client_id: oauth.client_id.clone(),
        device_authorization_url: oauth.device_authorization_url.clone(),
        token_url: oauth.token_url.clone(),
        revocation_url: oauth.revocation_url.clone(),
        scope: oauth.scope.clone(),
        login_url,
        steps: oauth.steps.clone(),
        success_selector: oauth.success_selector.clone(),
        failure_selector: oauth.failure_selector.clone(),
        secret: ExecutorApiProxyOAuthSecret {
            username: Zeroizing::new(credential.username.as_str().to_owned()),
            password: Zeroizing::new(credential.password.as_str().to_owned()),
            totp: current_totp(credential).map(Zeroizing::new),
        },
        cookies,
    };
    Ok(ApiProxyStartOptions {
        value_template: Some(value_template.to_owned()),
        header_value: None,
        oauth: Some(oauth),
    })
}

async fn credential_metadata(
    state: &SharedState,
    cred_id: &str,
) -> Result<Option<CredentialMetadata>, ErrorCode> {
    let Some((_, entry_id)) = cred_id.split_once(':') else {
        return Ok(None);
    };
    let Some((refs, _)) = credential_refs(state, cred_id).await? else {
        return Ok(None);
    };
    Ok(refs
        .into_iter()
        .find(|credential| credential.id == entry_id)
        .map(|credential| CredentialMetadata {
            uri: credential.uri,
        }))
}

async fn credential_refs(
    state: &SharedState,
    cred_id: &str,
) -> Result<Option<(Vec<CredentialRef>, bool)>, ErrorCode> {
    let Some((namespace, _)) = cred_id.split_once(':') else {
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
    Ok(Some((refs, locked)))
}

/// Splits a URL into scheme, authority, and the rest (path, query, fragment).
/// The authority runs from after `://` up to just before the first `/`, `?`, or `#`.
fn split_authority(value: &str) -> Option<(&str, &str, &str)> {
    let (scheme, remainder) = value.split_once("://")?;
    let authority_end = remainder.find(['/', '?', '#']).unwrap_or(remainder.len());
    let (authority, rest) = remainder.split_at(authority_end);
    Some((scheme, authority, rest))
}

fn http_origin(value: &str) -> Option<String> {
    let (scheme, authority, _) = split_authority(value)?;
    if !scheme.eq_ignore_ascii_case("http") && !scheme.eq_ignore_ascii_case("https") {
        return None;
    }
    if authority.is_empty()
        || authority
            .chars()
            .any(|character| character.is_ascii_control() || character.is_ascii_whitespace())
    {
        return None;
    }
    Some(format!("{}://{authority}", scheme.to_ascii_lowercase()))
}

fn audit_target_url(value: &str) -> Option<String> {
    let origin = http_origin(value)?;
    let (scheme, authority) = origin.split_once("://")?;
    // The userinfo (`user:pw@`) may contain authentication information, so it is removed before
    // being passed to the audit and the approval hook.
    let host = authority
        .rsplit_once('@')
        .map_or(authority, |(_, host)| host);
    if host.is_empty() {
        return None;
    }
    let (_, _, rest) = split_authority(value)?;
    let path = if rest.starts_with('/') {
        &rest[..rest.find(['?', '#']).unwrap_or(rest.len())]
    } else {
        ""
    };
    Some(format!("{scheme}://{host}{path}"))
}

fn valid_authorize_steps(steps: Option<&[tegata_core::wire::LoginStep]>) -> bool {
    steps.is_none_or(|steps| {
        steps.iter().all(|step| match step.action.as_str() {
            "click" => step.value.is_none(),
            "wait_for" => step.value.is_none(),
            "fill" => matches!(
                step.value.as_deref(),
                Some("{{username}}")
                    | Some("{{password}}")
                    | Some("{{totp}}")
                    | Some("{{user_code}}")
            ),
            _ => false,
        })
    })
}

/// State of the credential confirmed by the approval gate.
struct CredentialState {
    locked: bool,
    /// Whether the credential was included in the enumeration result and its existence could be
    /// confirmed.
    confirmed: bool,
}

async fn credential_state(
    state: &SharedState,
    cred_id: &str,
) -> Result<Option<CredentialState>, ErrorCode> {
    let Some((_, entry_id)) = cred_id.split_once(':') else {
        return Ok(None);
    };
    let Some((refs, locked)) = credential_refs(state, cred_id).await? else {
        return Ok(None);
    };
    if refs.iter().any(|credential| credential.id == entry_id) {
        return Ok(Some(CredentialState {
            locked: false,
            confirmed: true,
        }));
    }
    // While locked the enumeration can be empty, so it is let through, but the existence has
    // not been confirmed.
    if locked && refs.is_empty() {
        return Ok(Some(CredentialState {
            locked: false,
            confirmed: false,
        }));
    }
    Ok(None)
}

async fn approve_authorize_device(
    state: &SharedState,
    params: &AuthorizeDeviceParams,
    peer: &PeerIdentity,
) -> Result<Option<grants::ApprovalGrant>, ErrorCode> {
    // To avoid spreading the user_code carried in the query of verification_uri_complete to the
    // approval hook and the pending list,
    // the URL is passed with the query, fragment, and userinfo removed, the same as in the
    // audit.
    let target_url = audit_target_url(&params.verification_url).ok_or(ErrorCode::Internal)?;
    approve_with_grant(
        state,
        &params.cred_id,
        &target_url,
        "authorize_device",
        peer,
    )
    .await
}

#[cfg(unix)]
async fn approve_command(
    state: &SharedState,
    cred_id: &str,
    target_url: &str,
    method: &str,
    peer: &PeerIdentity,
) -> Result<(), ErrorCode> {
    let (approve_cmd, approve_timeout, grant_ttl) = {
        let daemon = state.lock().await;
        (
            daemon.approve_cmd.clone(),
            daemon.approve_timeout,
            daemon.approval_grants.ttl(),
        )
    };
    let Some(approve_cmd) = approve_cmd else {
        return Ok(());
    };
    // The verification number is a per-request binding and not a secret. Verification is the
    // responsibility of the hook side.
    let approval_code = grants::approval_code().map_err(|_| ErrorCode::Internal)?;
    let peer_uid = match peer {
        PeerIdentity::Uid(uid) => uid.to_string(),
        _ => peer.principal(),
    };
    let mut command = Command::new("sh");
    command
        .args(["-c", approve_cmd.as_str()])
        .env("TEGATA_CRED_ID", cred_id)
        .env("TEGATA_TARGET_URL", target_url)
        .env("TEGATA_METHOD", method)
        .env("TEGATA_PEER", peer_uid)
        .env("TEGATA_APPROVAL_CODE", approval_code.to_string())
        .env(
            "TEGATA_APPROVAL_GRANT_TTL_SECS",
            grant_ttl.as_secs().to_string(),
        )
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

/// Returns whether the approval gate is configured. Unix uses `approve_cmd`, and Windows uses the
/// pending queue of
/// `approve_operator`.
fn approval_required(daemon: &DaemonState) -> bool {
    #[cfg(unix)]
    {
        daemon.approve_cmd.is_some()
    }
    #[cfg(windows)]
    {
        daemon.approve_operator
    }
}

/// Asks the configured approval means for approval. Unix starts `approve_cmd`, and Windows
/// registers in the pending queue and waits for the operator's decision.
async fn request_approval(
    state: &SharedState,
    cred_id: &str,
    target_url: &str,
    method: &str,
    peer: &PeerIdentity,
) -> Result<(), ErrorCode> {
    #[cfg(unix)]
    {
        approve_command(state, cred_id, target_url, method, peer).await
    }
    #[cfg(windows)]
    {
        approve_by_operator(state, cred_id, target_url, method, peer).await
    }
}

/// Registers in the pending queue and waits for the decision made through the management RPC of an
/// elevated operator.
#[cfg(windows)]
async fn approve_by_operator(
    state: &SharedState,
    cred_id: &str,
    target_url: &str,
    method: &str,
    peer: &PeerIdentity,
) -> Result<(), ErrorCode> {
    let (queue, approve_timeout) = {
        let daemon = state.lock().await;
        (daemon.approvals.clone(), daemon.approve_timeout)
    };
    let pending = queue.register(approvals::ApprovalRequest {
        method: method.to_owned(),
        cred_id: cred_id.to_owned(),
        target_url: target_url.to_owned(),
        principal: peer.principal(),
    });
    eprintln!(
        "tegatad: approval pending {} {method} {cred_id}",
        pending.id()
    );
    pending
        .wait(approve_timeout)
        .await
        .map_err(|error| match error {
            approvals::ApprovalError::Denied => ErrorCode::ApprovalDenied,
            approvals::ApprovalError::Timeout => ErrorCode::ApprovalTimeout,
        })
}

/// Ends the caller's lease and closes the browser if it was the last lease. The session on the site
/// side is not touched.
async fn disconnect(
    request: &RpcRequest,
    state: SharedState,
    peer: &PeerIdentity,
) -> HandledRequest {
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
        let (lease, executor, empty, cookie_key) = {
            let browser = daemon
                .browsers
                .get_mut(&browser_id)
                .expect("browser exists");
            let lease = browser.leases.remove(&session_id).expect("lease exists");
            let executor = browser.executor.clone();
            let empty = browser.leases.is_empty();
            let cookie_key = browser.persist_cookies.then(|| browser.key.clone());
            (lease, executor, empty, cookie_key)
        };
        if empty {
            let browser = daemon.browsers.remove(&browser_id).expect("browser exists");
            if !browser.exclusive {
                daemon.shared_browsers.remove(&browser.key);
            }
        }
        let _ = daemon
            .ports
            .write()
            .map(|mut ports| ports.remove(&session_id));
        Some((lease, executor, empty, cookie_key))
    };
    let mut cookie_audit = None;
    if let Some((lease, executor, empty, cookie_key)) = removed {
        // The end of the last lease closes the browser, so the cookies are written out
        // before closing the tab.
        if empty && let Some(key) = cookie_key {
            let saved = export_browser_cookies(&state, &key, &executor).await;
            cookie_audit = Some(CookieAudit::session_end(Some(saved)));
        }
        let release_failed = release_lease(&executor, &lease.target).await.is_err();
        if empty || release_failed {
            shutdown_executor(executor).await;
        }
    }
    success(request.id.clone(), json!({ "ok": true })).with_audit_cookies(cookie_audit)
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
        let mut daemon = state.lock().await;
        daemon.approval_grants.revoke(namespace.as_deref());
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
    stepwise::terminate(&state, namespace.as_deref(), stepwise::EndReason::LockVault).await;
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
            if let Ok(mut ports) = daemon.ports.write() {
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
        tasks.spawn(async move {
            terminate_browser(&state, browser, "session_terminated", true).await;
        });
    }
    while tasks.join_next().await.is_some() {}
}

async fn terminate_browser(
    state: &SharedState,
    browser: sessions::Browser,
    audit_method: &'static str,
    release_leases: bool,
) {
    let namespace = browser.key.namespace.clone();
    // If the browser is subject to persistence, its cookies are written out before the whole
    // browser closes.
    let cookies_saved = if browser.persist_cookies {
        Some(export_browser_cookies(state, &browser.key, &browser.executor).await)
    } else {
        None
    };
    let leases = browser.leases.into_iter().collect::<Vec<_>>();
    // To avoid accumulating the wait for every lease when the executor does not respond,
    // individual releases are abandoned at the first failure.
    // Stopping the executor closes the whole browser, so the remaining tabs are reclaimed by
    // the stop processing.
    // The leases of injection proxies and MCP servers are released by a stop request even when
    // release_leases is false. Within
    // this request the executor revokes the OAuth token, terminates the MCP server, and deletes
    // the temporary directory,
    // so it must not be cut off by the short wait of the stop processing.
    for (_, lease) in &leases {
        if !release_leases && !lease.target.is_service() {
            continue;
        }
        if release_lease(&browser.executor, &lease.target)
            .await
            .is_err()
        {
            break;
        }
    }
    shutdown_executor(browser.executor).await;
    for (session_id, _) in leases {
        audit_system_session(
            state,
            audit_method,
            session_id,
            namespace.clone(),
            cookies_saved,
        )
        .await;
    }
}

async fn terminate_peer_leases(state: SharedState, peer_id: &str) {
    let principal = format!("peer:{peer_id}");
    stepwise::terminate_principal(&state, &principal).await;
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
                    browser.persist_cookies,
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
        for (session_id, _, _, _, _, _) in &removed {
            let _ = daemon
                .ports
                .write()
                .map(|mut ports| ports.remove(session_id));
        }
        removed
    };
    for (session_id, lease, executor, namespace, shutdown, persist_cookies) in removed {
        let _ = release_lease(&executor, &lease.target).await;
        if shutdown {
            shutdown_executor(executor).await;
        }
        // The cookies of a revoked peer will not be used afterward, so they are not written
        // out, and the fact that they were not stored is recorded.
        let cookies_saved = (shutdown && persist_cookies).then_some(false);
        let daemon = state.lock().await;
        if let Err(error) = append_audit(
            &daemon,
            AuditPeer::System,
            "session_terminated".to_owned(),
            AuditFields {
                session_id: Some(session_id),
                namespace: Some(namespace),
                cookies_saved,
                ..AuditFields::default()
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
    cookies_saved: Option<bool>,
) {
    let daemon = state.lock().await;
    if let Err(error) = append_audit(
        &daemon,
        AuditPeer::System,
        method.to_owned(),
        AuditFields {
            session_id: Some(session_id),
            namespace: Some(namespace),
            cookies_saved,
            ..AuditFields::default()
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

async fn connect_executor(
    entry: &Path,
    executor_socket: Option<&Path>,
    node_path: &Path,
    browsers_path: Option<&Path>,
) -> Result<ExecutorHandle, io::Error> {
    #[cfg(not(windows))]
    let _ = browsers_path;
    #[cfg(windows)]
    let _ = executor_socket;
    let mut command = Command::new(node_path);
    command
        .arg(entry)
        .stdin(std::process::Stdio::piped())
        .stdout(std::process::Stdio::piped())
        .stderr(std::process::Stdio::piped())
        .kill_on_drop(true);
    #[cfg(windows)]
    if let Some(browsers_path) = browsers_path {
        command.env("PLAYWRIGHT_BROWSERS_PATH", browsers_path);
    }
    #[cfg(unix)]
    if let Some(socket) = executor_socket {
        let stream = timeout(EXECUTOR_TIMEOUT, tokio::net::UnixStream::connect(socket))
            .await
            .map_err(|_| io::Error::from(io::ErrorKind::TimedOut))??;
        let (reader, writer) = stream.into_split();
        Ok(ExecutorHandle::Socket {
            reader: Arc::new(Mutex::new(reader)),
            writer,
        })
    } else {
        let mut child = command.spawn()?;
        forward_executor_stderr(&mut child);
        Ok(ExecutorHandle::Spawned(child))
    }
    #[cfg(windows)]
    {
        let mut child = command.spawn()?;
        forward_executor_stderr(&mut child);
        Ok(ExecutorHandle::Spawned(child))
    }
}

const EXECUTOR_STDERR_LINE_MAX_BYTES: usize = 1000;

fn truncate_executor_stderr_line(line: &[u8]) -> String {
    let line = line.strip_suffix(b"\n").unwrap_or(line);
    let line = line.strip_suffix(b"\r").unwrap_or(line);
    let mut line = String::from_utf8_lossy(line).into_owned();
    if line.len() > EXECUTOR_STDERR_LINE_MAX_BYTES {
        let mut end = EXECUTOR_STDERR_LINE_MAX_BYTES;
        while !line.is_char_boundary(end) {
            end -= 1;
        }
        line.truncate(end);
    }
    line
}

fn forward_executor_stderr(child: &mut Child) {
    let Some(stderr) = child.stderr.take() else {
        return;
    };
    tokio::spawn(async move {
        let mut reader = BufReader::new(stderr);
        let mut line = Vec::new();
        loop {
            line.clear();
            match reader.read_until(b'\n', &mut line).await {
                Ok(0) => break,
                Ok(_) => {
                    let line = truncate_executor_stderr_line(&line);
                    eprintln!("tegatad: executor {line}");
                }
                Err(_) => break,
            }
        }
    });
}

/// Writes the initial request with id 1 to the executor as one line and reads one response line.
///
/// The request may contain secrets, so the value is discarded immediately after serialization, and
/// the serialized bytes are erased after the write.
async fn exchange_first_request<T: Serialize>(
    executor: &mut ExecutorHandle,
    request: T,
) -> Result<String, ErrorCode> {
    let serialized = serde_json::to_vec(&request);
    drop(request);
    let mut line = serialized.map_err(|_| ErrorCode::Internal)?;
    line.push(b'\n');
    let written = executor.write_line(&line).await;
    line.zeroize();
    written.map_err(|_| ErrorCode::Internal)?;
    let response_line = timeout(EXECUTOR_TIMEOUT, executor.read_line())
        .await
        .map_err(|_| ErrorCode::Internal)?
        .map_err(|_| ErrorCode::Internal)?;
    if response_line.is_empty() {
        return Err(ErrorCode::Internal);
    }
    Ok(response_line)
}

/// Opens one executor connection, sends the initial request, and interprets the response line with
/// `parse_response`.
/// Used for requests that keep the connection open (login and api_proxy_start), and stops the
/// executor on failure.
async fn open_executor_with<T, R, E>(
    entry: &Path,
    executor_socket: Option<&Path>,
    node_path: &Path,
    browsers_path: Option<&Path>,
    build_request: impl FnOnce() -> T,
    parse_response: impl FnOnce(&str) -> Result<R, E>,
) -> Result<(R, ExecutorHandle), E>
where
    T: Serialize,
    E: From<ErrorCode>,
{
    let mut executor = connect_executor(entry, executor_socket, node_path, browsers_path)
        .await
        .map_err(|_| ErrorCode::Internal)?;
    let result = async {
        let response_line = exchange_first_request(&mut executor, build_request()).await?;
        parse_response(&response_line)
    }
    .await;
    match result {
        Ok(parsed) => Ok((parsed, executor)),
        Err(error) => {
            stop_child(executor).await;
            Err(error)
        }
    }
}

fn current_totp(credential: &ResolvedCredential) -> Option<String> {
    credential.totp_seed.as_ref().map(|seed| {
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map(|duration| duration.as_secs())
            .unwrap_or(0);
        tegata_core::totp(seed.as_str(), now).0
    })
}

/// `login` request to the executor. `cookies` are the stored cookies to restore, and null when
/// nothing is restored.
#[derive(Serialize)]
struct ExecutorLoginWithCookies<'a> {
    #[serde(flatten)]
    login: ExecutorLoginRequest,
    cookies: Option<&'a [cookie_store::Cookie]>,
}

/// Values extracted from the successful `login` response of the executor.
struct ParsedLoginResponse {
    endpoint: String,
    target_id: String,
    /// All cookies of the context at that time. Absent from older executors.
    cookies: Option<Value>,
    /// Whether steps were skipped thanks to the restored cookies. Treated as false when absent.
    steps_skipped: bool,
}

/// Executor of a started login browser, and its success response.
struct ExecutorLoginStarted {
    endpoint: String,
    target_id: String,
    executor: ExecutorHandle,
    cookies: Option<Value>,
    steps_skipped: bool,
}

async fn start_executor(
    entry: &Path,
    executor_socket: Option<&Path>,
    node_path: &Path,
    browsers_path: Option<&Path>,
    params: &LoginParams,
    credential: &ResolvedCredential,
    cookies: Option<&[cookie_store::Cookie]>,
) -> Result<ExecutorLoginStarted, ExecutorFailure> {
    let build_request = || ExecutorLoginWithCookies {
        login: ExecutorLoginRequest {
            op: "login",
            id: 1,
            target_url: params.target_url.clone(),
            steps: params.steps.clone(),
            success_selector: params.success_selector.clone(),
            failure_selector: params.failure_selector.clone(),
            secret: ExecutorSecret {
                username: credential.username.as_str().to_owned(),
                password: credential.password.as_str().to_owned(),
                totp: current_totp(credential),
            },
        },
        cookies,
    };
    let (parsed, executor) = open_executor_with(
        entry,
        executor_socket,
        node_path,
        browsers_path,
        build_request,
        parse_login_response,
    )
    .await?;
    Ok(ExecutorLoginStarted {
        endpoint: parsed.endpoint,
        target_id: parsed.target_id,
        executor,
        cookies: parsed.cookies,
        steps_skipped: parsed.steps_skipped,
    })
}

/// Extracts the CDP endpoint, the target_id, and the cookie persistence values from the response to
/// `login`.
/// `cookies` and `steps_skipped` are absent from older executors, so their absence is still treated
/// as success.
fn parse_login_response(line: &str) -> Result<ParsedLoginResponse, ExecutorFailure> {
    let response: ExecutorResponse = serde_json::from_str(line).map_err(|_| ErrorCode::Internal)?;
    if response.id != Some(1) {
        return Err(ErrorCode::Internal.into());
    }
    if response.ok {
        let endpoint = response.endpoint.ok_or(ErrorCode::Internal)?;
        let target_id = response.target_id.ok_or(ErrorCode::Internal)?;
        let ReturnedCookies {
            cookies,
            steps_skipped,
        } = parse_returned_cookies(line);
        Ok(ParsedLoginResponse {
            endpoint,
            target_id,
            cookies,
            steps_skipped,
        })
    } else {
        let code = response
            .error
            .as_deref()
            .map(parse_error_code)
            .unwrap_or(ErrorCode::Internal);
        Err(ExecutorFailure {
            code,
            step: selector_step(&response, code),
        })
    }
}

/// Builds the `authorize_device` request to the executor. `cookies` are the stored cookies restored
/// before the login steps.
fn authorize_device_request(
    params: &AuthorizeDeviceParams,
    login_url: String,
    credential: &ResolvedCredential,
    cookies: Option<Vec<Value>>,
) -> ExecutorAuthorizeDeviceRequest {
    ExecutorAuthorizeDeviceRequest {
        op: "authorize_device",
        id: 1,
        login_url,
        verification_url: params.verification_url.clone(),
        user_code: params.user_code.clone(),
        steps: params.steps.clone(),
        success_selector: params.success_selector.clone(),
        failure_selector: params.failure_selector.clone(),
        secret: ExecutorSecret {
            username: credential.username.as_str().to_owned(),
            password: credential.password.as_str().to_owned(),
            totp: current_totp(credential),
        },
        cookies,
    }
}

/// Opens one executor connection, sends the `authorize_device` request of `build_request`, and
/// stops the connection after the response.
/// On success it returns the cookie persistence values carried in the response.
async fn authorize_device_with_executor(
    entry: &Path,
    executor_socket: Option<&Path>,
    node_path: &Path,
    browsers_path: Option<&Path>,
    build_request: impl FnOnce() -> ExecutorAuthorizeDeviceRequest,
) -> Result<ReturnedCookies, ExecutorFailure> {
    let mut executor = connect_executor(entry, executor_socket, node_path, browsers_path)
        .await
        .map_err(|_| ErrorCode::Internal)?;
    let result = async {
        let response_line = exchange_first_request(&mut executor, build_request()).await?;
        let response: ExecutorResponse =
            serde_json::from_str(&response_line).map_err(|_| ErrorCode::Internal)?;
        if response.id != Some(1) {
            return Err(ErrorCode::Internal.into());
        }
        if response.ok {
            Ok(parse_returned_cookies(&response_line))
        } else {
            let code = response
                .error
                .as_deref()
                .map(parse_authorize_error_code)
                .unwrap_or(ErrorCode::Internal);
            Err(ExecutorFailure {
                code,
                step: selector_step(&response, code),
            })
        }
    }
    .await;
    shutdown_authorize_executor(&mut executor).await;
    result
}

async fn shutdown_authorize_executor(executor: &mut ExecutorHandle) {
    shutdown_executor_handle(executor, 2).await;
}

/// Sends `shutdown` to an `ExecutorHandle`, waits for the response, and then stops it. If there is
/// no response, it is forcibly terminated.
/// This procedure is shared by the throwaway connection of `authorize_device` and the
/// `stop_pending` of a stepwise login.
async fn shutdown_executor_handle(executor: &mut ExecutorHandle, id: u64) {
    let Ok(mut request) = serde_json::to_vec(&json!({ "op": "shutdown", "id": id })) else {
        return;
    };
    request.push(b'\n');
    let write_result = timeout(EXECUTOR_SHUTDOWN_TIMEOUT, executor.write_line(&request)).await;
    if matches!(write_result, Ok(Ok(()))) {
        let _ = timeout(EXECUTOR_SHUTDOWN_TIMEOUT, executor.read_line()).await;
    }
    if !wait_or_kill_executor(executor).await {
        kill_executor_handle(executor).await;
    }
}

/// Opens one executor connection, sends `api_proxy_start`, and receives the listener port and the
/// path secret.
async fn start_api_proxy_executor(
    settings: &ServiceLaunchSettings,
    proxy: &ApiProxyConfig,
    options: ApiProxyStartOptions,
) -> Result<ServiceStarted, ErrorCode> {
    let ApiProxyStartOptions {
        value_template,
        header_value,
        oauth,
    } = options;
    let oauth_enabled = oauth.is_some();
    let build_request = || ExecutorApiProxyStartRequest {
        op: "api_proxy_start",
        id: 1,
        upstream: proxy.upstream.clone(),
        header: proxy.header.clone(),
        value_template,
        header_value,
        oauth,
    };
    let ((port, secret, returned_cookies), executor) = open_executor_with(
        &settings.executor_entry,
        settings.executor_socket.as_deref(),
        &settings.node_path,
        settings.browsers_path.as_deref(),
        build_request,
        |line| parse_api_proxy_start_response(line, oauth_enabled),
    )
    .await?;
    Ok(ServiceStarted {
        port,
        secret,
        executor,
        returned_cookies,
    })
}

/// Opens one executor connection, sends `mcp_server_start`, and receives the relay listener port
/// and the stream secret.
async fn start_mcp_server_executor(
    settings: &ServiceLaunchSettings,
    server: &McpServerConfig,
    launch: McpServerLaunch,
) -> Result<(u16, String, ExecutorHandle), ErrorCode> {
    let McpServerLaunch { env, scan } = launch;
    let build_request = || ExecutorMcpServerStartRequest {
        op: "mcp_server_start",
        id: 1,
        command: server.command.clone(),
        args: server.args.clone(),
        env,
        scan,
    };
    let ((port, stream_secret), executor) = open_executor_with(
        &settings.executor_entry,
        settings.executor_socket.as_deref(),
        &settings.node_path,
        settings.browsers_path.as_deref(),
        build_request,
        parse_mcp_server_start_response,
    )
    .await?;
    Ok((port, stream_secret, executor))
}

/// Extracts the relay listener port and the stream secret from the response to `mcp_server_start`.
/// Executor failures are not classified and uniformly yield `INTERNAL`.
fn parse_mcp_server_start_response(line: &str) -> Result<(u16, String), ErrorCode> {
    let response: ExecutorMcpServerStartResponse =
        serde_json::from_str(line).map_err(|_| ErrorCode::Internal)?;
    if response.id != Some(1) || !response.ok {
        return Err(ErrorCode::Internal);
    }
    let port = response
        .port
        .filter(|port| *port != 0)
        .ok_or(ErrorCode::Internal)?;
    let stream_secret = response
        .stream_secret
        .filter(|secret| valid_base64url_secret(secret))
        .ok_or(ErrorCode::Internal)?;
    Ok((port, stream_secret))
}

/// Extracts the listener port and the path secret from the response to `api_proxy_start`.
/// For OAuth it also extracts the cookie persistence values of the browser login (the default for a
/// static token).
fn parse_api_proxy_start_response(
    line: &str,
    oauth_enabled: bool,
) -> Result<(u16, String, ReturnedCookies), ErrorCode> {
    let response: ExecutorApiProxyStartResponse =
        serde_json::from_str(line).map_err(|_| ErrorCode::Internal)?;
    if response.id != Some(1) {
        return Err(ErrorCode::Internal);
    }
    if !response.ok {
        return Err(if oauth_enabled {
            response
                .error
                .as_deref()
                .map(parse_api_proxy_error_code)
                .unwrap_or(ErrorCode::Internal)
        } else {
            ErrorCode::Internal
        });
    }
    let port = response
        .port
        .filter(|port| *port != 0)
        .ok_or(ErrorCode::Internal)?;
    let secret = response
        .secret
        .filter(|secret| valid_base64url_secret(secret))
        .ok_or(ErrorCode::Internal)?;
    let returned_cookies = if oauth_enabled {
        parse_returned_cookies(line)
    } else {
        ReturnedCookies::default()
    };
    Ok((port, secret, returned_cookies))
}

/// Checks whether a secret value returned by the executor is a non-empty base64url string.
///
/// The path secret of an injection proxy is used as is, as one segment of base_url, and the stream
/// secret of an MCP server is used as is,
/// as the first line the runner sends when connecting to the relay. To avoid a delimiter or newline
/// slipping in and changing the interpretation, only base64url characters are accepted.
fn valid_base64url_secret(secret: &str) -> bool {
    !secret.is_empty()
        && secret
            .chars()
            .all(|character| character.is_ascii_alphanumeric() || matches!(character, '-' | '_'))
}

fn cdp_port_from_endpoint(endpoint: &str) -> Option<u16> {
    let authority = endpoint.split_once("://")?.1.split('/').next()?;
    let port = authority.rsplit_once(':')?.1.parse().ok()?;
    (port != 0).then_some(port)
}

fn selector_step(response: &ExecutorResponse, code: ErrorCode) -> Option<usize> {
    if !matches!(
        code,
        ErrorCode::SelectorNotFound | ErrorCode::FillMismatch | ErrorCode::FillTargetRefused
    ) {
        return None;
    }
    response
        .step
        .as_ref()
        .and_then(Value::as_u64)
        .and_then(|step| usize::try_from(step).ok())
}

fn parse_error_code(value: &str) -> ErrorCode {
    match value {
        "OAUTH_GRANT_FAILED" => ErrorCode::OAuthGrantFailed,
        "INVALID_CREDENTIAL" => ErrorCode::InvalidCredential,
        "MFA_REQUIRED" => ErrorCode::MfaRequired,
        "SELECTOR_NOT_FOUND" => ErrorCode::SelectorNotFound,
        "FILL_MISMATCH" => ErrorCode::FillMismatch,
        "FILL_TARGET_REFUSED" => ErrorCode::FillTargetRefused,
        "SNAPSHOT_REJECTED" => ErrorCode::SnapshotRejected,
        "DEVICE_CODE_REJECTED" => ErrorCode::DeviceCodeRejected,
        "LOGIN_RESULT_TIMEOUT" => ErrorCode::LoginResultTimeout,
        "VAULT_LOCKED" => ErrorCode::VaultLocked,
        "RATE_LIMITED" => ErrorCode::RateLimited,
        "TOTP_NOT_EXPOSABLE" => ErrorCode::TotpNotExposable,
        "APPROVAL_DENIED" => ErrorCode::ApprovalDenied,
        "APPROVAL_TIMEOUT" => ErrorCode::ApprovalTimeout,
        "PROVIDER_UNAVAILABLE" => ErrorCode::ProviderUnavailable,
        "INTERNAL" => ErrorCode::Internal,
        "NOT_FOUND" => ErrorCode::NotFound,
        _ => ErrorCode::Internal,
    }
}

fn parse_api_proxy_error_code(value: &str) -> ErrorCode {
    match value {
        "OAUTH_GRANT_FAILED" | "INTERNAL" => parse_error_code(value),
        _ => parse_authorize_error_code(value),
    }
}

fn parse_authorize_error_code(value: &str) -> ErrorCode {
    match value {
        "INVALID_CREDENTIAL"
        | "MFA_REQUIRED"
        | "SELECTOR_NOT_FOUND"
        | "FILL_MISMATCH"
        | "DEVICE_CODE_REJECTED"
        | "LOGIN_RESULT_TIMEOUT" => parse_error_code(value),
        _ => ErrorCode::Internal,
    }
}

async fn executor_request<T, F>(
    connection: &Arc<ExecutorConnection>,
    request: F,
    operation_timeout: Duration,
) -> Result<Value, ErrorCode>
where
    T: Serialize,
    F: FnOnce(u64) -> T,
{
    let operation = timeout(operation_timeout, connection.operation.lock())
        .await
        .map_err(|_| ErrorCode::Internal)?;
    let id = connection.next_id.fetch_add(1, Ordering::Relaxed);
    let mut request = serde_json::to_vec(&request(id)).map_err(|_| ErrorCode::Internal)?;
    request.push(b'\n');
    let mut executor = timeout(operation_timeout, connection.executor.lock())
        .await
        .map_err(|_| ErrorCode::Internal)?;
    timeout(operation_timeout, executor.write_line(&request))
        .await
        .map_err(|_| ErrorCode::Internal)?
        .map_err(|_| ErrorCode::Internal)?;
    drop(executor);
    let mut responses = timeout(operation_timeout, connection.responses.lock())
        .await
        .map_err(|_| ErrorCode::Internal)?;
    let response = timeout(operation_timeout, responses.recv())
        .await
        .map_err(|_| ErrorCode::Internal)?
        .ok_or(ErrorCode::Internal)?
        .map_err(|_| ErrorCode::Internal)?;
    let response: Value = serde_json::from_str(&response).map_err(|_| ErrorCode::Internal)?;
    if response.get("id").and_then(Value::as_u64) != Some(id) {
        drop(responses);
        drop(operation);
        kill_executor(connection).await;
        return Err(ErrorCode::Internal);
    }
    Ok(response)
}

async fn executor_lease(connection: &Arc<ExecutorConnection>) -> Result<String, ErrorCode> {
    let response = executor_request(
        connection,
        |id| ExecutorLeaseRequest { op: "lease", id },
        EXECUTOR_OPERATION_TIMEOUT,
    )
    .await?;
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
    let response = executor_request(
        connection,
        |id| ExecutorReleaseRequest {
            op: "release",
            id,
            target_id,
        },
        EXECUTOR_OPERATION_TIMEOUT,
    )
    .await?;
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

/// Sends the stop request that matches the kind of service and checks that the response is `ok:
/// true`.
async fn executor_service_stop(
    connection: &Arc<ExecutorConnection>,
    kind: ServiceKind,
) -> Result<(), ErrorCode> {
    let (op, stop_timeout) = kind.stop_request();
    let response = executor_request(
        connection,
        |id| ExecutorServiceStopRequest { op, id },
        stop_timeout,
    )
    .await?;
    (response.get("ok").and_then(Value::as_bool) == Some(true))
        .then_some(())
        .ok_or(ErrorCode::Internal)
}

/// Releases the resources on the executor that a lease occupies, with the request that matches its
/// kind.
async fn release_lease(
    connection: &Arc<ExecutorConnection>,
    target: &sessions::LeaseTarget,
) -> Result<(), ErrorCode> {
    match target {
        sessions::LeaseTarget::Tab(target_id) => {
            executor_release(connection, target_id.clone()).await
        }
        sessions::LeaseTarget::ApiProxy => {
            executor_service_stop(connection, ServiceKind::ApiProxy).await
        }
        sessions::LeaseTarget::McpServer => {
            executor_service_stop(connection, ServiceKind::McpServer).await
        }
    }
}

/// Stores the cookies received from the executor. Returns whether they could be stored, and records
/// a failure to stderr without including the values.
fn save_cookies(
    store: &cookie_store::CookieStore,
    key: &sessions::BrowserKey,
    cookies: &Value,
) -> bool {
    match store.save(key, cookies, cookie_store::unix_now()) {
        Ok(()) => true,
        Err(error) => {
            eprintln!("tegatad: cookie store: cookies of a session were {error}");
            false
        }
    }
}

/// Cookie persistence values carried in the success response of the executor.
#[derive(Default)]
struct ReturnedCookies {
    /// All cookies of the context at the time of success.
    cookies: Option<Value>,
    /// Whether the login steps were skipped thanks to the restored cookies.
    steps_skipped: bool,
}

/// Extracts `cookies` and `steps_skipped` from the success response line.
/// They are absent from older executors, so their absence is treated as no cookies and no skipping.
fn parse_returned_cookies(line: &str) -> ReturnedCookies {
    let mut response = serde_json::from_str::<Value>(line).unwrap_or(Value::Null);
    ReturnedCookies {
        cookies: response
            .get_mut("cookies")
            .map(Value::take)
            .filter(|cookies| !cookies.is_null()),
        steps_skipped: response
            .get("steps_skipped")
            .and_then(Value::as_bool)
            .unwrap_or(false),
    }
}

/// For the routes that log in with a throwaway browser (`authorize_device` and the OAuth injection
/// proxy),
/// the storage location of a persisted credential and the stored cookies read before the login.
struct LoginCookies {
    store: Arc<cookie_store::CookieStore>,
    key: sessions::BrowserKey,
    restored: Option<Vec<cookie_store::Cookie>>,
}

impl LoginCookies {
    /// Reads the stored cookies if the credential is persisted, and returns `None` if it is
    /// not.
    /// Call only after passing the approval gate and the unlock check.
    async fn load(state: &SharedState, key: sessions::BrowserKey) -> Option<Self> {
        let store = state.lock().await.cookie_store.clone();
        if !store.persists(&key.cred_id) {
            return None;
        }
        let restored = store.load(&key, cookie_store::unix_now());
        Some(Self {
            store,
            key,
            restored,
        })
    }

    /// Restored cookies in the shape carried in the request to the executor. Returns `None` if
    /// there is nothing to restore.
    fn wire_cookies(&self) -> Option<Vec<Value>> {
        self.restored.as_ref().map(|cookies| {
            cookies
                .iter()
                .filter_map(|cookie| serde_json::to_value(cookie).ok())
                .collect()
        })
    }

    /// Stores the cookies of the success response and returns the audit fields. Call only when
    /// the login succeeded.
    fn finish(self, returned: ReturnedCookies) -> CookieAudit {
        if let Some(cookies) = returned.cookies.as_ref() {
            save_cookies(&self.store, &self.key, cookies);
        }
        CookieAudit::login(self.restored.is_some(), returned.steps_skipped)
    }
}

/// Sends `export_cookies` to the executor and returns the cookie array of the response.
/// `executor_request` waits for each stage, such as writing and receiving the response,
/// independently
/// with `EXECUTOR_SHUTDOWN_TIMEOUT`, so the whole call is wrapped in a single
/// `timeout(EXECUTOR_SHUTDOWN_TIMEOUT, ..)` to cut it off so that the total also does not exceed
/// `EXECUTOR_SHUTDOWN_TIMEOUT`. Returns `None` on failure or an abnormal response.
async fn executor_export_cookies(connection: &Arc<ExecutorConnection>) -> Option<Value> {
    let mut response = timeout(
        EXECUTOR_SHUTDOWN_TIMEOUT,
        executor_request(
            connection,
            |id| json!({ "op": "export_cookies", "id": id }),
            EXECUTOR_SHUTDOWN_TIMEOUT,
        ),
    )
    .await
    .ok()?
    .ok()?;
    if response.get("ok").and_then(Value::as_bool) != Some(true) {
        return None;
    }
    response
        .get_mut("cookies")
        .map(Value::take)
        .filter(Value::is_array)
}

/// For a browser subject to persistence, writes out and stores the cookies before it ends. Returns
/// whether they could be stored.
/// Even when they could not be stored, the existing file is not touched.
async fn export_browser_cookies(
    state: &SharedState,
    key: &sessions::BrowserKey,
    executor: &Arc<ExecutorConnection>,
) -> bool {
    let store = state.lock().await.cookie_store.clone();
    match executor_export_cookies(executor).await {
        Some(cookies) => save_cookies(&store, key, &cookies),
        None => false,
    }
}

async fn shutdown_executor(connection: Arc<ExecutorConnection>) {
    let Ok(operation) = timeout(EXECUTOR_SHUTDOWN_TIMEOUT, connection.operation.lock()).await
    else {
        kill_executor(&connection).await;
        return;
    };
    let Ok(mut executor) = timeout(EXECUTOR_SHUTDOWN_TIMEOUT, connection.executor.lock()).await
    else {
        kill_executor(&connection).await;
        return;
    };
    let id = connection.next_id.fetch_add(1, Ordering::Relaxed);
    let mut request = match serde_json::to_vec(&json!({ "op": "shutdown", "id": id })) {
        Ok(request) => request,
        Err(_) => {
            kill_executor_handle(&mut executor).await;
            return;
        }
    };
    request.push(b'\n');
    let write_result = timeout(EXECUTOR_SHUTDOWN_TIMEOUT, executor.write_line(&request)).await;
    if !matches!(write_result, Ok(Ok(()))) {
        kill_executor_handle(&mut executor).await;
        return;
    }
    let _ = wait_or_kill_executor(&mut executor).await;
    drop(executor);
    if !shutdown_response_matches(&connection, id).await {
        drop(operation);
        kill_executor(&connection).await;
    }
}

async fn shutdown_response_matches(connection: &Arc<ExecutorConnection>, id: u64) -> bool {
    let Ok(mut responses) = timeout(EXECUTOR_SHUTDOWN_TIMEOUT, connection.responses.lock()).await
    else {
        return false;
    };
    let Ok(Some(Ok(response))) = timeout(EXECUTOR_SHUTDOWN_TIMEOUT, responses.recv()).await else {
        return false;
    };
    serde_json::from_str::<Value>(&response)
        .ok()
        .and_then(|response| response.get("id").and_then(Value::as_u64))
        == Some(id)
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

/// Context for connecting the event lines written by the executor of a service (injection proxy or
/// MCP server) to the audit and the lease termination.
/// `browser_id` is the key of `DaemonState::browsers` that holds the lease.
struct ServiceEventContext {
    kind: ServiceKind,
    browser_id: String,
    session_id: String,
    namespace: String,
    name: String,
    cred_id: String,
    peer: PeerIdentity,
}

impl ServiceEventContext {
    /// Returns the audit fields common to the session (credential, session, namespace, and
    /// service name) filled in.
    fn audit_fields(&self) -> AuditFields {
        AuditFields {
            cred_id: Some(self.cred_id.clone()),
            session_id: Some(self.session_id.clone()),
            namespace: Some(self.namespace.clone()),
            ..self.kind.named_audit_fields(self.name.clone())
        }
    }
}

/// Extracts a line that has `event` and no `id` as an executor event.
/// Sending an event line into the response channel would make a request being matched by id detect
/// a mismatch and stop the executor, so it is separated here.
fn executor_event(line: &str) -> Option<Value> {
    let value = serde_json::from_str::<Value>(line).ok()?;
    (value.get("id").is_none() && value.get("event").is_some()).then_some(value)
}

async fn handle_service_event(state: &SharedState, context: &ServiceEventContext, event: Value) {
    match context.kind {
        ServiceKind::ApiProxy => audit_api_proxy_event(state, context, event).await,
        ServiceKind::McpServer => handle_mcp_server_event(state, context, event).await,
    }
}

/// Audits an event line of an MCP server, and ends its lease if the server terminated (`exit`,
/// `leak`).
///
/// Ending the lease involves a stop request to the executor, and the reaper that read this event
/// hands over its response.
/// Waiting in the same task would leave nobody to read the response, so the termination is done in
/// a separate task.
async fn handle_mcp_server_event(state: &SharedState, context: &ServiceEventContext, event: Value) {
    let parsed = serde_json::from_value::<ExecutorMcpServerEvent>(event).ok();
    let Some((event, (end_reason, outcome, exit_code))) =
        parsed.and_then(|event| classify_mcp_server_event(&event).map(|effect| (event, effect)))
    else {
        eprintln!("tegatad: ignored an unrecognized executor event");
        return;
    };
    let fields = AuditFields {
        mcp_action: Some(event.action),
        exit_code,
        ..context.audit_fields()
    };
    append_service_audit(state, context, "mcp_server", fields, outcome.to_owned()).await;
    if let Some(reason) = end_reason {
        let state = state.clone();
        let browser_id = context.browser_id.clone();
        tokio::spawn(async move {
            end_service_lease(&state, &browser_id, reason).await;
        });
    }
}

/// Maps an event line of an MCP server to `(lease termination reason, audit outcome, exit_code)`.
/// `exit_code` is recorded in the audit only for `exit`. An unrecognized line yields `None`.
fn classify_mcp_server_event(
    event: &ExecutorMcpServerEvent,
) -> Option<(Option<&'static str>, &'static str, Option<i64>)> {
    if event.event != "mcp_server" {
        return None;
    }
    match event.action.as_str() {
        "connected" => Some((None, "ok", None)),
        "exit" => Some((Some("mcp_server_exit"), "ok", event.exit_code)),
        "leak" => Some((Some("mcp_server_leak"), "leak", None)),
        _ => None,
    }
}

/// Ends the lease of a service with a stop request and an executor stop, the same as disconnect,
/// and audits it with `audit_method`.
/// Does nothing if it has already been ended, for example by disconnect.
async fn end_service_lease(state: &SharedState, browser_id: &str, audit_method: &'static str) {
    let browser = take_browser_locked(&mut *state.lock().await, browser_id);
    if let Some(browser) = browser {
        terminate_browser(state, browser, audit_method, true).await;
    }
}

async fn audit_api_proxy_event(state: &SharedState, context: &ServiceEventContext, event: Value) {
    match event.get("event").and_then(Value::as_str) {
        Some("api_proxy_request") => {
            let Ok(event) = serde_json::from_value::<ExecutorApiProxyRequestEvent>(event) else {
                eprintln!("tegatad: ignored an unrecognized executor event");
                return;
            };
            let fields = AuditFields {
                http_method: Some(event.http_method),
                path: Some(audit_proxy_path(&event.path)),
                status: Some(event.status),
                ..context.audit_fields()
            };
            let outcome = api_proxy_outcome(event.status).to_owned();
            append_service_audit(state, context, "api_proxy_request", fields, outcome).await;
        }
        Some("oauth_token") => {
            let Ok(event) = serde_json::from_value::<ExecutorApiProxyOAuthTokenEvent>(event) else {
                eprintln!("tegatad: ignored an unrecognized executor event");
                return;
            };
            if !matches!(
                event.action.as_str(),
                "issued" | "refreshed" | "refresh_failed" | "revoked"
            ) {
                return;
            }
            let outcome = if event.action == "refresh_failed" {
                event.action.clone()
            } else {
                "ok".to_owned()
            };
            let fields = AuditFields {
                oauth_action: Some(event.action),
                ..context.audit_fields()
            };
            append_service_audit(state, context, "api_proxy_oauth", fields, outcome).await;
        }
        _ => eprintln!("tegatad: ignored an unrecognized executor event"),
    }
}

/// Appends the audit line of a service and reports a failure to stderr.
async fn append_service_audit(
    state: &SharedState,
    context: &ServiceEventContext,
    method: &str,
    fields: AuditFields,
    outcome: String,
) {
    let daemon = state.lock().await;
    if let Err(error) = append_audit(
        &daemon,
        AuditPeer::Peer(&context.peer),
        method.to_owned(),
        fields,
        outcome,
    )
    .await
    {
        eprintln!("tegatad: audit append failed: {error}");
    }
}

/// Upper bound in bytes on the proxy request path recorded in the audit.
const AUDIT_PROXY_PATH_MAX_BYTES: usize = 512;
/// Number of characters of the path secret. The executor encodes 16 random bytes in base64url
/// (without padding).
const API_PROXY_SECRET_LEN: usize = 22;

/// Normalizes the proxy request path for the audit.
///
/// In a request that concatenates a base_url onto a base_url, the second path secret appears as the
/// first segment,
/// so a first segment of the same shape as the secret (22 base64url characters) is replaced with
/// `[redacted]`.
/// It is then truncated to the upper bound in bytes while keeping UTF-8 character boundaries.
fn audit_proxy_path(path: &str) -> String {
    let mut sanitized = match path.strip_prefix('/') {
        Some(rest) => {
            let (segment, tail) = rest.split_at(rest.find('/').unwrap_or(rest.len()));
            if segment.len() == API_PROXY_SECRET_LEN && valid_base64url_secret(segment) {
                format!("/[redacted]{tail}")
            } else {
                path.to_owned()
            }
        }
        None => path.to_owned(),
    };
    if sanitized.len() > AUDIT_PROXY_PATH_MAX_BYTES {
        let mut end = AUDIT_PROXY_PATH_MAX_BYTES;
        while !sanitized.is_char_boundary(end) {
            end -= 1;
        }
        sanitized.truncate(end);
    }
    sanitized
}

/// Maps the upstream response status to the audit outcome. 502 is the value returned when the
/// executor could not reach the upstream.
fn api_proxy_outcome(status: u16) -> &'static str {
    match status {
        status if status < 400 => "ok",
        502 => "upstream_unreachable",
        _ => "upstream_error",
    }
}

fn spawn_executor_reaper(
    state: SharedState,
    browser_id: String,
    mut reader: ExecutorReader,
    sender: mpsc::UnboundedSender<io::Result<String>>,
    service: Option<ServiceEventContext>,
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
                    if let Some(event) = executor_event(&line) {
                        if let Some(context) = &service {
                            handle_service_event(&state, context, event).await;
                        }
                        continue;
                    }
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
                if let Ok(mut ports) = daemon.ports.write() {
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
        // After the executor is disconnected the cookies cannot be written out, so the fact
        // that they were not stored is recorded.
        let cookies_saved = browser.persist_cookies.then_some(false);
        for (session_id, _) in browser.leases {
            audit_system_session(
                &state,
                "session_terminated",
                session_id,
                browser.key.namespace.clone(),
                cookies_saved,
            )
            .await;
        }
    });
}

#[cfg(unix)]
fn kill_process_group_id(process_group_id: u32) {
    unsafe {
        libc::kill(-(process_group_id as libc::pid_t), libc::SIGKILL);
    }
}

#[cfg(unix)]
fn kill_process_group(child: &Child) {
    if let Some(process_group_id) = child.id() {
        kill_process_group_id(process_group_id);
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

/// Restricts, per method, the params keys that may be copied into the audit.
/// Copying keys that the method does not interpret would let the caller forge the audit record.
fn audit_param_keys(method: &str) -> &'static [&'static str] {
    match method {
        "login" | "login_begin" => &["cred_id", "target_url"],
        "authorize_device" => &["cred_id", "verification_url"],
        "disconnect" => &["session_id"],
        "get_totp" => &["cred_id"],
        "list_credentials" | "lock_vault" => &["namespace"],
        _ => &[],
    }
}

fn audit_fields(method: &str, params: &Value) -> AuditFields {
    let allowed = audit_param_keys(method);
    let field = |key: &str| {
        if !allowed.contains(&key) {
            return None;
        }
        params
            .get(key)
            .and_then(Value::as_str)
            .map(ToOwned::to_owned)
    };
    let target_url = match method {
        "authorize_device" => field("verification_url")
            .as_deref()
            .and_then(audit_target_url),
        _ => field("target_url"),
    };
    let cred_id = field("cred_id");
    let namespace = match method {
        "login" | "login_begin" | "authorize_device" | "get_totp" => cred_id
            .as_deref()
            .and_then(|cred_id| cred_id.split_once(':'))
            .map(|(namespace, _)| namespace.to_owned()),
        _ => field("namespace"),
    };
    let (login_id, action) = match method {
        "login_step" => (
            stepwise::audit_login_id(params),
            stepwise::audit_action(params),
        ),
        _ => (None, None),
    };
    AuditFields {
        cred_id,
        target_url,
        session_id: field("session_id"),
        namespace,
        login_id,
        action,
        stepwise: matches!(method, "login_begin" | "login_step").then_some(true),
        ..AuditFields::default()
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
        audit_approval: None,
        audit_approval_grant: None,
        audit_fields: None,
        audit_cookies: None,
    }
}

fn classified(id: Value, error: ErrorCode) -> HandledRequest {
    classified_with_step(id, error, None)
}

fn classified_with_step(id: Value, error: ErrorCode, step: Option<usize>) -> HandledRequest {
    HandledRequest {
        response: error_response_with_step(id, error, step),
        outcome: error.as_str().to_owned(),
        audit_shared: None,
        audit_approval: None,
        audit_approval_grant: None,
        audit_fields: None,
        audit_cookies: None,
    }
}

fn error_response(id: Value, error: ErrorCode) -> RpcResponse {
    error_response_with_step(id, error, None)
}

fn error_response_with_step(id: Value, error: ErrorCode, step: Option<usize>) -> RpcResponse {
    RpcResponse {
        jsonrpc: JSON_RPC_VERSION,
        id,
        result: None,
        error: Some(RpcError {
            code: CLASSIFICATION_ERROR,
            message: error.as_str().to_owned(),
            data: if matches!(
                error,
                ErrorCode::SelectorNotFound
                    | ErrorCode::FillMismatch
                    | ErrorCode::FillTargetRefused
            ) {
                step.map(|step| json!({ "step": step }))
            } else {
                None
            },
        }),
    }
}

#[cfg(all(test, unix))]
mod tests {
    use super::{
        AuditFields, AuditPeer, AuditRecord, ErrorCode, ExecutorResponse, PeerIdentity,
        valid_authorize_steps,
    };
    use tegata_core::wire::LoginStep;

    #[test]
    fn audit_record_names_the_peer_by_its_transport_identity() {
        let peer = PeerIdentity::Uid(1000);
        let record = AuditRecord {
            ts: "unix:1".to_owned(),
            peer: AuditPeer::Peer(&peer),
            method: "status".to_owned(),
            fields: AuditFields::default(),
            outcome: "ok".to_owned(),
        };
        assert_eq!(
            serde_json::to_string(&record).expect("serialize audit record"),
            r#"{"ts":"unix:1","peer_uid":1000,"principal":"uid:1000","method":"status","cred_id":null,"target_url":null,"session_id":null,"namespace":null,"outcome":"ok"}"#
        );
    }

    #[test]
    fn audit_proxy_path_redacts_a_leading_secret_shaped_segment() {
        assert_eq!(
            super::audit_proxy_path("/Ax7fQ2mN9pL3kR8sT1vW0y/api/whoami"),
            "/[redacted]/api/whoami"
        );
        assert_eq!(
            super::audit_proxy_path("/Ax7fQ2mN9pL3kR8sT1vW0y"),
            "/[redacted]"
        );
        assert_eq!(super::audit_proxy_path("/api/whoami"), "/api/whoami");
        // A segment containing characters other than base64url is not in the shape of a
        // secret even if it has 22 characters.
        assert_eq!(
            super::audit_proxy_path("/Ax7fQ2mN9pL3kR8sT1vW0.y/x"),
            "/Ax7fQ2mN9pL3kR8sT1vW0.y/x"
        );
    }

    #[test]
    fn audit_proxy_path_truncates_on_a_utf8_boundary() {
        let ascii = format!("/{}", "a".repeat(600));
        assert_eq!(super::audit_proxy_path(&ascii).len(), 512);
        // When the upper bound is reached in the middle of a 3-byte character, the cut is
        // made before that character.
        let multibyte = format!("/{}", "あ".repeat(200));
        let truncated = super::audit_proxy_path(&multibyte);
        assert_eq!(truncated.len(), 511);
        assert!(multibyte.starts_with(&truncated));
    }

    #[test]
    fn api_proxy_outcome_classifies_upstream_statuses() {
        assert_eq!(super::api_proxy_outcome(200), "ok");
        assert_eq!(super::api_proxy_outcome(302), "ok");
        assert_eq!(super::api_proxy_outcome(404), "upstream_error");
        assert_eq!(super::api_proxy_outcome(500), "upstream_error");
        assert_eq!(super::api_proxy_outcome(502), "upstream_unreachable");
    }

    #[test]
    fn wait_for_step_requires_no_value() {
        let valid = LoginStep {
            action: "wait_for".to_owned(),
            selector: "#ready".to_owned(),
            value: None,
        };
        let invalid = LoginStep {
            value: Some("unexpected".to_owned()),
            ..valid.clone()
        };
        assert!(valid_authorize_steps(Some(&[valid])));
        assert!(!valid_authorize_steps(Some(&[invalid])));
    }

    #[test]
    fn fill_mismatch_preserves_the_executor_step() {
        let response = ExecutorResponse {
            id: Some(1),
            ok: false,
            endpoint: None,
            error: Some("FILL_MISMATCH".to_owned()),
            step: Some(serde_json::json!(2)),
            target_id: None,
        };
        let code = super::parse_error_code(response.error.as_deref().unwrap());
        assert!(matches!(code, ErrorCode::FillMismatch));
        assert_eq!(super::selector_step(&response, code), Some(2));
    }
}

#[cfg(test)]
mod mcp_server_launch_tests {
    use super::{
        MCP_SECRET_PLACEHOLDER, MCP_USERNAME_PLACEHOLDER, McpPlaceholderValue, render_mcp_env_value,
    };

    fn values<'a>(password: &'a str, username: &'a str) -> [McpPlaceholderValue<'a>; 2] {
        [
            McpPlaceholderValue {
                placeholder: MCP_SECRET_PLACEHOLDER,
                value: password,
                scanned: true,
            },
            McpPlaceholderValue {
                placeholder: MCP_USERNAME_PLACEHOLDER,
                value: username,
                scanned: false,
            },
        ]
    }

    #[test]
    fn placeholders_are_replaced_in_one_pass() {
        let values = values("pa{{username}}ss", "user");
        let (rendered, scanned) = render_mcp_env_value("{{secret}}:{{username}}", &values);
        // Placeholder-shaped strings contained in the substituted values are not expanded.
        assert_eq!(rendered.as_str(), "pa{{username}}ss:user");
        assert!(scanned);
    }

    #[test]
    fn username_only_values_are_not_scanned() {
        let values = values("secret", "user");
        let (rendered, scanned) = render_mcp_env_value("as {{username}}", &values);
        assert_eq!(rendered.as_str(), "as user");
        assert!(!scanned);
    }

    #[test]
    fn literals_and_unknown_placeholders_are_kept() {
        let values = values("secret", "user");
        let (rendered, scanned) = render_mcp_env_value("{{other}} ä {{", &values);
        assert_eq!(rendered.as_str(), "{{other}} ä {{");
        assert!(!scanned);
    }
}

#[cfg(test)]
mod mcp_server_config_tests {
    use super::{McpServerConfig, validate_mcp_servers};
    use std::collections::BTreeMap;

    /// A command treated as an absolute path in the execution environment. On Windows, `/bin/…`
    /// is not an absolute path.
    #[cfg(windows)]
    const ABSOLUTE_COMMAND: &str = r"C:\bin\server.exe";
    #[cfg(not(windows))]
    const ABSOLUTE_COMMAND: &str = "/bin/server";

    fn server() -> McpServerConfig {
        McpServerConfig {
            name: "fx".to_owned(),
            cred_id: "mock:site".to_owned(),
            command: ABSOLUTE_COMMAND.to_owned(),
            args: vec!["--stdio".to_owned()],
            env: BTreeMap::from([("TOKEN".to_owned(), "{{secret}}".to_owned())]),
        }
    }

    fn rejection(server: McpServerConfig) -> String {
        validate_mcp_servers(&[server]).expect_err("invalid mcp_server accepted")
    }

    #[test]
    fn valid_mcp_server_is_accepted() {
        validate_mcp_servers(&[server()]).expect("valid mcp_server rejected");
    }

    #[test]
    fn mcp_server_rejects_nul_in_command_args_and_env() {
        let mut command = server();
        command.command = format!("{ABSOLUTE_COMMAND}\0x");
        let mut args = server();
        args.args.push("a\0b".to_owned());
        let mut env_name = server();
        env_name.env.insert("NA\0ME".to_owned(), "value".to_owned());
        let mut env_value = server();
        env_value
            .env
            .insert("OTHER".to_owned(), "va\0lue".to_owned());
        for invalid in [command, args, env_name, env_value] {
            assert!(rejection(invalid).contains("must not contain NUL"));
        }
    }

    #[test]
    fn mcp_server_rejects_empty_env_names_and_names_with_equals() {
        let mut empty = server();
        empty.env.insert(String::new(), "value".to_owned());
        let mut equals = server();
        equals.env.insert("A=B".to_owned(), "value".to_owned());
        for invalid in [empty, equals] {
            assert!(rejection(invalid).contains("env names must not be empty or contain '='"));
        }
    }
}

#[cfg(test)]
mod mcp_server_executor_tests {
    use super::{
        ExecutorMcpServerEvent, classify_mcp_server_event, parse_mcp_server_start_response,
    };

    #[test]
    fn start_response_ignores_an_error_field() {
        let (port, secret) = parse_mcp_server_start_response(
            r#"{"id":1,"ok":true,"port":4000,"stream_secret":"abc_-9","error":"INTERNAL"}"#,
        )
        .unwrap_or_else(|_| panic!("start response with an error field rejected"));
        assert_eq!(port, 4000);
        assert_eq!(secret, "abc_-9");
        assert!(
            parse_mcp_server_start_response(r#"{"id":1,"ok":false,"error":"INTERNAL"}"#).is_err()
        );
    }

    fn event(event: &str, action: &str, exit_code: Option<i64>) -> ExecutorMcpServerEvent {
        ExecutorMcpServerEvent {
            event: event.to_owned(),
            action: action.to_owned(),
            exit_code,
        }
    }

    #[test]
    fn events_map_to_reason_outcome_and_exit_code() {
        assert_eq!(
            classify_mcp_server_event(&event("mcp_server", "connected", Some(1))),
            Some((None, "ok", None))
        );
        assert_eq!(
            classify_mcp_server_event(&event("mcp_server", "exit", Some(3))),
            Some((Some("mcp_server_exit"), "ok", Some(3)))
        );
        assert_eq!(
            classify_mcp_server_event(&event("mcp_server", "leak", Some(1))),
            Some((Some("mcp_server_leak"), "leak", None))
        );
        assert_eq!(
            classify_mcp_server_event(&event("mcp_server", "other", None)),
            None
        );
        assert_eq!(
            classify_mcp_server_event(&event("api_proxy_request", "exit", None)),
            None
        );
    }
}

#[cfg(test)]
mod api_proxy_config_tests {
    use super::{
        ApiProxyConfig, ApiProxyOAuthConfig, default_api_proxy_value, validate_api_proxies,
    };

    fn oauth_config() -> ApiProxyOAuthConfig {
        ApiProxyOAuthConfig {
            client_id: "client".to_owned(),
            device_authorization_url: "https://oauth.example/device".to_owned(),
            token_url: "https://oauth.example/token".to_owned(),
            revocation_url: None,
            scope: None,
            login_cred_id: "mock:site".to_owned(),
            steps: None,
            success_selector: "#success".to_owned(),
            failure_selector: None,
        }
    }

    fn proxy() -> ApiProxyConfig {
        ApiProxyConfig {
            name: "fx".to_owned(),
            cred_id: Some("mock:site".to_owned()),
            upstream: "https://api.example".to_owned(),
            header: "Authorization".to_owned(),
            value: default_api_proxy_value(),
            oauth: None,
        }
    }

    #[test]
    fn api_proxy_requires_exactly_one_credential_mode() {
        let mut both = proxy();
        both.oauth = Some(oauth_config());
        let error = validate_api_proxies(&[both]).expect_err("both credential modes accepted");
        assert!(error.contains("mutually exclusive"));

        let mut neither = proxy();
        neither.cred_id = None;
        let error = validate_api_proxies(&[neither]).expect_err("missing credential mode accepted");
        assert!(error.contains("exactly one of cred_id or oauth"));
    }

    #[test]
    fn api_proxy_rejects_external_http_token_url_and_invalid_login_credential_id() {
        let mut external_token = proxy();
        external_token.cred_id = None;
        let mut oauth = oauth_config();
        oauth.token_url = "http://example.com/token".to_owned();
        external_token.oauth = Some(oauth);
        let error =
            validate_api_proxies(&[external_token]).expect_err("external token URL accepted");
        assert!(error.contains("token_url"));

        let mut invalid_login_cred = proxy();
        invalid_login_cred.cred_id = None;
        let mut oauth = oauth_config();
        oauth.login_cred_id = "mocksite".to_owned();
        invalid_login_cred.oauth = Some(oauth);
        let error = validate_api_proxies(&[invalid_login_cred])
            .expect_err("invalid login credential ID accepted");
        assert!(error.contains("login_cred_id"));
    }
}

#[cfg(test)]
mod executor_stderr_tests {
    use super::truncate_executor_stderr_line;

    #[test]
    fn truncates_executor_stderr_lines_to_1000_bytes() {
        let line = format!("{}\n", "a".repeat(1200));
        let truncated = truncate_executor_stderr_line(line.as_bytes());

        assert_eq!(truncated.len(), 1000);
        assert!(truncated.chars().all(|character| character == 'a'));
    }

    #[test]
    fn truncates_executor_stderr_lines_at_a_utf8_boundary() {
        let line = format!("{}\n", "あ".repeat(400));
        let truncated = truncate_executor_stderr_line(line.as_bytes());

        assert_eq!(truncated.len(), 999);
        assert!(truncated.chars().all(|character| character == 'あ'));
    }

    #[test]
    fn replaces_invalid_utf8_before_truncating() {
        let line = vec![0xff; 400];
        let truncated = truncate_executor_stderr_line(&line);

        assert_eq!(truncated.len(), 999);
        assert!(truncated.chars().all(|character| character == '\u{fffd}'));
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

#[cfg(test)]
mod persist_cookies_config_tests {
    use super::ProviderConfig;

    fn persist_cookies(provider: &str) -> Vec<String> {
        toml::from_str::<ProviderConfig>(provider)
            .expect("provider config")
            .persist_cookies
    }

    #[test]
    fn every_provider_type_accepts_persist_cookies() {
        let providers = [
            "type = \"bitwarden-cli\"\nserver_url = \"https://vault.test\"\nemail = \"a@example.test\"\naskpass_cmd = \"true\"\n",
            "type = \"age-file\"\nentries_path = \"/e\"\nidentity_path = \"/i\"\n",
            "type = \"pass\"\nstore_dir = \"/s\"\n",
        ];
        for provider in providers {
            let listed =
                format!("namespace = \"ns\"\npersist_cookies = [\"*\", \"x\"]\n{provider}");
            assert_eq!(persist_cookies(&listed), ["*", "x"], "{provider}");
            let omitted = format!("namespace = \"ns\"\n{provider}");
            assert!(persist_cookies(&omitted).is_empty(), "{provider}");
        }
    }
}

#[cfg(test)]
mod returned_cookies_tests {
    use super::{parse_api_proxy_start_response, parse_returned_cookies};
    use serde_json::json;

    #[test]
    fn missing_cookie_fields_mean_no_cookies_and_no_skip() {
        let returned = parse_returned_cookies(r#"{"id":1,"ok":true}"#);
        assert!(returned.cookies.is_none());
        assert!(!returned.steps_skipped);
        let returned = parse_returned_cookies(r#"{"id":1,"ok":true,"cookies":null}"#);
        assert!(returned.cookies.is_none());
    }

    #[test]
    fn cookie_fields_are_taken_from_a_success_response() {
        let returned = parse_returned_cookies(
            r#"{"id":1,"ok":true,"cookies":[{"name":"a"}],"steps_skipped":true}"#,
        );
        assert_eq!(returned.cookies, Some(json!([{ "name": "a" }])));
        assert!(returned.steps_skipped);
    }

    #[test]
    fn api_proxy_start_takes_cookies_only_for_oauth() {
        let line =
            r#"{"id":1,"ok":true,"port":4000,"secret":"abc","cookies":[],"steps_skipped":true}"#;
        let Ok((_, _, oauth)) = parse_api_proxy_start_response(line, true) else {
            panic!("OAuth start response rejected");
        };
        assert_eq!(oauth.cookies, Some(json!([])));
        assert!(oauth.steps_skipped);
        let Ok((_, _, fixed)) = parse_api_proxy_start_response(line, false) else {
            panic!("static start response rejected");
        };
        assert!(fixed.cookies.is_none());
        assert!(!fixed.steps_skipped);
        let legacy = r#"{"id":1,"ok":true,"port":4000,"secret":"abc"}"#;
        let Ok((port, secret, legacy)) = parse_api_proxy_start_response(legacy, true) else {
            panic!("OAuth start response without cookies rejected");
        };
        assert_eq!((port, secret.as_str()), (4000, "abc"));
        assert!(legacy.cookies.is_none());
        assert!(!legacy.steps_skipped);
    }
}
