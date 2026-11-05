//! JSON wire types shared by the daemon and its clients.

use std::collections::BTreeMap;
use std::fmt;

use serde::{Deserialize, Serialize};
use serde_json::Value;
use zeroize::Zeroizing;

#[derive(Debug, Deserialize)]
pub struct RpcRequest {
    pub jsonrpc: String,
    pub id: Value,
    pub method: String,
    #[serde(default)]
    pub params: Value,
}

#[derive(Serialize)]
pub struct RpcResponse {
    pub jsonrpc: &'static str,
    pub id: Value,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub result: Option<Value>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub error: Option<RpcError>,
}

#[derive(Serialize)]
pub struct RpcError {
    pub code: i32,
    pub message: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub data: Option<Value>,
}

#[derive(Deserialize)]
pub struct LoginParams {
    pub cred_id: String,
    pub target_url: String,
    pub steps: Option<Vec<LoginStep>>,
    pub success_selector: Option<String>,
    pub failure_selector: Option<String>,
}

#[derive(Deserialize)]
pub struct AuthorizeDeviceParams {
    pub cred_id: String,
    pub verification_url: String,
    pub user_code: String,
    pub steps: Option<Vec<LoginStep>>,
    pub success_selector: String,
    pub failure_selector: Option<String>,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct LoginStep {
    pub action: String,
    pub selector: String,
    pub value: Option<String>,
}

#[derive(Serialize)]
pub struct ExecutorHelloRequest {
    pub op: &'static str,
}

#[derive(Deserialize)]
pub struct ExecutorHelloResponse {
    pub ok: bool,
    pub uid: Option<u32>,
    pub pid: u32,
    /// Human-readable refusal reason the executor reports when `ok` is false. Older executors do
    /// not send it.
    #[serde(default)]
    pub reason: Option<String>,
}

/// Login request written as one JSON line to the executor sidecar.
///
/// The sidecar is started as `node <executor_entry>` and receives secrets only
/// through this stdin message, never through argv or environment variables.
/// The response is either `{"ok":true,"endpoint":"ws://..."}` or
/// `{"ok":false,"error":"<classification code>"}`.
#[derive(Serialize)]
pub struct ExecutorLoginRequest {
    pub op: &'static str,
    pub id: u64,
    pub target_url: String,
    pub steps: Option<Vec<LoginStep>>,
    pub success_selector: Option<String>,
    pub failure_selector: Option<String>,
    pub secret: ExecutorSecret,
}

#[derive(Serialize)]
pub struct ExecutorAuthorizeDeviceRequest {
    pub op: &'static str,
    pub id: u64,
    pub login_url: String,
    pub verification_url: String,
    pub user_code: String,
    pub steps: Option<Vec<LoginStep>>,
    pub success_selector: String,
    pub failure_selector: Option<String>,
    pub secret: ExecutorSecret,
    /// Stored persistent cookies restored before the login steps (Playwright `Cookie` shape).
    /// Null for credentials that are not persisted, or when no cookies are stored.
    pub cookies: Option<Vec<Value>>,
}

#[derive(Serialize)]
pub struct ExecutorSecret {
    pub username: String,
    pub password: String,
    pub totp: Option<String>,
}

/// Executor response returned as one JSON line after a login attempt. A
/// successful response contains a browser endpoint; a failed response carries
/// a classification code and may carry an explicit-step index.
#[derive(Deserialize)]
pub struct ExecutorResponse {
    pub id: Option<u64>,
    pub ok: bool,
    pub endpoint: Option<String>,
    pub error: Option<String>,
    pub step: Option<Value>,
    pub target_id: Option<String>,
}

/// Message asking the executor for a new lease tab.
#[derive(Serialize)]
pub struct ExecutorLeaseRequest {
    pub op: &'static str,
    pub id: u64,
}

/// Message closing an executor tab.
#[derive(Serialize)]
pub struct ExecutorReleaseRequest {
    pub op: &'static str,
    pub id: u64,
    pub target_id: String,
}

/// Response to an executor lease operation.
#[derive(Deserialize)]
pub struct ExecutorLeaseResponse {
    pub id: Option<u64>,
    pub ok: bool,
    pub target_id: Option<String>,
    pub error: Option<String>,
}

/// Parameters of the `open_api_proxy` RPC. The agent selects only by the `[[api_proxy]]` name and
/// cannot specify the upstream.
#[derive(Deserialize)]
pub struct OpenApiProxyParams {
    pub name: String,
}

/// Request to start the injection proxy listener on a dedicated executor connection.
///
/// `header_value` contains a resolved secret, so it must not be used for anything other than
/// writing to the executor (no logging or auditing).
/// It is held in `Zeroizing` so that it is erased on drop.
#[derive(Serialize)]
pub struct ExecutorApiProxyStartRequest {
    pub op: &'static str,
    pub id: u64,
    pub upstream: String,
    pub header: String,
    #[serde(
        skip_serializing_if = "Option::is_none",
        serialize_with = "serialize_optional_zeroizing"
    )]
    pub header_value: Option<Zeroizing<String>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub value_template: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub oauth: Option<ExecutorApiProxyOAuth>,
}

/// OAuth settings of `api_proxy_start`.
#[derive(Serialize)]
pub struct ExecutorApiProxyOAuth {
    pub client_id: String,
    pub device_authorization_url: String,
    pub token_url: String,
    pub revocation_url: Option<String>,
    pub scope: Option<String>,
    pub login_url: String,
    pub steps: Option<Vec<LoginStep>>,
    pub success_selector: String,
    pub failure_selector: Option<String>,
    pub secret: ExecutorApiProxyOAuthSecret,
    /// Stored persistent cookies restored before the browser login (Playwright `Cookie` shape).
    /// Null for credentials that are not persisted, or when no cookies are stored.
    pub cookies: Option<Vec<Value>>,
}

/// OAuth browser login credential. The secret storage is zeroized even after serialization.
///
/// The `ExecutorSecret` of `login` is created inside the closure that builds the request,
/// immediately before writing to the executor.
/// This one, in contrast, is kept while waiting for the executor to start, even after the daemon
/// has discarded the resolved credential,
/// so it is held in `Zeroizing`.
#[derive(Serialize)]
pub struct ExecutorApiProxyOAuthSecret {
    #[serde(serialize_with = "serialize_zeroizing")]
    pub username: Zeroizing<String>,
    #[serde(serialize_with = "serialize_zeroizing")]
    pub password: Zeroizing<String>,
    #[serde(serialize_with = "serialize_optional_zeroizing")]
    pub totp: Option<Zeroizing<String>>,
}

/// Serializes a `Zeroizing<String>` as a string. This conversion avoids depending on the serde
/// feature of zeroize.
fn serialize_zeroizing<S: serde::Serializer>(
    value: &Zeroizing<String>,
    serializer: S,
) -> Result<S::Ok, S::Error> {
    serializer.serialize_str(value.as_str())
}

/// Serializes an `Option<Zeroizing<String>>` as a string if present, or null if absent.
fn serialize_optional_zeroizing<S: serde::Serializer>(
    value: &Option<Zeroizing<String>>,
    serializer: S,
) -> Result<S::Ok, S::Error> {
    match value {
        Some(value) => serializer.serialize_some(value.as_str()),
        None => serializer.serialize_none(),
    }
}

/// Response to `api_proxy_start`. On success it carries the loopback port and the path secret.
#[derive(Deserialize)]
pub struct ExecutorApiProxyStartResponse {
    pub id: Option<u64>,
    pub ok: bool,
    pub port: Option<u16>,
    pub secret: Option<String>,
    pub error: Option<String>,
}

/// Request to stop a service that occupies one executor connection. `op` is `api_proxy_stop`
/// (closes the injection proxy listener)
/// or `mcp_server_stop` (terminates the MCP server and cleans up the relay listener and the
/// temporary directory).
#[derive(Serialize)]
pub struct ExecutorServiceStopRequest {
    pub op: &'static str,
    pub id: u64,
}

/// Event line the executor writes for each request that passes through the proxy. It has no `id`,
/// so it is never matched against a request awaiting a response. `path` has the path secret and the
/// query removed.
#[derive(Deserialize)]
pub struct ExecutorApiProxyRequestEvent {
    pub event: String,
    pub http_method: String,
    pub path: String,
    pub status: u16,
}

/// Event line the executor writes when the state of an OAuth token changes.
#[derive(Deserialize)]
pub struct ExecutorApiProxyOAuthTokenEvent {
    pub event: String,
    pub action: String,
}

/// Parameters of the `open_mcp_server` RPC. The agent selects only by the `[[mcp_server]]` name and
/// cannot specify the command, arguments, or environment variables.
#[derive(Deserialize)]
pub struct OpenMcpServerParams {
    pub name: String,
}

/// Request to start a stdio MCP server on a dedicated executor connection.
///
/// `env` holds values with placeholders already substituted, and `scan` holds the strings subject
/// to leak scanning. Both contain resolved
/// secrets, so they must not be used for anything other than writing to the executor (no logging or
/// auditing). They are held in
/// `Zeroizing` so that they are erased on drop, and `Debug` is not derived.
#[derive(Serialize)]
pub struct ExecutorMcpServerStartRequest {
    pub op: &'static str,
    pub id: u64,
    pub command: String,
    pub args: Vec<String>,
    #[serde(serialize_with = "serialize_zeroizing_map")]
    pub env: BTreeMap<String, Zeroizing<String>>,
    #[serde(serialize_with = "serialize_zeroizing_list")]
    pub scan: Vec<Zeroizing<String>>,
}

/// Response to `mcp_server_start`. On success it carries the loopback port and the stream secret.
///
/// The daemon does not classify failures and uniformly reports `INTERNAL`, so the `error` that the
/// executor attaches is not read
/// (it is ignored as an unknown field).
#[derive(Deserialize)]
pub struct ExecutorMcpServerStartResponse {
    pub id: Option<u64>,
    pub ok: bool,
    pub port: Option<u16>,
    pub stream_secret: Option<String>,
}

/// Event line the executor writes when the state of an MCP server changes. It has no `id`, so it is
/// never matched against a request awaiting a response.
/// `exit_code` is meaningful only for `exit`, and is null when the process was terminated by a
/// signal.
#[derive(Deserialize)]
pub struct ExecutorMcpServerEvent {
    pub event: String,
    pub action: String,
    #[serde(default)]
    pub exit_code: Option<i64>,
}

/// Serializes a map whose values are `Zeroizing<String>` as a map of strings.
fn serialize_zeroizing_map<S: serde::Serializer>(
    value: &BTreeMap<String, Zeroizing<String>>,
    serializer: S,
) -> Result<S::Ok, S::Error> {
    serializer.collect_map(value.iter().map(|(key, value)| (key, value.as_str())))
}

/// Serializes a sequence of `Zeroizing<String>` as an array of strings.
fn serialize_zeroizing_list<S: serde::Serializer>(
    value: &[Zeroizing<String>],
    serializer: S,
) -> Result<S::Ok, S::Error> {
    serializer.collect_seq(value.iter().map(|value| value.as_str()))
}

/// Preamble version understood by this build.
pub const PREAMBLE_VERSION: u32 = 1;

/// First line a client writes on a transport that authenticates by token
/// instead of by operating system peer credentials.
///
/// Without `tunnel` the connection continues as JSON-RPC, in the same wire
/// format as the UNIX domain socket transport, and the daemon stays silent on
/// success. With `tunnel` the daemon answers `{"ok":true}` and then splices
/// the connection to the requested loopback port on its own side.
///
/// The `auth` token is plain text on the wire. A daemon must compare it
/// against the stored hash and drop it immediately; it must never be logged,
/// and any retained copy belongs in a [`crate::Secret`].
#[derive(Deserialize, Serialize)]
pub struct Preamble {
    pub v: u32,
    pub auth: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub tunnel: Option<PreambleTunnel>,
}

impl fmt::Debug for Preamble {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("Preamble")
            .field("v", &self.v)
            .field("auth", &"<redacted>")
            .field("tunnel", &self.tunnel)
            .finish()
    }
}

/// Tunnel request carried by a preamble. The port must be the CDP port of the
/// named active session; any other port is refused.
#[derive(Debug, Deserialize, Serialize)]
pub struct PreambleTunnel {
    pub session_id: String,
    pub port: u16,
}

/// Preamble reply written as one JSON line. It is emitted only when a tunnel
/// is accepted (`{"ok":true}`) or when the preamble is refused
/// (`{"ok":false,"error":"<code>"}`); accepting an RPC connection is silent.
#[derive(Debug, Deserialize, Serialize)]
pub struct PreambleResponse {
    pub ok: bool,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub error: Option<String>,
}

impl PreambleResponse {
    /// Reply that accepts a tunnel request.
    pub fn accepted() -> Self {
        Self {
            ok: true,
            error: None,
        }
    }

    /// Reply that refuses a preamble with a transport-level error code.
    pub fn refused(error: PreambleError) -> Self {
        Self {
            ok: false,
            error: Some(error.as_str().to_owned()),
        }
    }
}

/// Transport level failures of the preamble exchange. These are distinct from
/// the JSON-RPC classification codes and never reach the RPC layer.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum PreambleError {
    /// The preamble was malformed, unsupported, or carried a wrong token.
    Unauthorized,
    /// The requested tunnel is not owned by the authenticated peer.
    NotFound,
    /// The token was accepted but the requested tunnel target is not allowed.
    Forbidden,
}

impl PreambleError {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Unauthorized => "UNAUTHORIZED",
            Self::NotFound => "NOT_FOUND",
            Self::Forbidden => "FORBIDDEN",
        }
    }
}

/// Parameters of the `admin_seal` administrative RPC, which hands a master
/// password to the daemon so that the daemon itself can seal it.
#[derive(Deserialize)]
pub struct AdminSealParams {
    pub master_password: String,
}

/// Result of the `admin_token_issue` administrative RPC. The plain token is
/// returned once and only the hash is retained by the daemon.
#[derive(Serialize)]
pub struct AdminTokenIssueResult {
    pub token: String,
}

#[cfg(test)]
mod tests {
    use std::collections::BTreeMap;

    use zeroize::Zeroizing;

    use super::{
        ExecutorMcpServerStartRequest, PREAMBLE_VERSION, Preamble, PreambleError, PreambleResponse,
        PreambleTunnel,
    };

    #[test]
    fn rpc_preamble_matches_the_pinned_line() {
        let preamble = Preamble {
            v: PREAMBLE_VERSION,
            auth: "token".to_owned(),
            tunnel: None,
        };
        assert_eq!(
            serde_json::to_string(&preamble).expect("serialize preamble"),
            r#"{"v":1,"auth":"token"}"#
        );
    }

    #[test]
    fn tunnel_preamble_matches_the_pinned_line() {
        let preamble = Preamble {
            v: PREAMBLE_VERSION,
            auth: "token".to_owned(),
            tunnel: Some(PreambleTunnel {
                session_id: "session".to_owned(),
                port: 9222,
            }),
        };
        assert_eq!(
            serde_json::to_string(&preamble).expect("serialize preamble"),
            r#"{"v":1,"auth":"token","tunnel":{"session_id":"session","port":9222}}"#
        );
    }

    #[test]
    fn mcp_server_start_request_matches_the_pinned_line() {
        let request = ExecutorMcpServerStartRequest {
            op: "mcp_server_start",
            id: 1,
            command: "/bin/server".to_owned(),
            args: vec!["--stdio".to_owned()],
            env: BTreeMap::from([
                ("TOKEN".to_owned(), Zeroizing::new("value".to_owned())),
                ("A".to_owned(), Zeroizing::new("literal".to_owned())),
            ]),
            scan: vec![Zeroizing::new("value".to_owned())],
        };
        assert_eq!(
            serde_json::to_string(&request).expect("serialize request"),
            r#"{"op":"mcp_server_start","id":1,"command":"/bin/server","args":["--stdio"],"env":{"A":"literal","TOKEN":"value"},"scan":["value"]}"#
        );
    }

    #[test]
    fn preamble_responses_match_the_pinned_lines() {
        assert_eq!(
            serde_json::to_string(&PreambleResponse::accepted()).expect("serialize response"),
            r#"{"ok":true}"#
        );
        assert_eq!(
            serde_json::to_string(&PreambleResponse::refused(PreambleError::Unauthorized))
                .expect("serialize response"),
            r#"{"ok":false,"error":"UNAUTHORIZED"}"#
        );
        assert_eq!(
            serde_json::to_string(&PreambleResponse::refused(PreambleError::Forbidden))
                .expect("serialize response"),
            r#"{"ok":false,"error":"FORBIDDEN"}"#
        );
    }
}
