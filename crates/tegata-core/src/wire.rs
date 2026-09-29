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
    /// ログイン段の前に復元する保管済みの永続 cookie（Playwright の `Cookie` 形）。
    /// 永続化対象外の資格、または保管済みの cookie が無い場合は null とする。
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

/// Executor に新しいリース用タブを要求するメッセージ。
#[derive(Serialize)]
pub struct ExecutorLeaseRequest {
    pub op: &'static str,
    pub id: u64,
}

/// Executor のタブを閉じるメッセージ。
#[derive(Serialize)]
pub struct ExecutorReleaseRequest {
    pub op: &'static str,
    pub id: u64,
    pub target_id: String,
}

/// Executor のリース操作に対する応答。
#[derive(Deserialize)]
pub struct ExecutorLeaseResponse {
    pub id: Option<u64>,
    pub ok: bool,
    pub target_id: Option<String>,
    pub error: Option<String>,
}

/// `open_api_proxy` RPC のパラメータ。agent は `[[api_proxy]]` の名前でのみ選び、上流は指定できない。
#[derive(Deserialize)]
pub struct OpenApiProxyParams {
    pub name: String,
}

/// 専用の executor 接続で注入プロキシのリスナーを起動する要求。
///
/// `header_value` は解決済みの秘密を含むため、executor へ書き込む以外の用途（ログ・監査）に出してはならない。
/// 破棄時に消去されるよう `Zeroizing` で保持する。
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

/// `api_proxy_start` の OAuth 設定。
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
    /// ブラウザログインの前に復元する保管済みの永続 cookie（Playwright の `Cookie` 形）。
    /// 永続化対象外の資格、または保管済みの cookie が無い場合は null とする。
    pub cookies: Option<Vec<Value>>,
}

/// OAuth のブラウザログイン資格。直列化後も秘密の保持領域をゼロ化する。
///
/// `login` の `ExecutorSecret` は、executor への書き込みの直前に要求を組み立てる閉包の中で作られる。
/// これに対しこちらは、デーモンが解決済み資格を破棄した後も executor の起動を待つ間保持されるため、
/// `Zeroizing` で持つ。
#[derive(Serialize)]
pub struct ExecutorApiProxyOAuthSecret {
    #[serde(serialize_with = "serialize_zeroizing")]
    pub username: Zeroizing<String>,
    #[serde(serialize_with = "serialize_zeroizing")]
    pub password: Zeroizing<String>,
    #[serde(serialize_with = "serialize_optional_zeroizing")]
    pub totp: Option<Zeroizing<String>>,
}

/// `Zeroizing<String>` を文字列として直列化する。zeroize の serde 機能に依存しないための変換である。
fn serialize_zeroizing<S: serde::Serializer>(
    value: &Zeroizing<String>,
    serializer: S,
) -> Result<S::Ok, S::Error> {
    serializer.serialize_str(value.as_str())
}

/// `Option<Zeroizing<String>>` を、値があれば文字列、無ければ null として直列化する。
fn serialize_optional_zeroizing<S: serde::Serializer>(
    value: &Option<Zeroizing<String>>,
    serializer: S,
) -> Result<S::Ok, S::Error> {
    match value {
        Some(value) => serializer.serialize_some(value.as_str()),
        None => serializer.serialize_none(),
    }
}

/// `api_proxy_start` への応答。成功時は loopback のポートと path secret を持つ。
#[derive(Deserialize)]
pub struct ExecutorApiProxyStartResponse {
    pub id: Option<u64>,
    pub ok: bool,
    pub port: Option<u16>,
    pub secret: Option<String>,
    pub error: Option<String>,
}

/// executor 接続 1 本を占有するサービスを止める要求。`op` は `api_proxy_stop`（注入プロキシのリスナーを
/// 閉じる）または `mcp_server_stop`（MCP サーバーを終了させ、中継のリスナーと一時ディレクトリを片付ける）である。
#[derive(Serialize)]
pub struct ExecutorServiceStopRequest {
    pub op: &'static str,
    pub id: u64,
}

/// プロキシ経由の要求 1 件ごとに executor が書くイベント行。`id` を持たないため、
/// 応答待ちの要求と照合されることはない。`path` は path secret と query を除去済みである。
#[derive(Deserialize)]
pub struct ExecutorApiProxyRequestEvent {
    pub event: String,
    pub http_method: String,
    pub path: String,
    pub status: u16,
}

/// OAuth トークンの状態変化を executor が書くイベント行。
#[derive(Deserialize)]
pub struct ExecutorApiProxyOAuthTokenEvent {
    pub event: String,
    pub action: String,
}

/// `open_mcp_server` RPC のパラメータ。agent は `[[mcp_server]]` の名前でのみ選び、コマンド・引数・環境変数は指定できない。
#[derive(Deserialize)]
pub struct OpenMcpServerParams {
    pub name: String,
}

/// 専用の executor 接続で stdio MCP サーバーを起動する要求。
///
/// `env` はプレースホルダを置換済みの値であり、`scan` は漏洩検査の対象文字列である。いずれも解決済みの
/// 秘密を含むため、executor へ書き込む以外の用途（ログ・監査）に出してはならない。破棄時に消去されるよう
/// `Zeroizing` で保持し、`Debug` は導出しない。
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

/// `mcp_server_start` への応答。成功時は loopback のポートと stream secret を持つ。
///
/// デーモンは失敗を分類せず一律に `INTERNAL` とするため、executor が添える `error` は読まない
/// （未知のフィールドとして無視される）。
#[derive(Deserialize)]
pub struct ExecutorMcpServerStartResponse {
    pub id: Option<u64>,
    pub ok: bool,
    pub port: Option<u16>,
    pub stream_secret: Option<String>,
}

/// MCP サーバーの状態変化を executor が書くイベント行。`id` を持たないため、応答待ちの要求と照合されることはない。
/// `exit_code` は `exit` でのみ意味を持ち、シグナルで終了した場合は null となる。
#[derive(Deserialize)]
pub struct ExecutorMcpServerEvent {
    pub event: String,
    pub action: String,
    #[serde(default)]
    pub exit_code: Option<i64>,
}

/// 値が `Zeroizing<String>` の対応表を、文字列の対応表として直列化する。
fn serialize_zeroizing_map<S: serde::Serializer>(
    value: &BTreeMap<String, Zeroizing<String>>,
    serializer: S,
) -> Result<S::Ok, S::Error> {
    serializer.collect_map(value.iter().map(|(key, value)| (key, value.as_str())))
}

/// `Zeroizing<String>` の列を、文字列の配列として直列化する。
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
