//! JSON wire types shared by the daemon and its clients.

use std::fmt;

use serde::{Deserialize, Serialize};
use serde_json::Value;

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
}

#[derive(Deserialize)]
pub struct LoginParams {
    pub cred_id: String,
    pub target_url: String,
    pub steps: Option<Vec<LoginStep>>,
    pub success_selector: Option<String>,
    pub failure_selector: Option<String>,
}

#[derive(Clone, Deserialize, Serialize)]
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
pub struct ExecutorSecret {
    pub username: String,
    pub password: String,
    pub totp: Option<String>,
}

/// Executor response returned as one JSON line after a login attempt. A
/// successful response contains a browser endpoint; a failed response carries
/// a classification code.
#[derive(Deserialize)]
pub struct ExecutorResponse {
    pub id: Option<u64>,
    pub ok: bool,
    pub endpoint: Option<String>,
    pub error: Option<String>,
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
    use super::{PREAMBLE_VERSION, Preamble, PreambleError, PreambleResponse, PreambleTunnel};

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
