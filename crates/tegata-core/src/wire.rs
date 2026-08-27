//! JSON wire types shared by the daemon and its clients.

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

/// Login request written as one JSON line to the executor sidecar.
///
/// The sidecar is started as `node <executor_entry>` and receives secrets only
/// through this stdin message, never through argv or environment variables.
/// The response is either `{"ok":true,"endpoint":"ws://..."}` or
/// `{"ok":false,"error":"<classification code>"}`.
#[derive(Serialize)]
pub struct ExecutorLoginRequest {
    pub op: &'static str,
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
    pub ok: bool,
    pub endpoint: Option<String>,
    pub error: Option<String>,
}
