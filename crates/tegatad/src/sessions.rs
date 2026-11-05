use std::collections::HashMap;
use std::sync::Arc;
use std::time::Duration;

use tokio::time::Instant;

use crate::ExecutorConnection;

#[derive(Clone, Debug, Eq, Hash, PartialEq)]
pub(crate) struct BrowserKey {
    pub(crate) principal: String,
    pub(crate) namespace: String,
    pub(crate) cred_id: String,
}

impl BrowserKey {
    pub(crate) fn new(principal: String, namespace: String, cred_id: String) -> Self {
        Self {
            principal,
            namespace,
            cred_id,
        }
    }
}

/// A unit that shares launch control (the attempt limit and backoff).
#[derive(Clone, Debug, Eq, Hash, PartialEq)]
pub(crate) enum StartKey {
    /// Browser launch for `login`. Controlled per pair of credential and caller.
    Browser(BrowserKey),
    /// Proxy launch for `open_api_proxy`. Controlled per pair of caller and `[[api_proxy]]` name.
    ApiProxy { principal: String, name: String },
    /// MCP server launch for `open_mcp_server`. Controlled per pair of caller and `[[mcp_server]]`
    /// name.
    McpServer { principal: String, name: String },
}

pub(crate) struct Lease {
    pub(crate) principal: String,
    pub(crate) expires_at: Instant,
    pub(crate) target: LeaseTarget,
}

/// The resource a lease occupies on the executor. It determines the kind of release request sent
/// when the lease ends.
pub(crate) enum LeaseTarget {
    /// A browser tab. It is released with `release {target_id}`.
    Tab(String),
    /// A listener of the injection proxy. It is released with `api_proxy_stop`.
    ApiProxy,
    /// A stdio MCP server started by the executor, together with the relay listener. It is released
    /// with `mcp_server_stop`.
    McpServer,
}

impl LeaseTarget {
    /// Returns whether this is a service (injection proxy or MCP server) that occupies one executor
    /// connection, rather than a browser tab.
    pub(crate) fn is_service(&self) -> bool {
        matches!(self, Self::ApiProxy | Self::McpServer)
    }
}

/// One executor connection and the set of leases on it.
///
/// It represents not only browsers but also injection proxies and MCP servers. For these services,
/// `port` is the port of the
/// listener, `endpoint` is empty, and there is exactly one lease, either `LeaseTarget::ApiProxy` or
/// `LeaseTarget::McpServer`.
pub(crate) struct Browser {
    pub(crate) key: BrowserKey,
    pub(crate) executor: Arc<ExecutorConnection>,
    pub(crate) port: u16,
    pub(crate) endpoint: String,
    pub(crate) deadline: Instant,
    pub(crate) leases: HashMap<String, Lease>,
    pub(crate) exclusive: bool,
    /// Whether this is a browser started by `login` whose credential is a `persist_cookies` target.
    /// If true, the cookies are written out and stored when the browser exits.
    pub(crate) persist_cookies: bool,
}

impl Browser {
    /// Returns whether this represents an injection proxy or an MCP server. Only these leases carry
    /// the service `LeaseTarget`.
    pub(crate) fn is_service(&self) -> bool {
        self.leases.values().any(|lease| lease.target.is_service())
    }
}

/// The period over which the attempt limit is counted.
const START_ATTEMPT_WINDOW_SECS: u64 = 600;
/// The number of launch attempts allowed within the period.
const MAX_START_ATTEMPTS: usize = 3;

pub(crate) struct StartControl {
    pub(crate) attempts: Vec<Instant>,
    pub(crate) consecutive_failures: usize,
    pub(crate) retry_at: Option<Instant>,
}

impl StartControl {
    pub(crate) fn new() -> Self {
        Self {
            attempts: Vec::new(),
            consecutive_failures: 0,
            retry_at: None,
        }
    }

    pub(crate) fn prune_attempts(&mut self, now: Instant) {
        self.attempts
            .retain(|attempt| now.duration_since(*attempt).as_secs() < START_ATTEMPT_WINDOW_SECS);
    }

    /// Returns whether the attempt limit has been reached or a backoff is in effect.
    pub(crate) fn is_limited(&mut self, now: Instant) -> bool {
        self.prune_attempts(now);
        self.attempts.len() >= MAX_START_ATTEMPTS || self.retry_at.is_some_and(|retry| retry > now)
    }

    pub(crate) fn record_attempt(&mut self, now: Instant) {
        self.prune_attempts(now);
        self.attempts.push(now);
    }

    pub(crate) fn record_success(&mut self) {
        self.consecutive_failures = 0;
        self.retry_at = None;
    }

    /// Sets a backoff of 2, 5 or 15 seconds according to the number of consecutive failures.
    pub(crate) fn record_failure(&mut self, now: Instant) {
        self.consecutive_failures += 1;
        let delay = match self.consecutive_failures {
            1 => 2,
            2 => 5,
            _ => 15,
        };
        self.retry_at = Some(now + Duration::from_secs(delay));
    }
}
