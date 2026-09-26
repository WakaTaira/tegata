use std::collections::HashMap;
use std::sync::Arc;

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

pub(crate) struct Lease {
    pub(crate) principal: String,
    pub(crate) expires_at: Instant,
    pub(crate) target: LeaseTarget,
}

/// リースが executor 上で占有している資源。リース終了時の解放要求の種類を決める。
pub(crate) enum LeaseTarget {
    /// ブラウザのタブ。解放は `release {target_id}` で行う。
    Tab(String),
    /// 注入プロキシのリスナー。解放は `api_proxy_stop` で行う。
    ApiProxy,
}

pub(crate) struct Browser {
    pub(crate) key: BrowserKey,
    pub(crate) executor: Arc<ExecutorConnection>,
    pub(crate) cdp_port: u16,
    pub(crate) endpoint: String,
    pub(crate) leases: HashMap<String, Lease>,
    pub(crate) exclusive: bool,
}

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
            .retain(|attempt| now.duration_since(*attempt).as_secs() < 600);
    }
}
