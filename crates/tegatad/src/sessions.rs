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

/// 起動制御（試行回数の上限とバックオフ）を共有する単位。
#[derive(Clone, Debug, Eq, Hash, PartialEq)]
pub(crate) enum StartKey {
    /// `login` のブラウザ起動。資格と呼び出し元の組ごとに制御する。
    Browser(BrowserKey),
    /// `open_api_proxy` のプロキシ起動。呼び出し元と `[[api_proxy]]` の名前の組ごとに制御する。
    ApiProxy { principal: String, name: String },
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

/// executor 接続 1 本と、その上のリースの集合。
///
/// ブラウザだけでなく注入プロキシも表す。プロキシの場合、`port` はプロキシのリスナーの
/// ポートであり、`endpoint` は空、リースは `LeaseTarget::ApiProxy` の 1 件のみとなる。
pub(crate) struct Browser {
    pub(crate) key: BrowserKey,
    pub(crate) executor: Arc<ExecutorConnection>,
    pub(crate) port: u16,
    pub(crate) endpoint: String,
    pub(crate) deadline: Instant,
    pub(crate) leases: HashMap<String, Lease>,
    pub(crate) exclusive: bool,
}

impl Browser {
    /// 注入プロキシを表すかを判定する。プロキシのリースだけが `LeaseTarget::ApiProxy` を持つ。
    pub(crate) fn is_api_proxy(&self) -> bool {
        self.leases
            .values()
            .any(|lease| matches!(lease.target, LeaseTarget::ApiProxy))
    }
}

/// 試行の上限を数える期間。
const START_ATTEMPT_WINDOW_SECS: u64 = 600;
/// 期間内に許す起動の試行回数。
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

    /// 試行回数の上限に達しているか、バックオフ中であるかを判定する。
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

    /// 連続失敗の回数に応じて 2 秒・5 秒・15 秒のバックオフを設定する。
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
