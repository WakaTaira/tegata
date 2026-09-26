//! 操作者承認の保留キューである。
//!
//! 承認を要する要求はここに保留として登録され、管理 RPC 経由の決定か
//! タイムアウトまで待機する。キュー自体はプラットフォームに依存しない。

use std::collections::HashMap;
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use tokio::sync::oneshot;

/// 操作者が読み上げて入力できる長さに収めるため、保留 id は 6 桁の 10 進数とする。
const ID_SPACE: u128 = 1_000_000;

/// 承認を求める要求の内容である。
pub(crate) struct ApprovalRequest {
    pub(crate) method: String,
    pub(crate) cred_id: String,
    pub(crate) target_url: String,
    pub(crate) principal: String,
}

/// `list` が返す保留の写しである。
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct PendingSummary {
    pub(crate) id: String,
    pub(crate) method: String,
    pub(crate) cred_id: String,
    pub(crate) target_url: String,
    pub(crate) principal: String,
    pub(crate) age_secs: u64,
}

/// 待機が承認以外で終わった理由である。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum ApprovalError {
    Denied,
    Timeout,
}

/// `decide` に渡された id が保留中に存在しないことを表す。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct NotFound;

struct Entry {
    request: ApprovalRequest,
    created_at: Instant,
    decision: oneshot::Sender<bool>,
}

type Entries = Arc<Mutex<HashMap<String, Entry>>>;

#[derive(Clone, Default)]
pub(crate) struct ApprovalQueue {
    entries: Entries,
}

/// 登録済みの保留である。破棄時にキューから取り除かれるため、待機側が
/// 途中で打ち切られても保留が残らない。
pub(crate) struct Pending {
    id: String,
    entries: Entries,
    decision: Option<oneshot::Receiver<bool>>,
}

impl ApprovalQueue {
    pub(crate) fn new() -> Self {
        Self::default()
    }

    /// 保留を登録する。id は同時保留の間で一意になるまで再生成する。
    pub(crate) fn register(&self, request: ApprovalRequest) -> Pending {
        self.register_with(request, random_id)
    }

    fn register_with(
        &self,
        request: ApprovalRequest,
        mut next_id: impl FnMut() -> u128,
    ) -> Pending {
        let (sender, receiver) = oneshot::channel();
        let mut entries = lock(&self.entries);
        let id = loop {
            let candidate = format!("{:06}", next_id() % ID_SPACE);
            if !entries.contains_key(&candidate) {
                break candidate;
            }
        };
        entries.insert(
            id.clone(),
            Entry {
                request,
                created_at: Instant::now(),
                decision: sender,
            },
        );
        Pending {
            id,
            entries: self.entries.clone(),
            decision: Some(receiver),
        }
    }

    /// 保留中の要求を登録の古い順に返す。
    pub(crate) fn list(&self) -> Vec<PendingSummary> {
        let entries = lock(&self.entries);
        let mut pending = entries
            .iter()
            .map(|(id, entry)| (entry.created_at, summarize(id, entry)))
            .collect::<Vec<_>>();
        drop(entries);
        pending.sort_by(|left, right| left.0.cmp(&right.0).then(left.1.id.cmp(&right.1.id)));
        pending.into_iter().map(|(_, summary)| summary).collect()
    }

    /// 保留に決定を与える。取り除きと通知を同じロック区間で行うことで、
    /// 同時に起きたタイムアウト側が決定の有無を取りこぼさないようにする。
    pub(crate) fn decide(&self, id: &str, allow: bool) -> Result<(), NotFound> {
        let mut entries = lock(&self.entries);
        let entry = entries.remove(id).ok_or(NotFound)?;
        let _ = entry.decision.send(allow);
        Ok(())
    }
}

impl Pending {
    pub(crate) fn id(&self) -> &str {
        &self.id
    }

    /// 決定を待つ。`limit` を過ぎた場合は保留を取り除いて `Timeout` を返す。
    pub(crate) async fn wait(mut self, limit: Duration) -> Result<(), ApprovalError> {
        let Some(mut decision) = self.decision.take() else {
            return Err(ApprovalError::Denied);
        };
        match tokio::time::timeout(limit, &mut decision).await {
            Ok(Ok(true)) => Ok(()),
            Ok(Ok(false)) => Err(ApprovalError::Denied),
            // 送信側が決定なしに失われた場合は承認されていないものとして扱う。
            Ok(Err(_)) => Err(ApprovalError::Denied),
            Err(_) => {
                let removed = lock(&self.entries).remove(&self.id).is_some();
                if removed {
                    return Err(ApprovalError::Timeout);
                }
                // 取り除く前に決定が確定していた場合は、その決定に従う。
                match decision.try_recv() {
                    Ok(true) => Ok(()),
                    Ok(false) => Err(ApprovalError::Denied),
                    Err(_) => Err(ApprovalError::Timeout),
                }
            }
        }
    }
}

impl Drop for Pending {
    fn drop(&mut self) {
        lock(&self.entries).remove(&self.id);
    }
}

fn summarize(id: &str, entry: &Entry) -> PendingSummary {
    PendingSummary {
        id: id.to_owned(),
        method: entry.request.method.clone(),
        cred_id: entry.request.cred_id.clone(),
        target_url: entry.request.target_url.clone(),
        principal: entry.request.principal.clone(),
        age_secs: entry.created_at.elapsed().as_secs(),
    }
}

fn random_id() -> u128 {
    uuid::Uuid::new_v4().as_u128()
}

fn lock(entries: &Entries) -> std::sync::MutexGuard<'_, HashMap<String, Entry>> {
    entries
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::HashSet;

    const LONG: Duration = Duration::from_secs(10);

    fn request(cred_id: &str) -> ApprovalRequest {
        ApprovalRequest {
            method: "login".to_owned(),
            cred_id: cred_id.to_owned(),
            target_url: "https://example.test/login".to_owned(),
            principal: "sid:S-1-5-21-1".to_owned(),
        }
    }

    #[tokio::test]
    async fn allowed_request_continues() {
        let queue = ApprovalQueue::new();
        let pending = queue.register(request("mock:a"));
        let id = pending.id().to_owned();
        let listed = queue.list();
        assert_eq!(listed.len(), 1);
        assert_eq!(listed[0].id, id);
        assert_eq!(listed[0].method, "login");
        assert_eq!(listed[0].cred_id, "mock:a");
        assert_eq!(listed[0].target_url, "https://example.test/login");
        assert_eq!(listed[0].principal, "sid:S-1-5-21-1");

        let waiter = tokio::spawn(pending.wait(LONG));
        queue.decide(&id, true).expect("decide pending approval");

        assert_eq!(waiter.await.expect("join waiter"), Ok(()));
        assert!(queue.list().is_empty());
    }

    #[tokio::test]
    async fn denied_request_reports_denied() {
        let queue = ApprovalQueue::new();
        let pending = queue.register(request("mock:a"));
        let id = pending.id().to_owned();

        let waiter = tokio::spawn(pending.wait(LONG));
        queue.decide(&id, false).expect("decide pending approval");

        assert_eq!(
            waiter.await.expect("join waiter"),
            Err(ApprovalError::Denied)
        );
        assert!(queue.list().is_empty());
    }

    #[tokio::test]
    async fn timeout_reports_timeout_and_removes_the_pending_entry() {
        let queue = ApprovalQueue::new();
        let pending = queue.register(request("mock:a"));
        let id = pending.id().to_owned();

        let started = Instant::now();
        let result = pending.wait(Duration::from_millis(50)).await;

        assert_eq!(result, Err(ApprovalError::Timeout));
        assert!(started.elapsed() >= Duration::from_millis(50));
        assert!(queue.list().is_empty());
        assert_eq!(queue.decide(&id, true), Err(NotFound));
    }

    #[tokio::test]
    async fn decision_recorded_before_timeout_cleanup_is_honoured() {
        let queue = ApprovalQueue::new();
        let pending = queue.register(request("mock:a"));
        let id = pending.id().to_owned();
        queue.decide(&id, true).expect("decide pending approval");

        assert_eq!(pending.wait(Duration::ZERO).await, Ok(()));
    }

    #[test]
    fn deciding_an_unknown_id_is_not_found() {
        let queue = ApprovalQueue::new();
        let _pending = queue.register(request("mock:a"));

        assert_eq!(queue.decide("not-an-id", true), Err(NotFound));
        assert_eq!(queue.list().len(), 1);
    }

    #[test]
    fn dropping_a_pending_entry_removes_it() {
        let queue = ApprovalQueue::new();
        let pending = queue.register(request("mock:a"));
        let id = pending.id().to_owned();
        drop(pending);

        assert!(queue.list().is_empty());
        assert_eq!(queue.decide(&id, true), Err(NotFound));
    }

    #[test]
    fn ids_are_six_decimal_digits_and_unique_among_pending() {
        let queue = ApprovalQueue::new();
        let pending = (0..2_000)
            .map(|index| queue.register(request(&format!("mock:{index}"))))
            .collect::<Vec<_>>();
        let ids = pending
            .iter()
            .map(|pending| pending.id().to_owned())
            .collect::<HashSet<_>>();

        assert_eq!(ids.len(), pending.len());
        for id in &ids {
            assert_eq!(id.len(), 6, "id {id} has six characters");
            assert!(id.bytes().all(|byte| byte.is_ascii_digit()), "id {id}");
        }
    }

    #[test]
    fn colliding_ids_are_regenerated_and_keep_leading_zeros() {
        let queue = ApprovalQueue::new();
        let mut sequence = [42_u128, 42, 42, 1_000_007].into_iter();
        let first = queue.register_with(request("mock:a"), || sequence.next().unwrap());
        let second = queue.register_with(request("mock:b"), || sequence.next().unwrap());

        assert_eq!(first.id(), "000042");
        assert_eq!(second.id(), "000007");
        assert_eq!(queue.list().len(), 2);
    }
}
