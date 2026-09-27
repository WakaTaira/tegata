use std::collections::HashMap;
#[cfg(unix)]
use std::io;
use std::time::Duration;

use serde::Serialize;
use tokio::time::Instant;

#[cfg(unix)]
use crate::peers;

#[cfg(any(unix, test))]
const APPROVAL_CODE_MIN: u8 = 10;
#[cfg(any(unix, test))]
const APPROVAL_CODE_SPAN: u8 = 90;

/// 承認ゲートの通過が付与によるものかを監査行に示す値。
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "lowercase")]
pub(crate) enum ApprovalGrant {
    /// 承認が成立し、付与を新たに記録した。
    Issued,
    /// 有効な付与があり、承認を求めずに通した。
    Reused,
}

/// (principal, cred_id) ごとの承認の付与。メモリにのみ保持し、永続化しない。
///
/// 有効期間は付与時刻からの固定であり、参照しても延長しない。有効期間が 0 の場合は
/// 付与を記録せず、毎回承認を求める従来の挙動となる。
pub(crate) struct ApprovalGrants {
    ttl: Duration,
    issued: HashMap<(String, String), Instant>,
}

impl ApprovalGrants {
    pub(crate) fn new(ttl: Duration) -> Self {
        Self {
            ttl,
            issued: HashMap::new(),
        }
    }

    #[cfg(unix)]
    pub(crate) fn ttl(&self) -> Duration {
        self.ttl
    }

    /// 有効な付与があれば真を返す。期限切れの付与はこの時点で除去する。
    pub(crate) fn reuse(&mut self, principal: &str, cred_id: &str, now: Instant) -> bool {
        if self.ttl.is_zero() {
            return false;
        }
        self.prune(now);
        self.issued
            .contains_key(&(principal.to_owned(), cred_id.to_owned()))
    }

    /// 付与を記録し、記録したかを返す。有効期間が 0 の構成では記録しない。
    pub(crate) fn issue(&mut self, principal: String, cred_id: String, now: Instant) -> bool {
        if self.ttl.is_zero() {
            return false;
        }
        self.prune(now);
        self.issued.insert((principal, cred_id), now);
        true
    }

    /// `namespace` に属する資格の付与を破棄する。`None` の場合はすべて破棄する。
    pub(crate) fn revoke(&mut self, namespace: Option<&str>) {
        let Some(namespace) = namespace else {
            self.issued.clear();
            return;
        };
        let prefix = format!("{namespace}:");
        self.issued
            .retain(|(_, cred_id), _| !cred_id.starts_with(&prefix));
    }

    fn prune(&mut self, now: Instant) {
        // 期限を付与時刻からの経過で判定するのは、設定値が極端に大きい場合に
        // Instant の加算が桁あふれしないようにするためである。
        let ttl = self.ttl;
        self.issued
            .retain(|_, issued_at| now.saturating_duration_since(*issued_at) < ttl);
    }
}

/// 承認フックへ渡す照合番号（10〜99）を CSPRNG から生成する。
#[cfg(unix)]
pub(crate) fn approval_code() -> io::Result<u8> {
    loop {
        let mut byte = [0_u8; 1];
        peers::fill_random(&mut byte)?;
        if let Some(code) = approval_code_from_byte(byte[0]) {
            return Ok(code);
        }
    }
}

/// 256 は 90 で割り切れないため、90 の倍数未満の値のみを採用して剰余の偏りを除く。
#[cfg(any(unix, test))]
fn approval_code_from_byte(byte: u8) -> Option<u8> {
    (byte < APPROVAL_CODE_SPAN * 2).then(|| APPROVAL_CODE_MIN + byte % APPROVAL_CODE_SPAN)
}

#[cfg(test)]
mod tests {
    use super::*;

    const TTL: Duration = Duration::from_secs(60);

    #[test]
    fn a_zero_ttl_never_issues_nor_reuses() {
        let now = Instant::now();
        let mut grants = ApprovalGrants::new(Duration::ZERO);
        assert!(!grants.issue("uid:1000".to_owned(), "vault:a".to_owned(), now));
        assert!(!grants.reuse("uid:1000", "vault:a", now));
    }

    #[test]
    fn an_issued_grant_is_reused_by_the_same_principal_and_credential_only() {
        let now = Instant::now();
        let mut grants = ApprovalGrants::new(TTL);
        assert!(!grants.reuse("uid:1000", "vault:a", now));
        assert!(grants.issue("uid:1000".to_owned(), "vault:a".to_owned(), now));
        assert!(grants.reuse("uid:1000", "vault:a", now));
        assert!(!grants.reuse("uid:1000", "vault:b", now));
        assert!(!grants.reuse("peer:01ABC", "vault:a", now));
    }

    #[test]
    fn a_grant_expires_at_a_fixed_time_after_issue_even_when_reused() {
        let issued_at = Instant::now();
        let mut grants = ApprovalGrants::new(TTL);
        grants.issue("uid:1000".to_owned(), "vault:a".to_owned(), issued_at);
        assert!(grants.reuse("uid:1000", "vault:a", issued_at + TTL / 2));
        assert!(grants.reuse(
            "uid:1000",
            "vault:a",
            issued_at + TTL - Duration::from_millis(1)
        ));
        assert!(!grants.reuse("uid:1000", "vault:a", issued_at + TTL));
    }

    #[test]
    fn expired_grants_are_removed_on_lookup() {
        let issued_at = Instant::now();
        let mut grants = ApprovalGrants::new(TTL);
        grants.issue("uid:1000".to_owned(), "vault:a".to_owned(), issued_at);
        grants.issue("uid:1000".to_owned(), "vault:b".to_owned(), issued_at);
        assert!(!grants.reuse("uid:1000", "vault:a", issued_at + TTL));
        assert!(grants.issued.is_empty());
        assert!(!grants.reuse("uid:1000", "vault:a", issued_at));
    }

    #[test]
    fn reissuing_restarts_the_validity_period() {
        let issued_at = Instant::now();
        let mut grants = ApprovalGrants::new(TTL);
        grants.issue("uid:1000".to_owned(), "vault:a".to_owned(), issued_at);
        let reissued_at = issued_at + TTL;
        grants.issue("uid:1000".to_owned(), "vault:a".to_owned(), reissued_at);
        assert!(grants.reuse("uid:1000", "vault:a", reissued_at + TTL / 2));
    }

    #[test]
    fn a_huge_ttl_does_not_overflow() {
        let now = Instant::now();
        let mut grants = ApprovalGrants::new(Duration::from_secs(u64::MAX));
        grants.issue("uid:1000".to_owned(), "vault:a".to_owned(), now);
        assert!(grants.reuse("uid:1000", "vault:a", now + Duration::from_secs(3600)));
    }

    #[test]
    fn revoking_a_namespace_keeps_other_namespaces() {
        let now = Instant::now();
        let mut grants = ApprovalGrants::new(TTL);
        grants.issue("uid:1000".to_owned(), "vault:a".to_owned(), now);
        grants.issue("uid:1000".to_owned(), "vaultx:a".to_owned(), now);
        grants.issue("peer:01ABC".to_owned(), "other:a".to_owned(), now);
        grants.revoke(Some("vault"));
        assert!(!grants.reuse("uid:1000", "vault:a", now));
        assert!(grants.reuse("uid:1000", "vaultx:a", now));
        assert!(grants.reuse("peer:01ABC", "other:a", now));
    }

    #[test]
    fn revoking_without_a_namespace_clears_every_grant() {
        let now = Instant::now();
        let mut grants = ApprovalGrants::new(TTL);
        grants.issue("uid:1000".to_owned(), "vault:a".to_owned(), now);
        grants.issue("peer:01ABC".to_owned(), "other:a".to_owned(), now);
        grants.revoke(None);
        assert!(grants.issued.is_empty());
    }

    #[test]
    fn approval_codes_cover_ten_to_ninety_nine_uniformly() {
        let mut counts = [0_u32; 100];
        for byte in 0..=u8::MAX {
            if let Some(code) = approval_code_from_byte(byte) {
                counts[usize::from(code)] += 1;
            }
        }
        assert!(counts[..10].iter().all(|count| *count == 0));
        assert!(counts[10..].iter().all(|count| *count == 2));
    }

    #[cfg(unix)]
    #[test]
    fn generated_approval_codes_stay_in_range() {
        for _ in 0..1000 {
            let code = approval_code().expect("approval code");
            assert!((10..=99).contains(&code), "code: {code}");
        }
    }
}
