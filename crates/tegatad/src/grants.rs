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

/// A value that tells the audit line whether passing the approval gate was due to a grant.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "lowercase")]
pub(crate) enum ApprovalGrant {
    /// Approval was given and a new grant was recorded.
    Issued,
    /// A valid grant existed, so the request passed without asking for approval.
    Reused,
}

/// Approval grants per (principal, cred_id). They are held in memory only and are not persisted.
///
/// The validity period is fixed from the time of the grant and is not extended by lookups. With a
/// validity
/// period of 0, no grant is recorded and approval is requested every time, as in the earlier
/// behavior.
pub(crate) struct ApprovalGrants {
    ttl: Duration,
    issued: HashMap<(String, String), Instant>,
    /// A generation that increases on every revocation. It is used to detect whether a revocation
    /// happened while waiting for approval.
    generation: u64,
}

impl ApprovalGrants {
    pub(crate) fn new(ttl: Duration) -> Self {
        Self {
            ttl,
            issued: HashMap::new(),
            generation: 0,
        }
    }

    /// Returns the current revocation generation. Take it before asking for approval and pass it to
    /// `issue`.
    pub(crate) fn generation(&self) -> u64 {
        self.generation
    }

    #[cfg(unix)]
    pub(crate) fn ttl(&self) -> Duration {
        self.ttl
    }

    /// Returns true if a valid grant exists. An expired grant is removed at this point.
    pub(crate) fn reuse(&mut self, principal: &str, cred_id: &str, now: Instant) -> bool {
        if self.ttl.is_zero() {
            return false;
        }
        self.prune(now);
        self.issued
            .contains_key(&(principal.to_owned(), cred_id.to_owned()))
    }

    /// Records a grant and returns whether it was recorded. Nothing is recorded when the validity
    /// period is 0,
    /// or when a revocation happened after `observed` was taken. This keeps a grant from
    /// overwriting a `lock_vault` that occurred while waiting for approval.
    pub(crate) fn issue(
        &mut self,
        principal: String,
        cred_id: String,
        now: Instant,
        observed: u64,
    ) -> bool {
        if self.ttl.is_zero() || observed != self.generation {
            return false;
        }
        self.prune(now);
        self.issued.insert((principal, cred_id), now);
        true
    }

    /// Revokes the grants of credentials belonging to `namespace`; with `None`, revokes all of
    /// them.
    /// The generation advances regardless of namespace, which conservatively cancels the recording
    /// of grants awaiting approval.
    pub(crate) fn revoke(&mut self, namespace: Option<&str>) {
        self.generation = self.generation.wrapping_add(1);
        let Some(namespace) = namespace else {
            self.issued.clear();
            return;
        };
        let prefix = format!("{namespace}:");
        self.issued
            .retain(|(_, cred_id), _| !cred_id.starts_with(&prefix));
    }

    fn prune(&mut self, now: Instant) {
        // Expiry is judged by the time elapsed since the grant so that adding to an Instant
        // cannot overflow when the configured value is extremely large.
        let ttl = self.ttl;
        self.issued
            .retain(|_, issued_at| now.saturating_duration_since(*issued_at) < ttl);
    }
}

/// Generates from the CSPRNG the verification number (10 to 99) passed to the approval hook.
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

/// 256 is not divisible by 90, so only values below the largest multiple of 90 are accepted to
/// remove modulo bias.
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
        assert!(!grants.issue(
            "uid:1000".to_owned(),
            "vault:a".to_owned(),
            now,
            grants.generation()
        ));
        assert!(!grants.reuse("uid:1000", "vault:a", now));
    }

    #[test]
    fn an_issued_grant_is_reused_by_the_same_principal_and_credential_only() {
        let now = Instant::now();
        let mut grants = ApprovalGrants::new(TTL);
        assert!(!grants.reuse("uid:1000", "vault:a", now));
        assert!(grants.issue(
            "uid:1000".to_owned(),
            "vault:a".to_owned(),
            now,
            grants.generation()
        ));
        assert!(grants.reuse("uid:1000", "vault:a", now));
        assert!(!grants.reuse("uid:1000", "vault:b", now));
        assert!(!grants.reuse("peer:01ABC", "vault:a", now));
    }

    #[test]
    fn a_grant_expires_at_a_fixed_time_after_issue_even_when_reused() {
        let issued_at = Instant::now();
        let mut grants = ApprovalGrants::new(TTL);
        grants.issue(
            "uid:1000".to_owned(),
            "vault:a".to_owned(),
            issued_at,
            grants.generation(),
        );
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
        grants.issue(
            "uid:1000".to_owned(),
            "vault:a".to_owned(),
            issued_at,
            grants.generation(),
        );
        grants.issue(
            "uid:1000".to_owned(),
            "vault:b".to_owned(),
            issued_at,
            grants.generation(),
        );
        assert!(!grants.reuse("uid:1000", "vault:a", issued_at + TTL));
        assert!(grants.issued.is_empty());
        assert!(!grants.reuse("uid:1000", "vault:a", issued_at));
    }

    #[test]
    fn reissuing_restarts_the_validity_period() {
        let issued_at = Instant::now();
        let mut grants = ApprovalGrants::new(TTL);
        grants.issue(
            "uid:1000".to_owned(),
            "vault:a".to_owned(),
            issued_at,
            grants.generation(),
        );
        let reissued_at = issued_at + TTL;
        grants.issue(
            "uid:1000".to_owned(),
            "vault:a".to_owned(),
            reissued_at,
            grants.generation(),
        );
        assert!(grants.reuse("uid:1000", "vault:a", reissued_at + TTL / 2));
    }

    #[test]
    fn a_huge_ttl_does_not_overflow() {
        let now = Instant::now();
        let mut grants = ApprovalGrants::new(Duration::from_secs(u64::MAX));
        grants.issue(
            "uid:1000".to_owned(),
            "vault:a".to_owned(),
            now,
            grants.generation(),
        );
        assert!(grants.reuse("uid:1000", "vault:a", now + Duration::from_secs(3600)));
    }

    #[test]
    fn revoking_a_namespace_keeps_other_namespaces() {
        let now = Instant::now();
        let mut grants = ApprovalGrants::new(TTL);
        grants.issue(
            "uid:1000".to_owned(),
            "vault:a".to_owned(),
            now,
            grants.generation(),
        );
        grants.issue(
            "uid:1000".to_owned(),
            "vaultx:a".to_owned(),
            now,
            grants.generation(),
        );
        grants.issue(
            "peer:01ABC".to_owned(),
            "other:a".to_owned(),
            now,
            grants.generation(),
        );
        grants.revoke(Some("vault"));
        assert!(!grants.reuse("uid:1000", "vault:a", now));
        assert!(grants.reuse("uid:1000", "vaultx:a", now));
        assert!(grants.reuse("peer:01ABC", "other:a", now));
    }

    #[test]
    fn revoking_without_a_namespace_clears_every_grant() {
        let now = Instant::now();
        let mut grants = ApprovalGrants::new(TTL);
        grants.issue(
            "uid:1000".to_owned(),
            "vault:a".to_owned(),
            now,
            grants.generation(),
        );
        grants.issue(
            "peer:01ABC".to_owned(),
            "other:a".to_owned(),
            now,
            grants.generation(),
        );
        grants.revoke(None);
        assert!(grants.issued.is_empty());
    }

    #[test]
    fn a_revoke_while_awaiting_approval_prevents_the_grant() {
        let now = Instant::now();
        let mut grants = ApprovalGrants::new(TTL);
        let observed = grants.generation();
        grants.revoke(Some("vault"));
        assert!(!grants.issue("uid:1000".to_owned(), "vault:a".to_owned(), now, observed));
        assert!(!grants.reuse("uid:1000", "vault:a", now));
    }

    #[test]
    fn a_revoke_of_another_namespace_also_prevents_a_pending_grant() {
        let now = Instant::now();
        let mut grants = ApprovalGrants::new(TTL);
        let observed = grants.generation();
        grants.revoke(Some("other"));
        assert!(!grants.issue("uid:1000".to_owned(), "vault:a".to_owned(), now, observed));
        let observed = grants.generation();
        grants.revoke(None);
        assert!(!grants.issue("uid:1000".to_owned(), "vault:a".to_owned(), now, observed));
    }

    #[test]
    fn a_grant_observed_after_a_revoke_is_issued() {
        let now = Instant::now();
        let mut grants = ApprovalGrants::new(TTL);
        grants.revoke(None);
        let observed = grants.generation();
        assert!(grants.issue("uid:1000".to_owned(), "vault:a".to_owned(), now, observed));
        assert!(grants.reuse("uid:1000", "vault:a", now));
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
