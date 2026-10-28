//! The scan queue's rules — `common.domain.scans.ScanQueue`, pure, no queries: what becomes of an attempt that could
//! not run, how long a retry waits, the lease a claim sets.
//!
//! **The queue lives in the database, not in a thread pool**, for the reasons Java's class gives: a pool hides the
//! queue, a restart loses it, and the concurrency limit becomes the process's instead of a setting. The order is
//! creation order with no priority — "in the order they were asked for" is a rule an operator can predict.
//!
//! Held to Java by `reference/scanning/java-answers.json` (`queue`): every attempt from below one to past the limit,
//! both kinds, four policies.

use std::time::Duration;

use crate::FailureKind;
use crate::instant::Instant;

/// `LEASE_EXHAUSTED_MESSAGE`: what a scan failed by its lapses says.
pub const LEASE_EXHAUSTED_MESSAGE: &str = "The scan was taken over too many times without completing: its worker \
     stops responding before the end. Check the agent's logs, then run the scan again.";

/// `ScanQueue.Policy`: the queue's tunables, passed in so that a test can vary them — a lease nobody can vary in a test
/// is a lease nobody checks.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Policy {
    /// Past this, a scan is abandoned and claimable again.
    pub lease: Duration,
    /// How many takeovers before failing for good: without a cap, a target that jams its worker circulates through
    /// the whole fleet for ever.
    pub max_attempts: i32,
    /// Claim attempts before a round gives up — for MySQL, which counts skipped rows against a `LIMIT`.
    pub claim_attempts: i32,
    /// The wait after each failed attempt: the first after the first, the last for every attempt past the list.
    pub retry_delays: Vec<Duration>,
}

impl Policy {
    /// One minute, then five, then fifteen: what the owner decided on 2026-09-28.
    pub fn default_retry_delays() -> Vec<Duration> {
        vec![Duration::from_secs(60), Duration::from_secs(300), Duration::from_secs(900)]
    }

    /// `Policy.DEFAULT`: a twenty-minute lease, three attempts, twelve claim attempts.
    pub fn default_policy() -> Policy {
        Policy {
            lease: Duration::from_secs(20 * 60),
            max_attempts: 3,
            claim_attempts: 12,
            retry_delays: Policy::default_retry_delays(),
        }
    }
}

impl Default for Policy {
    fn default() -> Policy {
        Policy::default_policy()
    }
}

/// `ScanQueue.Next`: back in the queue from an instant, or failed for good.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Next {
    Retry {
        not_before: Instant,
    },
    /// `permanent`: failed because another attempt would meet the same refusal, not because the attempts ran out.
    Fail {
        permanent: bool,
    },
}

/// `capacity`: how many scans can still start — computed on every dispatch, so a changed limit applies without a
/// restart.
pub fn capacity(max_concurrent: i32, running: i32) -> i32 {
    max_concurrent.saturating_sub(running).max(0)
}

/// `afterLapse`: a lapsed lease fails the scan at the limit, and requeues it below.
pub fn lapse_fails(attempts: i32, policy: &Policy) -> bool {
    attempts >= policy.max_attempts
}

/// `afterFailure`: what becomes of a scan whose attempt `attempt` (from one) could not run. A permanent failure fails
/// at once, whatever the attempt — retrying a changed host key spends the attempts on the same refusal; a transient one
/// follows the lapse's rule and waits [`retry_delay`] from `failed_at`, so that a lone agent does not take back at its
/// next poll the scan it just reported.
pub fn after_failure(attempt: i32, kind: FailureKind, failed_at: Instant, policy: &Policy) -> Next {
    if kind == FailureKind::Permanent {
        return Next::Fail { permanent: true };
    }
    if lapse_fails(attempt, policy) {
        return Next::Fail { permanent: false };
    }
    // Java's `plus` throws past the range of an `Instant`; no clock reaches it.
    let not_before = failed_at.plus(retry_delay(attempt, policy)).unwrap_or(failed_at);
    Next::Retry { not_before }
}

/// `retryDelay`: the policy's delay for that attempt, the last one past the end, none for an empty list. An attempt
/// below one is a scan whose count was given back, and waits the first delay, as its first failure would.
pub fn retry_delay(attempt: i32, policy: &Policy) -> Duration {
    let delays = &policy.retry_delays;
    if delays.is_empty() {
        return Duration::ZERO;
    }
    let index = usize::try_from(attempt.max(1)).unwrap_or(1).min(delays.len()).saturating_sub(1);
    delays.get(index).copied().unwrap_or(Duration::ZERO)
}

/// `leaseUntil`: the lease a claim sets.
pub fn lease_until(claimed_at: Instant, policy: &Policy) -> Instant {
    claimed_at.plus(policy.lease).unwrap_or(claimed_at)
}
