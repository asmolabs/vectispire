//! Claiming scans from a queue several instances share — `ScanQueue`.
//!
//! **One path on every engine, and no row lock.** The claim is a read, then a conditional update per candidate:
//! `set status = scanning where id = ? and status = pending and due` is atomic on every engine — two claimants racing on
//! one row both issue it, and exactly one changes a row. `SELECT … FOR UPDATE SKIP LOCKED` was dropped for what it did
//! on MySQL: next-key locks deadlocked eight claimants, and the skipped rows counted against the `LIMIT`, so a claimant
//! came back empty while rows remained. A wider window, trimmed after, starved PostgreSQL instead: a claimant holding
//! rows it will not take starves the others for as long as it holds them. Both were seen only on real servers.
//!
//! **Deliberately not one transaction.** Each take is its own, and every candidate read is outside any: under MySQL's
//! REPEATABLE READ a transaction's snapshot is fixed at its first read, so a claim wrapped whole saw the same five rows
//! a competitor had taken on every retry, for ever — the queue stopped draining at five of twenty with no error.
//! PostgreSQL's READ COMMITTED hid it. Here every read opens a transaction of its own and commits it at once.

use std::collections::BTreeSet;
use std::sync::Arc;
use std::time::Duration;

use time::OffsetDateTime;
use uuid::Uuid;
use vectispire_cp_db::{Db, Tx};
use vectispire_cp_http::credentials::BoxFuture;
use vectispire_cp_targets::Clock;
use vectispire_domain::scan_queue::{self, LEASE_EXHAUSTED_MESSAGE, Next, Policy};
use vectispire_domain::{FailureKind, ScanStatus};

use crate::instants::{instant, offset};
use crate::persistence::{self, ClaimCandidate, StoreError};
use crate::ports::{AgentClaimLock, PortError};
use crate::views::ScanView;

/// How many waiting scans one page of an excluding agent's walk reads, and so the most repositories an [`Exclusion`]
/// is asked about at once — far below every engine's bind-parameter limit.
pub const PAGE: usize = 256;

/// How many pages one attempt walks before giving up: **a cost bound, not a correctness one** — a scan the agent may
/// take behind four thousand it may not waits for the queue ahead to drain; it is not lost.
pub const PAGES: usize = 16;

/// The width of `t_scan.error` a reason is kept within: a scanner's stack trace runs to tens of kilobytes, and the
/// write carrying it whole failed on the length — "the scan failed *and we could not say so*", the lease left running.
pub const ERROR_MAX_LENGTH: usize = 2_000;

/// The repositories an agent must be kept from — for an agent that cannot be handed a delegated credential, those
/// that carry one (decision 0031). Asked a page at a time, never of the whole queue.
pub trait Exclusion: Send + Sync {
    /// Which of these repositories — at most [`PAGE`] of them — the agent must not take.
    fn among<'a>(&'a self, repositories: &'a BTreeSet<i64>) -> BoxFuture<'a, Result<BTreeSet<i64>, PortError>>;

    /// Nothing left out: no page is walked.
    fn excludes_nothing(&self) -> bool {
        false
    }
}

/// `Exclusion.NONE`.
#[derive(Debug, Clone, Copy, Default)]
pub struct NoExclusion;

impl Exclusion for NoExclusion {
    fn among<'a>(&'a self, _repositories: &'a BTreeSet<i64>) -> BoxFuture<'a, Result<BTreeSet<i64>, PortError>> {
        Box::pin(async { Ok(BTreeSet::new()) })
    }

    fn excludes_nothing(&self) -> bool {
        true
    }
}

/// What [`ScanQueue::claim_within`] came back with. `kept`: the exclusion left a scan this agent could otherwise have
/// taken for another executor — what the caller tells the agent when nothing else was there for it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AgentClaim {
    pub scan: Option<ScanView>,
    pub kept: bool,
}

impl AgentClaim {
    pub const NOTHING: AgentClaim = AgentClaim { scan: None, kept: false };
}

/// What became of an attempt its executor could not run: back in the queue from an instant, or failed for good.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Abandoned {
    pub next: Next,
    /// The attempt that failed, from one.
    pub attempt: i32,
    pub max_attempts: i32,
}

impl Abandoned {
    pub fn retried(&self) -> bool {
        matches!(self.next, Next::Retry { .. })
    }

    /// When the scan can be claimed again; `None` when it failed for good.
    pub fn not_before(&self) -> Option<OffsetDateTime> {
        match self.next {
            Next::Retry { not_before } => Some(offset(not_before)),
            Next::Fail { .. } => None,
        }
    }

    /// Failed because another attempt would meet the same refusal, not because the attempts ran out.
    pub fn permanent(&self) -> bool {
        matches!(self.next, Next::Fail { permanent: true })
    }
}

/// What the reclaim did: handed back to the queue, or failed for good out of attempts — a target that jams its worker
/// every time would otherwise circulate through the whole fleet.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct Reclaimed {
    pub requeued: Vec<i64>,
    pub failed: Vec<i64>,
}

/// The candidates an attempt tries, and whether the exclusion skipped any on the way.
struct Selection {
    candidates: Vec<i64>,
    kept: bool,
}

/// What one attempt of [`ScanQueue::claim_within`] came back with.
enum Taken {
    Scan(i64),
    /// The agent runs its limit — counted behind the lock, so final.
    Full,
    /// Every candidate was taken elsewhere meanwhile; worth another read.
    Lost,
}

/// Claiming and releasing scans. Every method is a statement or a few, each in a transaction of its own, unless it
/// takes the caller's `&mut Tx`.
pub struct ScanQueue {
    db: Db,
    agents: Arc<dyn AgentClaimLock>,
    policy: Policy,
    clock: Arc<dyn Clock>,
}

impl std::fmt::Debug for ScanQueue {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.debug_struct("ScanQueue").field("policy", &self.policy).finish_non_exhaustive()
    }
}

const PENDING: &str = "pending";
const SCANNING: &str = "scanning";
const FAILED: &str = "failed";

impl ScanQueue {
    pub fn new(db: Db, agents: Arc<dyn AgentClaimLock>, policy: Policy, clock: Arc<dyn Clock>) -> ScanQueue {
        debug_assert_eq!(ScanStatus::Pending.wire_name(), PENDING);
        ScanQueue { db, agents, policy, clock }
    }

    pub fn policy(&self) -> &Policy {
        &self.policy
    }

    /// How long a lease runs before it has to be renewed.
    pub fn lease(&self) -> Duration {
        self.policy.lease
    }

    fn lease_until(&self, at: OffsetDateTime) -> OffsetDateTime {
        offset(scan_queue::lease_until(instant(at), &self.policy))
    }

    /// `claim`: up to `limit` pending scans for this worker — the built-in worker's round. Takes in batches until it
    /// has `limit`, the queue holds nothing due, or [`Policy::claim_attempts`] ran out: an attempt that took nothing
    /// tells "taken elsewhere meanwhile" from "nothing there" by counting what is due — a scan waiting out its retry
    /// is no reason to turn again.
    pub async fn claim(&self, limit: i64, worker: &str, labels: &[String]) -> Result<Vec<ScanView>, StoreError> {
        if limit <= 0 {
            return Ok(Vec::new());
        }
        let mut claimed: Vec<ScanView> = Vec::new();
        for _ in 0..self.policy.claim_attempts {
            let wanted = limit.saturating_sub(i64::try_from(claimed.len()).unwrap_or(i64::MAX));
            let batch = self.take_batch(wanted, worker, labels).await?;
            let took_nothing = batch.is_empty();
            claimed.extend(batch);
            if i64::try_from(claimed.len()).unwrap_or(i64::MAX) >= limit {
                break;
            }
            if took_nothing && self.read_count_due().await? == 0 {
                break;
            }
        }
        Ok(claimed)
    }

    async fn read_count_due(&self) -> Result<i64, StoreError> {
        let now = self.clock.now();
        let mut tx = persistence::read(&self.db).await?;
        let due = persistence::count_due(&mut tx, PENDING, now).await;
        commit(tx).await?;
        due
    }

    /// `takeBatch`: the candidates read, then each taken by its conditional update in a transaction of its own. An
    /// engine that answers a losing update with an error rather than zero rows — "Record has changed since last read"
    /// — reports the same event: somebody else took the row.
    async fn take_batch(&self, wanted: i64, worker: &str, labels: &[String]) -> Result<Vec<ScanView>, StoreError> {
        let claimed_at = self.clock.now();
        let lease_expires_at = self.lease_until(claimed_at);
        let candidates = self.candidates(wanted, labels, claimed_at, None).await?;
        let mut taken = Vec::new();
        for candidate in candidates {
            if self.take_alone(candidate.id, worker, claimed_at, lease_expires_at).await {
                taken.push(candidate.id);
            }
        }
        if taken.is_empty() {
            return Ok(Vec::new());
        }
        let mut tx = persistence::read(&self.db).await?;
        let rows = persistence::scans_by_ids(&mut tx, &taken).await;
        commit(tx).await?;
        Ok(rows?.into_iter().map(ScanView::from).collect())
    }

    /// One take, committed on its own; any failure is a take lost, as Java's catch reads it.
    async fn take_alone(
        &self,
        id: i64,
        worker: &str,
        claimed_at: OffsetDateTime,
        lease_expires_at: OffsetDateTime,
    ) -> bool {
        let Ok(mut tx) = persistence::write(&self.db).await else { return false };
        match persistence::take(&mut tx, id, PENDING, SCANNING, worker, claimed_at, lease_expires_at).await {
            Ok(1) => tx.commit().await.is_ok(),
            Ok(_) | Err(_) => {
                let _ = tx.rollback().await;
                false
            }
        }
    }

    /// The claimable selection's first page, or the one after `after`, in a read of its own.
    async fn candidates(
        &self,
        wanted: i64,
        labels: &[String],
        as_of: OffsetDateTime,
        after: Option<(OffsetDateTime, i64)>,
    ) -> Result<Vec<ClaimCandidate>, StoreError> {
        let mut tx = persistence::read(&self.db).await?;
        let rows = persistence::claimable(&mut tx, PENDING, labels, as_of, after, wanted).await;
        commit(tx).await?;
        rows
    }

    /// `claimWithin`: one pending scan for a remote agent, **unless it already runs `limit`**.
    ///
    /// **The count and the take commit together, behind the agent's own row.** Counting, then taking, as two
    /// statements lets two polls of one agent both count one scan under a limit of two and both take; most of the time
    /// they read the same candidate and the conditional update turns one away, but not when they read *different*
    /// rows. So the transaction starts by writing the agent's row ([`AgentClaimLock`]), which both engines serialize,
    /// and counts after: under REPEATABLE READ the snapshot is fixed at the first plain read — the count, taken after
    /// the lock was granted and so after the competitor's commit.
    ///
    /// **Both cheap checks first, unlocked**: a poll re-checks every second for as long as it waits, and a write per
    /// second per idle agent would buy nothing these two reads do not say. **A lapsed lease does not count**: its agent
    /// stopped renewing, and counting it would leave a restarted agent idle until somebody else's timer ran. **An
    /// exclusion narrows the selection, never the take**: a repository given a key between the two is taken all the
    /// same, and the dispatcher, which reads the repository again to build the task, is what notices.
    pub async fn claim_within(
        &self,
        agent: Uuid,
        limit: i64,
        labels: &[String],
        exclusion: &dyn Exclusion,
    ) -> Result<AgentClaim, StoreError> {
        let worker = agent.as_hyphenated().to_string();
        if limit <= 0 {
            return Ok(AgentClaim::NOTHING);
        }
        let mut kept = false;
        for _ in 0..self.policy.claim_attempts {
            if self.count_held(&worker).await? >= limit {
                return Ok(AgentClaim { scan: None, kept });
            }
            let as_of = self.clock.now();
            let selection = if exclusion.excludes_nothing() {
                Selection {
                    candidates: self.candidates(1, labels, as_of, None).await?.iter().map(|row| row.id).collect(),
                    kept: false,
                }
            } else {
                self.eligible(labels, exclusion, as_of).await?
            };
            kept |= selection.kept;
            if selection.candidates.is_empty() {
                return Ok(AgentClaim { scan: None, kept });
            }
            match self.take_within_limit(agent, &worker, limit, &selection.candidates).await {
                Taken::Scan(id) => return Ok(AgentClaim { scan: self.by_id(id).await?, kept }),
                Taken::Full => return Ok(AgentClaim { scan: None, kept }),
                // Taken elsewhere between our read and our update: read again, outside, and try the next one.
                Taken::Lost => {}
            }
        }
        Ok(AgentClaim { scan: None, kept })
    }

    /// `eligible`: the first scan in claim order that the exclusion does not keep from this agent, **a page at a time**
    /// — the exclusion used to travel as `not in :excluded`, one bind parameter per waiting repository carrying a
    /// credential, and past the engines' limits the claim failed on every poll. Each page is read in claim order from
    /// where the last ended, and only its repositories are asked about.
    async fn eligible(
        &self,
        labels: &[String],
        exclusion: &dyn Exclusion,
        as_of: OffsetDateTime,
    ) -> Result<Selection, StoreError> {
        let mut kept = false;
        let mut after = None;
        for _ in 0..PAGES {
            let rows = self.candidates(i64::try_from(PAGE).unwrap_or(256), labels, as_of, after).await?;
            let repositories: BTreeSet<i64> = rows.iter().filter_map(|row| row.repo_id).collect();
            let excluded = if repositories.is_empty() {
                BTreeSet::new()
            } else {
                exclusion.among(&repositories).await.map_err(StoreError)?
            };
            for row in &rows {
                // An image scan, or a repository with no key and no token, stays the agent's to take.
                if row.repo_id.is_none_or(|repository| !excluded.contains(&repository)) {
                    return Ok(Selection { candidates: vec![row.id], kept });
                }
                kept = true;
            }
            if rows.len() < PAGE {
                break;
            }
            after = rows.last().map(|last| (last.created_at, last.id));
        }
        Ok(Selection { candidates: Vec::new(), kept })
    }

    /// `takeWithinLimit`: the lock first, the count behind it, then the takes — one transaction. A failure anywhere,
    /// the commit included, is a take lost: the conditional update may have marked the transaction for rollback.
    async fn take_within_limit(&self, agent: Uuid, worker: &str, limit: i64, candidates: &[i64]) -> Taken {
        let Ok(mut tx) = persistence::write(&self.db).await else { return Taken::Lost };
        let outcome = self.take_in(&mut tx, agent, worker, limit, candidates).await;
        match outcome {
            Ok(Taken::Scan(id)) => {
                if tx.commit().await.is_ok() {
                    Taken::Scan(id)
                } else {
                    Taken::Lost
                }
            }
            Ok(other) => {
                let _ = tx.commit().await;
                other
            }
            Err(_) => {
                let _ = tx.rollback().await;
                Taken::Lost
            }
        }
    }

    async fn take_in(
        &self,
        tx: &mut Tx,
        agent: Uuid,
        worker: &str,
        limit: i64,
        candidates: &[i64],
    ) -> Result<Taken, PortError> {
        let claimed_at = self.clock.now();
        // The lock, and it has to come first. Zero rows: the agent was deleted while it polled.
        if !self.agents.lock_for_claim(tx, agent, claimed_at).await? {
            return Ok(Taken::Full);
        }
        if persistence::count_held(tx, worker, SCANNING, claimed_at).await? >= limit {
            return Ok(Taken::Full);
        }
        let lease_expires_at = self.lease_until(claimed_at);
        for candidate in candidates {
            if persistence::take(tx, *candidate, PENDING, SCANNING, worker, claimed_at, lease_expires_at).await? == 1 {
                return Ok(Taken::Scan(*candidate));
            }
        }
        Ok(Taken::Lost)
    }

    /// `countHeld`: the scans this worker holds and is still renewing.
    pub async fn count_held(&self, worker: &str) -> Result<i64, StoreError> {
        let now = self.clock.now();
        let mut tx = persistence::read(&self.db).await?;
        let held = persistence::count_held(&mut tx, worker, SCANNING, now).await;
        commit(tx).await?;
        held
    }

    pub async fn by_id(&self, id: i64) -> Result<Option<ScanView>, StoreError> {
        let mut tx = persistence::read(&self.db).await?;
        let row = persistence::scan(&mut tx, id).await;
        commit(tx).await?;
        Ok(row?.map(ScanView::from))
    }

    /// The scan, read inside the caller's transaction.
    pub async fn by_id_in(&self, tx: &mut Tx, id: i64) -> Result<Option<ScanView>, StoreError> {
        Ok(persistence::scan(tx, id).await?.map(ScanView::from))
    }

    /// How many scans run, anywhere.
    pub async fn count_running(&self) -> Result<i64, StoreError> {
        self.count_by_status(SCANNING).await
    }

    /// How many scans wait, those serving out a retry delay included — what the queue gauge shows.
    pub async fn count_pending(&self) -> Result<i64, StoreError> {
        self.count_by_status(PENDING).await
    }

    async fn count_by_status(&self, status: &str) -> Result<i64, StoreError> {
        let mut tx = persistence::read(&self.db).await?;
        let count = persistence::count_by_status(&mut tx, status).await;
        commit(tx).await?;
        count
    }

    /// The languages the Semgrep rules of a scan's task read, as the column keeps them — `None` when none was carried.
    pub async fn record_sast_languages(&self, id: i64, column: Option<&str>) -> Result<(), StoreError> {
        let mut tx = persistence::write(&self.db).await?;
        let done = persistence::record_sast_languages(&mut tx, id, column).await;
        settle(tx, done).await.map(|_| ())
    }

    /// `renewLease`: a progressing scan's lease extended — `false` when it is no longer this worker's. The owner is in
    /// the statement, not checked before: a worker deposed in between must renew nothing.
    pub async fn renew_lease(&self, id: i64, worker: &str) -> Result<bool, StoreError> {
        let mut tx = persistence::write(&self.db).await?;
        let renewed = self.renew_lease_in(&mut tx, id, worker).await;
        settle(tx, renewed).await
    }

    async fn renew_lease_in(&self, tx: &mut Tx, id: i64, worker: &str) -> Result<bool, StoreError> {
        let until = self.lease_until(self.clock.now());
        Ok(persistence::renew_lease(tx, id, SCANNING, worker, until).await? > 0)
    }

    /// `holdForWrite`: this worker's scan held for the write that records its results, or reported lost. **An
    /// update, inside the writing transaction**: a plain read of the owner let a reclaim and a new take commit between
    /// it and the final write, which then merged stale results over the successor's claim. The update takes the row
    /// lock and keeps it until the write commits; a concurrent reclaim waits, then finds the scan no longer lapsed.
    pub async fn hold_for_write(&self, tx: &mut Tx, id: i64, worker: &str) -> Result<bool, StoreError> {
        self.renew_lease_in(tx, id, worker).await
    }

    /// `requeue`: this worker's scan back in the queue, its attempt kept — a scan that keeps going undelivered should
    /// reach its limit rather than circulate for ever.
    pub async fn requeue(&self, id: i64, worker: &str) -> Result<bool, StoreError> {
        let mut tx = persistence::write(&self.db).await?;
        let done = persistence::release_owned(&mut tx, id, SCANNING, worker, PENDING, None).await;
        settle(tx, done).await.map(|changed| changed > 0)
    }

    /// `requeueRefunded`: back in the queue **with the claim's attempt refunded** — only for a claim that could never
    /// have been honoured, on a path that cannot repeat for the same scan and executor (a key added between an
    /// excluding agent's selection and the delivery, which the next selection excludes). Anywhere else a refund turns
    /// a scan that keeps going undelivered into one that circulates for ever.
    pub async fn requeue_refunded(&self, id: i64, worker: &str) -> Result<bool, StoreError> {
        let mut tx = persistence::write(&self.db).await?;
        let done = persistence::release_owned_refunded(&mut tx, id, SCANNING, worker, PENDING).await;
        settle(tx, done).await.map(|changed| changed > 0)
    }

    /// `abandon`: ends one attempt of this worker's scan that could not run, **whichever executor it was** — failed
    /// for good if the failure is permanent or the attempt the last, otherwise back in the queue with the wait
    /// [`scan_queue::after_failure`] gives. The reason is stored either way, so a waiting scan says why the last
    /// attempt did not run. `None` when the scan is no longer this worker's at that attempt — a report already applied,
    /// or one about an attempt since superseded: nothing is written then.
    pub async fn abandon(
        &self,
        id: i64,
        worker: &str,
        attempt: i32,
        kind: FailureKind,
        reason: &(dyn Fn(&Abandoned) -> String + Send + Sync),
    ) -> Result<Option<Abandoned>, StoreError> {
        let held = self.by_id(id).await?.filter(|scan| {
            scan.status == SCANNING && scan.claimed_by.as_deref() == Some(worker) && scan.attempts == attempt
        });
        if held.is_none() {
            return Ok(None);
        }
        let abandoned = Abandoned {
            next: scan_queue::after_failure(attempt, kind, instant(self.clock.now()), &self.policy),
            attempt,
            max_attempts: self.policy.max_attempts,
        };
        let to = if abandoned.retried() { PENDING } else { FAILED };
        let sentence = truncate(&reason(&abandoned));
        // The condition read above is repeated by the statement: between the two, the lease may have lapsed and the
        // reclaim run, and the scan been taken again — by this very agent.
        let mut tx = persistence::write(&self.db).await?;
        let done = persistence::release_owned_attempt(
            &mut tx,
            id,
            SCANNING,
            worker,
            attempt,
            to,
            Some(&sentence),
            abandoned.not_before(),
        )
        .await;
        let changed = settle(tx, done).await?;
        Ok((changed > 0).then_some(abandoned))
    }

    /// `reclaimLapsedLeases`: the scans whose worker stopped reporting, made claimable again — **nothing is stopped**,
    /// the work may still run elsewhere, and `hold_for_write` is what will refuse the deposed worker's results. A lapse
    /// is a transient failure nobody reported, and waits as a reported one does: a worker that dies on a target every
    /// time would otherwise hand it to the next claimant at once, and the fleet spend the attempts in as many ticks.
    ///
    /// **No transaction around the loop**: each release is a conditional update of its own, conditioned on the lease
    /// still being lapsed, so a renewal or a final write committed meanwhile is never undone; one transaction around
    /// the loop would only hold every lapsed scan's lock until the last release.
    pub async fn reclaim_lapsed_leases(&self) -> Result<Reclaimed, StoreError> {
        let as_of = self.clock.now();
        let lapsed = {
            let mut tx = persistence::read(&self.db).await?;
            let lapsed = persistence::lapsed(&mut tx, SCANNING, as_of).await;
            commit(tx).await?;
            lapsed?
        };
        let mut reclaimed = Reclaimed::default();
        for (id, attempts) in lapsed {
            let mut tx = persistence::write(&self.db).await?;
            // Counted only when the row really changed: the owner may have renewed or finished since it was read.
            match scan_queue::after_failure(attempts, FailureKind::Transient, instant(as_of), &self.policy) {
                Next::Fail { .. } => {
                    let done = persistence::release_lapsed(
                        &mut tx,
                        id,
                        SCANNING,
                        as_of,
                        FAILED,
                        Some(LEASE_EXHAUSTED_MESSAGE),
                        None,
                    )
                    .await;
                    if settle(tx, done).await? > 0 {
                        reclaimed.failed.push(id);
                    }
                }
                Next::Retry { not_before } => {
                    let done = persistence::release_lapsed(
                        &mut tx,
                        id,
                        SCANNING,
                        as_of,
                        PENDING,
                        None,
                        Some(offset(not_before)),
                    )
                    .await;
                    if settle(tx, done).await? > 0 {
                        reclaimed.requeued.push(id);
                    }
                }
            }
        }
        Ok(reclaimed)
    }
}

/// `truncate`: a reason kept within [`ERROR_MAX_LENGTH`] UTF-16 units, as `String.substring` cuts — and where the cut
/// falls inside a surrogate pair, the high half left alone is what the JDBC drivers write of it, `?`.
pub fn truncate(reason: &str) -> String {
    truncate_to(reason, ERROR_MAX_LENGTH)
}

/// The same cut at `length` units.
pub fn truncate_to(reason: &str, length: usize) -> String {
    let mut units = 0usize;
    let mut kept = String::with_capacity(reason.len().min(length.saturating_mul(4)));
    for c in reason.chars() {
        let width = c.len_utf16();
        if units + width > length {
            if units < length {
                kept.push('?');
            }
            return kept;
        }
        units += width;
        kept.push(c);
    }
    kept
}

/// A read's transaction closed.
async fn commit(tx: Tx) -> Result<(), StoreError> {
    tx.commit().await.map_err(StoreError::from)
}

/// A write's transaction committed when the statement succeeded, rolled back otherwise.
async fn settle<T>(tx: Tx, done: Result<T, StoreError>) -> Result<T, StoreError> {
    match done {
        Ok(value) => {
            tx.commit().await?;
            Ok(value)
        }
        Err(failure) => {
            let _ = tx.rollback().await;
            Err(failure)
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_reason_is_cut_as_java_cuts_it_in_utf_16_units() {
        assert_eq!(truncate("short"), "short");
        let ascii = "a".repeat(ERROR_MAX_LENGTH + 5);
        assert_eq!(truncate(&ascii).len(), ERROR_MAX_LENGTH);
        let astral = format!("{}{}", "a".repeat(ERROR_MAX_LENGTH - 1), "\u{1F600}tail");
        assert_eq!(truncate(&astral), format!("{}?", "a".repeat(ERROR_MAX_LENGTH - 1)));
        let fits = format!("{}{}", "a".repeat(ERROR_MAX_LENGTH - 2), "\u{1F600}tail");
        assert_eq!(truncate(&fits), format!("{}\u{1F600}", "a".repeat(ERROR_MAX_LENGTH - 2)));
    }
}
