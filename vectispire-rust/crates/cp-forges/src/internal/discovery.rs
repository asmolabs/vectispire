//! `DiscoveryQueue`, `DiscoveryExecution` and `DiscoveryWorker`: the discoveries claimed from the table by a control-
//! plane instance under a lease, and carried out (decision 0037 §3).
//!
//! **The scan queue's pattern**: the waiting runs read oldest first, each taken by a conditional update naming the
//! state it expects; a lapsed lease puts the run back to waiting, three attempts and it fails `executor_lost`. **A run
//! of a suspended connection waits**: the claim passes it over. **Each page is written in a transaction that first
//! renews the lease**, rolled back when the run is no longer this instance's. **Ended by what stopped it**: a bound
//! ends it partial, a rejected token or a forge that does not answer failed; a next page elsewhere or a refused
//! address failed *and* recorded `FORGE_CONNECTION_REFUSED` in the requester's name. **Only `completed` marks gone**
//! what the run did not list — never in a namespace it could not read.

use std::collections::{BTreeSet, HashMap};
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use time::OffsetDateTime;
use vectispire_cp_audit::{AuditLog, AuditOperation, RequestActor};
use vectispire_cp_crypto::{Encryption, SecretState, forge_connection_context};
use vectispire_cp_db::{Db, Tx};
use vectispire_cp_outbound::json::{OutboundJson, TIMEOUT};
use vectispire_cp_outbound::pager::{Heartbeat, OutboundPager, PagerClock, PagerCounters, PagerError, Settings};
use vectispire_cp_targets::Clock;
use vectispire_domain::bounded_text;
use vectispire_domain::forges::{
    DiscoveredRepository, DiscoveryReason, DiscoveryState, ForgeKind, UnreadableNamespace,
};
use vectispire_domain::instant::Instant;

use super::integrations::{self, ForgeIntegrations};
use super::listers::{self, ListError, Listing};
use super::targets::{self, ForgeTarget};
use crate::persistence::{self, Ending, Progress, RepositoryRow, StoreError};
use crate::views::{instant, stored};

/// Longer than anything between two renewals: a request's twenty seconds, a rate-limit wait of up to a minute.
pub(crate) const LEASE: time::Duration = time::Duration::minutes(3);
/// How many times a run is taken before a lost one is failed rather than resumed.
pub(crate) const MAX_ATTEMPTS: i32 = 3;
/// How many waiting runs a claim reads before it gives up for this turn.
pub(crate) const CANDIDATES: u64 = 8;
/// How often, at most, a run renews its lease between pages.
pub(crate) const RENEWAL: time::Duration = time::Duration::seconds(15);
/// Namespaces per statement when the gone marks are confined or taken back.
pub(crate) const NAMESPACE_BATCH: usize = 1_000;

/// A discovery's bounds (answer 8): thirty minutes and twenty thousand repositories per run, a rate-limit wait of up to
/// a minute inside it — `vectispire.forges.discovery.*`, configurable so that a test reaches each in seconds.
#[derive(Debug, Clone, Copy)]
pub struct DiscoveryBounds {
    pub max_duration: Duration,
    pub max_repositories: usize,
    pub max_rate_limit_wait: Duration,
}

impl Default for DiscoveryBounds {
    fn default() -> DiscoveryBounds {
        DiscoveryBounds {
            max_duration: Duration::from_secs(30 * 60),
            max_repositories: 20_000,
            max_rate_limit_wait: Duration::from_secs(60),
        }
    }
}

const PENDING: &str = "pending";
const RUNNING: &str = "running";

/// The queue.
#[derive(Clone)]
pub(crate) struct DiscoveryQueue {
    db: Db,
    integrations: ForgeIntegrations,
    clock: Arc<dyn Clock>,
}

impl DiscoveryQueue {
    pub(crate) fn new(db: Db, integrations: ForgeIntegrations, clock: Arc<dyn Clock>) -> DiscoveryQueue {
        DiscoveryQueue { db, integrations, clock }
    }

    /// Takes the oldest waiting run of a connection whose forge is enabled, for `owner`.
    pub(crate) async fn claim(&self, owner: &str) -> Result<Option<i64>, String> {
        let now = self.clock.now();
        let suspended = self.integrations.disabled().await.map_err(|failure| failure.to_string())?;
        let kinds: Vec<&str> = suspended.iter().map(|kind| kind.wire_name()).collect();
        let mut tx = persistence::write(&self.db).await.map_err(|failure| failure.to_string())?;
        let waiting = persistence::waiting(&mut tx, PENDING, &kinds, CANDIDATES).await.map_err(|f| f.to_string())?;
        for id in waiting {
            if persistence::take(&mut tx, id, PENDING, RUNNING, owner, now, now + LEASE)
                .await
                .map_err(|f| f.to_string())?
                == 1
            {
                tx.commit().await.map_err(|failure| failure.to_string())?;
                return Ok(Some(id));
            }
        }
        tx.commit().await.map_err(|failure| failure.to_string())?;
        Ok(None)
    }

    /// How many runs wait on a connection of one of these forge kinds.
    pub(crate) async fn waiting_on(&self, kinds: &BTreeSet<ForgeKind>) -> Result<i64, String> {
        if kinds.is_empty() {
            return Ok(0);
        }
        let names: Vec<&str> = kinds.iter().map(|kind| kind.wire_name()).collect();
        let mut tx = persistence::read(&self.db).await.map_err(|failure| failure.to_string())?;
        let count = persistence::count_waiting_on(&mut tx, PENDING, &names).await.map_err(|f| f.to_string())?;
        tx.commit().await.map_err(|failure| failure.to_string())?;
        Ok(count)
    }

    /// Puts back every run whose lease lapsed, or fails it once its attempts are spent.
    pub(crate) async fn recover_lapsed(&self) -> Result<u64, String> {
        let now = self.clock.now();
        let mut tx = persistence::write(&self.db).await.map_err(|failure| failure.to_string())?;
        let mut recovered = 0;
        let detail = format!(
            "The instances that took this discovery stopped answering {MAX_ATTEMPTS} times before it ended. What it \
             listed is kept; request it again."
        );
        for id in persistence::lapsed(&mut tx, RUNNING, now).await.map_err(|failure| failure.to_string())? {
            recovered += persistence::requeue_lapsed(&mut tx, id, RUNNING, PENDING, now, MAX_ATTEMPTS)
                .await
                .map_err(|failure| failure.to_string())?;
            recovered += persistence::fail_lapsed(
                &mut tx,
                id,
                RUNNING,
                DiscoveryState::Failed.wire_name(),
                DiscoveryReason::ExecutorLost.wire_name(),
                &detail,
                now,
                MAX_ATTEMPTS,
            )
            .await
            .map_err(|failure| failure.to_string())?;
        }
        tx.commit().await.map_err(|failure| failure.to_string())?;
        Ok(recovered)
    }
}

/// How a run ended.
#[derive(Debug, Clone)]
struct Outcome {
    state: DiscoveryState,
    reason: Option<DiscoveryReason>,
    detail: Option<String>,
    rate_limit_reset_at: Option<Instant>,
}

impl Outcome {
    fn of(reason: DiscoveryReason, detail: impl Into<String>) -> Outcome {
        Outcome { state: reason.state(), reason: Some(reason), detail: Some(detail.into()), rate_limit_reset_at: None }
    }
}

/// The execution.
#[derive(Clone)]
pub(crate) struct DiscoveryExecution {
    pub(crate) db: Db,
    pub(crate) encryption: Arc<Encryption>,
    pub(crate) outbound: OutboundJson,
    pub(crate) bounds: DiscoveryBounds,
    pub(crate) integrations: ForgeIntegrations,
    pub(crate) audit: Arc<AuditLog>,
    pub(crate) clock: Arc<dyn Clock>,
    pub(crate) pager_clock: Arc<dyn PagerClock>,
}

/// Why opening a run did not lead to a listing.
enum Opened {
    Lost,
    Suspended(ForgeKind),
    Ended(Outcome),
}

impl DiscoveryExecution {
    /// Whether this version lists the repositories of a forge of this kind: GitLab and GitHub both.
    pub(crate) fn lists(_kind: ForgeKind) -> bool {
        true
    }

    /// Carries out the run `owner` claimed, to its end — or to the moment it learns the run is no longer its.
    pub(crate) async fn execute(&self, id: i64, owner: &str) {
        let entity = match self.read_run(id).await {
            Ok(Some(run)) if run.claimed_by.as_deref() == Some(owner) => run,
            Ok(_) => return,
            Err(failure) => {
                tracing::error!("Forge discovery {id} could not be read: {failure}");
                return;
            }
        };
        let shared = Arc::new(Shared {
            db: self.db.clone(),
            id,
            owner: owner.to_owned(),
            clock: self.clock.clone(),
            renewed: Mutex::new(self.clock.now()),
            counts: Mutex::new(Counts::default()),
            counters: Arc::new(PagerCounters::default()),
        });
        let mut run = Run {
            execution: self,
            shared: shared.clone(),
            connection_id: entity.connection_id.clone(),
            target: None,
            token: String::new(),
            deadline: instant(self.clock.now()),
            languages: Vec::new(),
            unreadable: Vec::new(),
            withheld: Vec::new(),
        };
        let outcome = match run.open().await {
            Err(Opened::Lost) => {
                tracing::info!("Forge discovery {id} is no longer this instance's ({owner}); left to its new owner.");
                return;
            }
            Err(Opened::Suspended(kind)) => {
                // Switched off between the claim and here: given back as it was taken, the attempt not counted.
                if self.give_back(id, owner).await == 1 {
                    tracing::info!(
                        "Forge discovery {id} left waiting: the {} integration is disabled.",
                        kind.integration_key()
                    );
                }
                return;
            }
            Err(Opened::Ended(outcome)) => outcome,
            Ok(kind) => {
                let listed = match kind {
                    ForgeKind::Gitlab => listers::list_gitlab(&mut run).await,
                    ForgeKind::Github => listers::list_github(&mut run).await,
                };
                match listed {
                    Ok(()) => Outcome {
                        state: DiscoveryState::Completed,
                        reason: None,
                        detail: None,
                        rate_limit_reset_at: None,
                    },
                    Err(ListError::LeaseLost) => {
                        tracing::info!(
                            "Forge discovery {id} is no longer this instance's ({owner}); left to its new owner."
                        );
                        return;
                    }
                    Err(failure) => self.outcome_of(id, failure),
                }
            }
        };
        let blocked =
            matches!(outcome.reason, Some(DiscoveryReason::CrossOriginPage | DiscoveryReason::DestinationBlocked));
        if run.finish(&outcome).await && blocked {
            let actor =
                RequestActor { username: Some(entity.requested_by.clone()), ip_address: None, user_agent: None };
            self.audit
                .record(actor.entry(
                    AuditOperation::ForgeConnectionRefused,
                    &entity.connection_id,
                    &format!(
                        "Forge discovery {id} stopped ({}, {}): {}",
                        outcome.reason.map_or("", DiscoveryReason::wire_name),
                        run.where_(),
                        outcome.detail.as_deref().unwrap_or("null")
                    ),
                ))
                .await;
        }
    }

    fn outcome_of(&self, id: i64, failure: ListError) -> Outcome {
        match failure {
            ListError::BoundReached(message) => Outcome::of(DiscoveryReason::RepositoryBound, message),
            ListError::Pager(PagerError::DeadlineReached(_)) => Outcome::of(
                DiscoveryReason::TimeBound,
                format!(
                    "The discovery reached its bound of {} minutes; what it listed is kept, nothing is marked gone.",
                    self.bounds.max_duration.as_secs() / 60
                ),
            ),
            ListError::Pager(PagerError::RateLimited { message, lifts_at }) => Outcome {
                state: DiscoveryState::Partial,
                reason: Some(DiscoveryReason::RateLimited),
                detail: Some(format!(
                    "{message} What was listed is kept; run the discovery again once the limit lifts."
                )),
                rate_limit_reset_at: Some(lifts_at),
            },
            ListError::Pager(PagerError::CrossOrigin(message)) => {
                Outcome::of(DiscoveryReason::CrossOriginPage, message)
            }
            ListError::Pager(PagerError::Unsafe(message)) => Outcome::of(DiscoveryReason::DestinationBlocked, message),
            ListError::Pager(PagerError::Failure(message)) => Outcome::of(DiscoveryReason::ForgeUnavailable, message),
            ListError::Refused(reason, message) => Outcome::of(reason, message),
            ListError::Pager(PagerError::Stopped(_)) | ListError::LeaseLost => Outcome::of(
                DiscoveryReason::InternalError,
                "The discovery stopped on an error this version did not foresee; the control plane's log has it.",
            ),
            ListError::Store(failure) => {
                tracing::error!("Forge discovery {id} failed unexpectedly: {failure}");
                Outcome::of(
                    DiscoveryReason::InternalError,
                    "The discovery stopped on an error this version did not foresee; the control plane's log has it.",
                )
            }
        }
    }

    async fn read_run(&self, id: i64) -> Result<Option<persistence::DiscoveryRow>, StoreError> {
        let mut tx = persistence::read(&self.db).await?;
        let run = persistence::discovery(&mut tx, id).await?;
        tx.commit().await?;
        Ok(run)
    }

    async fn give_back(&self, id: i64, owner: &str) -> u64 {
        let given = async {
            let mut tx = persistence::write(&self.db).await?;
            let given = persistence::give_back(&mut tx, id, RUNNING, PENDING, owner).await?;
            tx.commit().await?;
            Ok::<_, StoreError>(given)
        };
        given.await.unwrap_or(0)
    }
}

/// What the run counted so far.
#[derive(Debug, Default)]
struct Counts {
    namespaces: BTreeSet<String>,
    listed: BTreeSet<String>,
    skipped: i32,
}

/// The part of a run its pagers' heartbeat reaches.
struct Shared {
    db: Db,
    id: i64,
    owner: String,
    clock: Arc<dyn Clock>,
    renewed: Mutex<OffsetDateTime>,
    counts: Mutex<Counts>,
    counters: Arc<PagerCounters>,
}

impl Shared {
    fn progress(&self) -> Progress {
        let counts = self.counts.lock().unwrap_or_else(std::sync::PoisonError::into_inner);
        Progress {
            namespaces: i32::try_from(counts.namespaces.len()).unwrap_or(i32::MAX),
            repositories: i32::try_from(counts.listed.len()).unwrap_or(i32::MAX),
            skipped: counts.skipped,
            requests: i32::try_from(self.counters.requests()).unwrap_or(i32::MAX),
            waited: self.counters.waited_seconds(),
        }
    }

    /// The lease renewed and the progress written, in `tx`; `Err` when the run is no longer this instance's.
    async fn renew_in(&self, tx: &mut Tx) -> Result<(), ListError> {
        let now = self.clock.now();
        let renewed = persistence::renew(tx, self.id, RUNNING, &self.owner, now + LEASE, self.progress())
            .await
            .map_err(|failure| ListError::Store(failure.to_string()))?;
        if renewed != 1 {
            return Err(ListError::LeaseLost);
        }
        *self.renewed.lock().unwrap_or_else(std::sync::PoisonError::into_inner) = now;
        Ok(())
    }
}

impl Heartbeat for Shared {
    /// Before every request: the lease renewed when [`RENEWAL`] has passed.
    fn beat(&self) -> std::pin::Pin<Box<dyn std::future::Future<Output = Result<(), String>> + Send + '_>> {
        Box::pin(async move {
            let last = *self.renewed.lock().unwrap_or_else(std::sync::PoisonError::into_inner);
            if self.clock.now() - last < RENEWAL {
                return Ok(());
            }
            let mut tx = persistence::write(&self.db).await.map_err(|failure| failure.to_string())?;
            match self.renew_in(&mut tx).await {
                Ok(()) => tx.commit().await.map_err(|failure| failure.to_string()),
                Err(_) => Err("The discovery's lease is no longer held.".to_owned()),
            }
        })
    }
}

/// One run's state while it lists.
struct Run<'a> {
    execution: &'a DiscoveryExecution,
    shared: Arc<Shared>,
    connection_id: String,
    target: Option<ForgeTarget>,
    token: String,
    deadline: Instant,
    languages: Vec<String>,
    /// By lower-case path: GitHub's logins are case-insensitive.
    unreadable: Vec<(String, UnreadableNamespace)>,
    withheld: Vec<UnreadableNamespace>,
}

impl Run<'_> {
    async fn open(&mut self) -> Result<ForgeKind, Opened> {
        let execution = self.execution;
        let connection = {
            let read = async {
                let mut tx = persistence::read(&execution.db).await?;
                let row = persistence::connection(&mut tx, &self.connection_id).await?;
                tx.commit().await?;
                Ok::<_, StoreError>(row)
            };
            match read.await {
                Ok(Some(row)) => row,
                Ok(None) => return Err(Opened::Lost),
                Err(failure) => return Err(Opened::Ended(internal(&failure.to_string()))),
            }
        };
        let kind = ForgeKind::parse(Some(&connection.kind)).map_err(|refused| Opened::Ended(internal(&refused.0)))?;
        // Before the token is decrypted: a disabled forge is handed nothing (decision 0040 §1).
        match execution.integrations.enabled(kind).await {
            Ok(true) => {}
            Ok(false) => return Err(Opened::Suspended(kind)),
            Err(failure) => return Err(Opened::Ended(internal(&failure.to_string()))),
        }
        let now = execution.clock.now();
        let trust = targets::stored_ca(&connection, instant(now)).map_err(|unusable| {
            Opened::Ended(Outcome::of(
                DiscoveryReason::ConnectionUnusable,
                format!("{} Replace the CA on the connection.", unusable.0),
            ))
        })?;
        let sealed =
            execution.encryption.inspect(&connection.token, &forge_connection_context(&self.connection_id)).await;
        if sealed.state() == SecretState::Unreadable {
            return Err(Opened::Ended(Outcome::of(
                DiscoveryReason::ConnectionUnusable,
                "The connection's token can no longer be decrypted by any configured key: replace it on the \
                 connection.",
            )));
        }
        self.token = sealed.plain_text().to_owned();
        self.target = Some(
            targets::of(&connection, connection.internal_network, trust)
                .map_err(|refused| Opened::Ended(internal(&refused.0)))?,
        );
        self.deadline = instant(now).plus(execution.bounds.max_duration).unwrap_or(instant(now));
        Ok(kind)
    }

    fn where_(&self) -> String {
        self.target.as_ref().map_or_else(|| format!("connection {}", self.connection_id), ForgeTarget::where_)
    }

    fn recorded(&self) -> Vec<UnreadableNamespace> {
        self.unreadable.iter().map(|(_, namespace)| namespace.clone()).chain(self.withheld.iter().cloned()).collect()
    }

    /// The outcome's sentence; for a run that otherwise completed, what it could not read.
    fn detail(&self, outcome: &Outcome) -> Option<String> {
        if outcome.detail.is_some() {
            return outcome.detail.clone();
        }
        let all = self.recorded();
        if all.is_empty() {
            return None;
        }
        Some(format!(
            "{} {} could not be read with this token, and none of their repositories is marked gone: {}",
            all.len(),
            if all.len() == 1 { "namespace" } else { "namespaces" },
            all.iter()
                .map(|namespace| match &namespace.path {
                    None => namespace.reason.clone(),
                    Some(path) => format!("{path} — {}", namespace.reason),
                })
                .collect::<Vec<_>>()
                .join("; ")
        ))
    }

    /// Marks gone what this completed run did not list: everything but what lay in a namespace it could not read;
    /// only within the namespaces it read when the forge withheld some unnamed. How many.
    async fn mark_gone(&self, tx: &mut Tx, now: OffsetDateTime) -> Result<i64, StoreError> {
        let id = self.shared.id;
        if !self.withheld.is_empty() {
            let namespaces =
                self.shared.counts.lock().unwrap_or_else(std::sync::PoisonError::into_inner).namespaces.clone();
            let refused: BTreeSet<&str> = self.unreadable.iter().map(|(key, _)| key.as_str()).collect();
            let read: Vec<String> = namespaces
                .iter()
                .map(|path| vectispire_domain::java::to_lower_root(path))
                .filter(|path| !refused.contains(path.as_str()))
                .collect::<BTreeSet<_>>()
                .into_iter()
                .collect();
            let mut gone = 0;
            for batch in read.chunks(NAMESPACE_BATCH) {
                gone += persistence::mark_gone(tx, &self.connection_id, id, now, Some(batch)).await?;
            }
            return Ok(i64::try_from(gone).unwrap_or(i64::MAX));
        }
        let mut gone =
            i64::try_from(persistence::mark_gone(tx, &self.connection_id, id, now, None).await?).unwrap_or(0);
        let refused: Vec<String> = self.unreadable.iter().map(|(key, _)| key.clone()).collect();
        for batch in refused.chunks(NAMESPACE_BATCH) {
            gone -= i64::try_from(persistence::unmark_gone(tx, &self.connection_id, id, batch).await?).unwrap_or(0);
        }
        Ok(gone)
    }

    /// Ends the run, with the comparison; rolled back whole when the run is no longer this instance's.
    async fn finish(&self, outcome: &Outcome) -> bool {
        let now = self.execution.clock.now();
        let ended = async {
            let mut tx = persistence::write(&self.execution.db).await?;
            let gone = if outcome.state == DiscoveryState::Completed {
                Some(i32::try_from(self.mark_gone(&mut tx, now).await?).unwrap_or(i32::MAX))
            } else {
                None
            };
            let id = self.shared.id;
            let new_count =
                persistence::count_seen(&mut tx, &self.connection_id, persistence::SeenBy::First, id).await?;
            let changed =
                persistence::count_seen(&mut tx, &self.connection_id, persistence::SeenBy::Changed, id).await?;
            let detail = self.detail(outcome);
            let ending = Ending {
                state: outcome.state.wire_name().to_owned(),
                reason: outcome.reason.map(|reason| reason.wire_name().to_owned()),
                detail: detail.as_deref().and_then(|detail| bounded_text::clip(Some(detail), 2000)).map(str::to_owned),
                finished_at: now,
                progress: self.shared.progress(),
                reset_at: outcome.rate_limit_reset_at.and_then(stored),
                new_count: Some(i32::try_from(new_count).unwrap_or(i32::MAX)),
                changed_count: Some(i32::try_from(changed).unwrap_or(i32::MAX)),
                gone_count: gone,
                unreadable: UnreadableNamespace::encode(&self.recorded()),
            };
            if persistence::finish(&mut tx, id, RUNNING, &self.shared.owner, &ending).await? != 1 {
                tx.rollback().await?;
                return Ok::<_, StoreError>(false);
            }
            tx.commit().await?;
            Ok(true)
        };
        match ended.await {
            Ok(true) => {
                let progress = self.shared.progress();
                tracing::info!(
                    "Forge discovery {} {}{}: {} namespaces, {} repositories, {} requests.",
                    self.shared.id,
                    outcome.state.wire_name(),
                    outcome.reason.map(|reason| format!(" ({})", reason.wire_name())).unwrap_or_default(),
                    progress.namespaces,
                    progress.repositories,
                    progress.requests
                );
                true
            }
            Ok(false) => false,
            Err(failure) => {
                tracing::error!("Forge discovery {} could not be ended: {failure}", self.shared.id);
                false
            }
        }
    }

    /// The page's repositories into the snapshot, each compared with what the snapshot knew.
    async fn write(&mut self, tx: &mut Tx, page: Vec<DiscoveredRepository>) -> Result<(), StoreError> {
        let id = self.shared.id;
        let mut storable = Vec::new();
        for repository in page {
            match repository.unstorable() {
                Some(why) => {
                    self.shared.counts.lock().unwrap_or_else(std::sync::PoisonError::into_inner).skipped += 1;
                    tracing::warn!(
                        "Forge discovery {id}: repository {} not kept — {why}.",
                        bounded_text::clip(Some(&repository.forge_id), 64).unwrap_or_default()
                    );
                }
                None => storable.push(repository.bounded()),
            }
        }
        if storable.is_empty() {
            return Ok(());
        }
        let ids: Vec<String> = storable.iter().map(|repository| repository.forge_id.clone()).collect();
        let known: HashMap<String, RepositoryRow> = persistence::snapshot_rows(tx, &self.connection_id, &ids)
            .await?
            .into_iter()
            .map(|row| (row.forge_id.clone(), row))
            .collect();
        let now = self.execution.clock.now();
        let mut rows = Vec::with_capacity(storable.len());
        for repository in storable {
            let mut row = match known.get(&repository.forge_id) {
                None => {
                    self.wants_language(&repository.forge_id);
                    RepositoryRow {
                        id: 0,
                        connection_id: self.connection_id.clone(),
                        forge_id: repository.forge_id.clone(),
                        full_path: String::new(),
                        namespace_path: String::new(),
                        personal: false,
                        name: String::new(),
                        default_branch: None,
                        archived: None,
                        fork: None,
                        visibility: None,
                        last_activity_at: None,
                        language: None,
                        size_bytes: None,
                        http_url: None,
                        ssh_url: None,
                        web_url: None,
                        first_seen_by: id,
                        first_seen_at: now,
                        last_seen_by: id,
                        last_seen_at: now,
                        changed_by: None,
                        change_summary: None,
                        gone_by: None,
                        gone_at: None,
                    }
                }
                Some(existing) => {
                    let mut row = existing.clone();
                    // Compared with the previous run's reading — not with this run's own, which a resumed attempt
                    // already wrote: its changes were counted then.
                    let earlier_run = row.last_seen_by != id && row.first_seen_by != id;
                    if earlier_run {
                        let changes = repository.changes_since(
                            Some(&row.full_path),
                            row.default_branch.as_deref(),
                            row.archived,
                            row.gone_by.is_some(),
                        );
                        if !changes.is_empty() {
                            row.changed_by = Some(id);
                            let summary = changes.join("; ");
                            row.change_summary = bounded_text::clip(Some(&summary), 1500).map(str::to_owned);
                        }
                    }
                    if row.last_activity_at.map(instant) != repository.last_activity_at
                        || (row.last_seen_by == id && row.language.is_none())
                    {
                        self.wants_language(&repository.forge_id);
                    }
                    row
                }
            };
            self.shared
                .counts
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner)
                .listed
                .insert(repository.forge_id.clone());
            apply(&mut row, &repository);
            row.last_seen_by = id;
            row.last_seen_at = now;
            row.gone_by = None;
            row.gone_at = None;
            rows.push(row);
        }
        persistence::save_snapshot_rows(tx, &rows).await
    }

    fn wants_language(&mut self, forge_id: &str) {
        if !self.languages.iter().any(|known| known == forge_id) {
            self.languages.push(forge_id.to_owned());
        }
    }
}

/// The listing's facts onto the row; the language only when the listing carries one.
fn apply(row: &mut RepositoryRow, repository: &DiscoveredRepository) {
    if repository.language.is_some() {
        row.language.clone_from(&repository.language);
    }
    row.full_path.clone_from(&repository.full_path);
    row.namespace_path.clone_from(&repository.namespace_path);
    row.personal = repository.personal;
    row.name.clone_from(&repository.name);
    row.default_branch.clone_from(&repository.default_branch);
    row.archived = repository.archived;
    row.fork = repository.fork;
    row.visibility = repository.visibility.as_deref().map(vectispire_domain::java::to_lower_root);
    row.last_activity_at = repository.last_activity_at.and_then(stored);
    row.size_bytes = repository.size_bytes;
    row.http_url.clone_from(&repository.http_url);
    row.ssh_url.clone_from(&repository.ssh_url);
    row.web_url.clone_from(&repository.web_url);
}

fn internal(failure: &str) -> Outcome {
    tracing::error!("A forge discovery failed unexpectedly: {failure}");
    Outcome::of(
        DiscoveryReason::InternalError,
        "The discovery stopped on an error this version did not foresee; the control plane's log has it.",
    )
}

impl Listing for Run<'_> {
    fn api_root(&self) -> &str {
        self.target.as_ref().map_or("", |target| target.address.api_root.as_str())
    }

    fn owner(&self) -> Option<&str> {
        self.target.as_ref().and_then(|target| target.owner.as_deref())
    }

    fn token(&self) -> &str {
        &self.token
    }

    fn pager(&mut self, credential: Vec<(String, String)>) -> Result<OutboundPager, ListError> {
        let target = self.target.as_ref().ok_or(ListError::LeaseLost)?;
        let settings = Settings {
            origin: target.address.api_root.clone(),
            policy: target.policy,
            label: target.where_(),
            credential,
            trust: target.sending().cloned(),
            deadline: self.deadline,
            max_wait: self.execution.bounds.max_rate_limit_wait,
            timeout: TIMEOUT,
            heartbeat: Some(self.shared.clone()),
            counters: self.shared.counters.clone(),
        };
        self.execution.outbound.pager(settings, self.execution.pager_clock.clone()).map_err(ListError::Store)
    }

    fn namespace(&mut self, path: &str) {
        self.shared.counts.lock().unwrap_or_else(std::sync::PoisonError::into_inner).namespaces.insert(path.to_owned());
    }

    fn unreadable(&mut self, path: &str, reason: &str) {
        self.namespace(path);
        let key = vectispire_domain::java::to_lower_root(path);
        if !self.unreadable.iter().any(|(known, _)| *known == key) {
            self.unreadable.push((key, UnreadableNamespace::new(Some(path), Some(reason))));
        }
    }

    fn namespaces_incomplete(&mut self, reason: &str) {
        self.withheld.push(UnreadableNamespace::new(None, Some(reason)));
    }

    async fn repositories(&mut self, page: Vec<DiscoveredRepository>) -> Result<(), ListError> {
        // One forge id once per run, should a page repeat one.
        let listed = self.shared.counts.lock().unwrap_or_else(std::sync::PoisonError::into_inner).listed.clone();
        let mut fresh: Vec<DiscoveredRepository> = Vec::new();
        for repository in page {
            if !listed.contains(&repository.forge_id)
                && !fresh.iter().any(|known| known.forge_id == repository.forge_id)
            {
                fresh.push(repository);
            }
        }
        let room = self.execution.bounds.max_repositories.saturating_sub(listed.len());
        let over = fresh.len() > room;
        let kept: Vec<DiscoveredRepository> = fresh.into_iter().take(room).collect();
        let shared = self.shared.clone();
        let mut tx =
            persistence::write(&self.execution.db).await.map_err(|failure| ListError::Store(failure.to_string()))?;
        shared.renew_in(&mut tx).await?;
        self.write(&mut tx, kept).await.map_err(|failure| ListError::Store(failure.to_string()))?;
        tx.commit().await.map_err(|failure| ListError::Store(failure.to_string()))?;
        if over {
            return Err(ListError::BoundReached(format!(
                "The discovery stopped at {} repositories, its bound; the rest were not listed, and nothing is marked \
                 gone.",
                self.execution.bounds.max_repositories
            )));
        }
        Ok(())
    }

    fn languages_wanted(&self) -> Vec<String> {
        self.languages.clone()
    }

    async fn language(&mut self, forge_id: &str, language: Option<String>) -> Result<(), ListError> {
        let value = language.filter(|language| {
            !vectispire_domain::java::is_blank(language)
                && vectispire_domain::java::utf16_len(language) <= DiscoveredRepository::LANGUAGE_LENGTH
        });
        let store = async {
            let mut tx = persistence::write(&self.execution.db).await?;
            persistence::set_language(&mut tx, &self.connection_id, forge_id, value.as_deref()).await?;
            tx.commit().await?;
            Ok::<_, StoreError>(())
        };
        store.await.map_err(|failure| ListError::Store(failure.to_string()))
    }
}

/// The worker: a bounded pool claiming waiting discoveries and carrying each out, on every control-plane instance.
#[derive(Clone)]
pub struct DiscoveryWorker {
    owner: String,
    queue: DiscoveryQueue,
    execution: DiscoveryExecution,
    integrations: ForgeIntegrations,
    concurrency: usize,
    in_flight: Arc<AtomicUsize>,
    ticking: Arc<AtomicBool>,
    held: Arc<Mutex<String>>,
}

impl std::fmt::Debug for DiscoveryWorker {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.debug_struct("DiscoveryWorker").field("owner", &self.owner).finish_non_exhaustive()
    }
}

impl DiscoveryWorker {
    pub(crate) fn new(
        queue: DiscoveryQueue,
        execution: DiscoveryExecution,
        integrations: ForgeIntegrations,
        concurrency: usize,
        host: &str,
    ) -> DiscoveryWorker {
        let suffix = uuid::Uuid::new_v4().as_hyphenated().to_string();
        let host = bounded_text::clip(Some(host), 80).unwrap_or_default();
        DiscoveryWorker {
            owner: format!("{host}/discovery-{}", &suffix[..8]),
            queue,
            execution,
            integrations,
            concurrency: concurrency.max(1),
            in_flight: Arc::new(AtomicUsize::new(0)),
            ticking: Arc::new(AtomicBool::new(false)),
            held: Arc::new(Mutex::new(String::new())),
        }
    }

    /// What this instance calls itself in `claimed_by`.
    pub fn identity(&self) -> &str {
        &self.owner
    }

    /// Recovers the lapsed runs, then claims what the pool has room for and hands each over; returns at once.
    pub async fn tick(&self) {
        if self.ticking.swap(true, Ordering::SeqCst) {
            return;
        }
        if let Err(failure) = self.turn().await {
            tracing::error!("The discovery turn failed: {failure}");
        }
        self.ticking.store(false, Ordering::SeqCst);
    }

    async fn turn(&self) -> Result<(), String> {
        self.queue.recover_lapsed().await?;
        self.report_held().await;
        while self.in_flight.load(Ordering::SeqCst) < self.concurrency {
            let Some(id) = self.queue.claim(&self.owner).await? else {
                break;
            };
            self.in_flight.fetch_add(1, Ordering::SeqCst);
            let (execution, owner, in_flight) = (self.execution.clone(), self.owner.clone(), self.in_flight.clone());
            tokio::spawn(async move {
                execution.execute(id, &owner).await;
                in_flight.fetch_sub(1, Ordering::SeqCst);
            });
        }
        Ok(())
    }

    /// The turn run to the end of the queue on the calling task — what a test observes deterministically.
    pub async fn drain(&self) -> Result<usize, String> {
        self.queue.recover_lapsed().await?;
        self.report_held().await;
        let mut carried = 0;
        while let Some(id) = self.queue.claim(&self.owner).await? {
            self.execution.execute(id, &self.owner).await;
            carried += 1;
        }
        Ok(carried)
    }

    /// Logs the runs left waiting on disabled forges, when that has changed since the last turn.
    async fn report_held(&self) {
        let Ok(disabled) = self.integrations.disabled().await else {
            return;
        };
        let waiting = self.queue.waiting_on(&disabled).await.unwrap_or(0);
        let now = if waiting == 0 { String::new() } else { format!("{waiting} on {}", integrations::keys(&disabled)) };
        let previous =
            std::mem::replace(&mut *self.held.lock().unwrap_or_else(std::sync::PoisonError::into_inner), now.clone());
        if previous != now && waiting > 0 {
            tracing::info!(
                "Forge discoveries: {waiting} waiting run(s) left waiting, the {} integration(s) disabled; their \
                 connections are suspended, and the runs resume when a governor re-enables them.",
                integrations::keys(&disabled)
            );
        }
    }
}

/// The pager's clock: the control plane's, and tokio's sleep.
#[derive(Debug, Clone)]
pub(crate) struct ClockForPager(pub Arc<dyn Clock>);

impl PagerClock for ClockForPager {
    fn now(&self) -> Instant {
        instant(self.0.now())
    }

    fn sleep(&self, duration: Duration) -> std::pin::Pin<Box<dyn std::future::Future<Output = ()> + Send + '_>> {
        Box::pin(tokio::time::sleep(duration))
    }
}
