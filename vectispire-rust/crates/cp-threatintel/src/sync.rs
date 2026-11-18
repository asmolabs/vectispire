//! `ThreatIntelFeedService`'s synchronisations: the CISA KEV catalogue written here, FIRST's EPSS file by
//! [`EpssFeed`], which this calls and audits — and the backlog re-evaluated against the catalogue.
//!
//! **The catalogue is a replacement, not a delta.** A CVE it does not list is not exploited as far as this feed knows,
//! and an open issue flagged exploited is un-flagged when its CVE leaves it. That is why only a whole catalogue is
//! applied ([`KevCatalog`]), and why one older than the catalogue in use is refused.
//!
//! **No transaction is open while a feed is fetched**, and **the one way in**: both routes and the schedule come
//! through [`ThreatIntelFeedService::sync_threat_intel`], [`ThreatIntelFeedService::sync_if_due`] and
//! [`ThreatIntelFeedService::sync_epss_if_due`], each audited once what it describes has committed — one entry per
//! feed, since they are fetched from different places and fail for different reasons. A failed attempt is audited as
//! one: the outbound call was made either way.

use std::collections::{HashMap, HashSet};
use std::sync::Arc;

use time::{Duration, OffsetDateTime};
use vectispire_cp_audit::{AuditLog, AuditOperation, RequestActor};
use vectispire_cp_db::{Db, Tx};
use vectispire_cp_issues::IssueCatalog;
use vectispire_cp_issues::catalog::Exploitation;
use vectispire_cp_outbox::SecurityEvents;
use vectispire_cp_targets::Clock;
use vectispire_domain::java;
use vectispire_domain::siem::{CefEvent, SecurityEventType};

use crate::epss_feed::{Attempt, EpssFeed, Outcome, closed, truncate};
use crate::feeds::{EpssFeedStatus, FeedError, SyncStatus};
use crate::kev_catalog::KevCatalog;
use crate::persistence::repository::{IntelRepository, SyncRepository};
use crate::persistence::{self, FeedRow, Listing, SINGLETON_ID, SyncRow};
use crate::sources::KevSource;
use crate::status::State;
use crate::time_text::{java_string, of_instant, shifted, to_instant};

/// How old the catalogue in use may get before the schedule reads it again: six hours bounds how late a newly listed
/// CVE is announced to the SIEM, for four downloads of a megabyte and a half a day.
pub const REFRESH_AFTER: Duration = Duration::hours(6);

/// How long after a failed attempt the schedule tries again: under the hourly turn, so that its drift never makes it
/// skip one; above zero, so several instances ask once between them rather than once each.
pub const RETRY_AFTER: Duration = Duration::minutes(30);

/// Open issues re-evaluated per transaction.
pub const BACKLOG_PAGE: u64 = 500;

/// The audit entries' resource.
const RESOURCE: &str = "threat_intel";

/// Where a synchronisation was asked from, as its audit entry says.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Origin {
    ThreatIntelligenceScreen,
    EpssScreen,
    Schedule,
}

impl Origin {
    fn phrase(self) -> &'static str {
        match self {
            Origin::ThreatIntelligenceScreen => "the threat intelligence screen",
            Origin::EpssScreen => "the EPSS screen",
            Origin::Schedule => "the maintenance schedule",
        }
    }
}

/// The actor of a synchronisation nobody asked for, as the audit log names it.
fn schedule() -> RequestActor {
    RequestActor { username: Some("system".to_owned()), ip_address: None, user_agent: None }
}

/// The synchronisations.
#[derive(Clone)]
pub struct ThreatIntelFeedService {
    db: Db,
    events: Arc<dyn SecurityEvents>,
    audit: Arc<AuditLog>,
    catalogue: Arc<dyn KevSource>,
    epss: EpssFeed,
    clock: Arc<dyn Clock>,
}

impl std::fmt::Debug for ThreatIntelFeedService {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("ThreatIntelFeedService")
            .field("catalogue", &self.catalogue.location())
            .field("epss", &self.epss)
            .finish_non_exhaustive()
    }
}

/// A page's outcome: the rows read, the last id, the flags changed.
struct Page {
    read: u64,
    last: i64,
    updated: u64,
}

impl ThreatIntelFeedService {
    pub fn new(
        db: Db,
        events: Arc<dyn SecurityEvents>,
        audit: Arc<AuditLog>,
        catalogue: Arc<dyn KevSource>,
        epss: EpssFeed,
        clock: Arc<dyn Clock>,
    ) -> ThreatIntelFeedService {
        ThreatIntelFeedService { db, events, audit, catalogue, epss, clock }
    }

    /// `syncThreatIntel`: the catalogue, then the EPSS file, each audited once it has committed.
    pub async fn sync_threat_intel(&self, actor: &RequestActor, origin: Origin) -> Result<SyncStatus, FeedError> {
        let kev = self.synchronize().await?;
        self.audit.record(actor.entry(AuditOperation::ThreatIntelSynced, RESOURCE, &describe_kev(&kev, origin))).await;
        let scored = self.epss.sync().await?;
        self.audit
            .record(actor.entry(AuditOperation::ThreatIntelSynced, RESOURCE, &describe_epss(&scored, origin)))
            .await;
        Ok(SyncStatus { epss: scored.status, ..kev })
    }

    /// `syncIfDue`: the scheduled catalogue synchronisation, when one is due and this instance won it. Called every
    /// hourly turn on every instance; the claim decides whether anything happens.
    pub async fn sync_if_due(&self) -> Result<Option<SyncStatus>, FeedError> {
        let now = self.clock.now();
        let mut tx = persistence::write(&self.db).await?;
        let claimed = SyncRepository::claim_scheduled(
            &mut tx,
            SINGLETON_ID,
            now,
            shifted(now, -REFRESH_AFTER),
            shifted(now, -RETRY_AFTER),
        )
        .await?
            > 0;
        let exists = SyncRepository::find(&mut tx, SINGLETON_ID).await?.is_some();
        persistence::commit(tx).await?;
        if !claimed && exists {
            return Ok(None);
        }
        let kev = self.synchronize().await?;
        self.audit
            .record(schedule().entry(
                AuditOperation::ThreatIntelSynced,
                RESOURCE,
                &describe_kev(&kev, Origin::Schedule),
            ))
            .await;
        Ok(Some(SyncStatus { epss: self.epss.status().await?, ..kev }))
    }

    /// `syncEpssIfDue`: the scheduled EPSS synchronisation — daily, where the catalogue's is every six hours: FIRST
    /// publishes once a day. Audited as a lead's is.
    pub async fn sync_epss_if_due(&self) -> Result<Option<SyncStatus>, FeedError> {
        let Some(scored) = self.epss.sync_if_due().await? else {
            return Ok(None);
        };
        self.audit
            .record(schedule().entry(
                AuditOperation::ThreatIntelSynced,
                RESOURCE,
                &describe_epss(&scored, Origin::Schedule),
            ))
            .await;
        let kev = self.kev_status().await?;
        Ok(Some(SyncStatus { epss: scored.status, ..kev }))
    }

    async fn kev_status(&self) -> Result<SyncStatus, FeedError> {
        let mut tx = persistence::read(&self.db).await?;
        let row = SyncRepository::find(&mut tx, SINGLETON_ID).await?;
        persistence::commit(tx).await?;
        Ok(row.as_ref().map_or_else(SyncStatus::never, SyncStatus::kev_of))
    }

    /// `synchronize`: the fetch, outside any transaction; the catalogue written in one; then the backlog, a page per
    /// transaction. **Applied once stored**: a page that fails is logged, and the next synchronisation walks the whole
    /// backlog again — the flags are compared, not toggled, so a page applied twice changes nothing.
    async fn synchronize(&self) -> Result<SyncStatus, FeedError> {
        let attempted = self.clock.now();
        let read = match self.catalogue.fetch().await {
            Ok(read) => read,
            Err(failure) => {
                // The catalogue in use stays: an outage is not a catalogue that lists nothing. What changes is the
                // status, so a stale flag is visible as stale rather than trusted.
                let reason = truncate(&failure);
                tracing::warn!("KEV catalogue not synchronised from {}: {reason}", self.catalogue.location());
                let mut tx = persistence::write(&self.db).await?;
                let held = hold_sync_row(&mut tx, attempted).await?;
                let status = record_failure(&mut tx, held, reason).await?;
                persistence::commit(tx).await?;
                return Ok(status);
            }
        };
        let mut tx = persistence::write(&self.db).await?;
        let stored = self.apply(&mut tx, &read, attempted).await?;
        persistence::commit(tx).await?;
        if stored.status != State::Synced {
            return Ok(stored);
        }
        let updated = match self.reevaluate().await {
            Ok(updated) => updated,
            Err(failure) => {
                tracing::warn!(
                    "KEV catalogue applied, but the open issues were not all re-evaluated: {}",
                    truncate(&failure.to_string())
                );
                0
            }
        };
        Ok(SyncStatus { backlog_updated_count: i64::try_from(updated).unwrap_or(i64::MAX), ..stored })
    }

    /// `apply`: within the transaction `synchronize` opens — the catalogue stored, and the sync row.
    async fn apply(&self, tx: &mut Tx, read: &KevCatalog, attempted: OffsetDateTime) -> Result<SyncStatus, FeedError> {
        let mut sync = hold_sync_row(tx, attempted).await?;
        let released = read.released.and_then(of_instant);

        // **A catalogue older than the one in use is refused.** A mirror restored from last month's copy would
        // otherwise un-flag every CVE listed since, on the word of a document CISA itself has replaced.
        if let (Some(read_released), Some(in_use)) = (released, sync.kev_released_at)
            && read_released < in_use
        {
            let reason = truncate(&format!(
                "the catalogue read (released {}) is older than the one in use (released {}); kept the newer",
                java_string(read_released),
                java_string(in_use)
            ));
            return record_failure(tx, sync, reason).await;
        }

        let now = self.clock.now();
        // `toMap(upper-case id, …, (a, b) -> a)`: the first row stored under an id wins.
        let mut stored: HashMap<String, FeedRow> = HashMap::new();
        for row in IntelRepository::all(tx).await? {
            stored.entry(java::to_upper_root(&row.cve_id)).or_insert(row);
        }
        let listed_ids: HashSet<&str> = read.added.iter().map(|(cve, _)| cve.as_str()).collect();
        let mut changed: Vec<FeedRow> = Vec::new();
        // New entries many to a statement: one by one they were 3,000 round trips for the first synchronisation.
        let mut listed: Vec<Listing> = Vec::new();
        for (cve, added) in &read.added {
            let added = added.and_then(of_instant);
            match stored.get_mut(cve) {
                None => {
                    listed.push(Listing { cve_id: cve.clone(), date_added: added });
                    stored.insert(
                        cve.clone(),
                        FeedRow { cve_id: cve.clone(), is_kev: true, date_added: added, updated_at: now },
                    );
                }
                Some(row) if row.is_kev && row.date_added == added => {}
                Some(row) => {
                    row.is_kev = true;
                    row.date_added = added;
                    row.updated_at = now;
                    changed.push(row.clone());
                }
            }
        }
        // Delisted: kept as a row, no longer as exploited — what the catalogue says today.
        for (cve, row) in &mut stored {
            if row.is_kev && !listed_ids.contains(cve.as_str()) {
                row.is_kev = false;
                row.updated_at = now;
                changed.push(row.clone());
            }
        }
        IntelRepository::insert_listed(tx, &listed, now).await?;
        for row in &changed {
            IntelRepository::update(tx, row).await?;
        }

        sync.last_synced_at = Some(now);
        sync.cve_count = i64::try_from(stored.len()).unwrap_or(i64::MAX);
        sync.kev_count = i64::try_from(read.added.len()).unwrap_or(i64::MAX);
        sync.status = State::Synced.name().to_owned();
        sync.kev_catalog_version.clone_from(&read.version);
        sync.kev_released_at = released;
        sync.last_error = None;
        SyncRepository::save(tx, &sync).await?;
        Ok(SyncStatus::kev_of(&sync))
    }

    /// `reevaluate`: the open issues' exploitation against the catalogue stored, a page of [`BACKLOG_PAGE`] at a time
    /// in id order — each page its own short transaction, walked by key so each costs the same however deep the walk
    /// is.
    ///
    /// **Announced once.** Each page takes the sync row's lock before it reads its issues, so a second
    /// synchronisation's page reads the flags the first one's committed: a newly listed CVE raises
    /// `CRITICAL_KEV_DETECTED` once per issue, whoever walks the backlog second.
    async fn reevaluate(&self) -> Result<u64, FeedError> {
        let mut after = 0;
        let mut updated: u64 = 0;
        loop {
            let mut tx = persistence::write(&self.db).await?;
            let page = self.reevaluate_page(&mut tx, after).await?;
            persistence::commit(tx).await?;
            updated = updated.saturating_add(page.updated);
            if page.read < BACKLOG_PAGE {
                return Ok(updated);
            }
            after = page.last;
        }
    }

    /// One page, in its own transaction: the lock, the page, the catalogue's word on it, the flags written — and each
    /// promotion's event queued in the same transaction, so a page that rolls back announces nothing.
    async fn reevaluate_page(&self, tx: &mut Tx, after: i64) -> Result<Page, FeedError> {
        SyncRepository::hold_for_reevaluation(tx, SINGLETON_ID).await?;
        let page = IssueCatalog::kev_candidates_after(tx, after, &closed(), BACKLOG_PAGE).await.map_err(boxed)?;
        let Some(last) = page.last().map(|issue| issue.id) else {
            return Ok(Page { read: 0, last: after, updated: 0 });
        };
        let listed = listed_among(tx, page.iter().map(|issue| issue.identifier.as_str())).await?;

        // The figures are this module's decision; the rows are the backlog's (decision 0029).
        let mut updates: Vec<Exploitation> = Vec::new();
        for issue in &page {
            if java::is_blank(&issue.identifier) {
                continue;
            }
            let kev = listed.contains(&java::to_upper_root(java::trim(&issue.identifier)));
            if kev == issue.is_kev {
                continue;
            }
            updates.push(Exploitation { issue_id: issue.id, kev });
            if kev {
                tracing::warn!(
                    "CVE {} newly listed as actively exploited in the CISA KEV catalogue. Notifying SOC/SIEM.",
                    issue.identifier
                );
                let target = target_of(issue.repo_id, issue.container_id);
                let event = CefEvent::builder(SecurityEventType::CriticalKevDetected, to_instant(self.clock.now()))
                    .message(
                        format!(
                            "Vulnerability {} promoted to CISA Known Exploited Vulnerability (KEV)",
                            issue.identifier
                        )
                        .as_str(),
                    )
                    .target(target.as_deref())
                    .identifier(issue.identifier.as_str())
                    .component(issue.package_name.as_deref())
                    .build()
                    .map_err(|refused| FeedError(Box::from(refused.to_string())))?;
                self.events.raise(tx, &event).await.map_err(FeedError)?;
            }
        }
        IssueCatalog::record_exploitation(tx, &updates).await.map_err(boxed)?;
        Ok(Page { read: page.len() as u64, last, updated: updates.len() as u64 })
    }
}

fn boxed(error: impl std::error::Error + Send + Sync + 'static) -> FeedError {
    FeedError(Box::new(error))
}

/// `listedAmong`: those of these identifiers the stored catalogue lists, upper-case — one page's, so one statement.
async fn listed_among<'a>(
    tx: &mut Tx,
    identifiers: impl IntoIterator<Item = &'a str>,
) -> Result<HashSet<String>, FeedError> {
    let mut seen = HashSet::new();
    let wanted: Vec<String> = identifiers
        .into_iter()
        .map(|id| java::to_lower_root(java::trim(id)))
        .filter(|id| !id.is_empty() && seen.insert(id.clone()))
        .collect();
    if wanted.is_empty() {
        return Ok(HashSet::new());
    }
    Ok(IntelRepository::exploited_among(tx, &wanted).await?.iter().map(|id| java::to_upper_root(id)).collect())
}

/// `holdSyncRow`: the singleton row with this attempt marked on it — which also holds its write lock until the
/// transaction ends, so two synchronisations never re-evaluate the backlog at once. Created when missing.
async fn hold_sync_row(tx: &mut Tx, attempted: OffsetDateTime) -> Result<SyncRow, FeedError> {
    if SyncRepository::mark_attempt(tx, SINGLETON_ID, attempted).await? == 0 {
        let fresh = SyncRow { last_attempt_at: Some(attempted), ..SyncRow::fresh() };
        SyncRepository::insert(tx, &fresh).await?;
        return Ok(fresh);
    }
    SyncRepository::find(tx, SINGLETON_ID).await?.ok_or_else(|| FeedError(Box::from("the sync row is missing")))
}

/// `recordFailure`: within the caller's transaction.
async fn record_failure(tx: &mut Tx, mut sync: SyncRow, reason: String) -> Result<SyncStatus, FeedError> {
    sync.status = State::Failed.name().to_owned();
    sync.last_error = Some(reason);
    SyncRepository::save(tx, &sync).await?;
    Ok(SyncStatus::kev_of(&sync))
}

/// The catalogue's audit entry.
fn describe_kev(result: &SyncStatus, origin: Origin) -> String {
    if result.status == State::Synced {
        format!(
            "CISA KEV catalogue synchronized from {} (version {}, KEV={}, updated={})",
            origin.phrase(),
            result.kev_catalog_version.as_deref().unwrap_or("unstated"),
            result.total_kev,
            result.backlog_updated_count
        )
    } else {
        format!(
            "CISA KEV catalogue synchronization from {} failed: {} (catalogue in use kept, KEV={})",
            origin.phrase(),
            result.last_error.as_deref().unwrap_or("null"),
            result.total_kev
        )
    }
}

/// The EPSS feed's entry: what was read, from where, and what it left in use.
fn describe_epss(attempt: &Attempt, origin: Origin) -> String {
    let feed: &EpssFeedStatus = &attempt.status;
    let in_use = match &feed.model_version {
        None => "none".to_owned(),
        Some(model) => format!(
            "model {model}, scores of {}, {} CVE",
            feed.score_date.map_or_else(|| "null".to_owned(), java_string),
            feed.total_scored
        ),
    };
    let phrase = origin.phrase();
    match attempt.outcome {
        Outcome::Applied => {
            format!("EPSS scores synchronized from {phrase} ({in_use}, updated={})", feed.backlog_updated_count)
        }
        Outcome::Unchanged => {
            format!("EPSS scores confirmed from {phrase}: the file read is the one in use ({in_use})")
        }
        Outcome::Failed => format!(
            "EPSS scores synchronization from {phrase} failed: {} (scores in use kept: {in_use})",
            attempt.reason.as_deref().unwrap_or("null")
        ),
        Outcome::Busy => {
            format!(
                "EPSS scores synchronization from {phrase} not run: another one is in progress (scores in use: {in_use})"
            )
        }
    }
}

/// The target a finding belongs to, as the CEF target field names it: `repository 12`, `container 3`.
fn target_of(repo_id: Option<i64>, container_id: Option<i64>) -> Option<String> {
    match (repo_id, container_id) {
        (Some(repo), _) => Some(format!("repository {repo}")),
        (None, Some(container)) => Some(format!("container {container}")),
        (None, None) => None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn kev(status: State, version: Option<&str>, error: Option<&str>) -> SyncStatus {
        SyncStatus {
            status,
            total_kev: 3,
            backlog_updated_count: 2,
            kev_catalog_version: version.map(str::to_owned),
            last_error: error.map(str::to_owned),
            ..SyncStatus::never()
        }
    }

    #[test]
    fn the_catalogues_entry_says_what_was_read_or_why_not() {
        assert_eq!(
            describe_kev(&kev(State::Synced, Some("2026.09.26"), None), Origin::ThreatIntelligenceScreen),
            "CISA KEV catalogue synchronized from the threat intelligence screen (version 2026.09.26, KEV=3, updated=2)"
        );
        assert_eq!(
            describe_kev(&kev(State::Synced, None, None), Origin::Schedule),
            "CISA KEV catalogue synchronized from the maintenance schedule (version unstated, KEV=3, updated=2)"
        );
        assert_eq!(
            describe_kev(&kev(State::Failed, None, Some("unreachable")), Origin::EpssScreen),
            "CISA KEV catalogue synchronization from the EPSS screen failed: unreachable (catalogue in use kept, KEV=3)"
        );
    }

    #[test]
    fn the_files_entry_names_the_file_in_use() {
        let mut status = EpssFeedStatus::never();
        let attempt = |outcome, status: &EpssFeedStatus, reason: Option<&str>| Attempt {
            outcome,
            status: status.clone(),
            reason: reason.map(str::to_owned),
        };
        assert_eq!(
            describe_epss(&attempt(Outcome::Failed, &status, Some("refused")), Origin::EpssScreen),
            "EPSS scores synchronization from the EPSS screen failed: refused (scores in use kept: none)"
        );
        assert_eq!(
            describe_epss(&attempt(Outcome::Busy, &status, None), Origin::Schedule),
            "EPSS scores synchronization from the maintenance schedule not run: another one is in progress (scores \
             in use: none)"
        );
        status.model_version = Some("v2025.03.14".to_owned());
        status.score_date = Some(OffsetDateTime::UNIX_EPOCH);
        status.total_scored = 120_000;
        status.backlog_updated_count = 4;
        assert_eq!(
            describe_epss(&attempt(Outcome::Applied, &status, None), Origin::ThreatIntelligenceScreen),
            "EPSS scores synchronized from the threat intelligence screen (model v2025.03.14, scores of \
             1970-01-01T00:00:00Z, 120000 CVE, updated=4)"
        );
        assert_eq!(
            describe_epss(&attempt(Outcome::Unchanged, &status, None), Origin::EpssScreen),
            "EPSS scores confirmed from the EPSS screen: the file read is the one in use (model v2025.03.14, scores \
             of 1970-01-01T00:00:00Z, 120000 CVE)"
        );
    }

    #[test]
    fn a_finding_names_its_repository_first() {
        assert_eq!(target_of(Some(12), Some(3)).as_deref(), Some("repository 12"));
        assert_eq!(target_of(None, Some(3)).as_deref(), Some("container 3"));
        assert_eq!(target_of(None, None), None);
    }
}
