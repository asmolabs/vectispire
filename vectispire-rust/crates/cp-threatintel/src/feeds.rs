//! What the two stored feeds say, read — Java's `ThreatIntelFeedService.getStatus`, `exploitationOf`, `lookupCve`
//! and `lookupCves`, and `EpssFeed.status`, `scoresOf` and `synchronised`.
//!
//! **Local reads only.** Both feeds are synchronised whole, so asking about a CVE tells no third party which ones
//! somebody here was looking at. And **unknown is said as unknown**: before the catalogue was first read no CVE is
//! "not listed", and before the first EPSS file no score is zero.

use std::collections::{HashMap, HashSet};
use std::sync::Arc;

use time::OffsetDateTime;
use vectispire_cp_db::Db;
use vectispire_cp_targets::Clock;
use vectispire_domain::java;

use crate::persistence::repository::{EpssScoreRepository, IntelRepository, SyncRepository};
use crate::persistence::{self, FeedRow, SINGLETON_ID, StoreError, SyncRow};
use crate::status::{Exploitation, KevListing, State};

pub use crate::persistence::KnownEpssScore;

/// Identifiers per KEV lookup, under every engine's bind-parameter ceiling — `ThreatIntelFeedService.LOOKUP_BATCH`.
pub const KEV_LOOKUP_BATCH: usize = 1_000;

/// Identifiers per EPSS lookup — `EpssFeed.LOOKUP_BATCH`.
pub const EPSS_LOOKUP_BATCH: usize = 500;

/// The feeds' tables did not answer.
#[derive(Debug, thiserror::Error)]
#[error("{0}")]
pub struct FeedError(#[source] pub Box<dyn std::error::Error + Send + Sync>);

impl From<StoreError> for FeedError {
    fn from(error: StoreError) -> FeedError {
        FeedError(Box::new(error))
    }
}

/// `ThreatIntelSyncStatus.EpssFeedStatus`: where FIRST's file stands.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EpssFeedStatus {
    pub status: State,
    pub last_synced_at: Option<OffsetDateTime>,
    pub model_version: Option<String>,
    pub score_date: Option<OffsetDateTime>,
    pub total_scored: i64,
    pub last_attempt_at: Option<OffsetDateTime>,
    pub last_error: Option<String>,
    pub backlog_updated_count: i64,
    /// Whether a synchronisation holds the lease now: a lead's request made meanwhile is not run a second time.
    pub in_progress: bool,
}

impl EpssFeedStatus {
    /// `never()`: nothing read yet.
    pub fn never() -> EpssFeedStatus {
        EpssFeedStatus {
            status: State::NeverSynced,
            last_synced_at: None,
            model_version: None,
            score_date: None,
            total_scored: 0,
            last_attempt_at: None,
            last_error: None,
            backlog_updated_count: 0,
            in_progress: false,
        }
    }

    /// `EpssFeed.status`'s reading of the row: **the count only once a file is in use** — a row whose generation is
    /// none counts nothing, whatever the column holds; in progress while the lease runs.
    fn of(sync: &SyncRow, now: OffsetDateTime) -> EpssFeedStatus {
        EpssFeedStatus {
            status: State::of(Some(&sync.epss_status)),
            last_synced_at: sync.epss_synced_at,
            model_version: sync.epss_model_version.clone(),
            score_date: sync.epss_score_date,
            total_scored: if sync.epss_generation.is_none() { 0 } else { sync.epss_count },
            last_attempt_at: sync.epss_attempt_at,
            last_error: sync.epss_error.clone(),
            backlog_updated_count: 0,
            in_progress: sync.epss_lease_until.is_some_and(|until| until > now),
        }
    }
}

/// `ThreatIntelSyncStatus`: the KEV catalogue at the top level, under the names the wire has always carried, and the
/// EPSS file in a record of its own — fetched, refused and retried apart.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SyncStatus {
    pub last_synced_at: Option<OffsetDateTime>,
    pub total_cves: i64,
    pub total_kev: i64,
    pub status: State,
    pub backlog_updated_count: i64,
    pub kev_catalog_version: Option<String>,
    pub kev_released_at: Option<OffsetDateTime>,
    pub last_attempt_at: Option<OffsetDateTime>,
    pub last_error: Option<String>,
    pub epss: EpssFeedStatus,
}

impl SyncStatus {
    /// `ThreatIntelFeedService.status(sync, 0)`: the catalogue's state, the EPSS one left for the caller.
    pub(crate) fn kev_of(sync: &SyncRow) -> SyncStatus {
        SyncStatus {
            last_synced_at: sync.last_synced_at,
            total_cves: sync.cve_count,
            total_kev: sync.kev_count,
            status: State::of(Some(&sync.status)),
            backlog_updated_count: 0,
            kev_catalog_version: sync.kev_catalog_version.clone(),
            kev_released_at: sync.kev_released_at,
            last_attempt_at: sync.last_attempt_at,
            last_error: sync.last_error.clone(),
            epss: EpssFeedStatus::never(),
        }
    }

    fn never() -> SyncStatus {
        SyncStatus {
            last_synced_at: None,
            total_cves: 0,
            total_kev: 0,
            status: State::NeverSynced,
            backlog_updated_count: 0,
            kev_catalog_version: None,
            kev_released_at: None,
            last_attempt_at: None,
            last_error: None,
            epss: EpssFeedStatus::never(),
        }
    }
}

/// `ThreatIntelRecord`: what the two feeds recorded about one CVE.
#[derive(Debug, Clone, PartialEq)]
pub struct ThreatIntelRecord {
    pub cve_id: String,
    pub is_kev: bool,
    pub epss_score: Option<f64>,
    pub epss_percentile: Option<f64>,
    pub date_added: Option<OffsetDateTime>,
    pub notes: String,
}

/// The two feeds as stored, read.
#[derive(Clone)]
pub struct ThreatIntel {
    db: Db,
    clock: Arc<dyn Clock>,
}

impl std::fmt::Debug for ThreatIntel {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.debug_struct("ThreatIntel").finish_non_exhaustive()
    }
}

impl ThreatIntel {
    pub fn new(db: Db, clock: Arc<dyn Clock>) -> ThreatIntel {
        ThreatIntel { db, clock }
    }

    async fn sync_row(&self) -> Result<Option<SyncRow>, FeedError> {
        let mut tx = persistence::read(&self.db).await?;
        let row = SyncRepository::find(&mut tx, SINGLETON_ID).await?;
        persistence::commit(tx).await?;
        Ok(row)
    }

    /// `getStatus`: both feeds; never synchronised, both, when the row is missing.
    pub async fn status(&self) -> Result<SyncStatus, FeedError> {
        let now = self.clock.now();
        Ok(match self.sync_row().await? {
            Some(sync) => SyncStatus { epss: EpssFeedStatus::of(&sync, now), ..SyncStatus::kev_of(&sync) },
            None => SyncStatus::never(),
        })
    }

    /// `EpssFeed.status`.
    pub async fn epss_status(&self) -> Result<EpssFeedStatus, FeedError> {
        let now = self.clock.now();
        Ok(self.sync_row().await?.map_or_else(EpssFeedStatus::never, |sync| EpssFeedStatus::of(&sync, now)))
    }

    /// `EpssFeed.synchronised`: whether a file has ever been applied.
    pub async fn epss_synchronised(&self) -> Result<bool, FeedError> {
        Ok(self.sync_row().await?.is_some_and(|sync| sync.epss_generation.is_some()))
    }

    /// `EpssFeed.scoresOf`: these identifiers' scores in the file in use, keyed upper-case; none before the first
    /// synchronisation — unknown, which is not zero.
    pub async fn scores_of<'a>(
        &self,
        identifiers: impl IntoIterator<Item = &'a str>,
    ) -> Result<HashMap<String, KnownEpssScore>, FeedError> {
        let Some(generation) = self.sync_row().await?.and_then(|sync| sync.epss_generation) else {
            return Ok(HashMap::new());
        };
        let mut tx = persistence::read(&self.db).await?;
        let found = scores_in(&mut tx, generation, identifiers).await?;
        persistence::commit(tx).await?;
        Ok(found)
    }

    /// `exploitationOf`: [`KevListing::Unknown`] before the catalogue's first synchronisation and for an identifier
    /// that is not a CVE, which the catalogue could never list; no score when the file in use has none, or there is no
    /// file yet.
    pub async fn exploitation_of(&self, identifier: Option<&str>) -> Result<Exploitation, FeedError> {
        let Some(identifier) = identifier.filter(|identifier| Exploitation::names_a_cve(Some(identifier))) else {
            return Ok(Exploitation::unknown());
        };
        let id = java::to_upper_root(java::trim(identifier));
        let score = self.scores_of([id.as_str()]).await?.remove(&id).map(|score| score.score);
        let catalogue_read = self.sync_row().await?.is_some_and(|sync| sync.last_synced_at.is_some());
        let kev = if !catalogue_read {
            KevListing::Unknown
        } else {
            let mut tx = persistence::read(&self.db).await?;
            let listed = IntelRepository::exploited_among(&mut tx, &[java::to_lower_root(&id)]).await?;
            persistence::commit(tx).await?;
            if listed.is_empty() { KevListing::NotListed } else { KevListing::Listed }
        };
        Ok(Exploitation { kev, epss_score: score })
    }

    /// `lookupCve`: none when neither feed recorded anything — which is neither "not exploited" before a sync nor a
    /// probability of zero.
    pub async fn lookup_cve(&self, cve_id: Option<&str>) -> Result<Option<ThreatIntelRecord>, FeedError> {
        let Some(cve_id) = cve_id.filter(|id| !java::is_blank(id)) else {
            return Ok(None);
        };
        Ok(self.lookup_cves([cve_id]).await?.remove(&java::to_lower_root(java::trim(cve_id))))
    }

    /// `lookupCves`: keyed by the trimmed, lower-cased identifier — the feed and the scanners do not agree on case —
    /// one query per feed and per batch, where the fleet summary once asked one per open issue.
    pub async fn lookup_cves<'a>(
        &self,
        cve_ids: impl IntoIterator<Item = &'a str>,
    ) -> Result<HashMap<String, ThreatIntelRecord>, FeedError> {
        let wanted = ordered_distinct(
            cve_ids.into_iter().filter(|id| !java::is_blank(id)).map(|id| java::to_lower_root(java::trim(id))),
        );
        if wanted.is_empty() {
            return Ok(HashMap::new());
        }
        let mut listed: HashMap<String, FeedRow> = HashMap::new();
        let mut tx = persistence::read(&self.db).await?;
        for batch in wanted.chunks(KEV_LOOKUP_BATCH) {
            for row in IntelRepository::by_ids_ignore_case(&mut tx, batch).await? {
                listed.insert(java::to_lower_root(&row.cve_id), row);
            }
        }
        persistence::commit(tx).await?;
        let mut scored = self.scores_of(wanted.iter().map(String::as_str)).await?;
        let catalogue_read = self.sync_row().await?.is_some_and(|sync| sync.last_synced_at.is_some());

        let mut found = HashMap::new();
        for id in wanted {
            let kev = listed.remove(&id);
            let score = scored.remove(&java::to_upper_root(&id));
            if let Some(record) = record(kev, score, catalogue_read) {
                found.insert(id, record);
            }
        }
        Ok(found)
    }
}

/// `EpssFeed.scoresOf(generation, …)`: only what can be a CVE — a secret's rule id, or a SAST rule's, would be sent
/// for no answer — trimmed, upper-cased, once each, in batches.
pub(crate) async fn scores_in<'a>(
    tx: &mut vectispire_cp_db::Tx,
    generation: i64,
    identifiers: impl IntoIterator<Item = &'a str>,
) -> Result<HashMap<String, KnownEpssScore>, StoreError> {
    let wanted = ordered_distinct(
        identifiers.into_iter().map(|id| java::to_upper_root(java::trim(id))).filter(|id| id.starts_with("CVE-")),
    );
    let mut found = HashMap::new();
    for batch in wanted.chunks(EPSS_LOOKUP_BATCH) {
        for score in EpssScoreRepository::scores_of(tx, generation, batch).await? {
            found.insert(score.cve_id.clone(), score);
        }
    }
    Ok(found)
}

/// A `LinkedHashSet`'s order: first occurrence kept.
fn ordered_distinct(items: impl IntoIterator<Item = String>) -> Vec<String> {
    let mut seen = HashSet::new();
    items.into_iter().filter(|item| seen.insert(item.clone())).collect()
}

/// `record`: the KEV row's word when there is one; otherwise, before the catalogue was ever read, nobody asked yet.
fn record(kev: Option<FeedRow>, score: Option<KnownEpssScore>, catalogue_read: bool) -> Option<ThreatIntelRecord> {
    let notes = match &kev {
        Some(row) if row.is_kev => "Listed in the CISA KEV catalogue",
        Some(_) => "No longer listed in the CISA KEV catalogue",
        None if catalogue_read => "Not listed in the CISA KEV catalogue",
        None => "CISA KEV catalogue never synchronised",
    };
    let cve_id = match (&kev, &score) {
        (Some(row), _) => row.cve_id.clone(),
        (None, Some(score)) => score.cve_id.clone(),
        (None, None) => return None,
    };
    Some(ThreatIntelRecord {
        cve_id,
        is_kev: kev.as_ref().is_some_and(|row| row.is_kev),
        epss_score: score.as_ref().map(|score| score.score),
        epss_percentile: score.as_ref().map(|score| score.percentile),
        date_added: kev.and_then(|row| row.date_added),
        notes: notes.to_owned(),
    })
}
