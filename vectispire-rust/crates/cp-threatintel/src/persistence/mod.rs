//! The tables threat intelligence owns: `t_threat_intel_feed` (the KEV catalogue as stored), `t_threat_intel_sync`
//! (the one row saying where both feeds stand) and `t_epss_score` (FIRST's file, one generation at a time).
//!
//! **Every statement Java's repositories hold is here, the writes included**, held to the Java answers by
//! persistence/tests.rs; the synchronisations that write are what calls them outside the tests.

pub(crate) mod entities;
pub mod repository;
#[cfg(test)]
mod tests;

use time::OffsetDateTime;
use vectispire_cp_db::{Db, Tx};

/// `ThreatIntelSyncEntity.SINGLETON_ID`: the sync row's only key.
pub const SINGLETON_ID: i64 = 1;

/// The state a feed starts in, and the one the columns default to.
pub const NEVER_SYNCED: &str = "NEVER_SYNCED";

#[derive(Debug, thiserror::Error)]
#[error("the threat intelligence tables did not answer: {0}")]
pub struct StoreError(#[source] pub Box<dyn std::error::Error + Send + Sync>);

impl From<sqlx::Error> for StoreError {
    fn from(error: sqlx::Error) -> StoreError {
        StoreError(Box::new(error))
    }
}

impl StoreError {
    /// Whether the engine refused a key already stored — the sync row created meanwhile by another instance.
    pub fn is_duplicate_key(&self) -> bool {
        self.0
            .downcast_ref::<sqlx::Error>()
            .and_then(sqlx::Error::as_database_error)
            .is_some_and(|error| error.is_unique_violation())
    }
}

pub async fn read(db: &Db) -> Result<Tx, StoreError> {
    Ok(db.begin(vectispire_cp_db::Mode::ReadOnly).await?)
}

pub async fn write(db: &Db) -> Result<Tx, StoreError> {
    Ok(db.begin(vectispire_cp_db::Mode::ReadWrite).await?)
}

pub async fn commit(tx: Tx) -> Result<(), StoreError> {
    Ok(tx.commit().await?)
}

/// One CVE the catalogue lists or has listed — `ThreatIntelEntity`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FeedRow {
    /// Upper-case, as the catalogue is stored.
    pub cve_id: String,
    pub is_kev: bool,
    /// The day CISA listed it; none when the catalogue did not say.
    pub date_added: Option<OffsetDateTime>,
    pub updated_at: OffsetDateTime,
}

/// An entry the catalogue lists that is not stored yet — `ThreatIntelBulkWrites.Listing`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Listing {
    pub cve_id: String,
    pub date_added: Option<OffsetDateTime>,
}

/// One CVE's figures as stored — `KnownEpssScore`, the identifier upper-case.
#[derive(Debug, Clone, PartialEq)]
pub struct KnownEpssScore {
    pub cve_id: String,
    pub score: f64,
    pub percentile: f64,
}

/// The one row saying where the KEV catalogue and the EPSS file stand — `ThreatIntelSyncEntity`.
///
/// **Saved whole by the KEV synchronisation only, and only after it holds the row's lock** (`mark_attempt` first,
/// then the read): an EPSS claim or result either committed before that read or waits for the save's commit. The
/// EPSS feed writes its own columns through the conditional updates of [`repository::SyncRepository`] alone.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SyncRow {
    pub id: i64,
    pub last_synced_at: Option<OffsetDateTime>,
    pub cve_count: i64,
    pub kev_count: i64,
    pub status: String,
    pub kev_catalog_version: Option<String>,
    pub kev_released_at: Option<OffsetDateTime>,
    pub last_attempt_at: Option<OffsetDateTime>,
    pub last_error: Option<String>,
    pub epss_status: String,
    pub epss_synced_at: Option<OffsetDateTime>,
    pub epss_model_version: Option<String>,
    pub epss_score_date: Option<OffsetDateTime>,
    pub epss_count: i64,
    /// The generation of `t_epss_score` in use; none until a file was applied.
    pub epss_generation: Option<i64>,
    /// The one in use before it, kept until the next file is applied (V47).
    pub epss_previous_generation: Option<i64>,
    pub epss_attempt_at: Option<OffsetDateTime>,
    /// Until when the synchronisation holding the claim may keep it.
    pub epss_lease_until: Option<OffsetDateTime>,
    /// The generation the synchronisation holding the lease is writing.
    pub epss_claim: Option<i64>,
    pub epss_error: Option<String>,
}

impl SyncRow {
    /// `new ThreatIntelSyncEntity()`: never synchronised, nothing counted.
    pub fn fresh() -> SyncRow {
        SyncRow {
            id: SINGLETON_ID,
            last_synced_at: None,
            cve_count: 0,
            kev_count: 0,
            status: NEVER_SYNCED.to_owned(),
            kev_catalog_version: None,
            kev_released_at: None,
            last_attempt_at: None,
            last_error: None,
            epss_status: NEVER_SYNCED.to_owned(),
            epss_synced_at: None,
            epss_model_version: None,
            epss_score_date: None,
            epss_count: 0,
            epss_generation: None,
            epss_previous_generation: None,
            epss_attempt_at: None,
            epss_lease_until: None,
            epss_claim: None,
            epss_error: None,
        }
    }
}
