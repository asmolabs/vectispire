//! `ScanCatalog`: scans as the other modules read them — views, never rows — and the one place, besides the
//! scheduler, that queues a scan (`trigger.rs`, `ScanTriggerService`).
//!
//! **What Phase 2 reads of it is here**: a scan by identifier, the latest scan per target and the newest languages
//! (`targets`' listings, through `TargetScans`), and what `agents` (2.9) reads of the queue — the waiting scans and
//! their attempts, the counts per claimant and per label. The readings of later phases (inventory's SBOMs, compliance's
//! examinations, checklists' plugin runs, exports' labels and outlines) come with them; `labels_of` is here already,
//! held to `ScanLabelsIntegrationTest`. It needs nothing but the database, so `targets` can be composed over it
//! before the rest of the module exists.

use std::collections::{BTreeMap, BTreeSet};
use std::sync::Arc;

use time::OffsetDateTime;
use vectispire_cp_db::Db;
use vectispire_cp_targets::Clock;

use crate::persistence::{self, LOOKUP_BATCH, LatestRow, StoreError};
use crate::views::{ScanView, detected_languages};

/// The catalogue, over the database and the clock that stamps a queued scan.
#[derive(Clone)]
pub struct ScanCatalog {
    pub(crate) db: Db,
    pub(crate) clock: Arc<dyn Clock>,
}

impl std::fmt::Debug for ScanCatalog {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.debug_struct("ScanCatalog").field("db", &self.db).finish_non_exhaustive()
    }
}

/// `ScanLabel`: a scan's branch, and the project version its manifest gave — `None` where it read none.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ScanLabel {
    pub branch: String,
    pub version: Option<String>,
}

/// `AttemptedScan`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct AttemptedScan {
    pub id: i64,
    pub repo_id: i64,
}

/// `WaitingScans`: waiting scans of one repository requiring one label — `None` when they require none.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct WaitingScans {
    pub required_label: Option<String>,
    pub repo_id: i64,
    pub scans: i64,
}

impl ScanCatalog {
    pub fn new(db: Db, clock: Arc<dyn Clock>) -> ScanCatalog {
        ScanCatalog { db, clock }
    }

    async fn read<T>(
        &self,
        statement: impl AsyncFnOnce(&mut vectispire_cp_db::Tx) -> Result<T, StoreError>,
    ) -> Result<T, StoreError> {
        let mut tx = persistence::read(&self.db).await?;
        let answer = statement(&mut tx).await;
        tx.commit().await?;
        answer
    }

    pub async fn scan(&self, id: i64) -> Result<Option<ScanView>, StoreError> {
        Ok(self.read(async |tx| persistence::scan(tx, id).await).await?.map(ScanView::from))
    }

    /// Each repository's newest scan, by the highest identifier.
    pub async fn latest_per_repository(&self) -> Result<Vec<LatestRow>, StoreError> {
        self.read(async |tx| persistence::latest_per_repository(tx).await).await
    }

    pub async fn latest_per_container(&self) -> Result<Vec<LatestRow>, StoreError> {
        self.read(async |tx| persistence::latest_per_container(tx).await).await
    }

    /// `newestDetectedLanguages`: the languages each of these repositories' newest **completed** scan found. **A
    /// repository missing from the answer is unknown** — no completed scan, or one that recorded no whole census —
    /// never an older scan's languages in its place: the newest completed scan is what the repository is now.
    pub async fn newest_detected_languages(
        &self,
        repositories: &[i64],
    ) -> Result<BTreeMap<i64, Vec<&'static str>>, StoreError> {
        let mut detected = BTreeMap::new();
        for batch in repositories.chunks(LOOKUP_BATCH) {
            let rows =
                self.read(async |tx| persistence::newest_detected_languages(tx, batch, "completed").await).await?;
            for (repository, column) in rows {
                if let Some(languages) = detected_languages::read(column.as_deref()) {
                    detected.insert(repository, languages);
                }
            }
        }
        Ok(detected)
    }

    /// `labelsOf`: each existing scan's label, a thousand identifiers per statement — a list sized by the data.
    pub async fn labels_of(&self, ids: &[i64]) -> Result<BTreeMap<i64, ScanLabel>, StoreError> {
        let rows = self.read(async |tx| persistence::labels_of(tx, ids).await).await?;
        Ok(rows.into_iter().map(|(id, branch, version)| (id, ScanLabel { branch, version })).collect())
    }

    /// `waitingWithAttempts`: the waiting scans of repositories that were counted at least one attempt.
    pub async fn waiting_with_attempts(&self) -> Result<Vec<AttemptedScan>, StoreError> {
        Ok(self
            .read(async |tx| persistence::attempted_repository_scans(tx, "pending").await)
            .await?
            .into_iter()
            .map(|(id, repo_id)| AttemptedScan { id, repo_id })
            .collect())
    }

    /// `refundAttempts`: these waiting scans given their attempts back — **the catalogue's one write**, on `agents`'
    /// behalf (the withheld claims' repair, 2.9). A scan claimed since it was read is left as it is.
    pub async fn refund_attempts(&self, ids: &[i64]) -> Result<u64, StoreError> {
        let distinct: Vec<i64> = ids.iter().copied().collect::<BTreeSet<i64>>().into_iter().collect();
        let mut tx = persistence::write(&self.db).await?;
        let mut changed = 0;
        for batch in distinct.chunks(LOOKUP_BATCH) {
            match persistence::reset_attempts(&mut tx, batch, "pending").await {
                Ok(rows) => changed += rows,
                Err(failure) => {
                    let _ = tx.rollback().await;
                    return Err(failure);
                }
            }
        }
        tx.commit().await?;
        Ok(changed)
    }

    /// `waitingRepositories`: the waiting scans of repositories, per required label and repository.
    pub async fn waiting_repositories(&self) -> Result<Vec<WaitingScans>, StoreError> {
        Ok(self
            .read(async |tx| persistence::waiting_by_label_and_repository(tx, "pending").await)
            .await?
            .into_iter()
            .map(|(required_label, repo_id, scans)| WaitingScans { required_label, repo_id, scans })
            .collect())
    }

    /// `countByClaimant`: running scans per claimant.
    pub async fn count_by_claimant(&self, status: &str) -> Result<BTreeMap<String, i64>, StoreError> {
        Ok(self.read(async |tx| persistence::count_by_claimant(tx, status).await).await?.into_iter().collect())
    }

    /// `countByRequiredLabel`.
    pub async fn count_by_required_label(&self, status: &str) -> Result<BTreeMap<String, i64>, StoreError> {
        Ok(self.read(async |tx| persistence::count_by_required_label(tx, status).await).await?.into_iter().collect())
    }

    /// `countWithStatusClaimedBy`: a lapsed lease counted too.
    pub async fn count_claimed_by(&self, status: &str, claimant: &str) -> Result<i64, StoreError> {
        self.read(async |tx| persistence::count_claimed_by(tx, status, claimant).await).await
    }

    /// `withStatusOldestFirst`, for the two statuses the agents' screen lists.
    pub async fn with_status_oldest_first(&self, statuses: [&str; 2]) -> Result<Vec<ScanView>, StoreError> {
        Ok(self
            .read(async |tx| persistence::with_status_oldest_first(tx, statuses).await)
            .await?
            .into_iter()
            .map(ScanView::from)
            .collect())
    }

    /// `countWithStatusSince`: created strictly after `after`.
    pub async fn count_since(&self, status: &str, after: OffsetDateTime) -> Result<i64, StoreError> {
        self.read(async |tx| persistence::count_since(tx, status, after).await).await
    }

    /// `averageDurationMsSince`: `None` when no such scan recorded a duration.
    pub async fn average_duration_since(&self, status: &str, after: OffsetDateTime) -> Result<Option<f64>, StoreError> {
        self.read(async |tx| persistence::average_duration_since(tx, status, after).await).await
    }
}
