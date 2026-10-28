//! Purging raw scanner payloads — `RetentionService`: a scan's SBOM and CVE blobs go, its summary, findings and issues
//! stay. **Idempotent, so safe without an election**: dropping a payload twice costs nothing, which lets the purge run
//! on every instance's hourly turn.
//!
//! No `VACUUM` after it, unlike the Python original: PostgreSQL and MySQL reuse the space, and a `VACUUM FULL` would
//! lock the table for as long as it takes to rewrite it.

use std::time::Duration;

use vectispire_cp_settings::Setting;
use vectispire_domain::ScanTarget;
use vectispire_domain::retention::{Candidate, RetentionPolicy};

use crate::Scanning;
use crate::instants::instant;
use crate::persistence::{self, StoreError};

/// How many identifiers one purge statement carries — Java's `BATCH_SIZE`: purging a long-neglected database is
/// exactly when the list is long.
pub const PURGE_BATCH: usize = 500;

/// Why retention did not run.
#[derive(Debug, thiserror::Error)]
pub enum RetentionError {
    #[error(transparent)]
    Store(#[from] StoreError),
    #[error("the retention settings could not be read: {0}")]
    Settings(String),
}

impl Scanning {
    /// `policy`: the two settings, as `SettingsService.asInt` reads them. A negative stored value — refused by the
    /// settings' validation since there was one — reads as zero here, where Java would carry it; see the README.
    pub async fn retention_policy(&self) -> Result<RetentionPolicy, RetentionError> {
        let keep = self.settings.as_int(Setting::RetentionKeepPerTarget).await.map_err(settings)?;
        let days = self.settings.as_int(Setting::RetentionMaxAgeDays).await.map_err(settings)?;
        Ok(RetentionPolicy {
            keep_per_target: u32::try_from(keep).unwrap_or(0),
            max_age: Duration::from_secs(u64::try_from(days).unwrap_or(0).saturating_mul(86_400)),
        })
    }

    /// `findPrunable`: **only the deciding columns are read** — loading whole rows would pull the payloads into
    /// memory in order to decide to erase them.
    pub async fn find_prunable(&self) -> Result<Vec<i64>, RetentionError> {
        let policy = self.retention_policy().await?;
        if !policy.is_enabled() {
            return Ok(Vec::new());
        }
        let mut tx = persistence::read(&self.db).await?;
        let rows = persistence::payload_bearing(&mut tx).await;
        tx.commit().await.map_err(StoreError::from)?;
        let candidates: Vec<Candidate> = rows?
            .into_iter()
            .map(|row| Candidate {
                scan_id: row.id,
                // A scan with neither target is grouped as repository 0: no path makes one, and it must not take the
                // hourly turn down.
                target: match (row.repo_id, row.container_id) {
                    (Some(id), _) => ScanTarget::Repository(id),
                    (None, Some(id)) => ScanTarget::Container(id),
                    (None, None) => ScanTarget::Repository(0),
                },
                created_at: instant(row.created_at),
            })
            .collect();
        Ok(policy.prunable(&candidates, instant(self.clock.now())))
    }

    /// `prune`: every prunable scan's payloads dropped, by a bulk update in one transaction, a batch at a time.
    pub async fn prune(&self) -> Result<usize, RetentionError> {
        let ids = self.find_prunable().await?;
        if ids.is_empty() {
            return Ok(0);
        }
        let mut tx = persistence::write(&self.db).await?;
        for batch in ids.chunks(PURGE_BATCH) {
            if let Err(failure) = persistence::drop_payloads(&mut tx, batch).await {
                let _ = tx.rollback().await;
                return Err(failure.into());
            }
        }
        tx.commit().await.map_err(StoreError::from)?;
        let policy = self.retention_policy().await?;
        tracing::info!(
            scans = ids.len(),
            keep_per_target = policy.keep_per_target,
            max_age_days = policy.max_age.as_secs() / 86_400,
            "Retention: raw payloads dropped."
        );
        Ok(ids.len())
    }

    /// `payloadCount`: how many scans still carry a payload — the figure the screen shows.
    pub async fn payload_count(&self) -> Result<i64, RetentionError> {
        let mut tx = persistence::read(&self.db).await?;
        let count = persistence::count_payload_bearing(&mut tx).await;
        tx.commit().await.map_err(StoreError::from)?;
        Ok(count?)
    }
}

fn settings(failure: impl std::fmt::Display) -> RetentionError {
    RetentionError::Settings(failure.to_string())
}
