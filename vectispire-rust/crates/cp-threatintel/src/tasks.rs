//! The module's maintenance tasks — `KevCatalogueSyncTask` and `EpssScoresSyncTask`, hourly, on every instance: the
//! feed service decides whether a synchronisation is due and which instance runs it, so most turns cost one
//! conditional update. **Never fails the turn**: a failure is recorded on the feed's status and audited, and the next
//! attempt is half an hour (the catalogue) or an hour (the file) away.

use std::sync::Arc;

use vectispire_cp_maintenance::{MaintenanceTask, Sequence, TaskRun};

use crate::status::State;
use crate::sync::ThreatIntelFeedService;

/// `KevCatalogueSyncTask`: the CISA KEV catalogue, read again once it is six hours old.
#[derive(Debug, Clone)]
pub struct KevCatalogueSyncTask(pub Arc<ThreatIntelFeedService>);

impl MaintenanceTask for KevCatalogueSyncTask {
    fn sequence(&self) -> Sequence {
        Sequence::KevCatalogue
    }

    fn run(&self) -> TaskRun<'_> {
        Box::pin(async move {
            match self.0.sync_if_due().await {
                Ok(Some(status)) if status.status == State::Synced => tracing::info!(
                    "Maintenance: KEV catalogue {} synchronised, {} issue(s) re-evaluated.",
                    status.kev_catalog_version.as_deref().unwrap_or("null"),
                    status.backlog_updated_count
                ),
                Ok(_) => {}
                Err(failed) => tracing::warn!("KEV catalogue synchronisation skipped: {failed}"),
            }
            Ok(())
        })
    }
}

/// `EpssScoresSyncTask`: FIRST's EPSS file, read again once a day.
#[derive(Debug, Clone)]
pub struct EpssScoresSyncTask(pub Arc<ThreatIntelFeedService>);

impl MaintenanceTask for EpssScoresSyncTask {
    fn sequence(&self) -> Sequence {
        Sequence::EpssScores
    }

    fn run(&self) -> TaskRun<'_> {
        Box::pin(async move {
            match self.0.sync_epss_if_due().await {
                Ok(Some(status)) if status.epss.status == State::Synced => tracing::info!(
                    "Maintenance: EPSS scores of {} ({}) in use, {} issue(s) re-scored.",
                    status.epss.score_date.map_or_else(|| "null".to_owned(), crate::time_text::java_string),
                    status.epss.model_version.as_deref().unwrap_or("null"),
                    status.epss.backlog_updated_count
                ),
                Ok(_) => {}
                Err(failed) => tracing::warn!("EPSS synchronisation skipped: {failed}"),
            }
            Ok(())
        })
    }
}
