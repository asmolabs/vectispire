//! Maintenance tasks for the inventory module:
//! - `InventoryBackfillTask`: indexes SBOM components from past scans.
//! - `BuildSbomRetentionTask`: purges build SBOMs older than the evidence retention window.

use std::sync::Arc;

use time::OffsetDateTime;
use vectispire_cp_maintenance::{MaintenanceTask, Sequence, TaskRun};
use vectispire_cp_settings::Settings;
use vectispire_cp_settings::catalog::Setting;
use vectispire_cp_targets::Clock;
use vectispire_domain::instant::Instant;
use vectispire_domain::retention::evidence;

use crate::backfill::InventoryBackfill;
use crate::build_sbom_inventory::BuildSbomInventory;

/// `InventoryBackfillTask`: fills the components inventory of past scans, a batch per turn.
#[derive(Clone, Debug)]
pub struct InventoryBackfillTask {
    backfill: Arc<InventoryBackfill>,
}

impl InventoryBackfillTask {
    pub fn new(backfill: Arc<InventoryBackfill>) -> Self {
        Self { backfill }
    }
}

impl MaintenanceTask for InventoryBackfillTask {
    fn sequence(&self) -> Sequence {
        Sequence::InventoryBackfill
    }

    fn run(&self) -> TaskRun<'_> {
        Box::pin(async move {
            if let Err(err) = self.backfill.run_once().await {
                tracing::warn!("Inventory backfill task failed: {err}");
            }
            Ok(())
        })
    }
}

/// `BuildSbomRetentionTask`: build SBOMs purged past the evidence retention window.
#[derive(Clone, Debug)]
pub struct BuildSbomRetentionTask {
    builds: Arc<BuildSbomInventory>,
    settings: Settings,
    clock: Arc<dyn Clock>,
}

impl BuildSbomRetentionTask {
    pub fn new(builds: Arc<BuildSbomInventory>, settings: Settings, clock: Arc<dyn Clock>) -> Self {
        Self { builds, settings, clock }
    }
}

impl MaintenanceTask for BuildSbomRetentionTask {
    fn sequence(&self) -> Sequence {
        Sequence::BuildSbomRetention
    }

    fn run(&self) -> TaskRun<'_> {
        Box::pin(async move {
            let days = match self.settings.as_int(Setting::EvidenceRetentionDays).await {
                Ok(d) => d,
                Err(err) => {
                    tracing::warn!("Build SBOM retention skipped: could not read setting: {err}");
                    return Ok(());
                }
            };

            let now = self.clock.now();
            let now_instant = Instant { epoch_second: now.unix_timestamp(), nano: now.nanosecond() };

            if let Some(cutoff) = evidence::cutoff(days, now_instant)
                && let Ok(cutoff_odt) = OffsetDateTime::from_unix_timestamp(cutoff.epoch_second)
            {
                let cutoff_exact = cutoff_odt.replace_nanosecond(cutoff.nano).unwrap_or(cutoff_odt);
                match self.builds.purge_imported_before(cutoff_exact).await {
                    Ok(purged) => {
                        if purged > 0 {
                            tracing::info!("Maintenance: {purged} build SBOM(s) past the evidence window removed.");
                        }
                    }
                    Err(err) => {
                        tracing::warn!("Build SBOM purge skipped: {err}");
                    }
                }
            }

            Ok(())
        })
    }
}
