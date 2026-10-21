//! Maintenance tasks for the gate module.

use std::sync::Arc;

use time::OffsetDateTime;
use vectispire_cp_db::Db;
use vectispire_cp_maintenance::{MaintenanceTask, Sequence, TaskRun};
use vectispire_cp_settings::{Setting, Settings};
use vectispire_cp_targets::Clock;
use vectispire_domain::instant::Instant;
use vectispire_domain::retention::evidence;

use crate::persistence::repository::GateVerdictRepository;

/// The gate's verdict register, purged past the evidence window.
#[derive(Clone)]
pub struct VerdictRetentionTask {
    db: Db,
    settings: Settings,
    clock: Arc<dyn Clock>,
}

impl VerdictRetentionTask {
    pub fn new(db: Db, settings: Settings, clock: Arc<dyn Clock>) -> Self {
        Self { db, settings, clock }
    }
}

impl MaintenanceTask for VerdictRetentionTask {
    fn sequence(&self) -> Sequence {
        Sequence::GateVerdicts
    }

    fn run(&self) -> TaskRun<'_> {
        Box::pin(async move {
            let days = match self.settings.as_int(Setting::EvidenceRetentionDays).await {
                Ok(d) => d,
                Err(err) => {
                    tracing::warn!("Gate verdict purge skipped: could not read setting: {err}");
                    return Ok(());
                }
            };

            let now = self.clock.now();
            let now_instant = Instant { epoch_second: now.unix_timestamp(), nano: now.nanosecond() };

            if let Some(cutoff) = evidence::cutoff(days, now_instant)
                && let Ok(cutoff_odt) = OffsetDateTime::from_unix_timestamp(cutoff.epoch_second)
            {
                let cutoff_exact = cutoff_odt.replace_nanosecond(cutoff.nano).unwrap_or(cutoff_odt);
                let mut tx = match crate::persistence::write(&self.db).await {
                    Ok(t) => t,
                    Err(err) => {
                        tracing::warn!("Gate verdict purge skipped: could not open transaction: {err}");
                        return Ok(());
                    }
                };

                match GateVerdictRepository::delete_before(&mut tx, cutoff_exact).await {
                    Ok(purged) => {
                        if let Err(err) = crate::persistence::commit(tx).await {
                            tracing::warn!("Gate verdict purge commit failed: {err}");
                        } else if purged > 0 {
                            tracing::info!("Maintenance: {purged} aged gate verdict(s) removed.");
                        }
                    }
                    Err(err) => {
                        tracing::warn!("Gate verdict purge skipped: {err}");
                    }
                }
            }

            Ok(())
        })
    }
}

impl std::fmt::Debug for VerdictRetentionTask {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.debug_struct("VerdictRetentionTask").finish_non_exhaustive()
    }
}
