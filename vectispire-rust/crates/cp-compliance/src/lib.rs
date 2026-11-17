//! Compliance — Java's `core/compliance`: the framework matrix and its per-scope reading, the statement of
//! applicability, the certified scope, the monthly history, the OWASP Top 10 grid with its weekly record, and the
//! OWASP report. The pure decisions are `vectispire_domain::compliance` and `owasp_coverage`; this crate holds what
//! reads and writes, in the module layout every ported module keeps (`persistence` beneath the services).

pub mod internal;
pub mod persistence;
pub mod purge;

use std::sync::Arc;

use vectispire_cp_db::Db;
use vectispire_cp_maintenance::MaintenanceTask;
use vectispire_cp_settings::Settings;
use vectispire_cp_targets::Clock;

/// The module's maintenance tasks so far: the evidence window of the snapshots and of the weekly OWASP record, and the
/// abandoned reports. The history's capture and the weekly record's come with their services.
pub fn tasks(db: Db, settings: Settings, clock: Arc<dyn Clock>) -> Vec<Arc<dyn MaintenanceTask>> {
    vec![
        Arc::new(internal::tasks::SnapshotRetentionTask::new(db.clone(), settings.clone(), clock.clone())),
        Arc::new(internal::tasks::WeeklyRetentionTask::new(db.clone(), settings, clock.clone())),
        Arc::new(internal::tasks::AbandonedReviewsTask::new(db, clock)),
    ]
}
