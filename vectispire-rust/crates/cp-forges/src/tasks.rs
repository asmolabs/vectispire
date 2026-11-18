//! The module's maintenance tasks — `ForgeTokenWatchTask` and `ChangeReviewTask`, hourly, on every instance: each
//! change and each reading is claimed first, so one instance announces or reads it.

use std::sync::Arc;

use vectispire_cp_maintenance::{MaintenanceTask, Sequence, TaskRun};

use crate::reviews::ForgeReviewService;
use crate::token_watch::ForgeTokenWatch;

/// `ForgeTokenWatchTask`: the tokens' expiries compared with the clock, each change announced once.
#[derive(Debug, Clone)]
pub struct TokenWatchTask(pub Arc<ForgeTokenWatch>);

impl MaintenanceTask for TokenWatchTask {
    fn sequence(&self) -> Sequence {
        Sequence::ForgeTokenWatch
    }

    fn run(&self) -> TaskRun<'_> {
        Box::pin(async move {
            self.0.watch().await.map_err(|failure| Box::new(failure) as vectispire_cp_maintenance::TaskError)?;
            Ok(())
        })
    }
}

/// `ChangeReviewTask`: the only caller of the reading. Never fails the turn: what it could not do it logs.
#[derive(Debug, Clone)]
pub struct ChangeReviewTask(pub Arc<ForgeReviewService>);

impl MaintenanceTask for ChangeReviewTask {
    fn sequence(&self) -> Sequence {
        Sequence::ChangeReviews
    }

    fn run(&self) -> TaskRun<'_> {
        Box::pin(async move {
            match self.0.read_due().await {
                Ok(read) if read > 0 => {
                    tracing::info!("Maintenance: {read} change-review reading(s) of forge projects written.");
                }
                Ok(_) => {}
                Err(failed) => tracing::warn!("Change-review readings skipped: {failed}"),
            }
            Ok(())
        })
    }
}
