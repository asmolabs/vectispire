//! `WeeklyDigestTask`: the weekly posture report, offered every hour. **This task is the only thing that makes the
//! feature exist** — the shape `expireStale` had when its javadoc claimed the tick ran it and nothing did. Hourly for a
//! weekly job: the digest decides for itself whether one went out since Monday.

use std::sync::Arc;

use vectispire_cp_maintenance::{MaintenanceTask, Sequence, TaskRun};

use crate::weekly::PostureDigests;

#[derive(Clone)]
pub struct WeeklyDigestTask {
    digests: Arc<PostureDigests>,
}

opaque_debug!(WeeklyDigestTask);

impl WeeklyDigestTask {
    pub fn new(digests: Arc<PostureDigests>) -> WeeklyDigestTask {
        WeeklyDigestTask { digests }
    }
}

impl MaintenanceTask for WeeklyDigestTask {
    fn sequence(&self) -> Sequence {
        Sequence::WeeklyDigest
    }

    fn run(&self) -> TaskRun<'_> {
        Box::pin(async move {
            self.digests.run_once().await;
            Ok(())
        })
    }
}
