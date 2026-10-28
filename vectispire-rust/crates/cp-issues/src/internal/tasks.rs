//! Maintenance tasks for the issues module:
//! - `TriageExpiryTask`: expires triage decisions past their review date, returning them under review.
//! - `SlaBreachTask`: signals remediation deadlines passed since the last turn to the SOC.

use std::sync::Arc;

use vectispire_cp_maintenance::{MaintenanceTask, Sequence, TaskRun};

use crate::sla::SlaBreachSignals;
use crate::triage::IssueTriageService;

/// `TriageExpiryTask`: returns risk acceptances and dismissals that reached their review date under review.
///
/// **Hourly rather than on page load.** A dismissal that lapses overnight must stop dismissing in the VEX
/// document a customer downloads and in the verdict a pipeline requests at three in the morning.
#[derive(Clone)]
pub struct TriageExpiryTask {
    triage: Arc<IssueTriageService>,
}

impl TriageExpiryTask {
    pub fn new(triage: Arc<IssueTriageService>) -> Self {
        Self { triage }
    }
}

impl MaintenanceTask for TriageExpiryTask {
    fn sequence(&self) -> Sequence {
        Sequence::TriageExpiry
    }

    fn run(&self) -> TaskRun<'_> {
        Box::pin(async move {
            match self.triage.expire_stale_now().await {
                Ok(expired) => {
                    if !expired.is_empty() {
                        tracing::info!("Maintenance: {} triage decision(s) returned under review.", expired.len());
                    }
                }
                Err(err) => {
                    tracing::warn!("Triage expiry maintenance task failed: {err}");
                }
            }
            Ok(())
        })
    }
}

/// `SlaBreachTask`: remediation deadlines passed since the last turn, told to the SOC.
///
/// **Hourly, and right after triage expiry.** An acceptance that lapsed this turn puts its issue back among
/// the undecided; if its deadline passed while accepted, it is announced now rather than an hour later.
#[derive(Clone)]
pub struct SlaBreachTask {
    breaches: Arc<SlaBreachSignals>,
}

impl SlaBreachTask {
    pub fn new(breaches: Arc<SlaBreachSignals>) -> Self {
        Self { breaches }
    }
}

impl MaintenanceTask for SlaBreachTask {
    fn sequence(&self) -> Sequence {
        Sequence::SlaBreaches
    }

    fn run(&self) -> TaskRun<'_> {
        Box::pin(async move {
            match self.breaches.signal_crossings().await {
                Ok(signalled) => {
                    if signalled > 0 {
                        tracing::info!("Maintenance: {} remediation deadline(s) passed and announced.", signalled);
                    }
                }
                Err(err) => {
                    tracing::warn!("SLA breach maintenance task failed: {err}");
                }
            }
            Ok(())
        })
    }
}

opaque_debug!(TriageExpiryTask, SlaBreachTask);
