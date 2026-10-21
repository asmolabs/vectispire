//! What runs once the control plane has started — Java's `ApplicationReadyEvent` listeners — as a list the binary
//! runs and `tests/startup_composition.rs` reads.
//!
//! **Why a list.** `WithheldClaimRepair` was ported, tested on both engines, and called by nothing: Java runs it when
//! the application is ready, and the binary never did, so the attempts a withheld claim inflated before the fix stayed
//! inflated. A job written inline in `main` is visible to no test — the `MaintenanceJobsTest` lesson of `AGENTS.md`.

use std::future::Future;
use std::pin::Pin;
use std::sync::Arc;

use vectispire_cp_agents::{RepairOutcome, WithheldClaimRepair};
use vectispire_cp_targets::Targets;

/// One job run once at start, named as the composition test lists it.
pub struct ReadyJob {
    pub name: &'static str,
    run: Box<dyn Fn() -> Pin<Box<dyn Future<Output = ()> + Send>> + Send + Sync>,
}

impl ReadyJob {
    /// The job's work; a failure is logged, never fatal, as a failed listener is in Java.
    pub fn run(&self) -> Pin<Box<dyn Future<Output = ()> + Send>> {
        (self.run)()
    }
}

impl std::fmt::Debug for ReadyJob {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ReadyJob").field("name", &self.name).finish_non_exhaustive()
    }
}

/// Every module's job at start, in Java's listeners' order.
pub fn ready_jobs(targets: Arc<Targets>, repair: Arc<WithheldClaimRepair>) -> Vec<ReadyJob> {
    vec![
        ReadyJob {
            name: "targets: the orphan sweep",
            run: Box::new(move || {
                let targets = targets.clone();
                Box::pin(async move {
                    if let Err(error) = targets.purge_orphans().await {
                        tracing::warn!("Orphan sweep on startup did not complete: {error}");
                    }
                })
            }),
        },
        ReadyJob {
            name: "agents: withheld-claim-repair",
            run: Box::new(move || {
                let repair = repair.clone();
                Box::pin(async move {
                    match repair.repair_once().await {
                        Ok(RepairOutcome::Repaired(scans)) if !scans.is_empty() => {
                            tracing::info!(?scans, "Attempts inflated by withheld claims were given back.");
                        }
                        Ok(_) => {}
                        Err(error) => tracing::warn!("The withheld-claim repair did not complete: {error}"),
                    }
                })
            }),
        },
    ]
}
