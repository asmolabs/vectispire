//! The maintenance tasks the binary composes — where a module's `MaintenanceTask` becomes a task that runs.
//!
//! Each module adds its tasks here in the commit that removes its lines from `crates/cp-maintenance/data/deferred.txt`.
//! `tests/maintenance_composition.rs` holds this list to Java's twenty-eight slots, which is the level at which a task
//! nobody calls is visible: `IssueTriageService.expireStale` passed its own tests for as long as nothing called it.
//!
//! **The outbox (task 2.2)** fills `NOTIFICATION_RELAY` and `SENT_MESSAGES`. Its relay task is composed **held back**:
//! it compares [`outbox_registry`] with the types the started Java application relays and claims nothing while they
//! differ, because a relay missing a handler abandons Java's pending messages of that type after eight attempts (plan
//! §7, Phase 2; `crates/cp-outbox/README.md`). The composition test asserts it is held today.
//!
//! **Targets (task 2.6)** fill `REPOSITORY_IDENTITIES` and `ORPHANED_TARGET_ROWS`: the identity keying of rows filed
//! before V73 or by an instance of the previous version, and the orphan sweep through the purge's listeners — which
//! the binary also runs once at every start (`Targets::purge_orphans`), as Java does on `ApplicationReadyEvent`.
//!
//! **Scanning (task 2.7)** fills `SCHEDULING_TICK` and `SCAN_RETENTION`. The tick runs on every instance's
//! scheduling turn, and only the holder of `t_leader_lease`'s `scheduler` row schedules — the service takes or renews
//! the lease at each tick and fails closed when the table does not answer; the retention is idempotent, so safe on
//! every instance.
//!
//! The turns are not started by `main` yet, because nothing composed needs a database the binary does not open;
//! when one does (2.11), `Turns::run_until` runs beside the server with the shutdown signal as its stop.

use std::sync::Arc;

use vectispire_cp_maintenance::{CompositionError, MaintenanceTask, Turns};
use vectispire_cp_outbox::{Outbox, Registry, UnreadableRegistry};
use vectispire_cp_scanning::Scanning;
use vectispire_cp_targets::Targets;

/// Why the maintenance composition could not be built.
#[derive(Debug, thiserror::Error)]
pub enum MaintenanceError {
    #[error(transparent)]
    Composition(#[from] CompositionError),
    #[error(transparent)]
    Registry(#[from] UnreadableRegistry),
}

/// The outbox's handlers and channels this binary has: none yet. Java relays eleven types
/// (`reference/outbox/registry.json`); the agents' audit delivery (`agent_result_audit`) comes with task 2.9, the
/// notifications' channels and token alerts, the SIEM export, the checklists' and compliance's deliveries with
/// Phases 4 and 5. Until all eleven are here the relay task is held.
#[must_use]
pub fn outbox_registry() -> Registry {
    Registry::new(Vec::new(), Vec::new())
}

/// Every module's maintenance task.
pub fn tasks(
    outbox: Arc<Outbox>,
    targets: Arc<Targets>,
    scanning: Arc<Scanning>,
) -> Result<Vec<Arc<dyn MaintenanceTask>>, MaintenanceError> {
    let mut tasks = vectispire_cp_outbox::tasks(outbox)?;
    tasks.extend(vectispire_cp_targets::tasks(targets));
    tasks.extend(vectispire_cp_scanning::tasks(scanning));
    Ok(tasks)
}

/// The turns over [`tasks`].
pub fn turns(outbox: Arc<Outbox>, targets: Arc<Targets>, scanning: Arc<Scanning>) -> Result<Turns, MaintenanceError> {
    Ok(Turns::new(tasks(outbox, targets, scanning)?)?)
}
