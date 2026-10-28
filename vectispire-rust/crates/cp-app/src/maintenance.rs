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
//! **Agents (task 2.9)** fills `CREDENTIALED_BACKLOG`: the backlog sweep over waiting repositories whose credentials
//! are unserved.
//!
//! **Inventory (Phase 3)** fills `INVENTORY_BACKFILL` and `BUILD_SBOM_RETENTION`: the backfill of past scans' components
//! from raw SBOMs, and build SBOM retention past the evidence window.
//!
//! **Gate (Phase 3)** fills `GATE_VERDICTS`: the gate's verdict register, purged past the evidence window.
//!
//! The turns are started by `main` (2.11) beside the server with the shutdown signal as their stop.

use std::sync::Arc;

use vectispire_cp_agents::{Agents, CredentialedBacklogTask};
use vectispire_cp_gate::GateModule;
use vectispire_cp_inventory::Inventory;
use vectispire_cp_maintenance::{CompositionError, MaintenanceTask, Turns};
use vectispire_cp_outbox::{Outbox, Registry, UnreadableRegistry};
use vectispire_cp_scanning::Scanning;
use vectispire_cp_settings::Settings;
use vectispire_cp_targets::{Clock, Targets};

/// Why the maintenance composition could not be built.
#[derive(Debug, thiserror::Error)]
pub enum MaintenanceError {
    #[error(transparent)]
    Composition(#[from] CompositionError),
    #[error(transparent)]
    Registry(#[from] UnreadableRegistry),
}

/// The outbox's handlers and channels this binary has: the agents' audit delivery (`agent_result_audit`, task 2.9) and
/// the SIEM export's (`siem_event`, task 4.2). Java relays eleven types (`reference/outbox/registry.json`); the
/// notifications' channels and token alerts, the checklists' and compliance's deliveries come with Phases 4 and 5.
/// Until all eleven are here the relay task is held — and each one that is here is registered, or the relay would open
/// without it the day the others land: the agents' entries were enqueued by every accepted result and had no handler.
#[must_use]
pub fn outbox_registry(audit: Arc<vectispire_cp_audit::AuditLog>, siem: &crate::siem::Siem) -> Registry {
    Registry::new(
        vec![Arc::new(vectispire_cp_agents::AgentResultAuditDelivery::new(audit)), siem.delivery.clone()],
        Vec::new(),
    )
}

/// Every module's maintenance task.
#[allow(clippy::too_many_arguments)]
pub fn tasks(
    outbox: Arc<Outbox>,
    targets: Arc<Targets>,
    scanning: Arc<Scanning>,
    agents: Arc<Agents>,
    inventory: Arc<Inventory>,
    issues: Arc<vectispire_cp_issues::Issues>,
    gate: Arc<GateModule>,
    settings: Settings,
    clock: Arc<dyn Clock>,
) -> Result<Vec<Arc<dyn MaintenanceTask>>, MaintenanceError> {
    let mut tasks = vectispire_cp_outbox::tasks(outbox)?;
    tasks.extend(vectispire_cp_targets::tasks(targets));
    tasks.extend(vectispire_cp_scanning::tasks(scanning.clone()));
    tasks.push(Arc::new(CredentialedBacklogTask::new(agents.admin.clone())));
    tasks.extend(vectispire_cp_issues::tasks(issues));
    tasks.extend(vectispire_cp_inventory::tasks(
        inventory,
        scanning.catalog().clone(),
        settings.clone(),
        clock.clone(),
    ));
    tasks.extend(gate.tasks(settings, clock));
    Ok(tasks)
}

/// The turns over [`tasks`].
#[allow(clippy::too_many_arguments)]
pub fn turns(
    outbox: Arc<Outbox>,
    targets: Arc<Targets>,
    scanning: Arc<Scanning>,
    agents: Arc<Agents>,
    inventory: Arc<Inventory>,
    issues: Arc<vectispire_cp_issues::Issues>,
    gate: Arc<GateModule>,
    settings: Settings,
    clock: Arc<dyn Clock>,
) -> Result<Turns, MaintenanceError> {
    Ok(Turns::new(tasks(outbox, targets, scanning, agents, inventory, issues, gate, settings, clock)?)?)
}
