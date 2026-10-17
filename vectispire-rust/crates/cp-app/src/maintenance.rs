//! The maintenance tasks the binary composes — where a module's `MaintenanceTask` becomes a task that runs.
//!
//! **None yet**: the modules whose tasks Phase 2 brings (outbox, scanning, agents, targets) land after
//! `cp-maintenance`, and each adds its task here in the commit that removes its line from
//! `crates/cp-maintenance/data/deferred.txt`. `tests/maintenance_composition.rs` holds this list to Java's
//! twenty-eight slots, which is the level at which a task nobody calls is visible: `IssueTriageService.expireStale`
//! passed its own tests for as long as nothing called it.
//!
//! The turns are not started by `main` yet, because nothing composed needs a database the binary does not open;
//! when one does, `Turns::run_until` runs beside the server with the shutdown signal as its stop, and the relay turn
//! waits until the outbox's handler registry equals Java's (plan §7, Phase 2).

use std::sync::Arc;

use vectispire_cp_maintenance::{CompositionError, MaintenanceTask, Turns};

/// Every module's maintenance task.
#[must_use]
pub fn tasks() -> Vec<Arc<dyn MaintenanceTask>> {
    Vec::new()
}

/// The turns over [`tasks`].
pub fn turns() -> Result<Turns, CompositionError> {
    Turns::new(tasks())
}
