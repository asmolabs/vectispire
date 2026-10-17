//! The maintenance tasks the binary composes, against Java's — `MaintenanceCompositionTest`, at the one level where
//! a task nobody runs is visible: the composition itself. Every slot of `MaintenanceTask.Sequence` is filled by a
//! task of `maintenance::tasks()`, or named in `cp-maintenance`'s `data/deferred.txt` with who fills it; none is both.

#![allow(clippy::unwrap_used, clippy::expect_used)]

use vectispire_cp_maintenance::composition::{DEFERRED, check};

#[test]
fn every_java_maintenance_task_is_composed_or_deferred_by_name() {
    let turns = vectispire_cp_app::maintenance::turns().unwrap();
    let problems = check(&turns.composition(), DEFERRED);
    assert!(problems.is_empty(), "the maintenance composition:\n  {}", problems.join("\n  "));
}
