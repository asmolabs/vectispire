//! The maintenance tasks the binary composes, against Java's — `MaintenanceCompositionTest`, at the one level where
//! a task nobody runs is visible: the composition itself. Every slot of `MaintenanceTask.Sequence` is filled by a
//! task of `maintenance::tasks()`, or named in `cp-maintenance`'s `data/deferred.txt` with who fills it; none is both.
//! And the outbox's relay, composed, is held back while the binary's registry is not Java's.

#![allow(clippy::unwrap_used, clippy::expect_used)]

use std::sync::Arc;

use time::OffsetDateTime;
use uuid::Uuid;
use vectispire_cp_maintenance::SystemClock;
use vectispire_cp_maintenance::composition::{DEFERRED, check};
use vectispire_cp_outbox::{DueMessage, JavaRegistry, NotificationRelayTask, Outbox, OutboxStore, StoreFuture};

/// A store nobody calls: the composition is built, never run.
struct Unused;

impl OutboxStore for Unused {
    fn find_due(&self, _: &'static str, _: OffsetDateTime, _: u32) -> StoreFuture<'_, Vec<DueMessage>> {
        unreachable!("the composition test runs no task")
    }
    fn claim(&self, _: Uuid, _: &'static str, _: OffsetDateTime, _: OffsetDateTime) -> StoreFuture<'_, u64> {
        unreachable!("the composition test runs no task")
    }
    fn record_attempt<'a>(
        &'a self,
        _: Uuid,
        _: i32,
        _: Option<&'a str>,
        _: &'static str,
        _: Option<OffsetDateTime>,
    ) -> StoreFuture<'a, u64> {
        unreachable!("the composition test runs no task")
    }
    fn mark_sent(&self, _: Uuid, _: i32, _: &'static str, _: OffsetDateTime) -> StoreFuture<'_, u64> {
        unreachable!("the composition test runs no task")
    }
    fn delete_sent_before(&self, _: &'static str, _: OffsetDateTime) -> StoreFuture<'_, u64> {
        unreachable!("the composition test runs no task")
    }
    fn count_by_status(&self) -> StoreFuture<'_, Vec<(String, i64)>> {
        unreachable!("the composition test runs no task")
    }
}

fn outbox() -> Arc<Outbox> {
    Arc::new(Outbox::new(Arc::new(Unused), vectispire_cp_app::maintenance::outbox_registry(), Arc::new(SystemClock)))
}

#[test]
fn every_java_maintenance_task_is_composed_or_deferred_by_name() {
    let turns = vectispire_cp_app::maintenance::turns(outbox()).unwrap();
    let problems = check(&turns.composition(), DEFERRED);
    assert!(problems.is_empty(), "the maintenance composition:\n  {}", problems.join("\n  "));
}

#[test]
fn the_binary_s_relay_is_held_until_its_registry_is_java_s() {
    let relay = NotificationRelayTask::new(outbox(), &JavaRegistry::compiled_in().unwrap());
    assert!(relay.is_held(), "the relay would abandon Java's messages of the types this binary lacks");
    assert!(relay.coverage().missing_handlers.contains(&"agent_result_audit".to_owned()), "{}", relay.coverage());
}
