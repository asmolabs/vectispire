//! The outbox's two slots in the maintenance turns — Java's `NotificationRelayTask` and `SentMessagesTask`.

use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};

use vectispire_cp_maintenance::{MaintenanceTask, Sequence, TaskRun};

use crate::{Coverage, JavaRegistry, Outbox, retry};

/// The relay, on the relay turn (every minute), a batch of [`retry::MAX_PER_PASS`] — the policy's number, not one
/// chosen here. Several instances may relay at once: the relay claims each message before sending it.
///
/// **Held back while this binary's handlers differ from Java's.** A relay that does not know a type retries its rows
/// and abandons them after eight attempts; on a database Java wrote — an upgrade, a drill on a copy — that destroys
/// every pending message of the types the port has not reached yet. So the task compares the outbox's registry with
/// the one the started Java application relays with (`reference/outbox/registry.json`) when it is built, and a run
/// while they differ claims nothing, reads nothing, and says why once, at `warn`. The rows wait for a binary that can
/// deliver them, or for Java. Only equality opens it: a type Java does not relay is a row Java would abandon after a
/// switch back.
#[derive(Debug)]
pub struct NotificationRelayTask {
    outbox: Arc<Outbox>,
    coverage: Coverage,
    told: AtomicBool,
}

impl NotificationRelayTask {
    /// The task for `outbox`, held to `java` — [`JavaRegistry::compiled_in`] in the binary.
    pub fn new(outbox: Arc<Outbox>, java: &JavaRegistry) -> NotificationRelayTask {
        let coverage = outbox.registry().coverage(java);
        NotificationRelayTask { outbox, coverage, told: AtomicBool::new(false) }
    }

    /// How the registry differs from Java's; empty when the relay runs.
    pub fn coverage(&self) -> &Coverage {
        &self.coverage
    }

    pub fn is_held(&self) -> bool {
        !self.coverage.is_complete()
    }
}

impl MaintenanceTask for NotificationRelayTask {
    fn sequence(&self) -> Sequence {
        Sequence::NotificationRelay
    }

    fn run(&self) -> TaskRun<'_> {
        Box::pin(async move {
            if self.is_held() {
                if !self.told.swap(true, Ordering::Relaxed) {
                    tracing::warn!(
                        "Outbox relay held back: this binary's handlers are not Java's ({}). No message is claimed \
                         until they are.",
                        self.coverage
                    );
                }
                return Ok(());
            }
            self.outbox.relay(retry::MAX_PER_PASS).await?;
            Ok(())
        })
    }
}

/// The delivered messages purged, on the hourly turn: the table is written on every scan, but the cleanup has no
/// reason to run every minute.
#[derive(Debug)]
pub struct SentMessagesTask {
    outbox: Arc<Outbox>,
}

impl SentMessagesTask {
    pub fn new(outbox: Arc<Outbox>) -> SentMessagesTask {
        SentMessagesTask { outbox }
    }
}

impl MaintenanceTask for SentMessagesTask {
    fn sequence(&self) -> Sequence {
        Sequence::SentMessages
    }

    fn run(&self) -> TaskRun<'_> {
        Box::pin(async move {
            let delivered = self.outbox.prune_sent().await?;
            if delivered > 0 {
                tracing::info!("Maintenance: {delivered} delivered notification(s) purged.");
            }
            Ok(())
        })
    }
}
