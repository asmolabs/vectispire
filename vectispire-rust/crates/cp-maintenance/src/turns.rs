//! The periodic housekeeping: three turns, each running the tasks of its cadence in the global order — Java's
//! `MaintenanceJobs`.

use std::collections::BTreeMap;
use std::future::Future;
use std::panic::AssertUnwindSafe;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::Duration;

use futures_util::FutureExt;

use crate::task::{Cadence, MaintenanceTask, Sequence};

/// The turns' timing: `vectispire.jobs.*`, with Java's defaults.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Intervals {
    /// `vectispire.jobs.relay-interval`.
    pub relay: Duration,
    /// `vectispire.jobs.scheduler-interval`.
    pub scheduler: Duration,
    /// `vectispire.jobs.maintenance-interval`.
    pub maintenance: Duration,
    /// `vectispire.jobs.initial-delay`, every turn's wait before its first run.
    ///
    /// **Every turn waits before its first run.** A fixed delay spaces out the runs that follow and does nothing
    /// about the first, which otherwise fires the instant the process is ready — while the migrations have just
    /// finished, the pool is still filling, and an instance about to lose a start-up race for the scheduler's lease
    /// is competing for it. Half a minute costs nothing and removes a whole class of "only on the first tick after a
    /// deploy".
    pub initial_delay: Duration,
}

impl Default for Intervals {
    fn default() -> Self {
        Intervals {
            relay: Duration::from_secs(60),
            scheduler: Duration::from_secs(60),
            maintenance: Duration::from_secs(60 * 60),
            initial_delay: Duration::from_secs(30),
        }
    }
}

impl Intervals {
    /// The fixed delay between two runs of a cadence's turn.
    pub fn of(&self, cadence: Cadence) -> Duration {
        match cadence {
            Cadence::Relay => self.relay,
            Cadence::Scheduling => self.scheduler,
            Cadence::Hourly => self.maintenance,
        }
    }
}

/// A composition the turns refuse.
#[derive(Debug, thiserror::Error, PartialEq, Eq)]
pub enum CompositionError {
    /// Two tasks claim one slot: the order between them would be the order the binary happened to list them in,
    /// which is the decision the slots exist to take.
    #[error("two tasks fill the slot {} ({})", .0.java_name(), .0.java_task())]
    TwoTasksInOneSlot(Sequence),
}

/// What one call of a turn did.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Turn {
    /// The cadence's previous turn was still running, so this one did nothing.
    Skipped,
    /// Every task of the cadence ran, in order; these failed.
    Ran { ran: Vec<Sequence>, failed: Vec<Sequence> },
}

/// The tasks, grouped by cadence in their global order, and a guard per cadence.
pub struct Turns {
    tasks: BTreeMap<Cadence, Vec<Arc<dyn MaintenanceTask>>>,
    running: BTreeMap<Cadence, AtomicBool>,
    composition: Vec<Sequence>,
}

impl std::fmt::Debug for Turns {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.debug_struct("Turns").field("composition", &self.composition()).finish()
    }
}

/// Releases a cadence's guard however its turn ends — returned, panicked through, or dropped by a stop — so that one
/// failure never silences the tick for ever.
struct Release<'a>(&'a AtomicBool);

impl Drop for Release<'_> {
    fn drop(&mut self) {
        self.0.store(false, Ordering::Release);
    }
}

impl Turns {
    /// The turns over `tasks`, in any order: each is placed by its slot.
    pub fn new(tasks: Vec<Arc<dyn MaintenanceTask>>) -> Result<Turns, CompositionError> {
        let mut by_slot: BTreeMap<Sequence, Arc<dyn MaintenanceTask>> = BTreeMap::new();
        for task in tasks {
            let sequence = task.sequence();
            if by_slot.insert(sequence, task).is_some() {
                return Err(CompositionError::TwoTasksInOneSlot(sequence));
            }
        }
        let mut grouped: BTreeMap<Cadence, Vec<Arc<dyn MaintenanceTask>>> =
            Cadence::ALL.into_iter().map(|cadence| (cadence, Vec::new())).collect();
        // The map iterates in `Sequence`'s order, which is Java's `@Order` (`tests/reference.rs` holds the two
        // together), so each turn receives its tasks in the global order, whatever order the binary listed them in.
        let composition: Vec<Sequence> = by_slot.keys().copied().collect();
        for (sequence, task) in by_slot {
            grouped.entry(sequence.cadence()).or_default().push(task);
        }
        let running = Cadence::ALL.into_iter().map(|cadence| (cadence, AtomicBool::new(false))).collect();
        Ok(Turns { tasks: grouped, running, composition })
    }

    /// Every slot filled, in the global order: `MaintenanceCompositionTest`'s list.
    pub fn composition(&self) -> Vec<Sequence> {
        self.composition.clone()
    }

    /// The slots of one cadence's turn, in order.
    pub fn of(&self, cadence: Cadence) -> Vec<Sequence> {
        self.tasks.get(&cadence).into_iter().flatten().map(|task| task.sequence()).collect()
    }

    /// Runs a cadence's tasks unless its turn is already running, each apart from the others.
    ///
    /// **One turn at a time, per cadence.** The loop of [`Turns::run_until`] already waits for the previous run, but a
    /// turn is also callable directly — from a test, from an operations endpoint — and a slow purge on a
    /// long-neglected database must not have the next turn start over the top of it.
    ///
    /// **A task that fails ends its own run, not the turn.** It used to end the turn in Java, when the turn was one
    /// method: a scan-retention purge failing on one database error left the triage decisions unexpired, the weekly
    /// digest unsent and the sessions unpurged, every hour, for as long as the error lasted. The order still holds for
    /// the tasks that run. A panic is a failure like an error — the Java turn caught every `RuntimeException`, and a
    /// panic is what Rust has where Java threw one — and the guard is released either way.
    pub async fn turn(&self, cadence: Cadence) -> Turn {
        let Some(guard) = self.running.get(&cadence) else {
            return Turn::Skipped;
        };
        if guard.compare_exchange(false, true, Ordering::Acquire, Ordering::Relaxed).is_err() {
            return Turn::Skipped;
        }
        let _release = Release(guard);
        let mut ran = Vec::new();
        let mut failed = Vec::new();
        for task in self.tasks.get(&cadence).into_iter().flatten() {
            let sequence = task.sequence();
            ran.push(sequence);
            let outcome = AssertUnwindSafe(task.run()).catch_unwind().await;
            let reason = match outcome {
                Ok(Ok(())) => continue,
                Ok(Err(error)) => error.to_string(),
                Err(panic) => panic_message(panic.as_ref()),
            };
            failed.push(sequence);
            // Logged and swallowed: a housekeeping failure must not bring down the process serving requests. The
            // sentence is Java's, so that one log search finds both programs' failures.
            tracing::error!(
                turn = cadence.label(),
                task = sequence.java_task(),
                "{}: {} failed, the turn goes on: {reason}",
                cadence.label(),
                sequence.java_task()
            );
        }
        Turn::Ran { ran, failed }
    }

    /// Runs the three turns at their intervals until `stop` resolves, each first after the initial delay and then a
    /// fixed delay after the end of its previous run — Spring's `fixedDelay`, not a fixed rate, so a slow turn is never
    /// queued behind itself.
    ///
    /// A stop drops whatever turn is in progress: its task's open transaction rolls back, as a Java task interrupted
    /// by the scheduler's shutdown would. Every task tolerates running again, which is the condition of being here.
    pub async fn run_until(&self, intervals: Intervals, stop: impl Future<Output = ()>) {
        let every = |cadence: Cadence| async move {
            tokio::time::sleep(intervals.initial_delay).await;
            loop {
                self.turn(cadence).await;
                tokio::time::sleep(intervals.of(cadence)).await;
            }
        };
        let turns = async {
            tokio::join!(every(Cadence::Relay), every(Cadence::Scheduling), every(Cadence::Hourly));
        };
        tokio::select! {
            () = turns => {}
            () = stop => {}
        }
    }
}

fn panic_message(panic: &(dyn std::any::Any + Send)) -> String {
    if let Some(text) = panic.downcast_ref::<&str>() {
        format!("panicked: {text}")
    } else if let Some(text) = panic.downcast_ref::<String>() {
        format!("panicked: {text}")
    } else {
        "panicked".to_owned()
    }
}
