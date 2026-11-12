//! What the periodic tick runs — `MaintenanceJobsTest`, over tasks that record their calls.
//!
//! What is asserted is not what the jobs do, it is that the turns call them: in the global order, each in its own
//! turn, past a task that fails or panics, never twice at once, and at Java's intervals.

#![allow(clippy::unwrap_used, clippy::expect_used)]

use std::sync::{Arc, Mutex};
use std::time::Duration;

use tokio::sync::Notify;
use vectispire_cp_maintenance::{
    Cadence, CompositionError, Intervals, MaintenanceTask, Sequence, TaskRun, Turn, Turns,
};

/// What a recorder does when run.
#[derive(Clone)]
enum Behaviour {
    Succeed,
    Fail(&'static str),
    Panic(&'static str),
    /// Waits for the notification before returning: a slow purge.
    Block(Arc<Notify>),
}

struct Recorder {
    sequence: Sequence,
    log: Arc<Mutex<Vec<Sequence>>>,
    behaviour: Behaviour,
}

impl MaintenanceTask for Recorder {
    fn sequence(&self) -> Sequence {
        self.sequence
    }

    fn run(&self) -> TaskRun<'_> {
        Box::pin(async move {
            self.log.lock().unwrap().push(self.sequence);
            match &self.behaviour {
                Behaviour::Succeed => Ok(()),
                Behaviour::Fail(message) => Err((*message).into()),
                Behaviour::Panic(message) => panic!("{message}"),
                Behaviour::Block(release) => {
                    release.notified().await;
                    Ok(())
                }
            }
        })
    }
}

type Log = Arc<Mutex<Vec<Sequence>>>;

/// Every Java slot filled by a recorder, `special` ones behaving as told, handed to the turns in reverse so that the
/// order can only come from the slots.
fn composition(special: &[(Sequence, Behaviour)]) -> (Turns, Log) {
    let log: Log = Arc::default();
    let tasks: Vec<Arc<dyn MaintenanceTask>> = Sequence::ALL
        .into_iter()
        .rev()
        .map(|sequence| {
            let behaviour = special
                .iter()
                .find(|(which, _)| *which == sequence)
                .map_or(Behaviour::Succeed, |(_, behaviour)| behaviour.clone());
            Arc::new(Recorder { sequence, log: log.clone(), behaviour }) as Arc<dyn MaintenanceTask>
        })
        .collect();
    (Turns::new(tasks).unwrap(), log)
}

fn taken(log: &Log) -> Vec<Sequence> {
    std::mem::take(&mut *log.lock().unwrap())
}

const HOURLY: [Sequence; 24] = [
    Sequence::ScanRetention,
    Sequence::SentMessages,
    Sequence::TicketSweep,
    Sequence::TicketTokenCheck,
    Sequence::ForgeTokenWatch,
    Sequence::InventoryBackfill,
    Sequence::RepositoryIdentities,
    Sequence::TriageExpiry,
    Sequence::SlaBreaches,
    Sequence::WeeklyDigest,
    Sequence::ChecklistReminders,
    Sequence::ComplianceHistory,
    Sequence::OwaspWeeklyCoverage,
    Sequence::SessionCleanup,
    Sequence::GateVerdicts,
    Sequence::ComplianceSnapshots,
    Sequence::OwaspWeeklyRetention,
    Sequence::ReportEvidenceRetention,
    Sequence::BuildSbomRetention,
    Sequence::AbandonedReviews,
    Sequence::KevCatalogue,
    Sequence::EpssScores,
    Sequence::ChangeReviews,
    Sequence::OrphanedTargetRows,
];

#[tokio::test]
async fn the_hourly_turn_runs_everything_it_is_responsible_for_in_its_order() {
    let (turns, log) = composition(&[]);
    let turn = turns.turn(Cadence::Hourly).await;
    assert_eq!(turn, Turn::Ran { ran: HOURLY.to_vec(), failed: Vec::new() });
    assert_eq!(taken(&log), HOURLY.to_vec());
    // The two positions that matter: the expiry before the digest and the compliance capture read the backlog, and
    // the orphaned rows after everything that could still name them.
    let at = |sequence| HOURLY.iter().position(|s| *s == sequence).unwrap();
    assert!(at(Sequence::TriageExpiry) < at(Sequence::WeeklyDigest));
    assert!(at(Sequence::TriageExpiry) < at(Sequence::ComplianceHistory));
    assert_eq!(HOURLY.last(), Some(&Sequence::OrphanedTargetRows));
}

#[tokio::test]
async fn the_hourly_turn_neither_relays_nor_schedules_and_the_others_are_their_own_turns() {
    let (turns, log) = composition(&[]);
    turns.turn(Cadence::Hourly).await;
    let hourly = taken(&log);
    for other in
        [Sequence::NotificationRelay, Sequence::SchedulingTick, Sequence::CredentialedBacklog, Sequence::ReportRunSweep]
    {
        assert!(!hourly.contains(&other), "{other:?} ran on the hourly turn");
    }
    turns.turn(Cadence::Relay).await;
    assert_eq!(taken(&log), [Sequence::NotificationRelay]);
    turns.turn(Cadence::Scheduling).await;
    assert_eq!(taken(&log), [Sequence::SchedulingTick, Sequence::CredentialedBacklog, Sequence::ReportRunSweep]);
    assert_eq!(turns.of(Cadence::Relay), [Sequence::NotificationRelay]);
    assert_eq!(turns.composition(), Sequence::ALL.to_vec(), "the composition, in the global order");
}

#[tokio::test]
async fn a_task_that_fails_or_panics_ends_its_own_run_only_and_the_next_turn_runs() {
    // The first job, one in the middle failing, and one panicking: every other job still runs, in order.
    let (turns, log) = composition(&[
        (Sequence::ScanRetention, Behaviour::Fail("the purge met a lock timeout")),
        (Sequence::TriageExpiry, Behaviour::Panic("an index out of bounds")),
        (Sequence::SessionCleanup, Behaviour::Fail("the connection dropped")),
    ]);
    let turn = turns.turn(Cadence::Hourly).await;
    assert_eq!(
        turn,
        Turn::Ran {
            ran: HOURLY.to_vec(),
            failed: vec![Sequence::ScanRetention, Sequence::TriageExpiry, Sequence::SessionCleanup]
        }
    );
    assert_eq!(taken(&log), HOURLY.to_vec());
    // And the guard was released: one failing job does not silence the tick for ever.
    assert!(matches!(turns.turn(Cadence::Hourly).await, Turn::Ran { .. }));
    assert_eq!(taken(&log), HOURLY.to_vec());
}

#[tokio::test]
async fn a_turn_does_not_start_over_the_top_of_its_cadence_s_running_one() {
    let release = Arc::new(Notify::new());
    let (turns, log) = composition(&[(Sequence::ScanRetention, Behaviour::Block(release.clone()))]);
    let turns = Arc::new(turns);
    let slow = tokio::spawn({
        let turns = turns.clone();
        async move { turns.turn(Cadence::Hourly).await }
    });
    // Wait until the slow purge has started.
    while !log.lock().unwrap().contains(&Sequence::ScanRetention) {
        tokio::task::yield_now().await;
    }
    assert_eq!(turns.turn(Cadence::Hourly).await, Turn::Skipped, "the hourly turn is already running");
    // Another cadence has its own guard.
    assert!(matches!(turns.turn(Cadence::Relay).await, Turn::Ran { .. }));
    release.notify_one();
    assert!(matches!(slow.await.unwrap(), Turn::Ran { .. }));
    // Released: the next one runs.
    let turns_again = turns.clone();
    let next = tokio::spawn(async move { turns_again.turn(Cadence::Hourly).await });
    while log.lock().unwrap().iter().filter(|s| **s == Sequence::ScanRetention).count() < 2 {
        tokio::task::yield_now().await;
    }
    release.notify_one();
    assert!(matches!(next.await.unwrap(), Turn::Ran { .. }));
}

#[tokio::test]
async fn a_turn_dropped_mid_way_releases_its_guard() {
    // A stop drops the turn in the middle of a task; the guard must not stay taken.
    let release = Arc::new(Notify::new());
    let (turns, log) = composition(&[(Sequence::ScanRetention, Behaviour::Block(release))]);
    let dropped = tokio::time::timeout(Duration::from_millis(50), turns.turn(Cadence::Hourly)).await;
    assert!(dropped.is_err(), "the blocked turn was cut");
    assert!(log.lock().unwrap().contains(&Sequence::ScanRetention));
    // The blocked task blocks again, so cut it again: what matters is that it started, i.e. was not Skipped.
    let again = tokio::time::timeout(Duration::from_millis(50), turns.turn(Cadence::Hourly)).await;
    assert!(again.is_err(), "the second turn started instead of being skipped");
    let started = log.lock().unwrap().iter().filter(|s| **s == Sequence::ScanRetention).count();
    assert_eq!(started, 2);
}

#[test]
fn two_tasks_in_one_slot_are_refused() {
    let log: Log = Arc::default();
    let task = |sequence| {
        Arc::new(Recorder { sequence, log: log.clone(), behaviour: Behaviour::Succeed }) as Arc<dyn MaintenanceTask>
    };
    let refused =
        Turns::new(vec![task(Sequence::TriageExpiry), task(Sequence::SlaBreaches), task(Sequence::TriageExpiry)])
            .unwrap_err();
    assert_eq!(refused, CompositionError::TwoTasksInOneSlot(Sequence::TriageExpiry));
    assert_eq!(refused.to_string(), "two tasks fill the slot TRIAGE_EXPIRY (TriageExpiryTask)");
}

#[tokio::test]
async fn an_empty_composition_runs_nothing_and_says_so() {
    let turns = Turns::new(Vec::new()).unwrap();
    assert!(turns.composition().is_empty());
    for cadence in Cadence::ALL {
        assert_eq!(turns.turn(cadence).await, Turn::Ran { ran: Vec::new(), failed: Vec::new() });
    }
}

/// The turns at their intervals, on a paused clock: nothing for the first thirty seconds, then each turn, then each at
/// its own fixed delay after its previous run — until the stop.
#[tokio::test(start_paused = true)]
async fn the_turns_wait_thirty_seconds_then_run_at_their_intervals_until_stopped() {
    let (turns, log) = composition(&[]);
    let turns = Arc::new(turns);
    let stop = Arc::new(Notify::new());
    let running = tokio::spawn({
        let (turns, stop) = (turns.clone(), stop.clone());
        async move { turns.run_until(Intervals::default(), async move { stop.notified().await }).await }
    });
    let count = |sequence: Sequence| log.lock().unwrap().iter().filter(|s| **s == sequence).count();

    tokio::time::sleep(Duration::from_secs(29)).await;
    assert!(log.lock().unwrap().is_empty(), "nothing before the initial delay");
    tokio::time::sleep(Duration::from_secs(2)).await;
    assert_eq!(count(Sequence::NotificationRelay), 1);
    assert_eq!(count(Sequence::SchedulingTick), 1);
    assert_eq!(count(Sequence::ScanRetention), 1);

    // 31 s → 92 s: the minute turns ran once more, the hourly one not.
    tokio::time::sleep(Duration::from_secs(61)).await;
    assert_eq!(count(Sequence::NotificationRelay), 2);
    assert_eq!(count(Sequence::SchedulingTick), 2);
    assert_eq!(count(Sequence::ScanRetention), 1);

    // Past 30 s + 1 h: the hourly turn's second run.
    tokio::time::sleep(Duration::from_secs(3600 - 61)).await;
    assert_eq!(count(Sequence::ScanRetention), 2);
    assert_eq!(count(Sequence::NotificationRelay), 61);

    stop.notify_one();
    running.await.unwrap();
    let before = log.lock().unwrap().len();
    tokio::time::sleep(Duration::from_secs(7200)).await;
    assert_eq!(log.lock().unwrap().len(), before, "nothing runs after the stop");
}

#[test]
fn the_intervals_are_java_s_defaults() {
    let intervals = Intervals::default();
    assert_eq!(intervals.of(Cadence::Relay), Duration::from_secs(60));
    assert_eq!(intervals.of(Cadence::Scheduling), Duration::from_secs(60));
    assert_eq!(intervals.of(Cadence::Hourly), Duration::from_secs(3600));
    assert_eq!(intervals.initial_delay, Duration::from_secs(30));
    let distinct = Intervals {
        relay: Duration::from_secs(1),
        scheduler: Duration::from_secs(2),
        maintenance: Duration::from_secs(3),
        initial_delay: Duration::ZERO,
    };
    assert_eq!(
        Cadence::ALL.map(|cadence| distinct.of(cadence)),
        [Duration::from_secs(1), Duration::from_secs(2), Duration::from_secs(3)]
    );
}
