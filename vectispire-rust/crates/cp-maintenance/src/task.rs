//! The port every module with periodic work implements — Java's `MaintenanceTask`, its `Cadence` and its
//! `Sequence`.
//!
//! **Why a port and not a list of services.** The Java tick once named ten services of eight domains and so sat
//! above all of them; each module now contributes its task beside the service it calls, and this crate names none of
//! them (decision 0029). The Rust crates do the same: a module implements [`MaintenanceTask`] in its own crate and the
//! binary hands the tasks to [`crate::Turns`].
//!
//! **Only work that tolerates being run twice.** No leader election happens here: every instance runs every task. A
//! task that must run once — scheduling scans — elects inside the service it calls (the scheduler's lease, task 2.7),
//! and a task that delivers something claims each item first (the outbox's relay, task 2.2).

use std::future::Future;
use std::pin::Pin;

/// How often a task runs. Three turns, each with its own interval and its own guard, because a single one would have
/// to run at the shortest of the three.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum Cadence {
    /// Every `vectispire.jobs.relay-interval` (one minute): the shortest retry delay of the outbox's backoff, so a
    /// slower turn would make a due message wait longer than intended.
    Relay,
    /// Every `vectispire.jobs.scheduler-interval` (one minute).
    Scheduling,
    /// Every `vectispire.jobs.maintenance-interval` (one hour): the purges walk tables that only change at the rate
    /// scans happen.
    Hourly,
}

impl Cadence {
    /// In Java's declaration order.
    pub const ALL: [Cadence; 3] = [Cadence::Relay, Cadence::Scheduling, Cadence::Hourly];

    /// How the turn names itself when one of its tasks fails — Java's `label()`, word for word, because the
    /// operators' log searches are written against it.
    pub fn label(self) -> &'static str {
        match self {
            Cadence::Relay => "notification relay",
            Cadence::Scheduling => "scheduling tick",
            Cadence::Hourly => "maintenance",
        }
    }

    /// The Java constant's name, as the reference set writes it.
    pub fn java_name(self) -> &'static str {
        match self {
            Cadence::Relay => "RELAY",
            Cadence::Scheduling => "SCHEDULING",
            Cadence::Hourly => "HOURLY",
        }
    }
}

/// One place in the global order of the periodic work — a constant of Java's `MaintenanceTask.Sequence` and the one
/// task that fills it (`MaintenanceJobsTest.COMPOSITION`).
///
/// **One list across every module, not one per crate.** Java sorts every task by `@Order` before splitting them by
/// cadence, and two of the positions matter: the triage decisions expire before the weekly digest and the compliance
/// capture read the backlog, so neither reports an acceptance that lapsed an hour ago; the orphaned rows go last,
/// after everything that could still name them. A per-crate list could not say "after issues' expiry", so the order
/// lives here, every slot reserved — those of modules not ported yet included — and a module's task names its slot.
///
/// **The slot carries the cadence.** In Java a task answers its own `cadence()`; here the slot does, so a task cannot
/// be filed in a turn Java does not run it in. `reference/maintenance/composition.json`, written from the Java tasks
/// themselves, holds every slot's value, owner and cadence.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum Sequence {
    NotificationRelay,
    SchedulingTick,
    /// Beside the scheduling tick: whether scans needing a credential have anyone to take them.
    CredentialedBacklog,
    /// On the scheduler's minute too: the report runs no executor holds or will claim.
    ReportRunSweep,
    ScanRetention,
    SentMessages,
    TicketSweep,
    /// After the sweep, which may just have met a refusal: the tracker token's daily check.
    TicketTokenCheck,
    ForgeTokenWatch,
    InventoryBackfill,
    /// Beside the other backfill: the repository rows V73 and older instances left without their identity.
    RepositoryIdentities,
    TriageExpiry,
    /// After the expiry: an acceptance that lapsed puts its issue back among those whose deadline counts.
    SlaBreaches,
    WeeklyDigest,
    ChecklistReminders,
    ComplianceHistory,
    OwaspWeeklyCoverage,
    SessionCleanup,
    GateVerdicts,
    ComplianceSnapshots,
    OwaspWeeklyRetention,
    ReportEvidenceRetention,
    BuildSbomRetention,
    AbandonedReviews,
    KevCatalogue,
    EpssScores,
    /// After the feeds: the forges' change-review readings, which call a forge for up to the turn's bound.
    ChangeReviews,
    /// Last: after everything that could still name the rows.
    OrphanedTargetRows,
}

/// What Java says of a slot: its constant, its `@Order`, the module and task that fill it, the turn it runs in.
struct Slot {
    java: &'static str,
    order: u32,
    module: &'static str,
    task: &'static str,
    cadence: Cadence,
}

const fn slot(java: &'static str, order: u32, module: &'static str, task: &'static str, cadence: Cadence) -> Slot {
    Slot { java, order, module, task, cadence }
}

impl Sequence {
    /// Every slot, in its order.
    pub const ALL: [Sequence; 28] = [
        Sequence::NotificationRelay,
        Sequence::SchedulingTick,
        Sequence::CredentialedBacklog,
        Sequence::ReportRunSweep,
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

    fn slot(self) -> Slot {
        use Cadence::{Hourly, Relay, Scheduling};
        match self {
            Sequence::NotificationRelay => slot("NOTIFICATION_RELAY", 10, "outbox", "NotificationRelayTask", Relay),
            Sequence::SchedulingTick => slot("SCHEDULING_TICK", 20, "scanning", "SchedulingTickTask", Scheduling),
            Sequence::CredentialedBacklog => {
                slot("CREDENTIALED_BACKLOG", 30, "agents", "CredentialedBacklogTask", Scheduling)
            }
            Sequence::ReportRunSweep => slot("REPORT_RUN_SWEEP", 40, "reportplugins", "ReportRunSweepTask", Scheduling),
            Sequence::ScanRetention => slot("SCAN_RETENTION", 100, "scanning", "ScanRetentionTask", Hourly),
            Sequence::SentMessages => slot("SENT_MESSAGES", 200, "outbox", "SentMessagesTask", Hourly),
            Sequence::TicketSweep => slot("TICKET_SWEEP", 300, "tickets", "TicketSweepTask", Hourly),
            Sequence::TicketTokenCheck => slot("TICKET_TOKEN_CHECK", 310, "tickets", "TicketTokenCheckTask", Hourly),
            Sequence::ForgeTokenWatch => slot("FORGE_TOKEN_WATCH", 320, "forges", "ForgeTokenWatchTask", Hourly),
            Sequence::InventoryBackfill => {
                slot("INVENTORY_BACKFILL", 400, "inventory", "InventoryBackfillTask", Hourly)
            }
            Sequence::RepositoryIdentities => {
                slot("REPOSITORY_IDENTITIES", 410, "targets", "RepositoryIdentityTask", Hourly)
            }
            Sequence::TriageExpiry => slot("TRIAGE_EXPIRY", 500, "issues", "TriageExpiryTask", Hourly),
            Sequence::SlaBreaches => slot("SLA_BREACHES", 510, "issues", "SlaBreachTask", Hourly),
            Sequence::WeeklyDigest => slot("WEEKLY_DIGEST", 600, "posture", "WeeklyDigestTask", Hourly),
            Sequence::ChecklistReminders => {
                slot("CHECKLIST_REMINDERS", 610, "checklists", "ChecklistReminderTask", Hourly)
            }
            Sequence::ComplianceHistory => {
                slot("COMPLIANCE_HISTORY", 700, "compliance", "ComplianceHistoryTask", Hourly)
            }
            Sequence::OwaspWeeklyCoverage => {
                slot("OWASP_WEEKLY_COVERAGE", 710, "compliance", "OwaspWeeklyCoverageTask", Hourly)
            }
            Sequence::SessionCleanup => slot("SESSION_CLEANUP", 800, "access", "SessionCleanupTask", Hourly),
            Sequence::GateVerdicts => slot("GATE_VERDICTS", 810, "gate", "VerdictRetentionTask", Hourly),
            Sequence::ComplianceSnapshots => {
                slot("COMPLIANCE_SNAPSHOTS", 820, "compliance", "SnapshotRetentionTask", Hourly)
            }
            Sequence::OwaspWeeklyRetention => {
                slot("OWASP_WEEKLY_RETENTION", 825, "compliance", "OwaspWeeklyRetentionTask", Hourly)
            }
            Sequence::ReportEvidenceRetention => {
                slot("REPORT_EVIDENCE_RETENTION", 826, "reportplugins", "ReportEvidenceRetentionTask", Hourly)
            }
            Sequence::BuildSbomRetention => {
                slot("BUILD_SBOM_RETENTION", 827, "inventory", "BuildSbomRetentionTask", Hourly)
            }
            Sequence::AbandonedReviews => slot("ABANDONED_REVIEWS", 830, "compliance", "AbandonedReviewsTask", Hourly),
            Sequence::KevCatalogue => slot("KEV_CATALOGUE", 840, "threatintel", "KevCatalogueSyncTask", Hourly),
            Sequence::EpssScores => slot("EPSS_SCORES", 850, "threatintel", "EpssScoresSyncTask", Hourly),
            Sequence::ChangeReviews => slot("CHANGE_REVIEWS", 860, "forges", "ChangeReviewTask", Hourly),
            Sequence::OrphanedTargetRows => {
                slot("ORPHANED_TARGET_ROWS", 900, "targets", "OrphanedTargetRowsTask", Hourly)
            }
        }
    }

    /// Java's `@Order` value. The gaps leave room for a task to be placed without renumbering.
    pub fn order(self) -> u32 {
        self.slot().order
    }

    /// The turn the slot's task runs in.
    pub fn cadence(self) -> Cadence {
        self.slot().cadence
    }

    /// The Java constant, `MaintenanceTask.Sequence.<name>`.
    pub fn java_name(self) -> &'static str {
        self.slot().java
    }

    /// The module whose crate fills the slot.
    pub fn module(self) -> &'static str {
        self.slot().module
    }

    /// The Java task that fills it — the name the log of a failure gives, so that one search finds both programs'.
    pub fn java_task(self) -> &'static str {
        self.slot().task
    }

    /// The slot a Java constant names.
    pub fn from_java_name(name: &str) -> Option<Sequence> {
        Sequence::ALL.into_iter().find(|sequence| sequence.java_name() == name)
    }
}

/// What a task's run fails with. Logged by the turn and swallowed: each task's own service already decided what a
/// failure costs it.
pub type TaskError = Box<dyn std::error::Error + Send + Sync>;

/// A task's run: boxed, because the turns hold every module's tasks behind one trait object.
pub type TaskRun<'a> = Pin<Box<dyn Future<Output = Result<(), TaskError>> + Send + 'a>>;

/// One module's share of the periodic housekeeping.
pub trait MaintenanceTask: Send + Sync {
    /// The place it fills in the global order, which also says its turn.
    fn sequence(&self) -> Sequence;

    /// Runs once. What it returns as an error, or panics with, is logged, and stops neither the tasks after it nor
    /// the next turn.
    fn run(&self) -> TaskRun<'_>;
}
