//! The composition check: every Java slot filled or deferred, never both, and the list's own form.

#![allow(clippy::unwrap_used, clippy::expect_used)]

use vectispire_cp_maintenance::Sequence;
use vectispire_cp_maintenance::composition::{DEFERRED, check, parse_deferred};

/// The slots a Rust task fills today: the outbox's two (task 2.2), the targets' two (task 2.6), scanning's two (2.7), agents' one (2.9/2.11), inventory's two (Phase 3.2), issues' two (Phase 3.3), gate's one (Phase 3.4), access's one (1.3), wave 1's seven — posture's one, checklists' one, compliance's five — and wave 2's forges' two and threatintel's two.
const FILLED: [Sequence; 26] = [
    Sequence::NotificationRelay,
    Sequence::SentMessages,
    Sequence::RepositoryIdentities,
    Sequence::OrphanedTargetRows,
    Sequence::SchedulingTick,
    Sequence::ScanRetention,
    Sequence::CredentialedBacklog,
    Sequence::InventoryBackfill,
    Sequence::BuildSbomRetention,
    Sequence::TriageExpiry,
    Sequence::SlaBreaches,
    Sequence::GateVerdicts,
    Sequence::SessionCleanup,
    Sequence::ScanMetrics,
    Sequence::AgentMetrics,
    Sequence::WeeklyDigest,
    Sequence::ChecklistReminders,
    Sequence::ComplianceHistory,
    Sequence::OwaspWeeklyCoverage,
    Sequence::ComplianceSnapshots,
    Sequence::OwaspWeeklyRetention,
    Sequence::AbandonedReviews,
    Sequence::ForgeTokenWatch,
    Sequence::ChangeReviews,
    Sequence::KevCatalogue,
    Sequence::EpssScores,
];

/// The filled slots and one more.
fn and(extra: Sequence) -> Vec<Sequence> {
    FILLED.iter().copied().chain([extra]).collect()
}

fn mentions(problems: &[String], needle: &str) -> bool {
    problems.iter().any(|problem| problem.contains(needle))
}

/// The deferred list with `slot`'s line taken out.
fn without(slot: &str) -> String {
    let text: String = DEFERRED
        .lines()
        .filter(|line| !line.starts_with(&format!("{slot} |")))
        .map(|line| format!("{line}\n"))
        .collect();
    assert_ne!(text.lines().count(), DEFERRED.lines().count(), "{slot} is in the list");
    text
}

#[test]
fn the_list_today_is_every_slot_with_its_reason() {
    let entries = parse_deferred(DEFERRED).unwrap();
    assert_eq!(
        entries.len(),
        4,
        "the outbox, the targets, scanning, agents, inventory, issues, gate, access, posture, checklists, compliance, forges, \
         threatintel and the gauges fill twenty-six of Java's thirty"
    );
    assert!(entries.iter().all(|entry| !entry.reason.is_empty()));
    assert!(check(&FILLED, DEFERRED).is_empty());
}

#[test]
fn a_slot_neither_filled_nor_deferred_fails() {
    let problems = check(&FILLED, &without("REPORT_EVIDENCE_RETENTION"));
    assert_eq!(problems.len(), 1, "{problems:#?}");
    assert!(
        mentions(
            &problems,
            "REPORT_EVIDENCE_RETENTION: Java runs ReportEvidenceRetentionTask (reportplugins) on the maintenance turn; no Rust task fills the slot"
        ),
        "{problems:#?}"
    );
    // Filled, it passes.
    assert!(check(&and(Sequence::ReportEvidenceRetention), &without("REPORT_EVIDENCE_RETENTION")).is_empty());
}

#[test]
fn a_slot_filled_and_still_deferred_fails() {
    let problems = check(&and(Sequence::ReportEvidenceRetention), DEFERRED);
    assert_eq!(problems.len(), 1, "{problems:#?}");
    assert!(
        mentions(&problems, "REPORT_EVIDENCE_RETENTION: filled by a Rust task and still in deferred.txt"),
        "{problems:#?}"
    );
}

#[test]
fn the_list_s_own_form_is_checked() {
    let unknown = format!("{DEFERRED}NO_SUCH_SLOT | why\n");
    assert!(mentions(&check(&FILLED, &unknown), "NO_SUCH_SLOT is no slot of MaintenanceTask.Sequence"));
    let twice = format!("{DEFERRED}REPORT_EVIDENCE_RETENTION | again\n");
    assert!(mentions(&check(&FILLED, &twice), "REPORT_EVIDENCE_RETENTION is listed twice"));
    let bare = format!("{}REPORT_EVIDENCE_RETENTION |  \n", without("REPORT_EVIDENCE_RETENTION"));
    assert!(mentions(&check(&FILLED, &bare), "REPORT_EVIDENCE_RETENTION is deferred without a reason"));
    let shapeless = format!("{}REPORT_EVIDENCE_RETENTION\n", without("REPORT_EVIDENCE_RETENTION"));
    assert!(mentions(&check(&FILLED, &shapeless), "`SLOT | reason`, not \"REPORT_EVIDENCE_RETENTION\""));
    // Comments and blank lines are not entries.
    let commented = format!("# a comment | with a bar\n\n{DEFERRED}");
    assert!(check(&FILLED, &commented).is_empty());
    // The line number is the file's, counted from one.
    let first = "BOGUS | x\n";
    assert!(mentions(&parse_deferred(first).unwrap_err(), "deferred.txt:1: BOGUS"));
}
