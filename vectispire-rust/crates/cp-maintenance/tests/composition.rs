//! The composition check: every Java slot filled or deferred, never both, and the list's own form.

#![allow(clippy::unwrap_used, clippy::expect_used)]

use vectispire_cp_maintenance::Sequence;
use vectispire_cp_maintenance::composition::{DEFERRED, check, parse_deferred};

/// The slots a Rust task fills today: the outbox's two (task 2.2), the targets' two (task 2.6), scanning's two (2.7), agents' one (2.9/2.11), inventory's two (Phase 3.2), issues' two (Phase 3.3), gate's one (Phase 3.4).
const FILLED: [Sequence; 12] = [
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
        16,
        "the outbox, the targets, scanning, agents, inventory, issues and gate fill twelve of Java's twenty-eight"
    );
    assert!(entries.iter().all(|entry| !entry.reason.is_empty()));
    assert!(check(&FILLED, DEFERRED).is_empty());
}

#[test]
fn a_slot_neither_filled_nor_deferred_fails() {
    let problems = check(&FILLED, &without("WEEKLY_DIGEST"));
    assert_eq!(problems.len(), 1, "{problems:#?}");
    assert!(
        mentions(
            &problems,
            "WEEKLY_DIGEST: Java runs WeeklyDigestTask (posture) on the maintenance turn; no Rust task fills the slot"
        ),
        "{problems:#?}"
    );
    // Filled, it passes.
    assert!(check(&and(Sequence::WeeklyDigest), &without("WEEKLY_DIGEST")).is_empty());
}

#[test]
fn a_slot_filled_and_still_deferred_fails() {
    let problems = check(&and(Sequence::WeeklyDigest), DEFERRED);
    assert_eq!(problems.len(), 1, "{problems:#?}");
    assert!(mentions(&problems, "WEEKLY_DIGEST: filled by a Rust task and still in deferred.txt"), "{problems:#?}");
}

#[test]
fn the_list_s_own_form_is_checked() {
    let unknown = format!("{DEFERRED}NO_SUCH_SLOT | why\n");
    assert!(mentions(&check(&FILLED, &unknown), "NO_SUCH_SLOT is no slot of MaintenanceTask.Sequence"));
    let twice = format!("{DEFERRED}EPSS_SCORES | again\n");
    assert!(mentions(&check(&FILLED, &twice), "EPSS_SCORES is listed twice"));
    let bare = format!("{}EPSS_SCORES |  \n", without("EPSS_SCORES"));
    assert!(mentions(&check(&FILLED, &bare), "EPSS_SCORES is deferred without a reason"));
    let shapeless = format!("{}EPSS_SCORES\n", without("EPSS_SCORES"));
    assert!(mentions(&check(&FILLED, &shapeless), "`SLOT | reason`, not \"EPSS_SCORES\""));
    // Comments and blank lines are not entries.
    let commented = format!("# a comment | with a bar\n\n{DEFERRED}");
    assert!(check(&FILLED, &commented).is_empty());
    // The line number is the file's, counted from one.
    let first = "BOGUS | x\n";
    assert!(mentions(&parse_deferred(first).unwrap_err(), "deferred.txt:1: BOGUS"));
}
