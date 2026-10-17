//! The composition check: every Java slot filled or deferred, never both, and the list's own form.

#![allow(clippy::unwrap_used, clippy::expect_used)]

use vectispire_cp_maintenance::Sequence;
use vectispire_cp_maintenance::composition::{DEFERRED, check, parse_deferred};

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
    assert_eq!(entries.len(), 28, "nothing registers a task yet");
    assert!(entries.iter().all(|entry| !entry.reason.is_empty()));
    assert!(check(&[], DEFERRED).is_empty());
}

#[test]
fn a_slot_neither_filled_nor_deferred_fails() {
    let problems = check(&[], &without("TRIAGE_EXPIRY"));
    assert_eq!(problems.len(), 1, "{problems:#?}");
    assert!(
        mentions(
            &problems,
            "TRIAGE_EXPIRY: Java runs TriageExpiryTask (issues) on the maintenance turn; no Rust task fills the slot"
        ),
        "{problems:#?}"
    );
    // Filled, it passes.
    assert!(check(&[Sequence::TriageExpiry], &without("TRIAGE_EXPIRY")).is_empty());
}

#[test]
fn a_slot_filled_and_still_deferred_fails() {
    let problems = check(&[Sequence::NotificationRelay], DEFERRED);
    assert_eq!(problems.len(), 1, "{problems:#?}");
    assert!(
        mentions(&problems, "NOTIFICATION_RELAY: filled by a Rust task and still in deferred.txt"),
        "{problems:#?}"
    );
}

#[test]
fn the_list_s_own_form_is_checked() {
    let unknown = format!("{DEFERRED}NO_SUCH_SLOT | why\n");
    assert!(mentions(&check(&[], &unknown), "NO_SUCH_SLOT is no slot of MaintenanceTask.Sequence"));
    let twice = format!("{DEFERRED}EPSS_SCORES | again\n");
    assert!(mentions(&check(&[], &twice), "EPSS_SCORES is listed twice"));
    let bare = format!("{}EPSS_SCORES |  \n", without("EPSS_SCORES"));
    assert!(mentions(&check(&[], &bare), "EPSS_SCORES is deferred without a reason"));
    let shapeless = format!("{}EPSS_SCORES\n", without("EPSS_SCORES"));
    assert!(mentions(&check(&[], &shapeless), "`SLOT | reason`, not \"EPSS_SCORES\""));
    // Comments and blank lines are not entries.
    let commented = format!("# a comment | with a bar\n\n{DEFERRED}");
    assert!(check(&[], &commented).is_empty());
    // The line number is the file's, counted from one.
    let first = "BOGUS | x\n";
    assert!(mentions(&parse_deferred(first).unwrap_err(), "deferred.txt:1: BOGUS"));
}
