//! What the running binary composes, against what Java runs — `MaintenanceCompositionTest`'s half of
//! `MaintenanceJobsTest`, for a port that arrives one module at a time.
//!
//! **A wiring that is not exercised is not wired.** `IssueTriageService.expireStale` was called by nothing while its
//! javadoc said "called from the maintenance tick": every service test green, the feature gone. In the Rust binary a
//! task exists only if the composition hands it to [`crate::Turns`], so the composition is checked against Java's
//! twenty-eight slots: each is filled, or named in `data/deferred.txt` with the phase that will fill it. Neither both
//! nor neither — so the list is exactly the slots still missing, and it shrinks by one line the day a module registers
//! its task, in the same commit, or the check fails on the stale line.

use std::collections::BTreeSet;

use crate::task::Sequence;

/// The slots no Rust task fills yet, with who fills them and when.
pub const DEFERRED: &str = include_str!("../data/deferred.txt");

/// One line of `deferred.txt`: `SLOT | reason`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Deferred {
    pub sequence: Sequence,
    pub reason: String,
}

/// Reads the list: `#` comments and blank lines aside, `JAVA_SLOT_NAME | reason` per line.
pub fn parse_deferred(text: &str) -> Result<Vec<Deferred>, Vec<String>> {
    let mut entries = Vec::new();
    let mut problems = Vec::new();
    for (number, line) in text.lines().enumerate() {
        let line = line.trim();
        if line.is_empty() || line.starts_with('#') {
            continue;
        }
        let at = number.saturating_add(1);
        let Some((name, reason)) = line.split_once('|') else {
            problems.push(format!("deferred.txt:{at}: `SLOT | reason`, not {line:?}"));
            continue;
        };
        let (name, reason) = (name.trim(), reason.trim());
        let Some(sequence) = Sequence::from_java_name(name) else {
            problems.push(format!("deferred.txt:{at}: {name} is no slot of MaintenanceTask.Sequence"));
            continue;
        };
        if reason.is_empty() {
            problems.push(format!("deferred.txt:{at}: {name} is deferred without a reason"));
            continue;
        }
        if entries.iter().any(|entry: &Deferred| entry.sequence == sequence) {
            problems.push(format!("deferred.txt:{at}: {name} is listed twice"));
            continue;
        }
        entries.push(Deferred { sequence, reason: reason.to_owned() });
    }
    if problems.is_empty() { Ok(entries) } else { Err(problems) }
}

/// Every way `composition` (the slots the binary fills, as [`crate::Turns::composition`] answers) and the deferred
/// list disagree with Java's slots. Empty when every slot is filled or deferred, and none is both.
pub fn check(composition: &[Sequence], deferred: &str) -> Vec<String> {
    let deferred = match parse_deferred(deferred) {
        Ok(entries) => entries,
        Err(problems) => return problems,
    };
    let filled: BTreeSet<Sequence> = composition.iter().copied().collect();
    let waiting: BTreeSet<Sequence> = deferred.iter().map(|entry| entry.sequence).collect();
    let mut problems = Vec::new();
    for sequence in Sequence::ALL {
        let label = sequence.cadence().label();
        match (filled.contains(&sequence), waiting.contains(&sequence)) {
            (false, false) => problems.push(format!(
                "{}: Java runs {} ({}) on the {label} turn; no Rust task fills the slot and deferred.txt does not \
                 list it — the task is gone, silently, as expireStale was",
                sequence.java_name(),
                sequence.java_task(),
                sequence.module()
            )),
            (true, true) => problems.push(format!(
                "{}: filled by a Rust task and still in deferred.txt; the list only shrinks — remove the line in the \
                 commit that registers the task",
                sequence.java_name()
            )),
            _ => {}
        }
    }
    problems
}
