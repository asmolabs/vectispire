//! The global order against Java's — `reference/maintenance/composition.json`, written by `MaintenanceReferenceSetTest`
//! from the Java tasks themselves: each slot's constant and value, each task's module, slot and cadence as its own
//! `cadence()` answers, and the intervals `MaintenanceJobs`' `@Scheduled` carries.

#![allow(clippy::unwrap_used, clippy::expect_used)]

use std::path::Path;
use std::time::Duration;

use serde_json::Value;
use vectispire_cp_maintenance::{Cadence, Intervals, Sequence};

fn reference() -> Value {
    let path = Path::new(env!("CARGO_MANIFEST_DIR")).join("../../reference/maintenance/composition.json");
    serde_json::from_str(&std::fs::read_to_string(path).unwrap()).unwrap()
}

#[test]
fn every_slot_of_java_s_sequence_with_its_value() {
    let java = reference();
    let slots: Vec<(String, u64)> = java["sequence"]
        .as_array()
        .unwrap()
        .iter()
        .map(|row| (row["slot"].as_str().unwrap().to_owned(), row["order"].as_u64().unwrap()))
        .collect();
    let rust: Vec<(String, u64)> =
        Sequence::ALL.iter().map(|s| (s.java_name().to_owned(), u64::from(s.order()))).collect();
    assert_eq!(rust, slots, "the slots, in their order");
    for sequence in Sequence::ALL {
        assert_eq!(Sequence::from_java_name(sequence.java_name()), Some(sequence));
    }
    // The turns order their tasks by the type's own order, so it must be Java's: a variant declared out of place
    // would run its task out of place without changing a single value above.
    for pair in Sequence::ALL.windows(2) {
        assert!(pair[0] < pair[1] && pair[0].order() < pair[1].order(), "{pair:?}");
    }
    assert_eq!(Sequence::from_java_name("NO_SUCH_SLOT"), None);
}

#[test]
fn every_java_task_fills_its_slot_in_its_module_on_its_turn() {
    let java = reference();
    let tasks = java["tasks"].as_array().unwrap();
    assert_eq!(tasks.len(), 28, "MaintenanceJobsTest.COMPOSITION");
    let mut seen = Vec::new();
    for row in tasks {
        let slot = row["slot"].as_str().unwrap();
        let sequence = Sequence::from_java_name(slot).unwrap_or_else(|| panic!("{slot} has no Rust slot"));
        assert_eq!(sequence.java_task(), row["task"].as_str().unwrap(), "{slot}");
        assert_eq!(sequence.module(), row["module"].as_str().unwrap(), "{slot}");
        assert_eq!(sequence.cadence().java_name(), row["cadence"].as_str().unwrap(), "{slot}");
        assert_eq!(u64::from(sequence.order()), row["order"].as_u64().unwrap(), "{slot}");
        seen.push(sequence);
    }
    // The composition, in the order Spring injects it: one task per slot, every slot filled in Java.
    assert_eq!(seen, Sequence::ALL.to_vec());
}

/// `${vectispire.jobs.relay-interval:60s}` → 60 s: the default Spring's placeholder carries, in its duration syntax.
fn default_of(placeholder: &str) -> Duration {
    let inner = placeholder.strip_prefix("${").and_then(|rest| rest.strip_suffix('}')).unwrap();
    let (_, value) = inner.split_once(':').unwrap();
    let (number, unit) = value.split_at(value.find(|c: char| !c.is_ascii_digit()).unwrap());
    let number: u64 = number.parse().unwrap();
    match unit {
        "s" => Duration::from_secs(number),
        "m" => Duration::from_secs(number * 60),
        "h" => Duration::from_secs(number * 3600),
        other => panic!("unit {other}"),
    }
}

#[test]
fn the_turns_their_labels_and_their_intervals() {
    let java = reference();
    let cadences = java["cadences"].as_array().unwrap();
    assert_eq!(cadences.len(), 3);
    let intervals = Intervals::default();
    for (row, cadence) in cadences.iter().zip(Cadence::ALL) {
        assert_eq!(cadence.java_name(), row["cadence"].as_str().unwrap());
        assert_eq!(cadence.label(), row["label"].as_str().unwrap());
        assert_eq!(intervals.of(cadence), default_of(row["fixedDelay"].as_str().unwrap()), "{cadence:?}");
        assert_eq!(intervals.initial_delay, default_of(row["initialDelay"].as_str().unwrap()), "{cadence:?}");
    }
    let property = |cadence: Cadence| {
        let row = cadences.iter().find(|row| row["cadence"] == cadence.java_name()).unwrap();
        row["fixedDelay"].as_str().unwrap().to_owned()
    };
    assert!(property(Cadence::Relay).starts_with("${vectispire.jobs.relay-interval:"));
    assert!(property(Cadence::Scheduling).starts_with("${vectispire.jobs.scheduler-interval:"));
    assert!(property(Cadence::Hourly).starts_with("${vectispire.jobs.maintenance-interval:"));
}
