//! The scheduling rule and the queue's rules against Java's answers in `reference/scanning/java-answers.json`
//! (`ScanningReferenceSetTest`, in `vectispire-core`): every mode against every kind of last round and default, the
//! cadence a rule reads, the default interval's SplitMix slots, and what becomes of an attempt that could not run.
//! Written by Java before the port: a reference written after the code tends to agree with the code.

#![allow(clippy::unwrap_used, clippy::expect_used, clippy::indexing_slicing)]

use std::time::Duration;

use serde_json::Value;
use vectispire_domain::cron::crontab;
use vectispire_domain::instant::Instant;
use vectispire_domain::scan_queue::{self, Next, Policy};
use vectispire_domain::schedules::{self, Schedulable};
use vectispire_domain::{FailureKind, ScanTarget};

/// `2026-10-18T12:34:56.789Z`, the instant every case was judged at.
const NOW: Instant = Instant { epoch_second: 1_792_326_896, nano: 789_000_000 };

fn answers() -> Value {
    let answers = vectispire_testkit::read_json("scanning/java-answers.json");
    assert_eq!(answers["now"], "2026-10-18T12:34:56.789Z", "the instant the cases were judged at");
    answers
}

fn opt(part: &str) -> Option<&str> {
    (part != "~").then_some(part)
}

fn target(key: &str) -> ScanTarget {
    let (kind, id) = key.split_once(':').unwrap();
    let id: i64 = id.parse().unwrap();
    if kind == "repo" { ScanTarget::Repository(id) } else { ScanTarget::Container(id) }
}

#[test]
fn every_schedule_is_judged_as_java_judges_it() {
    let answers = answers();
    let mut differences = Vec::new();
    let due = answers["schedules"]["isDue"].as_object().unwrap();
    assert_eq!(due.len(), 1080);
    for (key, expected) in due {
        let parts: Vec<&str> = key.split('|').collect();
        let [manual, cron, interval, days, last] = parts[..] else { panic!("{key}") };
        let stored = crontab::parse(opt(cron));
        let target = Schedulable {
            target: ScanTarget::Repository(42),
            manual_only: manual == "true",
            cron: &stored,
            interval_minutes: opt(interval).map(|minutes| minutes.parse().unwrap()),
            last_scheduled_at: opt(last).map(|seconds| NOW.plus_seconds(-seconds.parse::<i64>().unwrap()).unwrap()),
        };
        let default_minutes = days.parse::<i64>().unwrap() * 24 * 60;
        let in_force = schedules::in_force(target.manual_only, &stored, target.interval_minutes, default_minutes);
        let answer = format!(
            "{}|{}|{}",
            schedules::is_due(&target, default_minutes, NOW),
            in_force.mode.wire_name(),
            in_force.interval_minutes.map_or("~".to_owned(), |minutes| minutes.to_string())
        );
        if &answer != expected {
            differences.push(format!("isDue {key}: java {expected}, rust {answer}"));
        }
    }
    let cadence = answers["schedules"]["runsAtLeastEvery"].as_object().unwrap();
    assert_eq!(cadence.len(), 720);
    for (key, expected) in cadence {
        let parts: Vec<&str> = key.split('|').collect();
        let [manual, cron, interval, days, period] = parts[..] else { panic!("{key}") };
        let stored = crontab::parse(opt(cron));
        let target = Schedulable {
            target: ScanTarget::Repository(42),
            manual_only: manual == "true",
            cron: &stored,
            interval_minutes: opt(interval).map(|minutes| minutes.parse().unwrap()),
            last_scheduled_at: None,
        };
        let answer = schedules::runs_at_least_every(
            &target,
            days.parse::<i64>().unwrap() * 24 * 60,
            period.parse().unwrap(),
            NOW,
        );
        if Value::Bool(answer) != *expected {
            differences.push(format!("runsAtLeastEvery {key}: java {expected}, rust {answer}"));
        }
    }
    assert!(differences.is_empty(), "{} difference(s):\n{}", differences.len(), differences.join("\n"));
}

#[test]
fn every_target_falls_where_java_puts_it_in_the_default_interval() {
    let answers = answers();
    let mut differences = Vec::new();
    let offsets = answers["schedules"]["offsets"].as_object().unwrap();
    assert_eq!(offsets.len(), 12 * 7 * 2);
    for (key, expected) in offsets {
        let (who, interval) = key.split_once('|').unwrap();
        let answer = schedules::offset(target(who), interval.parse().unwrap());
        if expected.as_i64() != Some(answer) {
            differences.push(format!("offset {key}: java {expected}, rust {answer}"));
        }
    }
    let defaults = answers["schedules"]["defaultDue"].as_object().unwrap();
    for (key, expected) in defaults {
        let parts: Vec<&str> = key.split('|').collect();
        let [who, days, last] = parts[..] else { panic!("{key}") };
        let answer = schedules::default_due(
            target(who),
            days.parse::<i64>().unwrap() * 86_400,
            NOW.plus_seconds(-last.parse::<i64>().unwrap()),
            NOW,
        );
        if Value::Bool(answer) != *expected {
            differences.push(format!("defaultDue {key}: java {expected}, rust {answer}"));
        }
    }
    assert!(differences.is_empty(), "{} difference(s):\n{}", differences.len(), differences.join("\n"));
}

#[test]
fn an_attempt_that_could_not_run_ends_as_java_ends_it() {
    let answers = answers();
    let policies = [
        Policy::default_policy(),
        Policy { lease: Duration::from_secs(1_200), max_attempts: 3, claim_attempts: 12, retry_delays: Vec::new() },
        Policy {
            lease: Duration::from_secs(1_200),
            max_attempts: 5,
            claim_attempts: 12,
            retry_delays: vec![Duration::from_secs(30)],
        },
        Policy {
            lease: Duration::from_secs(60),
            max_attempts: 1,
            claim_attempts: 1,
            retry_delays: vec![Duration::from_secs(60), Duration::from_millis(2_500)],
        },
    ];
    let described: Vec<String> = policies
        .iter()
        .map(|policy| {
            let delays: Vec<String> =
                policy.retry_delays.iter().map(|delay| format!("{}ms", delay.as_millis())).collect();
            format!("{}ms|{}|[{}]", policy.lease.as_millis(), policy.max_attempts, delays.join(", "))
        })
        .collect();
    assert_eq!(answers["queue"]["policies"], serde_json::json!(described), "the policies the cases ran under");
    let mut differences = Vec::new();
    let after = answers["queue"]["afterFailure"].as_object().unwrap();
    assert_eq!(after.len(), 4 * 9 * 2);
    for (key, expected) in after {
        let parts: Vec<&str> = key.split('|').collect();
        let [index, attempt, kind] = parts[..] else { panic!("{key}") };
        let kind = if kind == "PERMANENT" { FailureKind::Permanent } else { FailureKind::Transient };
        let policy = &policies[index.parse::<usize>().unwrap()];
        let answer = match scan_queue::after_failure(attempt.parse().unwrap(), kind, NOW, policy) {
            Next::Retry { not_before } => {
                let nanos = (i128::from(not_before.epoch_second) - i128::from(NOW.epoch_second)) * 1_000_000_000
                    + i128::from(not_before.nano)
                    - i128::from(NOW.nano);
                format!("retry:{}ms", nanos / 1_000_000)
            }
            Next::Fail { permanent: true } => "fail:permanent".to_owned(),
            Next::Fail { permanent: false } => "fail:limit".to_owned(),
        };
        if answer != expected.as_str().unwrap() {
            differences.push(format!("afterFailure {key}: java {expected}, rust {answer}"));
        }
    }
    assert!(differences.is_empty(), "{} difference(s):\n{}", differences.len(), differences.join("\n"));
    assert_eq!(answers["queue"]["leaseExhausted"], scan_queue::LEASE_EXHAUSTED_MESSAGE);
}
