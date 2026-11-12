//! The cron parser against Spring's answers in `reference/cron/` (`CronReferenceSetTest`, in
//! `vectispire-core`, which alone links Spring): each expression's refusal sentence or its next six fire
//! times from four starts, and the product's crontab reading of it.

#![allow(clippy::unwrap_used, clippy::expect_used, clippy::indexing_slicing)]

use serde_json::{Value, json};
use vectispire_domain::cron::{CronSchedule, crontab};
use vectispire_domain::instant::Instant;

/// The starts Java searched from: near a second's end, a leap day, a year's last nanosecond, a month's end.
const STARTS: [Instant; 4] = [
    Instant { epoch_second: 1_792_240_496, nano: 789_000_000 },
    Instant { epoch_second: 1_709_164_799, nano: 0 },
    Instant { epoch_second: 1_767_225_599, nano: 999_999_999 },
    Instant { epoch_second: 1_801_353_600, nano: 0 },
];

#[test]
fn every_expression_is_read_as_spring_reads_it() {
    let inputs = vectispire_testkit::read_json("cron/inputs.json");
    let answers = vectispire_testkit::read_json("cron/java-answers.json");
    let (inputs, answers) = (inputs.as_array().unwrap(), answers["answers"].as_array().unwrap());
    assert_eq!(inputs.len(), answers.len(), "java-answers.json is regenerated after inputs.json");
    let mut differences = Vec::new();
    let (mut parsed, mut refused) = (0, 0);
    for answer in answers {
        let expression = answer["expression"].as_str().unwrap();
        let spring = match CronSchedule::parse(expression) {
            Ok(schedule) => {
                parsed += 1;
                let chains: Vec<Value> = STARTS
                    .iter()
                    .map(|&start| {
                        let mut chain = Vec::new();
                        let mut from = Some(start);
                        while chain.len() < 6 {
                            let Some(at) = from else { break };
                            from = schedule.next(at);
                            chain.push(json!(from));
                        }
                        Value::from(chain)
                    })
                    .collect();
                json!({ "next": chains })
            }
            Err(refusal) => {
                refused += 1;
                json!({ "refused": refusal.to_string() })
            }
        };
        if spring != answer["spring"] {
            differences.push(format!("{expression:?} spring:\n  java {}\n  rust {spring}", answer["spring"]));
        }
        let stored = crontab::parse(Some(expression));
        let crontab = json!({
            "valid": crontab::is_valid(Some(expression)),
            "schedule": match stored {
                crontab::Stored::Absent => "absent",
                crontab::Stored::Never => "never",
                crontab::Stored::Parsed(_) => "parsed",
            },
            "next": STARTS.iter().map(|&start| json!(stored.next_after(start))).collect::<Vec<_>>(),
        });
        if crontab != answer["crontab"] {
            differences.push(format!("{expression:?} crontab:\n  java {}\n  rust {crontab}", answer["crontab"]));
        }
    }
    assert!(differences.is_empty(), "{} difference(s):\n{}", differences.len(), differences.join("\n"));
    assert!(parsed > 60 && refused > 80, "{parsed} parsed, {refused} refused: the set lost its spread");
}

#[test]
fn an_absent_expression_is_not_a_broken_one() {
    // The distinction the crontab reading exists for: absent runs on the interval, broken never runs.
    assert_eq!(crontab::parse(None), crontab::Stored::Absent);
    assert!(!crontab::is_valid(None));
}
