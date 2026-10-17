//! The module's own rules against Java's answers in `reference/targets/rules.json` (`TargetRulesReferenceSetTest`):
//! the schedule an operator chooses, the cron refusal, the required label, the private-key header and the token's
//! white space — the parts of the reference set that live in this crate, the rest being `vectispire_domain`'s.
//! Then `CronExpressionsTest`, `UnnamedTargetTest`'s naming, and the purge's composition against Java's listeners.

#![allow(clippy::unwrap_used, clippy::expect_used, clippy::indexing_slicing, clippy::panic)]

use std::collections::BTreeSet;

use serde_json::{Value, json};
use vectispire_cp_targets::TargetError;
use vectispire_cp_targets::deletion::{JAVA_LISTENERS, PurgeRegistry};
use vectispire_cp_targets::schedule::{ScheduleChoice, required_label, validated_cron};
use vectispire_cp_targets::{credentials, naming};
use vectispire_domain::cron::crontab;
use vectispire_domain::instant::Instant;
use vectispire_domain::java;

fn outcome(result: Result<Option<String>, TargetError>) -> Value {
    match result {
        Ok(value) => json!({ "value": value }),
        Err(TargetError::Invalid(message)) => json!({ "refused": message }),
        Err(other) => panic!("not a refusal: {other:?}"),
    }
}

#[test]
fn the_rules_answer_as_java_does() {
    let rules = vectispire_testkit::read_json("targets/rules.json");
    let mut differences = Vec::new();
    let mut checked = 0;

    for case in rules["scheduleChoice"].as_array().unwrap() {
        let row = ScheduleChoice {
            manual_only: case["manualOnly"].as_bool().unwrap(),
            interval_minutes: case["intervalMinutes"].as_i64().map(|minutes| i32::try_from(minutes).unwrap()),
            cron: case["cron"].as_str().map(str::to_owned),
        };
        let got = match row.apply(
            case["askManualOnly"].as_bool(),
            case["askIntervalMinutes"].as_i64().map(|minutes| i32::try_from(minutes).unwrap()),
            case["askCron"].as_str(),
        ) {
            Ok(choice) => json!({ "result": {
                "manualOnly": choice.manual_only, "intervalMinutes": choice.interval_minutes, "cron": choice.cron } }),
            Err(TargetError::Invalid(message)) => json!({ "refused": message }),
            Err(other) => panic!("{other:?}"),
        };
        let expected = match case.get("refused") {
            Some(refused) => json!({ "refused": refused }),
            None => json!({ "result": case["result"] }),
        };
        if got != expected {
            differences.push(format!("schedule {case}: Java {expected}, Rust {got}"));
        }
        checked += 1;
    }

    for case in rules["validatedCron"].as_array().unwrap() {
        let got = outcome(validated_cron(case["input"].as_str().unwrap()));
        if got != case["validated"] {
            differences.push(format!("cron {case}: Rust {got}"));
        }
        checked += 1;
    }

    for case in rules["requiredLabel"].as_array().unwrap() {
        let got = outcome(required_label(case["input"].as_str()));
        if got != case["requiredLabel"] {
            differences.push(format!("label {case}: Rust {got}"));
        }
        checked += 1;
    }

    for case in rules["privateKeyHeader"].as_array().unwrap() {
        if credentials::looks_like_a_private_key(case["input"].as_str().unwrap()) != case["matches"].as_bool().unwrap()
        {
            differences.push(format!("private key header {case}"));
        }
        checked += 1;
    }

    for case in rules["tokenWhitespace"].as_array().unwrap() {
        let got = case["input"].as_str().unwrap().chars().any(java::is_whitespace);
        if got != case["whitespace"].as_bool().unwrap() {
            differences.push(format!("token white space {case}"));
        }
        checked += 1;
    }

    assert!(differences.is_empty(), "{} of {checked} differ:\n{}", differences.len(), differences.join("\n"));
}

/// `CronExpressionsTest`, case for case.
#[test]
fn cron_expressions_are_read_as_the_screens_teach_them() {
    // The literal example in both controllers' error message has to work, or the message is instructions nobody
    // can follow.
    for expression in ["0 2 * * *", "0 */6 * * *", "30 3 * * 1"] {
        assert!(crontab::is_valid(Some(expression)), "{expression}");
    }
    // The six-field form still works, so nothing already stored breaks.
    assert!(crontab::is_valid(Some("0 0 2 * * *")));
    // Five fields mean what crontab means: seconds are zero.
    let from = Instant { epoch_second: 1_787_097_600, nano: 0 }; // 2026-08-19T00:00:00Z
    let two = Instant { epoch_second: 1_787_097_600 + 2 * 3_600, nano: 0 };
    assert_eq!(crontab::parse(Some("0 2 * * *")).next_after(from), Some(two));
    assert_eq!(
        crontab::parse(Some("0 2 * * *")).next_after(from),
        crontab::parse(Some("0 0 2 * * *")).next_after(from)
    );
    // Nonsense is refused rather than translated into something plausible.
    for expression in ["0 2 * *", "not a cron", "99 99 * * *"] {
        assert!(!crontab::is_valid(Some(expression)), "{expression}");
    }
    // Absent means "use the interval"; broken must schedule nothing.
    assert_eq!(crontab::parse(Some("")), crontab::Stored::Absent);
    assert_eq!(crontab::parse(Some("not a cron")), crontab::Stored::Never);
    assert_eq!(crontab::parse(Some("not a cron")).next_after(from), None);
    assert!(matches!(validated_cron("0 2 * *"), Err(TargetError::Invalid(_))));
}

/// `UnnamedTargetTest`'s naming half: a repository with no operator-chosen name is named as every screen names it.
/// The remediation plan it also guards is `issues`', Phase 3.
#[test]
fn an_unnamed_target_is_named_like_everywhere_else() {
    assert_eq!(
        naming::repository_name(None, "ssh://git@example.invalid:2222/common/common-libs.git"),
        "common/common-libs"
    );
    assert_eq!(
        naming::repository_name(Some("  "), "ssh://git@example.invalid:2222/common/common-libs.git"),
        "common/common-libs"
    );
    assert_eq!(
        naming::repository_name(Some(" Libs "), "ssh://git@example.invalid:2222/common/common-libs.git"),
        "Libs"
    );
}

/// The purge a binary composes names every listener Java runs, in Java's phases — so that none of them is missing
/// at cut-over without a test saying so (the `MaintenanceJobsTest` lesson: a missing caller is visible only at the
/// level of the composition). Today every one is a stand-in; each owner's port replaces its own.
#[test]
fn the_purge_composes_every_java_listener() {
    let registry = PurgeRegistry::stand_ins();
    let composed: BTreeSet<(&str, &str)> =
        registry.names().iter().map(|(name, _)| (name.module, name.listener)).collect();
    let java: BTreeSet<(&str, &str)> =
        JAVA_LISTENERS.iter().map(|(module, listener, _, _)| (*module, *listener)).collect();
    assert_eq!(composed, java);
    for (name, phase) in registry.names() {
        let declared = JAVA_LISTENERS
            .iter()
            .find(|(module, listener, _, _)| *module == name.module && *listener == name.listener)
            .unwrap()
            .2;
        assert_eq!(phase, declared, "{name:?}");
    }
    let phases: Vec<_> = registry.names().into_iter().map(|(_, phase)| phase).collect();
    assert!(phases.windows(2).all(|pair| pair[0] <= pair[1]), "run in phase order: {phases:?}");
}
