//! The gate's decisions without a database, case by case as Java pins them: `PolicyGateTest`, `PolicyResolutionTest`,
//! `SecurityOverviewTest` (vectispire-common), `GatePolicyFieldsTest` and `RegisterCursorTest`. The HTTP answers are the
//! golden replay's; these are what the mutation list (`security/mutants/p3-4-gate.py`) breaks, since the replay is
//! too slow to run once per mutant.

#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use std::collections::HashMap;

use time::macros::datetime;
use vectispire_cp_gate::cursor::RegisterCursor;
use vectispire_cp_gate::overview::{Input, LatestScan, NamedTarget, SecurityOverview};
use vectispire_cp_gate::{
    Coverage, GateError, GateIssue, GatePolicy, GatePolicyFields, GateService, GateVerdict, Observation, PolicyFlag,
    PolicyGate, PolicyLookup, PolicyResolution, PolicyScope, PolicyScopeChoice, PolicySource, RequestedPolicy, Rule,
    ScanTarget, SeverityRequest, StoredPolicy,
};
use vectispire_cp_issues::triage::TriageStatus;
use vectispire_domain::{FindingType, ScanStatus, Severity};

fn issue(id: i64, type_: FindingType, severity: Severity, triage: Option<TriageStatus>) -> GateIssue {
    GateIssue::new(id, true, Some(type_), Some(severity), format!("CVE-{id}"), Some("pkg".into()), None, false, triage)
}

fn kev(id: i64, severity: Severity, triage: Option<TriageStatus>) -> GateIssue {
    GateIssue::new(
        id,
        true,
        Some(FindingType::Vulnerability),
        Some(severity),
        format!("CVE-{id}"),
        None,
        None,
        true,
        triage,
    )
}

/// `GatePolicy(failOnSeverity, failOnKev, fixableOnly, includeTriaged, includeAiReview, uncovered, plugins)`.
fn policy(severity: Option<Severity>, kev: bool, fixable: bool, triaged: bool, ai: bool) -> GatePolicy {
    GatePolicy {
        fail_on_severity: severity,
        fail_on_kev: kev,
        fixable_only: fixable,
        include_triaged: triaged,
        include_ai_review: ai,
        fail_on_uncovered_languages: false,
        include_plugins: false,
    }
}

/// Java's two-argument `evaluate`: one issue's question, where neither coverage nor the target's scans apply.
fn evaluate(issues: &[GateIssue], policy: &GatePolicy) -> GateVerdict {
    PolicyGate::evaluate(issues, policy, &Coverage::NOT_APPLICABLE, None)
}

fn rules(verdict: &GateVerdict) -> Vec<Rule> {
    verdict.violations.iter().map(|violation| violation.rule).collect()
}

fn built_in_with(flag: PolicyFlag, value: bool) -> GatePolicy {
    GatePolicy::BUILT_IN.with_flag(flag, value)
}

mod considered {
    use super::*;

    #[test]
    fn quality_findings_never_fail_a_build_whatever_the_policy_asks() {
        let everything = policy(Some(Severity::Negligible), true, false, true, true);
        let verdict = evaluate(&[issue(1, FindingType::Quality, Severity::Critical, None)], &everything);
        assert!(verdict.passed);
        assert_eq!(verdict.evaluated, 0);
    }

    #[test]
    fn ai_review_findings_are_excluded_by_default_and_countable_on_request() {
        let findings = [issue(1, FindingType::AiReview, Severity::Critical, None)];
        assert!(evaluate(&findings, &GatePolicy::BUILT_IN).passed);
        assert!(!evaluate(&findings, &built_in_with(PolicyFlag::IncludeAiReview, true)).passed);
    }

    #[test]
    fn the_ai_flag_admits_ai_findings_only() {
        let findings = [
            issue(1, FindingType::Plugin, Severity::Critical, None),
            issue(2, FindingType::Imported, Severity::Critical, None),
        ];
        assert!(evaluate(&findings, &GatePolicy::BUILT_IN).passed);
        assert!(evaluate(&findings, &built_in_with(PolicyFlag::IncludeAiReview, true)).passed);
    }

    #[test]
    fn plugin_and_imported_findings_count_when_plugins_are_included_and_ai_still_does_not() {
        let including = built_in_with(PolicyFlag::IncludePlugins, true);
        assert!(!evaluate(&[issue(1, FindingType::Plugin, Severity::Critical, None)], &including).passed);
        assert!(!evaluate(&[issue(2, FindingType::Imported, Severity::Critical, None)], &including).passed);
        assert!(evaluate(&[issue(3, FindingType::AiReview, Severity::Critical, None)], &including).passed);
        const { assert!(!GatePolicy::BUILT_IN.include_plugins) };
    }

    #[test]
    fn a_settled_issue_does_not_fail_a_build_unless_triage_is_included() {
        let findings = [issue(1, FindingType::Vulnerability, Severity::Critical, Some(TriageStatus::NotAffected))];
        assert!(evaluate(&findings, &GatePolicy::BUILT_IN).passed);
        assert!(!evaluate(&findings, &built_in_with(PolicyFlag::IncludeTriaged, true)).passed);
    }

    #[test]
    fn an_issue_still_under_review_keeps_counting() {
        let findings = [issue(1, FindingType::Vulnerability, Severity::Critical, Some(TriageStatus::UnderReview))];
        assert!(!evaluate(&findings, &GatePolicy::BUILT_IN).passed);
    }

    #[test]
    fn a_closed_issue_never_counts() {
        let closed = GateIssue::new(
            1,
            false,
            Some(FindingType::Vulnerability),
            Some(Severity::Critical),
            "CVE-1",
            None,
            None,
            true,
            None,
        );
        assert!(evaluate(&[closed], &GatePolicy::BUILT_IN).passed);
    }

    #[test]
    fn fixable_only_skips_what_has_no_published_fix_blank_included() {
        let fixable_only = built_in_with(PolicyFlag::FixableOnly, true);
        let fix = |versions: Option<&str>| {
            GateIssue::new(
                1,
                true,
                Some(FindingType::Vulnerability),
                Some(Severity::Critical),
                "CVE-1",
                None,
                versions.map(str::to_owned),
                false,
                None,
            )
        };
        assert!(evaluate(&[fix(Some("  "))], &fixable_only).passed);
        assert!(evaluate(&[fix(None)], &fixable_only).passed);
        assert!(!evaluate(&[fix(Some("1.2.3"))], &fixable_only).passed);
        // `isBlank` is Java's whitespace: a no-break space is not one, so Java reads it as a published fix.
        assert!(!evaluate(&[fix(Some("\u{a0}"))], &fixable_only).passed);
        // Without the flag, an unfixable issue counts.
        assert!(!evaluate(&[fix(None)], &GatePolicy::BUILT_IN).passed);
    }
}

mod verdict {
    use super::*;

    #[test]
    fn kev_fails_the_build_whatever_the_severity() {
        let verdict = evaluate(&[kev(1, Severity::Medium, None)], &GatePolicy::BUILT_IN);
        assert!(!verdict.passed);
        assert_eq!(rules(&verdict), [Rule::Kev]);
        assert_eq!(verdict.violations[0].reason, "actively exploited vulnerability (CISA KEV catalog)");
    }

    #[test]
    fn one_violation_per_issue_not_one_per_rule_tripped() {
        let verdict = evaluate(&[kev(1, Severity::Critical, None)], &GatePolicy::BUILT_IN);
        assert_eq!(rules(&verdict), [Rule::Kev]);
    }

    #[test]
    fn unknown_severity_ranks_below_low_and_does_not_fail_a_build() {
        let verdict = evaluate(&[issue(1, FindingType::Vulnerability, Severity::Unknown, None)], &GatePolicy::BUILT_IN);
        assert!(verdict.passed);
    }

    #[test]
    fn the_threshold_itself_fails_and_the_severity_below_it_does_not() {
        let high = evaluate(&[issue(1, FindingType::Vulnerability, Severity::High, None)], &GatePolicy::BUILT_IN);
        assert_eq!(rules(&high), [Rule::Severity]);
        assert_eq!(high.violations[0].reason, "severity high >= threshold high");
        assert_eq!(high.violations[0].issue_id, Some(1));
        assert!(
            evaluate(&[issue(2, FindingType::Vulnerability, Severity::Medium, None)], &GatePolicy::BUILT_IN).passed
        );
    }

    #[test]
    fn counts_by_severity_cover_what_was_evaluated_not_what_violated() {
        let verdict = evaluate(
            &[
                issue(1, FindingType::Vulnerability, Severity::Critical, None),
                issue(2, FindingType::Vulnerability, Severity::Low, None),
                issue(3, FindingType::Vulnerability, Severity::Low, None),
            ],
            &GatePolicy::BUILT_IN,
        );
        assert_eq!(verdict.evaluated, 3);
        assert_eq!(verdict.counts_by_severity.get(&Severity::Critical), Some(&1));
        assert_eq!(verdict.counts_by_severity.get(&Severity::Low), Some(&2));
        assert_eq!(verdict.violations.len(), 1);
    }

    #[test]
    fn a_null_threshold_disables_the_severity_rule_without_disabling_kev() {
        let kev_only = policy(None, true, false, false, false);
        assert!(evaluate(&[issue(1, FindingType::Vulnerability, Severity::Critical, None)], &kev_only).passed);
        assert!(!evaluate(&[kev(2, Severity::Low, None)], &kev_only).passed);
    }

    #[test]
    fn kev_off_lets_an_exploited_low_through() {
        let no_kev = policy(Some(Severity::High), false, false, false, false);
        assert!(evaluate(&[kev(2, Severity::Low, None)], &no_kev).passed);
    }
}

mod harden {
    use super::*;

    #[test]
    fn a_request_that_says_nothing_changes_nothing_and_complains_about_nothing() {
        let hardened = PolicyGate::harden(GatePolicy::BUILT_IN, &RequestedPolicy::none());
        assert_eq!(hardened.policy, GatePolicy::BUILT_IN);
        assert!(hardened.ignored_relaxations.is_empty());
    }

    #[test]
    fn a_lower_threshold_is_accepted_because_it_fails_on_more() {
        let requested = RequestedPolicy::none().with_severity(SeverityRequest::Threshold(Severity::Low));
        let hardened = PolicyGate::harden(GatePolicy::BUILT_IN, &requested);
        assert_eq!(hardened.policy.fail_on_severity, Some(Severity::Low));
        assert!(hardened.ignored_relaxations.is_empty());
    }

    #[test]
    fn a_higher_threshold_is_refused_and_the_caller_is_told() {
        let requested = RequestedPolicy::none().with_severity(SeverityRequest::Threshold(Severity::Critical));
        let hardened = PolicyGate::harden(GatePolicy::BUILT_IN, &requested);
        assert_eq!(hardened.policy.fail_on_severity, Some(Severity::High));
        assert_eq!(hardened.ignored_relaxations, ["fail_on_severity"]);
    }

    #[test]
    fn the_same_threshold_is_neither_a_change_nor_a_relaxation() {
        let requested = RequestedPolicy::none().with_severity(SeverityRequest::Threshold(Severity::High));
        let hardened = PolicyGate::harden(GatePolicy::BUILT_IN, &requested);
        assert_eq!(hardened.policy, GatePolicy::BUILT_IN);
        assert!(hardened.ignored_relaxations.is_empty());
    }

    #[test]
    fn switching_the_severity_rule_off_is_refused() {
        let requested = RequestedPolicy::none().with_severity(SeverityRequest::Disabled);
        let hardened = PolicyGate::harden(GatePolicy::BUILT_IN, &requested);
        assert_eq!(hardened.policy.fail_on_severity, Some(Severity::High));
        assert_eq!(hardened.ignored_relaxations, ["fail_on_severity"]);
    }

    #[test]
    fn switching_off_a_rule_that_was_already_off_is_not_a_relaxation() {
        let requested = RequestedPolicy::none().with_severity(SeverityRequest::Disabled);
        let hardened = PolicyGate::harden(policy(None, true, false, false, false), &requested);
        assert!(hardened.ignored_relaxations.is_empty());
    }

    #[test]
    fn adding_a_threshold_where_there_was_none_is_a_tightening() {
        let requested = RequestedPolicy::none().with_severity(SeverityRequest::Threshold(Severity::Critical));
        let hardened = PolicyGate::harden(policy(None, true, false, false, false), &requested);
        assert_eq!(hardened.policy.fail_on_severity, Some(Severity::Critical));
        assert!(hardened.ignored_relaxations.is_empty());
    }

    #[test]
    fn turning_fixable_only_on_is_a_relaxation() {
        let requested = RequestedPolicy::none().with_flag(PolicyFlag::FixableOnly, true);
        let hardened = PolicyGate::harden(GatePolicy::BUILT_IN, &requested);
        assert!(!hardened.policy.fixable_only);
        assert_eq!(hardened.ignored_relaxations, ["fixable_only"]);
    }

    #[test]
    fn turning_kev_off_is_refused_and_asking_for_triage_to_count_is_granted() {
        let requested =
            RequestedPolicy::none().with_flag(PolicyFlag::FailOnKev, false).with_flag(PolicyFlag::IncludeTriaged, true);
        let hardened = PolicyGate::harden(GatePolicy::BUILT_IN, &requested);
        assert!(hardened.policy.fail_on_kev);
        assert!(hardened.policy.include_triaged);
        assert_eq!(hardened.ignored_relaxations, ["fail_on_kev"]);
    }

    #[test]
    fn a_flag_asked_at_the_value_it_already_has_is_silent() {
        // At its strict value, and at its lax one: asking for what is already there relaxes nothing.
        let requested =
            RequestedPolicy::none().with_flag(PolicyFlag::FailOnKev, true).with_flag(PolicyFlag::IncludeTriaged, false);
        let hardened = PolicyGate::harden(GatePolicy::BUILT_IN, &requested);
        assert_eq!(hardened.policy, GatePolicy::BUILT_IN);
        assert!(hardened.ignored_relaxations.is_empty());
    }

    #[test]
    fn relaxations_are_reported_in_the_order_of_the_flags() {
        // `PolicyFlag.values()` order, which is what Java's loop walks and the answer's array shows.
        let requested = RequestedPolicy::none()
            .with_flag(PolicyFlag::FixableOnly, true)
            .with_flag(PolicyFlag::FailOnKev, false)
            .with_severity(SeverityRequest::Disabled);
        let hardened = PolicyGate::harden(GatePolicy::BUILT_IN, &requested);
        assert_eq!(hardened.ignored_relaxations, ["fail_on_severity", "fail_on_kev", "fixable_only"]);
    }
}

mod coverage {
    use super::*;

    fn nothing_reached() -> Coverage {
        Coverage::new(vec!["maven".into(), "npm".into()])
    }

    #[test]
    fn passes_a_target_no_rule_covers_until_somebody_asks_it_not_to() {
        let verdict = PolicyGate::evaluate(&[], &GatePolicy::BUILT_IN, &nothing_reached(), Some(Observation::Ok));
        assert!(verdict.passed);
        assert!(verdict.violations.is_empty());
    }

    #[test]
    fn refuses_it_once_the_flag_is_on_and_names_the_ecosystems_nothing_reached() {
        let strict = built_in_with(PolicyFlag::FailOnUncoveredLanguages, true);
        let verdict = PolicyGate::evaluate(&[], &strict, &nothing_reached(), Some(Observation::Ok));
        assert!(!verdict.passed);
        assert_eq!(rules(&verdict), [Rule::Coverage]);
        assert_eq!(verdict.violations[0].issue_id, None);
        assert_eq!(
            verdict.violations[0].reason,
            "no installed rule covers maven, npm — this target's code was not examined"
        );
    }

    #[test]
    fn says_nothing_when_every_ecosystem_is_covered() {
        let strict = built_in_with(PolicyFlag::FailOnUncoveredLanguages, true);
        assert!(PolicyGate::evaluate(&[], &strict, &Coverage::new(Vec::new()), Some(Observation::Ok)).passed);
    }

    #[test]
    fn does_not_apply_where_the_verdict_is_about_one_issue() {
        assert!(evaluate(&[], &built_in_with(PolicyFlag::FailOnUncoveredLanguages, true)).passed);
    }

    #[test]
    fn a_caller_cannot_switch_it_off_once_a_policy_has_switched_it_on() {
        let strict = built_in_with(PolicyFlag::FailOnUncoveredLanguages, true);
        let requested = RequestedPolicy::none().with_flag(PolicyFlag::FailOnUncoveredLanguages, false);
        let hardened = PolicyGate::harden(strict, &requested);
        assert!(hardened.policy.fail_on_uncovered_languages);
        assert_eq!(hardened.ignored_relaxations, ["fail_on_uncovered_languages"]);
    }
}

mod observation_clause {
    use super::*;

    const COVERED: Coverage = Coverage::NOT_APPLICABLE;

    #[test]
    fn refuses_a_target_never_scanned_with_no_issue_behind_the_violation() {
        let verdict = PolicyGate::evaluate(&[], &GatePolicy::BUILT_IN, &COVERED, Some(Observation::NeverScanned));
        assert!(!verdict.passed);
        assert_eq!(verdict.evaluated, 0);
        assert_eq!(rules(&verdict), [Rule::Observation]);
        assert_eq!(verdict.violations[0].issue_id, None);
        assert_eq!(verdict.violations[0].severity, None);
        assert!(verdict.violations[0].reason.contains("never examined"));
    }

    #[test]
    fn refuses_a_target_whose_last_scan_failed_and_says_so() {
        let verdict = PolicyGate::evaluate(&[], &GatePolicy::BUILT_IN, &COVERED, Some(Observation::LastScanFailed));
        assert!(!verdict.passed);
        assert_eq!(rules(&verdict), [Rule::Observation]);
        assert!(verdict.violations[0].reason.contains("last scan of this target failed"));
    }

    #[test]
    fn refuses_whatever_the_policy_says_the_laxest_included() {
        let laxest = policy(None, false, true, false, false);
        for unexamined in [Observation::NeverScanned, Observation::LastScanFailed] {
            let verdict = PolicyGate::evaluate(&[], &laxest, &COVERED, Some(unexamined));
            assert!(!verdict.passed, "{unexamined:?}");
            assert_eq!(rules(&verdict), [Rule::Observation]);
        }
    }

    #[test]
    fn comes_first_before_the_findings_a_stale_backlog_still_holds() {
        let verdict = PolicyGate::evaluate(
            &[issue(1, FindingType::Vulnerability, Severity::Critical, None)],
            &GatePolicy::BUILT_IN,
            &COVERED,
            Some(Observation::LastScanFailed),
        );
        assert_eq!(rules(&verdict), [Rule::Observation, Rule::Severity]);
        assert_eq!(verdict.evaluated, 1);
    }

    #[test]
    fn says_nothing_about_a_target_whose_newest_finished_scan_completed() {
        let verdict = PolicyGate::evaluate(&[], &GatePolicy::BUILT_IN, &COVERED, Some(Observation::Ok));
        assert!(verdict.passed);
        assert!(verdict.violations.is_empty());
    }

    #[test]
    fn a_scan_status_reads_as_its_observation() {
        assert_eq!(Observation::of(None), Observation::NeverScanned);
        assert_eq!(Observation::of(Some(ScanStatus::Failed)), Observation::LastScanFailed);
        assert_eq!(Observation::of(Some(ScanStatus::Completed)), Observation::Ok);
        assert_eq!(Observation::of(Some(ScanStatus::Pending)), Observation::InProgress);
        assert_eq!(Observation::of(Some(ScanStatus::Scanning)), Observation::InProgress);
        assert!(Observation::Ok.examined());
        assert!(!Observation::InProgress.examined());
    }
}

mod resolution {
    use super::*;

    fn global() -> StoredPolicy {
        StoredPolicy { policy: policy(Some(Severity::Medium), true, false, false, false), version: 4 }
    }

    fn for_target() -> StoredPolicy {
        StoredPolicy { policy: policy(Some(Severity::Low), true, false, false, false), version: 9 }
    }

    fn lookup(target: Option<StoredPolicy>, global: Option<StoredPolicy>) -> PolicyLookup {
        PolicyLookup { for_target: target, global }
    }

    #[test]
    fn a_target_s_policy_replaces_the_global_one_entirely() {
        let resolved = PolicyResolution::resolve(
            lookup(Some(for_target()), Some(global())),
            &RequestedPolicy::none(),
            PolicyScopeChoice::Target,
        );
        assert_eq!(resolved.policy, for_target().policy);
        assert_eq!(resolved.source, PolicySource::Target);
        assert_eq!(resolved.version, Some(9));
        assert_eq!(resolved.describe_source(), "the target's policy v9");
    }

    #[test]
    fn without_one_of_its_own_a_target_falls_back_to_the_global_policy() {
        let resolved = PolicyResolution::resolve(
            lookup(None, Some(global())),
            &RequestedPolicy::none(),
            PolicyScopeChoice::Target,
        );
        assert_eq!(resolved.source, PolicySource::Global);
        assert_eq!(resolved.describe_source(), "the global policy v4");
    }

    #[test]
    fn a_question_about_the_organization_ignores_any_target_policy() {
        let resolved = PolicyResolution::resolve(
            lookup(Some(for_target()), Some(global())),
            &RequestedPolicy::none(),
            PolicyScopeChoice::Global,
        );
        assert_eq!(resolved.source, PolicySource::Global);
        assert_eq!(resolved.policy, global().policy);
    }

    #[test]
    fn with_nothing_stored_the_built_in_policy_applies_and_carries_no_version() {
        let resolved =
            PolicyResolution::resolve(lookup(None, None), &RequestedPolicy::none(), PolicyScopeChoice::Target);
        assert_eq!(resolved.policy, GatePolicy::BUILT_IN);
        assert_eq!(resolved.source, PolicySource::BuiltIn);
        assert_eq!(resolved.version, None);
        assert_eq!(resolved.describe_source(), "the application's default policy");
    }

    #[test]
    fn a_caller_s_request_tightens_the_resolved_policy_and_reports_what_it_could_not() {
        let requested = RequestedPolicy::none()
            .with_severity(SeverityRequest::Threshold(Severity::Critical))
            .with_flag(PolicyFlag::IncludeTriaged, true);
        let resolved = PolicyResolution::resolve(lookup(None, Some(global())), &requested, PolicyScopeChoice::Target);
        assert_eq!(resolved.policy.fail_on_severity, Some(Severity::Medium));
        assert!(resolved.policy.include_triaged);
        assert_eq!(resolved.ignored_relaxations, ["fail_on_severity"]);
    }

    #[test]
    fn the_sources_are_named_as_the_wire_names_them() {
        assert_eq!(PolicySource::Target.wire_name(), "target");
        assert_eq!(PolicySource::Global.wire_name(), "global");
        assert_eq!(PolicySource::BuiltIn.wire_name(), "built-in");
    }
}

mod fields {
    use super::*;

    fn fields(severity: Option<&str>, kev: Option<bool>) -> GatePolicyFields {
        GatePolicyFields::new(severity.map(str::to_owned), kev, Some(false), Some(false), Some(false), None, None)
    }

    fn refusal(result: Result<impl std::fmt::Debug, GateError>) -> String {
        match result {
            Err(GateError::InvalidInput(message)) => message,
            other => panic!("expected a refusal, got {other:?}"),
        }
    }

    #[test]
    fn an_absent_field_is_not_mentioned() {
        assert_eq!(GatePolicyFields::default().as_request().unwrap(), RequestedPolicy::none());
    }

    #[test]
    fn a_sent_flag_is_mentioned_false_included() {
        let requested =
            GatePolicyFields::new(None, Some(false), None, None, None, None, Some(true)).as_request().unwrap();
        let expected =
            RequestedPolicy::none().with_flag(PolicyFlag::FailOnKev, false).with_flag(PolicyFlag::IncludePlugins, true);
        assert_eq!(requested, expected);
        assert_eq!(requested.fail_on_severity, SeverityRequest::Unset);
    }

    #[test]
    fn every_flag_of_a_request_reaches_its_own_knob() {
        let requested = GatePolicyFields::new(None, Some(true), Some(false), Some(true), Some(false), Some(true), None)
            .as_request()
            .unwrap();
        let expected = RequestedPolicy::none()
            .with_flag(PolicyFlag::FailOnKev, true)
            .with_flag(PolicyFlag::FixableOnly, false)
            .with_flag(PolicyFlag::IncludeTriaged, true)
            .with_flag(PolicyFlag::IncludeAiReview, false)
            .with_flag(PolicyFlag::FailOnUncoveredLanguages, true);
        assert_eq!(requested, expected);
    }

    #[test]
    fn none_disables_the_threshold_whatever_its_case_and_padding() {
        for none in ["None", " none ", "NONE", "\u{1}none\t"] {
            assert_eq!(
                fields(Some(none), None).as_request().unwrap().fail_on_severity,
                SeverityRequest::Disabled,
                "{none:?}"
            );
        }
        // `String.trim` stops at U+0020: a no-break space is not padding, so this is an unknown severity.
        assert_eq!(refusal(fields(Some("\u{a0}none"), None).as_request()), "Unknown severity: \"\u{a0}none\".");
    }

    #[test]
    fn a_severity_is_a_threshold() {
        assert_eq!(
            fields(Some("critical"), None).as_request().unwrap().fail_on_severity,
            SeverityRequest::Threshold(Severity::Critical)
        );
        assert_eq!(
            fields(Some(" High "), None).as_request().unwrap().fail_on_severity,
            SeverityRequest::Threshold(Severity::High)
        );
    }

    #[test]
    fn an_unreadable_severity_is_refused_never_read_as_unknown() {
        assert_eq!(refusal(fields(Some("hgh"), None).as_request()), "Unknown severity: \"hgh\".");
        assert_eq!(refusal(fields(Some(""), None).as_request()), "Unknown severity: \"\".");
        assert_eq!(refusal(fields(Some("unknown"), None).as_request()), "Unknown severity: \"unknown\".");
    }

    #[test]
    fn as_a_replacement_every_field_is_carried() {
        let policy = GatePolicyFields::new(
            Some("medium".into()),
            Some(false),
            Some(true),
            Some(true),
            Some(true),
            Some(true),
            Some(true),
        )
        .as_replacement()
        .unwrap();
        assert_eq!(
            policy,
            GatePolicy {
                fail_on_severity: Some(Severity::Medium),
                fail_on_kev: false,
                fixable_only: true,
                include_triaged: true,
                include_ai_review: true,
                fail_on_uncovered_languages: true,
                include_plugins: true,
            }
        );
    }

    #[test]
    fn as_a_replacement_none_is_the_severity_rule_off() {
        assert_eq!(fields(Some(" NONE "), Some(true)).as_replacement().unwrap().fail_on_severity, None);
    }

    #[test]
    fn as_a_replacement_an_absent_or_blank_severity_is_refused() {
        let required = "\"fail_on_severity\" is required — a severity, or \"none\" to switch the rule off.";
        assert_eq!(refusal(fields(None, Some(true)).as_replacement()), required);
        assert_eq!(refusal(fields(Some("  "), Some(true)).as_replacement()), required);
        // Not blank to Java: the no-break space reaches `Severity.of`, which does not know it.
        assert_eq!(refusal(fields(Some("\u{a0}"), Some(true)).as_replacement()), "Unknown severity: \"\u{a0}\".");
    }

    #[test]
    fn as_a_replacement_an_unreadable_severity_is_refused() {
        assert_eq!(
            refusal(fields(Some("catastrophic"), Some(true)).as_replacement()),
            "Unknown severity: \"catastrophic\"."
        );
    }

    #[test]
    fn as_a_replacement_an_absent_flag_is_refused_each_by_its_name() {
        assert_eq!(refusal(fields(Some("high"), None).as_replacement()), "\"fail_on_kev\" is required.");
        let missing = |fixable, triaged, ai| {
            refusal(
                GatePolicyFields::new(Some("high".into()), Some(true), fixable, triaged, ai, None, None)
                    .as_replacement(),
            )
        };
        assert_eq!(missing(None, Some(true), Some(true)), "\"fixable_only\" is required.");
        assert_eq!(missing(Some(true), None, Some(true)), "\"include_triaged\" is required.");
        assert_eq!(missing(Some(true), Some(true), None), "\"include_ai_review\" is required.");
    }

    #[test]
    fn as_a_replacement_the_two_newest_flags_may_be_absent_and_absent_is_off() {
        let policy = fields(Some("high"), Some(true)).as_replacement().unwrap();
        assert!(!policy.fail_on_uncovered_languages);
        assert!(!policy.include_plugins);
    }
}

mod targets {
    use super::*;

    #[test]
    fn a_verdict_names_exactly_one_target() {
        assert_eq!(GateService::verdict_target(Some(7), None).unwrap(), ScanTarget::Repository(7));
        assert_eq!(GateService::verdict_target(None, Some(3)).unwrap(), ScanTarget::Container(3));
        for (repository, container) in [(Some(7), Some(3)), (None, None)] {
            match GateService::verdict_target(repository, container) {
                Err(GateError::InvalidInput(message)) => {
                    assert_eq!(message, "Give exactly one of \"repository_id\" or \"container_id\".");
                }
                other => panic!("expected a refusal, got {other:?}"),
            }
        }
    }

    #[test]
    fn a_policy_path_names_a_repository_or_a_container_nothing_else() {
        let scope = PolicyScope::of("repository", 7).unwrap();
        assert_eq!((scope.kind.as_str(), scope.id), ("repository", 7));
        let scope = PolicyScope::of("container", 3).unwrap();
        assert_eq!((scope.kind.as_str(), scope.id), ("container", 3));
        for kind in ["global", "Repository", ""] {
            match PolicyScope::of(kind, 0) {
                Err(GateError::InvalidInput(message)) => assert!(message.contains("Unknown target kind"), "{message}"),
                other => panic!("{kind:?}: expected a refusal, got {other:?}"),
            }
        }
    }
}

mod overview {
    use super::*;

    const REPO: ScanTarget = ScanTarget::Repository(1);
    const IMAGE: ScanTarget = ScanTarget::Container(1);

    fn scan(status: ScanStatus) -> LatestScan {
        LatestScan { id: 7, status, created_at: datetime!(2026-08-10 08:00:00 UTC) }
    }

    fn critical(id: i64) -> GateIssue {
        issue(id, FindingType::Vulnerability, Severity::Critical, None)
    }

    fn input(
        issues: HashMap<ScanTarget, Vec<GateIssue>>,
        scans: HashMap<ScanTarget, LatestScan>,
        finished: HashMap<ScanTarget, LatestScan>,
    ) -> Input {
        Input {
            targets: vec![
                NamedTarget { target: REPO, name: "api-service".into() },
                NamedTarget { target: IMAGE, name: "api-image".into() },
            ],
            policies_by_target: HashMap::new(),
            global_policy: None,
            open_issues: issues,
            latest_scans: scans,
            latest_finished_scans: finished,
            uncovered_ecosystems: HashMap::new(),
        }
    }

    fn finished(scans: HashMap<ScanTarget, LatestScan>) -> Input {
        input(HashMap::new(), scans.clone(), scans)
    }

    #[test]
    fn a_repository_and_a_container_sharing_an_id_are_two_different_targets() {
        let scans = HashMap::from([(REPO, scan(ScanStatus::Completed)), (IMAGE, scan(ScanStatus::Completed))]);
        let overview = SecurityOverview::build(input(HashMap::from([(REPO, vec![critical(1)])]), scans.clone(), scans));
        let image = overview.targets.iter().find(|posture| posture.target == IMAGE).unwrap();
        assert!(image.passed);
        assert_eq!(overview.failing_count, 1);
        assert_eq!(overview.total_count, 2);
        // A critical's violation is not an exploited one: the banner counts KEV violations alone.
        assert_eq!(overview.kev_count, 0);
    }

    #[test]
    fn a_target_never_scanned_fails_and_says_it_was_never_looked_at() {
        let overview = SecurityOverview::build(finished(HashMap::new()));
        for posture in &overview.targets {
            assert!(!posture.passed);
            assert_eq!(rules(&posture.verdict), [Rule::Observation]);
            assert!(!posture.observed);
            assert_eq!(posture.observation, Observation::NeverScanned);
        }
        assert_eq!(overview.never_scanned_count, 2);
        assert_eq!(overview.failing_count, 2);
    }

    #[test]
    fn a_target_whose_last_scan_failed_is_not_observed_either() {
        let overview = SecurityOverview::build(finished(HashMap::from([
            (REPO, scan(ScanStatus::Failed)),
            (IMAGE, scan(ScanStatus::Completed)),
        ])));
        assert_eq!(overview.last_scan_failed_count, 1);
        let repo = overview.targets.iter().find(|posture| posture.target == REPO).unwrap();
        assert!(!repo.observed);
        assert_eq!(repo.observation, Observation::LastScanFailed);
        assert_eq!(rules(&repo.verdict), [Rule::Observation]);
        assert_eq!(overview.failing_count, 1);
    }

    #[test]
    fn the_verdict_rests_on_the_newest_finished_scan_and_a_running_one_is_its_own_state() {
        let overview = SecurityOverview::build(input(
            HashMap::new(),
            HashMap::from([(REPO, scan(ScanStatus::Scanning)), (IMAGE, scan(ScanStatus::Pending))]),
            HashMap::from([(REPO, scan(ScanStatus::Completed))]),
        ));
        for posture in &overview.targets {
            assert_eq!(posture.observation, Observation::InProgress);
            assert!(!posture.observed);
        }
        assert_eq!(overview.never_scanned_count, 0);
        assert_eq!(overview.last_scan_failed_count, 0);
        let repo = overview.targets.iter().find(|posture| posture.target == REPO).unwrap();
        assert!(repo.passed);
        let image = overview.targets.iter().find(|posture| posture.target == IMAGE).unwrap();
        assert!(!image.passed);
        assert_eq!(rules(&image.verdict), [Rule::Observation]);
    }

    #[test]
    fn the_kev_banner_counts_what_the_verdicts_actually_held_against_a_target() {
        let scans = HashMap::from([(REPO, scan(ScanStatus::Completed))]);
        let overview = SecurityOverview::build(input(
            HashMap::from([(
                REPO,
                vec![kev(2, Severity::Low, None), kev(3, Severity::Low, Some(TriageStatus::NotAffected))],
            )]),
            scans.clone(),
            scans,
        ));
        assert_eq!(overview.kev_count, 1);
    }

    #[test]
    fn a_target_s_own_policy_replaces_the_global_one_rather_than_merging_with_it() {
        let strict_global = StoredPolicy { policy: policy(Some(Severity::Low), true, false, false, false), version: 4 };
        let lenient_target =
            StoredPolicy { policy: policy(Some(Severity::Critical), false, false, false, false), version: 9 };
        let high = issue(1, FindingType::Vulnerability, Severity::High, None);
        let scans = HashMap::from([(REPO, scan(ScanStatus::Completed))]);
        let overview = SecurityOverview::build(Input {
            targets: vec![NamedTarget { target: REPO, name: "api-service".into() }],
            policies_by_target: HashMap::from([(REPO, lenient_target)]),
            global_policy: Some(strict_global),
            open_issues: HashMap::from([(REPO, vec![high])]),
            latest_scans: scans.clone(),
            latest_finished_scans: scans,
            uncovered_ecosystems: HashMap::new(),
        });
        let [posture] = overview.targets.as_slice() else { panic!("one target") };
        assert!(posture.passed);
        assert_eq!(posture.policy.source, PolicySource::Target);
        assert_eq!(posture.policy.describe_source(), "the target's policy v9");
    }

    #[test]
    fn with_nothing_stored_the_built_in_policy_applies_and_says_so() {
        let overview = SecurityOverview::build(finished(HashMap::new()));
        for posture in &overview.targets {
            assert_eq!(posture.policy.source, PolicySource::BuiltIn);
            assert_eq!(posture.policy.version, None);
            assert_eq!(posture.policy.describe_source(), "the application's default policy");
        }
    }

    #[test]
    fn a_target_s_uncovered_ecosystems_reach_its_verdict() {
        let strict = StoredPolicy { policy: built_in_with(PolicyFlag::FailOnUncoveredLanguages, true), version: 1 };
        let scans = HashMap::from([(REPO, scan(ScanStatus::Completed))]);
        let overview = SecurityOverview::build(Input {
            targets: vec![NamedTarget { target: REPO, name: "api-service".into() }],
            policies_by_target: HashMap::new(),
            global_policy: Some(strict),
            open_issues: HashMap::new(),
            latest_scans: scans.clone(),
            latest_finished_scans: scans,
            uncovered_ecosystems: HashMap::from([(REPO, vec!["npm".to_owned()])]),
        });
        assert_eq!(rules(&overview.targets[0].verdict), [Rule::Coverage]);
    }
}

mod cursor {
    use super::*;

    #[test]
    fn survives_the_round_trip_a_client_puts_it_through() {
        let cursor = RegisterCursor::new(datetime!(2026-09-14 08:00:00.123 UTC), "41");
        assert_eq!(cursor.encoded(), "1789372800123:41");
        assert_eq!(RegisterCursor::parse(Some(&cursor.encoded())), Some(cursor));
    }

    #[test]
    fn keeps_an_identifier_carrying_the_separator() {
        let cursor = RegisterCursor::new(datetime!(1970-01-01 00:00:00 UTC), "a:b:c");
        assert_eq!(RegisterCursor::parse(Some(&cursor.encoded())), Some(cursor));
    }

    #[test]
    fn encodes_no_more_precision_than_the_stores_keep() {
        let cursor = RegisterCursor::new(datetime!(2026-09-14 08:00:00.123456 UTC), "41");
        assert_eq!(RegisterCursor::parse(Some(&cursor.encoded())).unwrap().at, datetime!(2026-09-14 08:00:00.123 UTC));
    }

    #[test]
    fn reads_an_unusable_value_as_absent() {
        for unusable in
            [None, Some(""), Some("  "), Some("not-a-cursor"), Some("abc:41"), Some(":41"), Some("1757836800000:")]
        {
            assert_eq!(RegisterCursor::parse(unusable), None, "{unusable:?}");
        }
    }

    #[test]
    fn reads_the_rest_untrimmed_as_long_parse_long_does() {
        // `isBlank` decides absence, and nothing is trimmed: a padded number is no number, a trailing space is the id's.
        assert_eq!(RegisterCursor::parse(Some(" 1789372800123:41")), None);
        assert_eq!(RegisterCursor::parse(Some("1789372800123:41 ")).unwrap().id, "41 ");
        // `Long.parseLong` reads every script's digits: `١٢` is twelve.
        assert_eq!(RegisterCursor::parse(Some("١٢:41")).unwrap().at, datetime!(1970-01-01 00:00:00.012 UTC));
    }
}
