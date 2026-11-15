#!/usr/bin/env python3
"""Mutation check of Phase 3, task 3.4: the quality gate in crates/cp-gate — what a verdict considers, its rules and their
order, hardening a requested policy, resolving whose policy applies, reading a route's fields and a stored threshold,
the observation a scan stands for, the security overview, and the register's cursor. See README.md.
"""
import sys

import _runner

D = ["-p", "vectispire-cp-gate", "--test", "domain"]
L = ["-p", "vectispire-cp-gate", "--lib", "service::tests"]
C = "crates/cp-gate/src/"

# Equivalent, and removed: the cursor's `split == 0` — a cursor starting with its separator has an empty number, which
# `Long.parseLong` (`java::read_long`) refuses on its own, so the guard cannot be told apart from its absence.
MUTANTS = [
    # What a verdict considers.
    ("closed issues count", C + "gate.rs", "        if !issue.open {\n            return false;", "        if false {\n            return false;", D),
    ("quality counts", C + "gate.rs", "GateParticipation::Never => false,", "GateParticipation::Never => true,", D),
    ("ai flag reads plugins", C + "gate.rs", "FindingType::AiReview => policy.include_ai_review,", "FindingType::AiReview => policy.include_plugins,", D),
    ("plugin flag reads ai", C + "gate.rs", "FindingType::Plugin | FindingType::Imported => policy.include_plugins,", "FindingType::Plugin | FindingType::Imported => policy.include_ai_review,", D),
    ("triaged always excluded", C + "gate.rs", "        if !policy.include_triaged\n", "        if true\n", D),
    ("under review is settled", C + "gate.rs", "            && triage.is_settled()\n", "            && true\n", D),
    ("unfixable always skipped", C + "gate.rs", "if policy.fixable_only && !issue.has_published_fix() {", "if !issue.has_published_fix() {", D),
    ("published fix in rust whitespace", C + "issue.rs", "!java::is_blank(versions)", "!versions.trim().is_empty()", D),
    # The rules and their order.
    ("observation not refused", C + "gate.rs", "examination.and_then(|e| e.refusal())", "examination.and_then(|_| None::<&str>)", D),
    ("kev without the flag", C + "gate.rs", "if policy.fail_on_kev && issue.kev {", "if issue.kev {", D),
    ("kev and severity both", C + "gate.rs", "                continue;\n            }\n\n            if let Some(threshold)", "            }\n\n            if let Some(threshold)", D),
    ("severity compared backwards", C + "gate.rs", "&& issue.severity.is_at_least(threshold)", "&& threshold.is_at_least(issue.severity)", D),
    ("coverage without the flag", C + "gate.rs", "if policy.fail_on_uncovered_languages && !coverage.uncovered_ecosystems.is_empty() {", "if !coverage.uncovered_ecosystems.is_empty() {", D),
    ("observation passes", C + "gate.rs", "passed: violations.is_empty(),", "passed: violations.iter().all(|v| v.rule == Rule::Observation),", D),
    # Hardening: a request only tightens.
    ("disabling nothing is a relaxation", C + "gate.rs", "                if base.fail_on_severity.is_some() {\n", "                if true {\n", D),
    ("adding a threshold ignored", C + "gate.rs", "                if base.fail_on_severity.is_none() {\n", "                if false {\n", D),
    ("raising the threshold accepted", C + "gate.rs", "if wanted.is_stricter_threshold_than(base_thresh) {", "if base_thresh.is_stricter_threshold_than(wanted) {", D),
    ("same threshold a relaxation", C + "gate.rs", "} else if wanted != base_thresh {", "} else {", D),
    ("same flag weighed", C + "gate.rs", "                if wanted == policy.flag(flag) {\n", "                if false {\n", D),
    ("strict means true", C + "gate.rs", "if wanted == flag.strict_value() {", "if wanted {", D),
    ("fixable only strict when on", C + "flag.rs", "            PolicyFlag::FixableOnly => false,\n            PolicyFlag::FailOnUncoveredLanguages => true,", "            PolicyFlag::FixableOnly => true,\n            PolicyFlag::FailOnUncoveredLanguages => true,", D),
    # Whose policy applies.
    ("target policy for a global question", C + "resolution.rs", "if scope == PolicyScopeChoice::Target && lookup.for_target.is_some() {", "if lookup.for_target.is_some() {", D),
    ("built-in named global", C + "resolution.rs", "        if stored.is_none() {\n            source = PolicySource::BuiltIn;", "        if false {\n            source = PolicySource::BuiltIn;", D),
    # A route's fields.
    ("none in rust whitespace", C + "fields.rs", "java::trim(value).eq_ignore_ascii_case(\"none\")", "value.trim().eq_ignore_ascii_case(\"none\")", D),
    ("unknown severity accepted", C + "fields.rs", "        if sev == Severity::Unknown {\n", "        if false {\n", D),
    ("blank severity in rust whitespace", C + "fields.rs", "Some(s) if !java::is_blank(s) => s,", "Some(s) if !s.trim().is_empty() => s,", D),
    ("triaged flag misrouted", C + "fields.rs", "requested = requested.with_flag(PolicyFlag::IncludeTriaged, v);", "requested = requested.with_flag(PolicyFlag::IncludeAiReview, v);", D),
    ("fixable only defaulted", C + "fields.rs", "fixable_only: Self::required(self.fixable_only, \"fixable_only\")?,", "fixable_only: self.fixable_only.unwrap_or(false),", D),
    ("newest flag defaults on", C + "fields.rs", "fail_on_uncovered_languages: self.fail_on_uncovered_languages.unwrap_or(false),", "fail_on_uncovered_languages: self.fail_on_uncovered_languages.unwrap_or(true),", D),
    ("two targets accepted", C + "service.rs", "            (Some(repo_id), None) => Ok(ScanTarget::Repository(repo_id)),", "            (Some(repo_id), _) => Ok(ScanTarget::Repository(repo_id)),", D),
    ("global path kind accepted", C + "service.rs", "            \"container\" => Ok(Self { kind: \"container\".to_owned(), id }),", "            \"container\" | \"global\" => Ok(Self { kind: \"container\".to_owned(), id }),", D),
    # A stored threshold.
    ("stored threshold in rust whitespace", C + "service.rs", "        if java::is_blank(stored) {\n", "        if stored.trim().is_empty() {\n", L),
    ("stored unknown kept", C + "service.rs", "if severity == Severity::Unknown { GatePolicy::BUILT_IN.fail_on_severity } else { Some(severity) }", "Some(severity)", L),
    # The observation a scan stands for, and the overview.
    ("in flight read as its status", C + "observation.rs", "                if status.is_in_flight() {\n", "                if false {\n", D),
    ("in progress examined", C + "observation.rs", "        self == Observation::Ok\n", "        self != Observation::NeverScanned\n", D),
    ("verdict on the running scan", C + "overview.rs", "Observation::of(input.latest_finished_scans.get(&named.target).map(|s| s.status))", "observation", D),
    ("kev banner counts every violation", C + "overview.rs", ".filter(|v| v.rule == Rule::Kev)", ".filter(|_| true)", D),
    ("overview ignores coverage", C + "overview.rs", "&Coverage::new(uncovered)", "&Coverage::new(Vec::new())", D),
    # The register's cursor.
    ("cursor trimmed", C + "cursor.rs", "        let encoded = encoded?;\n", "        let encoded = encoded?.trim();\n", D),
    ("cursor ascii digits", C + "cursor.rs", "java::read_long(millis_str)?", "millis_str.parse::<i64>().ok()?", D),
    ("cursor empty id", C + "cursor.rs", "if split == 0 || split == encoded.len().saturating_sub(1) {", "if split == 0 {", D),
]

if __name__ == "__main__":
    sys.exit(_runner.main(MUTANTS, description=__doc__))
