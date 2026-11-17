#!/usr/bin/env python3
"""Mutation check of Phase 3, wave 1, posture: crates/cp-posture — the formula of decision 0036 and the grades, the
coverage cap, Java's arithmetic (half-up rounding, floored seconds, `%.Nf` on the shortest digits, fdlibm's `exp`), the
backlog series and analytics, the remediation distribution and coverage, the recommended version, the weekly report,
the grading terms and the cards, the ranking, the debt tally, the attack graph, and the 404 a hidden target gets
before anything is read. See README.md.
"""
import sys

import _runner

R = ["-p", "vectispire-cp-posture", "--test", "reference_set"]
L = ["-p", "vectispire-cp-posture", "--lib"]
H = ["-p", "vectispire-cp-posture", "--test", "refusals"]
# The aggregates' engine test (Docker; the run's engines, `VECTISPIRE_TEST_ENGINES`).
E = ["-p", "vectispire-cp-issues", "--lib", "persistence::tests"]
C = "crates/cp-posture/src/"

# Equivalent, and removed: the coverage cap divided in `double` rather than `float` — no share a scope of fewer than
# a few million targets can have rounds differently, so no test tells them apart; the trailing-segment trim of
# `Versions.compare` — a missing segment reads "0" and an empty one is a word below every digit, which no version
# carrying an empty trailing segment and a sibling differing only there exercises; and `Stream.max`'s first-of-equals —
# `Versions.highest` only meets ties between spellings of one version, which print the same once trimmed; and a weight
# refused by `is_nan` rather than `!is_finite` — an infinity is outside `[0, 1 000 000]` and refused by the range.
MUTANTS = [
    # The formula and the grades.
    ("exploited not capped", C + "scorecard.rs", "if counts.exploited > 0 {\n            score = score.min(EXPLOITED_CAP);", "if counts.exploited > 1 {\n            score = score.min(EXPLOITED_CAP);", R),
    ("score not held at one", C + "scorecard.rs", "let rounded = arithmetic::round(Self::exact(counts, weights)).max(1);", "let rounded = arithmetic::round(Self::exact(counts, weights)).max(0);", R),
    ("a plus boundary moved", C + "scorecard.rs", "95.. => SecurityGrade::APlus,", "96.. => SecurityGrade::APlus,", R),
    ("k of zero accepted", C + "scorecard.rs", "        if k <= 0.0 {\n", "        if k < 0.0 {\n", R),
    ("negative weight accepted", C + "scorecard.rs", "if !value.is_finite() || value < 0.0 || value > MAX_PARAMETER {", "if !value.is_finite() || value < -1.0 || value > MAX_PARAMETER {", R),
    ("fdlibm polynomial broken", C + "arithmetic.rs", "    let p5 = f64::from_bits(0x3E66_3769_72BE_A4D0);\n", "    let p5 = 0.0;\n", [L, R]),
    ("badge status width", C + "scorecard.rs", "let status_width = java::utf16_len(grade).saturating_mul(7).saturating_add(18);", "let status_width = java::utf16_len(grade).saturating_mul(7).saturating_add(17);", R),
    # Java's arithmetic.
    ("a half rounds down", "crates/domain/src/java_math.rs", "let rounded = if value - floor >= 0.5 { floor + 1.0 } else { floor };\n    // Java's cast saturates", "let rounded = if value - floor > 0.5 { floor + 1.0 } else { floor };\n    // Java's cast saturates", [L, R]),
    ("seconds truncated", C + "arithmetic.rs", "nanos.div_euclid(1_000_000_000)", "nanos / 1_000_000_000", L),
    ("fixed rounds the exact value", C + "arithmetic.rs", "let shortest = format!(\"{}\", value.abs());", "let shortest = format!(\"{:.60}\", value.abs());", [L, R]),
    ("coverage never capped", C + "coverage.rs", "    if coverage.never() > 0 {\n", "    if coverage.never() > 1 {\n", R),
    # The series and the analytics.
    ("open on the day it resolves", C + "trends.rs", "let still_open = issue.resolved_at.is_none_or(|at| at >= end);", "let still_open = issue.resolved_at.is_none_or(|at| at > end);", R),
    ("analytics open at midnight", C + "trends.rs", "let resolved_after_end = observation.resolved_at.is_none_or(|at| at > end);", "let resolved_after_end = observation.resolved_at.is_none_or(|at| at >= end);", R),
    ("negative resolution counted", C + "trends.rs", "let seconds = arithmetic::seconds_between(first_seen, resolved).max(0);", "let seconds = arithmetic::seconds_between(first_seen, resolved);", R),
    ("resolved before seen counted", C + "trends.rs", "                && resolved > first_seen\n", "                && resolved >= first_seen\n", L),
    ("touching ignores sightings", C + "trends.rs", "            || observation.first_seen.is_some_and(|at| at >= window_start)\n", "            || false\n", L),
    # The remediation distribution and coverage.
    ("no deadline still a share", C + "remediation.rs", "percentage_within_sla: (deadline != 0 && !seconds.is_empty())", "percentage_within_sla: (!seconds.is_empty())", R),
    ("late at the deadline", C + "remediation.rs", "if deadline > 0 && *value > deadline {", "if deadline > 0 && *value >= deadline {", R),
    ("the oldest is the last of equals", C + "remediation.rs", ".is_none_or(|current| days > current)", ".is_none_or(|current| days >= current)", R),
    ("unpackaged vulnerabilities addressable", C + "remediation.rs", "addressable = addressable.saturating_add(family.package_named);", "addressable = addressable.saturating_add(family.package_named + family.unnamed);", R),
    ("on request types planned", C + "remediation.rs", ".is_some_and(|kind| kind.gate_participation() == GateParticipation::OnRequest)", ".is_some_and(|kind| kind.gate_participation() == GateParticipation::Never)", R),
    # The version a fix recommends.
    ("a word beats a digit", C + "versions.rs", "return if left_number { Ordering::Greater } else { Ordering::Less };", "return if left_number { Ordering::Less } else { Ordering::Greater };", R),
    ("numbers compared as text", C + "versions.rs", "(Some(a), Some(b)) => a.cmp(&b),", "(Some(_), Some(_)) => java::compare_utf16(left, right),", R),
    ("blank candidates in rust whitespace", C + "versions.rs", "        if java::is_blank(candidate) {\n", "        if candidate.is_empty() {\n", R),
    # The weekly report.
    ("a failed scan not named", C + "digest.rs", "if counts.never_scanned > 0 || counts.last_scan_failed > 0 {", "if counts.never_scanned > 0 {", R),
    ("nothing late in the subject", C + "digest.rs", "if self.overdue_count > 0 { format!(", "if self.overdue_count >= 0 { format!(", R),
    # The grading terms and the cards.
    ("exploited also weighed by severity", C + "scorecards.rs", "                add(&mut weighed, 4, row.c);\n", "                add(&mut weighed, 4, row.c);\n                add(&mut weighed, slot, row.c);\n", L),
    ("closed counted open", C + "scorecards.rs", "!state.eq_ignore_ascii_case(\"closed\") && ", "", L),
    ("no severity is a low", C + "scorecards.rs", "None | Some(\"MEDIUM\") => 2,\n                Some(_) => 3,", "Some(\"MEDIUM\") => 2,\n                None | Some(_) => 3,", L),
    ("a row filed under its image", C + "scorecards.rs", "        (Some(id), _) => Some(ScanTarget::Repository(id)),\n        (None, Some(id)) => Some(ScanTarget::Container(id)),", "        (_, Some(id)) => Some(ScanTarget::Container(id)),\n        (Some(id), None) => Some(ScanTarget::Repository(id)),", L),
    ("nothing observed still graded", C + "scorecards.rs", "Some(uncapped) if coverage.observed > 0 =>", "Some(uncapped) =>", L),
    ("coverage advice not first", C + "scorecards.rs", "            recommendations.insert(\n                0,", "            recommendations.insert(\n                recommendations.len(),", L),
    ("weaker ignores risk points", C + "scorecards.rs", "candidate.score < current.score || (candidate.score == current.score && candidate.risk_points > current.risk_points)", "candidate.score < current.score", L),
    # The ranking and the home page.
    ("best score last", C + "dashboard.rs", "(Some(x), Some(y)) => y.cmp(&x),", "(Some(x), Some(y)) => x.cmp(&y),", L),
    ("ties by more points", C + "dashboard.rs", "(Some(x), Some(y)) => x.total_cmp(&y),", "(Some(x), Some(y)) => y.total_cmp(&x),", L),
    ("an image named with its branch", C + "dashboard.rs", "if scan.container_id.is_some() || java::is_blank(&scan.branch) {", "if java::is_blank(&scan.branch) {", L),
    ("blank branch in rust whitespace", C + "dashboard.rs", "if scan.container_id.is_some() || java::is_blank(&scan.branch) {", "if scan.container_id.is_some() || scan.branch.trim().is_empty() {", L),
    ("a day that does not exist accepted", C + "dashboard.rs", "Date::from_calendar_date(year, month, day).ok()", "Date::from_calendar_date(year, month, day.min(28)).ok()", L),
    # The debt.
    ("on request types costed", C + "debt.rs", "            if kind.gate_participation() == GateParticipation::OnRequest {\n                continue;", "            if false {\n                continue;", L),
    ("an unknown type dropped", C + "debt.rs", ".unwrap_or(FindingType::Vulnerability);", ".unwrap_or(FindingType::AiReview);", L),
    ("a high vulnerability ordinary", C + "debt.rs", "if matches!(severity, Severity::Critical | Severity::High) {", "if matches!(severity, Severity::Critical) {", L),
    ("effort ignores identifiers", C + "debt.rs", "tenths(1.0 + weight.distinct_identifiers as f64 * 0.1)", "tenths(1.0)", L),
    # The attack graph.
    ("sensitive by case", C + "attack_path.rs", "let lower = java::to_lower_root(path);", "let lower = path.to_owned();", L),
    ("cut before the ranking", C + "attack_path.rs", "    critical.sort_by(|a, b| worst_first(a, b));\n", "", L),
    ("kev not first", C + "attack_path.rs", "u8::from(!a.kev())\n        .cmp(&u8::from(!b.kev()))", "u8::from(a.kev())\n        .cmp(&u8::from(b.kev()))", L),
    ("more vulnerabilities scored", C + "attack_path.rs", ".saturating_add(count(vuln_count.min(3)).saturating_mul(10))", ".saturating_add(count(vuln_count.min(4)).saturating_mul(10))", L),
    ("no secret path", C + "attack_path.rs", "    if let Some(first) = secrets.first() {\n        critical_exploitable", "    if let Some(first) = secrets.first().filter(|_| false) {\n        critical_exploitable", L),
    ("a public route needs no missing auth", C + "attack_path.rs", "let public = endpoint.visibility.eq_ignore_ascii_case(\"PUBLIC\") || unauth;", "let public = unauth;", L),
    ("rust's inf read as a weight", C + "web/read.rs", "|| !decimal(whole) || !decimal(fraction) || !exponent_ok", "|| !exponent_ok", L),
    # The aggregates posture reads, each decoded under the name it is selected as (the replay found `from_col`).
    ("type read under its field name", "crates/cp-issues/src/persistence/aggregates.rs", "    #[sea_orm(from_alias = \"type\")]\n    pub type_: String,\n    pub package_named", "    pub type_: String,\n    pub package_named", E),
    ("an average not cast to a double", "crates/cp-issues/src/persistence/aggregates.rs", "        Engine::MySql => \"double\",\n", "        Engine::MySql => \"decimal(20,4)\",\n", E),
    ("a package named by spaces", "crates/cp-issues/src/persistence/aggregates.rs", ".and(Expr::expr(Func::cust(\"trim\").arg(Expr::col(IssueColumn::PackageName))).ne(\"\"))", "", E),
    # A hidden target: 404 before anything is read.
    ("repository card read before the guard", C + "scorecards.rs", "        let target = ScanTarget::Repository(repository);\n        rows::require_visible(target, allowed)?;\n", "        let target = ScanTarget::Repository(repository);\n", H),
    ("image card read before the guard", C + "scorecards.rs", "        let target = ScanTarget::Container(container);\n        rows::require_visible(target, allowed)?;\n", "        let target = ScanTarget::Container(container);\n", H),
    ("attack graph read before the guard", C + "attack_paths.rs", "        rows::require_visible(ScanTarget::Repository(repository), allowed)?;\n", "", H),
    ("badge read before the guard", C + "badges.rs", "        rows::require_visible(ScanTarget::Repository(repository), allowed)?;\n", "", H),
    ("simulation open to every account", C + "web/routes.rs", "scoped_get(\"/api/v1/scorecards/simulation\", Access::Administrator,", "scoped_get(\"/api/v1/scorecards/simulation\", Access::Account,", H),
]

if __name__ == "__main__":
    sys.exit(_runner.main(MUTANTS, description=__doc__))
