#!/usr/bin/env python3
"""Mutation check of Phase 3, wave 1, compliance stage 0b: the pure compliance domain in crates/domain — the engine's
thresholds, caps and coverage, the declaration of applicability's order of tests, the history's attribution, the
scope's gap, the OWASP grid's states, evidence and fold, the CWE lists' boundaries, the coverage week, the MTTR and the
spreadsheet neutralisation — held to Java's answers in reference/compliance/. See README.md.
"""
import sys

import _runner

R = ["-p", "vectispire-domain", "--test", "compliance_reference_set"]
U = ["-p", "vectispire-domain", "--lib"]
D = "crates/domain/src/"
E = D + "compliance/engine.rs"
S = D + "compliance/soa.rs"
H = D + "compliance/history.rs"
O = D + "owasp_coverage.rs"

# Equivalent, and removed (each was written, survived, and is listed so that nobody writes it again): the supply chain's and governance's `max(1)` on the total — the only estates with no target
# read no data before the division, so a total of zero never reaches it; `worse_of` keeping the right on a tie — equal
# statuses are one status; `Source::Code`'s `LanguagesUnrecorded` before `StepAbsent` — a scan with no code step never
# recorded its rules' languages in any evidence the grid is built from, so both orders name the same gap; and the MTTR's
# borrowed second — an hour boundary crossed by less than a second needs a resolution within a nanosecond of one, which
# a whole-second clock never stores; and the overdue count multiplied before its cast to `int` rather than after — the
# low 32 bits of a product are the product of the low 32 bits, so the two agree on every count.
MUTANTS = [
    # The engine: no data, the framework's verdict and its thresholds.
    ("audit read on no scan", E, "if control.category != Category::AuditAndLogging && input.scanned_targets == 0 {", "if input.scanned_targets == 0 {", R),
    ("no data scored", E, "if assessments.iter().any(|assessment| !assessment.status.measured()) {", "if assessments.iter().all(|assessment| !assessment.status.measured()) {", R),
    ("framework fails below 69", E, "let overall_status = if non_compliant || overall_score < 70 {", "let overall_status = if non_compliant || overall_score < 69 {", R),
    ("framework compliant at 94", E, "} else if partial || overall_score < 95 {", "} else if partial || overall_score < 94 {", R),
    ("a control compliant at 89", E, "    if score >= 90 {\n", "    if score >= 89 {\n", R),
    ("a control partial at 59", E, "    } else if score >= 60 {\n", "    } else if score >= 59 {\n", R),
    ("criticals uncapped", E, "50.min(int(input.critical_issues).wrapping_mul(20))", "int(input.critical_issues).wrapping_mul(20)", R),
    ("kev cap moved", E, "30.min(int(input.kev_issues).wrapping_mul(15))", "35.min(int(input.kev_issues).wrapping_mul(15))", R),
    ("five highs penalised", E, "    if input.high_issues > 5 {\n", "    if input.high_issues >= 5 {\n", R),
    ("secure coding floor lost", E, "20.max(100i32.wrapping_sub(int(sast).wrapping_mul(5)))", "0.max(100i32.wrapping_sub(int(sast).wrapping_mul(5)))", R),
    ("iac floor lost", E, "30.max(100i32.wrapping_sub(int(iac).wrapping_mul(10)))", "20.max(100i32.wrapping_sub(int(iac).wrapping_mul(10)))", R),
    # The platform's caps.
    ("encryption never capped", E, "            if platform.encryption_configured {\n", "            if true {\n", R),
    ("four eyes never capped", E, "            if platform.four_eyes_required {\n", "            if true {\n", R),
    ("no accounts read as enrolled", E, "if local.accounts > 0 && local.without_second_factor == 0 {", "if local.without_second_factor == 0 {", [U, R]),
    ("open password beside a provider", E, "    if platform.password_login_open {\n", "    if false {\n", R),
    ("a cap greens no data", E, "        Status::NonCompliant | Status::NoData => assessment.status,\n        Status::Compliant | Status::Partial => Status::Partial,", "        Status::NonCompliant => assessment.status,\n        Status::Compliant | Status::Partial | Status::NoData => Status::Partial,", R),
    # The coverage cap.
    ("stale estate uncapped", E, "    if never == 0 && stale == 0 {\n", "    if never == 0 {\n", R),
    ("never scanned only partial", E, "let status = if never > 0 { Status::NonCompliant } else { worse_of(assessment.status, Status::Partial) };", "let status = worse_of(assessment.status, Status::Partial);", R),
    ("a cap whitewashes", E, "    if left >= right { left } else { right }", "    if left <= right { left } else { right }", R),
    ("score not capped by observation", E, "score_percentage: assessment.score_percentage.min(observed),", "score_percentage: assessment.score_percentage,", [U, R]),
    # The declaration of applicability.
    ("exclusion judged", S, "    if declaration.applicability == Some(Applicability::Excluded) {\n", "    if false {\n", [U, R]),
    ("external judged", S, "    if declaration.evidence_source == Some(EvidenceSource::External) {\n", "    if false {\n", R),
    ("no data consistent", S, "let Some(measured) = measured.filter(|status| status.measured()) else {", "let Some(measured) = measured else {", [U, R]),
    ("understated read as consistent", S, "            if measured == Status::Compliant {\n", "            if measured == Status::Partial {\n", R),
    ("due today overdue", S, "self.review_due_at.is_some_and(|due| due < now)", "self.review_due_at.is_some_and(|due| due <= now)", R),
    ("other frameworks reconciled", S, ".filter(|declaration| declaration.framework == framework.name())", ".filter(|_| true)", R),
    # The history.
    ("one point is the work", H, "    } else if delta >= NOISE {\n", "    } else if delta >= 1 {\n", [U, R]),
    ("shape ignored", H, "    } else if snapshot.shape() != previous.shape() {\n", "    } else if false {\n", R),
    ("months unordered", H, "    ordered.sort_by(|left, right| java::compare_utf16(&left.period, &right.period));\n", "", R),
    ("one month comparable", H, "    let comparable = steps.len() > 1\n", "    let comparable = steps.len() > 0\n", R),
    # The scope.
    ("undeclared scope has a gap", D + "compliance/scope.rs", "if self.declared_assets <= 0 { 0 } else {", "if self.declared_assets < 0 { 0 } else {", R),
    # The OWASP grid.
    ("sast placed by its type", O, "if type_ == DECLARES_ITS_CATEGORY { declared_category.and_then(category_code) } else { None }", "declared_category.and_then(category_code)", R),
    ("an image read for secrets", O, "matches!(type_, FindingType::Vulnerability | FindingType::Eol | FindingType::License)", "matches!(type_, FindingType::Vulnerability | FindingType::Eol | FindingType::License | FindingType::Secret)", [U, R]),
    ("a failed scan's record kept", O, "let examined = if observation == Observation::Ok { examined } else { None };", "let examined = examined;", R),
    ("unknown languages read as none", O, "let code_reaches = if analysed.is_none() { None } else { Some(code_reaches.unwrap_or_default()) };", "let code_reaches = Some(code_reaches.unwrap_or_default());", R),
    ("a rule of another language credited", O, "Some(detected.intersection(rules).copied().collect::<BTreeSet<_>>())", "Some(detected.union(rules).copied().collect::<BTreeSet<_>>())", R),
    ("a failed scan never scanned", O, "Observation::LastScanFailed => return Some(Gap::LastScanFailed),", "Observation::LastScanFailed => return Some(Gap::NeverScanned),", R),
    ("eol measured when off", O, "FindingType::Eol => measurement.end_of_life_enabled,", "FindingType::Eol => true,", R),
    ("code measured when off", O, "let code_measured = declared && measurement.code_analysis_enabled;", "let code_measured = declared;", R),
    ("nothing scanned is examined", O, "    if measurement.targets.is_empty() {\n        return CoverageLine::of(id, title, State::NotMeasured", "    if false {\n        return CoverageLine::of(id, title, State::NotMeasured", R),
    ("a target's line as a scope's", O, "        if one_target {\n", "        if false {\n", [U, R]),
    ("settled below zero", O, ".wrapping_sub(line.findings).max(0),", ".wrapping_sub(line.findings),", R),
    ("the fold ignores an unexamined line", O, "} else if applicable.iter().all(|state| matches!(state, State::NoFinding | State::Findings)) {", "} else if applicable.iter().any(|state| matches!(state, State::NoFinding | State::Findings)) {", [U, R]),
    ("one is many", O, "if self.applicable == Some(1) { one } else { many },", "many,", R),
    ("unplaced counts foreign categories", O, ".filter(|(category, _)| is_category(category))", ".filter(|_| true)", R),
    ("the week starts on sunday", O, "let since_monday = day.wrapping_add(3).rem_euclid(7);", "let since_monday = day.wrapping_add(4).rem_euclid(7);", R),
    # The CWE lists.
    ("a word before the cwe", D + "owasp_cwe.rs", r'Regex::new(r"(?-u:\b)[Cc][Ww][Ee]-([0-9]+)(?-u:\b)")', r'Regex::new(r"[Cc][Ww][Ee]-([0-9]+)(?-u:\b)")', [U, R]),
    ("unicode boundaries", D + "owasp_cwe.rs", r'Regex::new(r"(?-u:\b)[Cc][Ww][Ee]-([0-9]+)(?-u:\b)")', r'Regex::new(r"\b[Cc][Ww][Ee]-([0-9]+)\b")', R),
    ("the first cwe only", D + "owasp_cwe.rs", "        .find_map(category_of)\n", "        .next()\n        .and_then(category_of)\n", [U, R]),
    ("password under a02", D + "owasp_cwe.rs", "            255, 259, 287,", "            255, 287,", [U, R]),
    # The MTTR and the cells.
    ("a fast fix is zero days", D + "mttr.rs", "let days = (whole_hours(first_seen, resolved_at) / 24).max(1);", "let days = whole_hours(first_seen, resolved_at) / 24;", [U, R]),
    ("resolved before seen counted", D + "mttr.rs", "        if resolved_at < first_seen {\n            continue;", "        if resolved_at < first_seen && false {\n            continue;", R),
    ("a tab is text", D + "spreadsheet_cells.rs", "value.starts_with(['=', '+', '-', '@', '\\t', '\\r'])", "value.starts_with(['=', '+', '-', '@', '\\r'])", [U, R]),
    ("a float half rounds down", D + "java_math.rs", "    let rounded = if value - floor >= 0.5 { floor + 1.0 } else { floor };\n    if rounded >= 2_147_483_648.0 {", "    let rounded = if value - floor > 0.5 { floor + 1.0 } else { floor };\n    if rounded >= 2_147_483_648.0 {", R),
]

if __name__ == "__main__":
    sys.exit(_runner.main(MUTANTS, description=__doc__))
