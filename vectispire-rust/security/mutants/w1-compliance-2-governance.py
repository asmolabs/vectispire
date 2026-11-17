#!/usr/bin/env python3
"""Mutation check of Phase 3, wave 1, compliance stage 2: the governance services — the declaration of
applicability's refusals, write and audit entry, the certified scope's membership and coverage, the history read back
— and the required boolean the scope routes read. See README.md.
"""
import sys

import _runner

G = ["-p", "vectispire-cp-compliance", "--test", "governance"]
W = ["-p", "vectispire-cp-compliance", "--lib", "web::read"]
D = "crates/cp-compliance/src/declarations.rs"
C = "crates/cp-compliance/src/certified.rs"
H = "crates/cp-compliance/src/progress.rs"
R = "crates/cp-compliance/src/web/read.rs"
F = "crates/cp-http/src/download_guard.rs"
H2 = ["-p", "vectispire-cp-http", "--lib", "download_guard"]

MUTANTS = [
    # The declaration.
    ("any control of the framework", D, "        if !framework.controls().iter().any(|control| control.id == control_id) {", "        if false {", G),
    ("an applicable line without its state", D, "        if applicability == Applicability::Applicable && submission.implementation.is_none() {", "        if false {", G),
    ("a bare exclusion", D, "        if applicability == Applicability::Excluded && blank(submission.justification.as_deref()) {", "        if applicability == Applicability::Excluded && submission.justification.is_none() {", G),
    ("only external evidence must say where", D, "        if evidence_source != EvidenceSource::Vectispire && blank(", "        if evidence_source == EvidenceSource::External && blank(", G),
    ("the identifier unbounded", D, "        bounded(Some(control_id), CONTROL_ID_LENGTH, \"The control identifier\")?;\n", "", G),
    ("the owner unbounded", D, "        bounded(submission.owner.as_deref(), OWNER_LENGTH, \"The control owner\")?;\n", "", G),
    ("the justification unbounded", D, "        bounded(submission.justification.as_deref(), bounded_text::TEXT_MAX, \"The justification\")?;\n", "", G),
    ("the evidence unbounded", D, "        bounded(submission.external_evidence.as_deref(), bounded_text::TEXT_MAX, \"The external evidence\")?;\n", "", G),
    ("the latest review date excluded", D, "latest.is_none_or(|latest| due > latest)", "latest.is_none_or(|latest| due >= latest)", G),
    ("no latest review date", D, "latest.is_none_or(|latest| due > latest) || ", "", G),
    ("the earliest review date excluded", D, "earliest.is_none_or(|earliest| due < earliest)", "earliest.is_none_or(|earliest| due <= earliest)", G),
    ("no earliest review date", D, " || earliest.is_none_or(|earliest| due < earliest)", "", G),
    ("an exclusion keeps its implementation", D, "        let implementation = if applicability == Applicability::Excluded { None } else { submission.implementation };", "        let implementation = submission.implementation;", G),
    ("a revision inserts a second line", D, "        if existing.is_some() {\n            DeclarationRepository::update", "        if false {\n            DeclarationRepository::update", G),
    ("the review not confirmed", D, "            reviewed_at: Some(now),\n            review_due_at: due,", "            reviewed_at: existing.as_ref().and_then(|row| row.reviewed_at),\n            review_due_at: due,", G),
    ("the wrong operation recorded", D, "                AuditOperation::ControlDeclared,", "                AuditOperation::CertifiedScopeChanged,", G),
    ("the author not recorded", D, "            decided_by: actor.map(str::to_owned),", "            decided_by: None,", G),
    # The certified scope.
    ("a hidden target set", C, "        require_visible(target, allowed).map_err(|_| ComplianceError::NotFound(TARGET_NOT_FOUND.to_owned()))?;\n", "", G),
    ("an absent target unchanged", C, "            ScopeChange::Absent => Err(ComplianceError::NotFound(TARGET_NOT_FOUND.to_owned())),", "            ScopeChange::Absent => Ok(false),", G),
    ("an unchanged membership audited", C, "            ScopeChange::Unchanged => Ok(false),\n            ScopeChange::Changed => {", "            ScopeChange::Unchanged | ScopeChange::Changed => {", G),
    ("every target in scope", C, "            .filter(|row| row.in_certified_scope)\n            .map(|row| ScanTarget::Repository(row.id))", "            .map(|row| ScanTarget::Repository(row.id))", G),
    ("the reader's view ignored", C, "            .filter(|target| allowed.permits(*target))\n", "", G),
    ("the cutoff itself stale", C, "Some(at) if cutoff.is_some_and(|cutoff| *at < cutoff)", "Some(at) if cutoff.is_some_and(|cutoff| *at <= cutoff)", G),
    ("no fallback window", C, "        let days = if configured > 0 { configured } else { DEFAULT_FRESHNESS_DAYS };", "        let days = configured;", G),
    ("a negative declared count", C, "            declared_assets: declared.max(0),", "            declared_assets: declared,", G),
    ("an image audited as a repository", C, "                    ScanTarget::Container(id) => (id, format!(\"Image {id}\")),", "                    ScanTarget::Container(id) => (id, format!(\"Repository {id}\")),", G),
    ("a removal said as an addition", C, "let change = if in_scope { \" put in the certified scope\" } else { \" taken out of the certified scope\" };", "let change = \" put in the certified scope\";", G),
    # The history.
    ("a framework never captured shown", H, "            .filter(|series| !series.steps.is_empty())\n", "", G),
    ("an unknown framework kept", H, "    let Some(framework) = ComplianceFramework::from_name(&row.framework) else {\n        return Ok(None);\n    };", "    let framework = ComplianceFramework::from_name(&row.framework).unwrap_or(ComplianceFramework::Nis2);", G),
    # The scope routes' boolean.
    ("an empty value read as false", R, "        \"\" => Err(Problem::handler(StatusCode::BAD_REQUEST, format!(\"Required parameter '{name}' is not present.\"))),\n", "", W),
    ("the value not trimmed", R, "    match java::trim(&raw).to_ascii_lowercase().as_str() {", "    match raw.to_ascii_lowercase().as_str() {", W),
    ("case matters", R, "    match java::trim(&raw).to_ascii_lowercase().as_str() {", "    match java::trim(&raw) {", W),
    # Spring's download guard.
    ("a redirect guarded", F, "if status < 200 || (300..400).contains(&status) ||", "if status < 200 ||", H2),
    ("the path parameters unread", F, "    if unsafe_extension(filename) || unsafe_extension(parameters) {", "    if unsafe_extension(filename) {", H2),
    ("case matters to the safe list", F, "(!after.is_empty() && !after.contains('/')).then(|| after.to_lowercase())", "(!after.is_empty() && !after.contains('/')).then(|| after.to_owned())", H2),
    ("a trailing dot is an extension", F, "(!after.is_empty() && !after.contains('/'))", "(!after.contains('/'))", H2),
    ("the pattern's own extension unsafe", F, "SAFE_EXTENSIONS.contains(&extension) || pattern.ends_with(&format!(\".{extension}\"))", "SAFE_EXTENSIONS.contains(&extension)", H2),
]

if __name__ == "__main__":
    sys.exit(_runner.main(MUTANTS, description=__doc__))
