#!/usr/bin/env python3
"""Mutation check of Phase 2 task 2.8: ingestion (cp-scanning's `ingestion.rs`) — the columns each value is clipped to
and that the clipping comes after the fingerprint, the low-confidence downgrade and the SAST category, the secrets'
deduplication by location, a plugin's scope (its tool, never the type), the end-of-life conditions, the licences read
at each scan from a catalogue only, enrichment's exploited flag, a `null` element refused in every list, and the
ingestor `cp-app` composes. See README.md.

Most mutants are killed by the Java-written reference set (`tests/ingestion.rs`, 145 cases in a transaction on MySQL);
the licences read per scan by the engine suite; the composition by `cp-app`'s `ingestion_composition`.
"""
import sys

import _runner

ING = "crates/cp-scanning/src/ingestion.rs"
APP = "crates/cp-app/src/ingestion.rs"

ORACLE = ["-p", "vectispire-cp-scanning", "--test", "ingestion"]
MY = ["-p", "vectispire-cp-scanning", "--test", "engines", "on_mysql"]
COMPOSED = ["-p", "vectispire-cp-app", "--test", "ingestion_composition"]


def clip(field, length, wider):
    old = f"bounded_text::clip(finding.{field}.as_deref(), {length})"
    return (f"{field} clipped past its column", ING, old, old.replace(f", {length})", f", {wider})"), ORACLE)


MUTANTS = [
    # ── the columns, and the order: after the fingerprint ──
    clip("identifier", 255, 256),
    clip("package_name", 255, 256),
    clip("package_version", 255, 256),
    clip("purl", 255, 256),
    clip("file_path", 500, 501),
    clip("fix_versions", 255, 256),
    clip("link", 500, 501),
    clip("cvss_vector", 255, 256),
    clip("fix_state", 50, 51),
    clip("severity", 50, 51),
    clip("tool", 200, 201),
    clip("tool_name", 100, 101),
    clip("tool_version", 100, 101),
    ("description clipped past its column", ING,
     "bounded_text::clip(finding.description.as_deref(), bounded_text::TEXT_MAX)",
     "bounded_text::clip(finding.description.as_deref(), bounded_text::TEXT_MAX + 1)", ORACLE),
    ("source clipped past its column", ING,
     "bounded_text::clip(Some(&finding.source), 50)", "bounded_text::clip(Some(&finding.source), 51)", ORACLE),
    ("the values clipped before the fingerprint", ING,
     "        let observed_findings: Vec<ObservedFinding> = findings.iter().map(ObservedFinding::from_finding).collect();",
     "        findings.iter_mut().for_each(fit_to_columns);\n"
     "        let observed_findings: Vec<ObservedFinding> = findings.iter().map(ObservedFinding::from_finding).collect();",
     ORACLE),

    # ── the low-confidence downgrade, and the category ──
    ("every confidence downgrades", ING, '    if confidence != Some("LOW") {', '    if confidence == Some("ZZZ") {', ORACLE),
    ("a low confidence keeps its rank", ING, '    if confidence != Some("LOW") {', '    if confidence != Some("NONE") {', ORACLE),
    ("critical is not downgraded", ING, "        Severity::Critical => Severity::High,", "        Severity::Critical => Severity::Critical,", ORACLE),
    ("high is not downgraded", ING, "        Severity::High => Severity::Medium,", "        Severity::High => Severity::High,", ORACLE),
    ("medium is not downgraded", ING, "        Severity::Medium | Severity::Low => Severity::Low,", "        Severity::Medium | Severity::Low => severity,", ORACLE),
    ("a security rule goes to quality", ING, 'result.category.as_deref() == Some("security")', 'result.category.as_deref() == Some("Security")', ORACLE),
    ("a SAST pass leaves quality unexamined", ING, "            scanned_types.insert(FindingType::Quality);\n", "", ORACLE),

    # ── the secrets, one per location ──
    ("every secret is kept", ING, "                if seen_secrets.insert(location_key) {", "                if { let _ = seen_secrets.insert(location_key); true } {", ORACLE),
    ("the location forgets the line", ING,
     'let location_key = format!("{}:{}", secret.file.as_deref().unwrap_or(""), secret.line);',
     'let location_key = format!("{}:", secret.file.as_deref().unwrap_or(""));', ORACLE),
    ("a missing file is not the empty one", ING,
     'let location_key = format!("{}:{}", secret.file.as_deref().unwrap_or(""), secret.line);',
     'let location_key = format!("{}:{}", secret.file.as_deref().unwrap_or("<none>"), secret.line);', ORACLE),

    # ── a plugin's scope: its tool, declared even when clean, never the type ──
    ("a plugin's tool is not declared", ING, "            scanned_tools.insert(plugin_key.clone());\n", "", ORACLE),
    ("a clean plugin declares nothing", ING,
     "            scanned_tools.insert(plugin_key.clone());\n            for result in every(step_findings, \"a plugin's findings\")? {\n",
     "            for result in every(step_findings, \"a plugin's findings\")? {\n                scanned_tools.insert(plugin_key.clone());\n",
     ORACLE),
    ("a plugin declares the whole type", ING,
     "            scanned_tools.insert(plugin_key.clone());\n",
     "            scanned_tools.insert(plugin_key.clone());\n            scanned_types.insert(FindingType::Plugin);\n", ORACLE),
    ("a plugin finding loses its tool", ING, "                    tool: Some(plugin_key.clone()),", "                    tool: None,", ORACLE),
    ("a plugin finding without severity is unknown", ING, "result.severity.unwrap_or(Severity::Medium)", "result.severity.unwrap_or(Severity::Unknown)", ORACLE),

    # ── end of life: a catalogue, switched on, and a lookup that answered ──
    ("end of life asked of any SBOM", ING, "        let end_of_life = if is_cat {", "        let end_of_life = if true {", ORACLE),
    ("end of life asked while switched off", ING,
     "if eol.is_enabled() { eol.findings(sbom).await } else { None }", "eol.findings(sbom).await", ORACLE),
    ("a failed lookup declares the type", ING,
     "        if let Some(found) = &prepared.end_of_life {\n            scanned_types.insert(FindingType::Eol);\n",
     "        scanned_types.insert(FindingType::Eol);\n        if let Some(found) = &prepared.end_of_life {\n", ORACLE),
    ("an end-of-life row dated at ingestion", ING,
     "findings.push(finding_from_observed(scan.id, finding, prepared.at));",
     "findings.push(finding_from_observed(scan.id, finding, now));", ORACLE),

    # ── licences: a catalogue only, the list read at each scan, composed ──
    ("licences read from any SBOM", ING,
     "        if is_catalogue && let (Some(sbom), Some(license_source)) = (&sbom_val, &self.licenses) {",
     "        if let (Some(sbom), Some(license_source)) = (&sbom_val, &self.licenses) {", ORACLE),
    ("the blocklist is not read from the settings", ING,
     "                let raw = settings\n                    .get(vectispire_cp_settings::Setting::LicenseBlocklist)\n"
     "                    .await\n                    .map_err(|e| Box::new(e) as PortError)?;",
     "                let _ = settings;\n                let raw = String::new();", MY),
    ("the binary composes no licence source", APP,
     "        Some(Arc::new(LicenseService::from_settings(settings))),", "        { let _ = settings; None },", COMPOSED),
    ("the binary drops the enrichment stand-in", APP, "        Some(Arc::new(EnrichmentStandIn)),", "        None,", COMPOSED),
    ("the binary drops the end-of-life stand-in", APP, "        Some(Arc::new(EndOfLifeStandIn)),", "        None,", COMPOSED),

    # ── enrichment: the exploited flag the gate reads ──
    ("the exploited flag is never set", ING, "                    finding.is_kev = enrichment.exploited.contains(id);\n", "", ORACLE),
    ("a score is applied to every type", ING,
     "                if finding.type_ == FindingType::Vulnerability.wire_name()\n                    && let Some(id) = &finding.identifier",
     "                if let Some(id) = &finding.identifier", ORACLE),

    # ── a null element refuses the result, in every list ──
    ("a null element is skipped everywhere", ING,
     "    list.iter()\n        .map(|element| element.as_ref().ok_or_else(|| IngestError::Failed(Box::new(NullElement(what)))))\n        .collect()",
     "    let _ = what;\n    Ok(list.iter().flatten().collect())", ORACLE),
    ("a null dependency is skipped", ING, 'for dep in every(dependencies, "dependencies")? {', "for dep in dependencies.iter().flatten() {", ORACLE),
    ("a null secret is skipped", ING, 'for secret in every(secrets, "secrets")? {', "for secret in secrets.iter().flatten() {", ORACLE),
    ("a null IaC check is skipped", ING, 'for check in every(iac, "iac")? {', "for check in iac.iter().flatten() {", ORACLE),
    ("a null SAST result is skipped", ING, 'for result in every(sast, "sast")? {', "for result in sast.iter().flatten() {", ORACLE),
    ("a null plugin finding is skipped", ING,
     "for result in every(step_findings, \"a plugin's findings\")? {", "for result in step_findings.iter().flatten() {", ORACLE),
    ("a null endpoint is skipped", ING,
     'artifacts.api_endpoints.as_ref().map(|list| every(list, "apiEndpoints")).transpose()?.map(cloned);',
     "artifacts.api_endpoints.as_ref().map(|list| list.iter().flatten().cloned().collect::<Vec<_>>());", ORACLE),
    ("a null contract is skipped", ING,
     'artifacts.api_contracts.as_ref().map(|list| every(list, "apiContracts")).transpose()?.map(cloned);',
     "artifacts.api_contracts.as_ref().map(|list| list.iter().flatten().cloned().collect::<Vec<_>>());", ORACLE),
    ("a refused result is still looked up", ING,
     "        if artifacts.dependencies.as_ref().is_some_and(|list| list.iter().any(Option::is_none)) {",
     "        if false {", ORACLE),
]

# Not listed:
# - the transaction being mandatory: it is the ports' type (`&mut Tx`); a mutant that makes it optional does not
#   compile, which proves nothing about the tests.
# - `vulnerability_identifiers`' `flatten()`: after the refusal in `prepare` it never meets a `null`, so skipping one
#   there is equivalent.
# - `EnrichmentStandIn` and `EndOfLifeStandIn` answering something: what a stand-in answers is held by the composition
#   test naming it, not by a case.

if __name__ == "__main__":
    sys.exit(_runner.main(MUTANTS, timeout=1200))
