#!/usr/bin/env python3
"""Mutation check of Phase 5, wave 2, threatintel stage 3: the two sources a scan's ingestion reads — end of life (a
cycle matched component by component, the longest winning; past its end high, inside the window medium, abandoned high;
the distribution and the packages, deduplicated on the cycle; absent on any failure; a day's caches; the setting) and
the enrichment from the stored feeds (spelled as the scan spelled it, nothing before a feed's first synchronisation).
See README.md.
"""
import sys

import _runner

T = ["-p", "vectispire-cp-threatintel", "--test", "scan_sources"]
U = ["-p", "vectispire-cp-threatintel", "--lib", "life_cycle"]
L = "crates/cp-threatintel/src/life_cycle.rs"
E = "crates/cp-threatintel/src/end_of_life.rs"
N = "crates/cp-threatintel/src/enrichment.rs"

MUTANTS = [
    # The rules.
    ("a cycle matched by prefix of its text", L, "other.0.starts_with(&self.0)", "other.0.iter().zip(&self.0).all(|(a, b)| a.to_string().starts_with(&b.to_string()))", U),
    ("the shortest cycle wins", L, "cycle.0.len() > length", "cycle.0.len() < length", U),
    ("ending today not ended", L, "eol_date.is_some_and(|date| date <= today)", "eol_date.is_some_and(|date| date < today)", U),
    ("the window's last day left out", L, "        if (0..=warning_days).contains(&days_left) {", "        if (0..warning_days).contains(&days_left) {", U),
    ("an abandoned product said supported", L, "    if release.maintained == Some(false) && eol_date.is_none() {", "    if false {", U),
    ("an ended cycle recommended", L, "release.maintained == Some(true) && release.eol != Some(true)", "release.maintained == Some(true)", U),
    ("a purl's trailing slash kept", L, "java::to_lower_root(value).trim_end_matches('/').to_owned()", "java::to_lower_root(value)", U),
    # The service.
    ("a negative window kept negative", E, "        Ok(if days >= 0 { i64::from(days) } else { DEFAULT_WARNING_DAYS })", "        Ok(i64::from(days))", T),
    ("one cycle reported twice", E, "            if !seen.insert(format!(\"{} {}\", candidate.product, release.name.as_deref().unwrap_or(\"null\"))) {", "            if !seen.insert(format!(\"{} {}\", candidate.label, candidate.version)) {", T),
    ("the distribution skipped", E, "            if self.product(&distro.id).await?.is_some() {", "            if false {", T),
    ("the packages skipped", E, "        found.extend(life_cycle::package_candidates(&sbom::artifacts(Some(document)), &index));\n", "        let _ = index;\n", T),
    ("nothing cached", E, "        if let Some(cached) = self.products.lock().map_err(poisoned)?.get(name).filter(|cached| fresh(cached, now)) {", "        if let Some(cached) = self.products.lock().map_err(poisoned)?.get(name).filter(|_| false) {", T),
    ("switched off still looks", E, "                Ok(false) => return None,\n", "                Ok(false) => {}\n", T),
    ("a failure said as nothing found", E, "                    tracing::warn!(\"End-of-life detection failed — step skipped, backlog left as it was: {failed}\");\n                    None", "                    tracing::warn!(\"End-of-life detection failed — step skipped, backlog left as it was: {failed}\");\n                    Some(Vec::new())", T),
    # The enrichment. (Its "no file yet" check is not listed: without a generation in use the lookup finds nothing
    # either way, so the mutant only silences the warning — an equivalent mutant.)
    ("exploited read before any catalogue", N, "is_some_and(|sync| sync.last_synced_at.is_some())", "is_some()", T),
    ("one spelling scored", N, "            for spelling in spellings.get(&known.cve_id).into_iter().flatten() {\n                scores.insert(spelling.clone(), known.score);\n            }", "            scores.insert(known.cve_id.clone(), known.score);", T),
    ("the identifier grouped untrimmed", N, "spellings.entry(java::to_upper_root(java::trim(identifier)))", "spellings.entry(java::to_upper_root(identifier))", T),
]

if __name__ == "__main__":
    sys.exit(_runner.main(MUTANTS, description=__doc__))
