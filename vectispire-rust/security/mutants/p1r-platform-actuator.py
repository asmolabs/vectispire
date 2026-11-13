#!/usr/bin/env python3
"""Mutation check of the recovery plan's Phase 1, platform: the actuator's Prometheus page and its scrape token
(crates/cp-runtime: metrics.rs, actuator.rs; crates/cp-http: chain.rs, access.rs) and the encryption census
(crates/cp-crypto/src/census.rs and its contributors in signing.rs, cp-siem's config.rs, cp-targets' credentials.rs).
The census's suites run on a database (Docker). See README.md.
"""
import sys

import _runner

RT = "crates/cp-runtime/src/"
HT = "crates/cp-http/src/"
CR = "crates/cp-crypto/src/"
ME, AC = RT + "metrics.rs", RT + "actuator.rs"
CH, AX = HT + "chain.rs", HT + "access.rs"
CE, SI = CR + "census.rs", CR + "signing.rs"
SC = "crates/cp-siem/src/config.rs"
TC = "crates/cp-targets/src/credentials.rs"
TRT = ["-p", "vectispire-cp-runtime", "--lib"]
THA = ["-p", "vectispire-cp-http", "--test", "actuator"]
THL = ["-p", "vectispire-cp-http", "--lib"]
TCL = ["-p", "vectispire-cp-crypto", "--lib"]
TCC = ["-p", "vectispire-cp-crypto", "--test", "census"]
TSE = ["-p", "vectispire-cp-siem", "--test", "engines"]
TTE = ["-p", "vectispire-cp-targets", "--test", "engines"]

MUTANTS = [
    # ── the Prometheus page ──
    ("no unit suffix", ME, "Some(unit) if !name.ends_with(&format!(\"_{unit}\")) => format!(\"{name}_{unit}\"),", "Some(_) => name,", TRT),
    ("a counter without _total", ME, "written: if kind == \"counter\" { format!(\"{name}_total\") } else { name },", "written: name,", TRT),
    # The families' order is the `BTreeMap`'s, not a guard of its own: a sort over it was removed as an equivalent mutant.
    ("the series unsorted", ME, "series.sort_by(|a, b| a.0.cmp(&b.0));", "", TRT),
    ("a summary's count as a double", ME, "format!(\"{name}_count{labels} {count}\"),", "format!(\"{name}_count{labels} {}\", prometheus_double(count as f64)),", TRT),
    ("no max beside a timer", ME, "add(max_name, \"gauge\", &meter.description, &meter.tags, vec![line]);", "let _ = (max_name, line);", TRT),
    ("a label value unescaped", ME, "format!(\"{}=\\\"{}\\\"\", prometheus_name(key), escape_label(value))", "format!(\"{}=\\\"{}\\\"\", prometheus_name(key), value)", TRT),
    # NaN has no branch of its own: Java's `Double.toString` writes it as the client does (an equivalent mutant, removed).
    ("infinity as Java writes it", ME, "    if value.is_infinite() {\n        if value > 0.0", "    if false {\n        if value > 0.0", TRT),
    ("prometheus not exposed", AC, "\"/prometheus\" => Some(Answer {", "\"/prometheus-not\" => Some(Answer {", TRT),
    # ── the scrape token ──
    ("the token on every path", CH, "        if principal.is_none()\n            && path == PROMETHEUS\n", "        if principal.is_none()\n            && true\n", THA),
    ("the token compared as a prefix", CH, "Ok(Some(expected)) if secret_equals(token, expected.expose()) => {", "Ok(Some(expected)) if expected.expose().starts_with(token) => {", THA),
    ("an unreadable file ignored", CH, "                Ok(_) => {}\n                // A file named and unreadable", "                Ok(_) | Err(_) => {}\n                // A file named and unreadable", THA),
    ("the scraper admitted anywhere", CH, "let scraper = gate == Gate::AdministratorSessionOrScraper && principal.is_metrics_scraper();", "let scraper = principal.is_metrics_scraper();", THA),
    ("no scraper admitted", CH, "if !administrator && !scraper {", "if !administrator {", THA),
    ("the gate below the page", AX, "    if path == PROMETHEUS {\n        return Gate::AdministratorSessionOrScraper;", "    if path.starts_with(PROMETHEUS) {\n        return Gate::AdministratorSessionOrScraper;", THL),
    # ── the census ──
    ("a previous key counted as current", CE, "            Seal::PreviousKey => &mut self.0.previous_key,", "            Seal::PreviousKey => &mut self.0.current,", TCL),
    ("an empty value counted", CE, "            Seal::Empty => return self,", "            Seal::Empty => &mut self.0.clear,", TCL),
    ("a blank value sealed", CE, "        let value = java::trim(stored.unwrap_or_default());", "        let value = stored.unwrap_or_default();", TCC),
    ("a clear value inspected", CE, "        if !Encryption::is_ciphertext(value) {\n            return Seal::Clear;", "        if false {\n            return Seal::Clear;", TSE),
    ("an unreadable store left out", CE, "            all.extend(store.census().await?);", "            all.extend(store.census().await.unwrap_or_default());", TCL),
    ("the stores unsorted", CE, "all.sort_by(|a, b| a.store.encode_utf16().cmp(b.store.encode_utf16()));", "", TCL),
    ("finished with a previous key", CE, "let finished = !stores.iter().any(StoreCensus::depends_on_previous_key);", "let finished = true;", TCL),
    ("the record under the key's context", SI, ".count(self.encryption.seal_of(record.as_deref(), KNOWN_KEYS_CONTEXT).await)", ".count(self.encryption.seal_of(record.as_deref(), CONTEXT).await)", TCC),
    ("the SIEM header not counted", SC, "            counter = counter.count(self.encryption.seal_of(row.auth_header.as_deref(), AUTH_HEADER_CONTEXT).await);", "            let _ = row;", TSE),
    ("a deploy key read under the token's context", TC, "let sealed_for = private_key_context(", "let sealed_for = git_token_context(", TTE),
]

if __name__ == "__main__":
    sys.exit(_runner.main(MUTANTS))
