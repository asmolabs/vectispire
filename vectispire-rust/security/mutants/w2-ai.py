#!/usr/bin/env python3
"""Mutation check of Phase 5, wave 2, ai: the advisor — the product's own advice (never `affected` for an identifier
no visible issue carries, a percentage to three decimals, references for a CVE only, an upgrade command only for the
ecosystem the purl names), the caller's visibility applied before anything is read, the model asked only when the
review is on and its provider switched on, its fenced JSON read, its own model list. See README.md.
"""
import sys

import _runner

T = ["-p", "vectispire-cp-ai", "--test", "advisor"]
U = ["-p", "vectispire-cp-ai", "--lib"]
A = "crates/cp-ai/src/advice.rs"
C = "crates/cp-ai/src/ecosystem.rs"
V = "crates/cp-ai/src/advisor.rs"
R = "crates/cp-ai/src/review.rs"

MUTANTS = [
    # The product's own advice.
    ("an identifier alone said affected", A, "if carried_by_an_issue && known.kev == KevListing::Listed", "if known.kev == KevListing::Listed", U),
    ("five rounded down", A, "fraction.as_bytes().get(3).is_some_and(|digit| *digit >= b'5')", "fraction.as_bytes().get(3).is_some_and(|digit| *digit > b'5')", U),
    ("references for any identifier", A, "    match identifier.filter(|identifier| Exploitation::names_a_cve(Some(identifier))) {", "    match identifier {", U),
    ("a Maven command without a group", C, "            let namespace = component.namespace.as_ref()?;", "            let namespace = component.namespace.as_ref().unwrap_or(&component.name);", U),
    ("a list of versions taken as one", C, "        && chars.all(|c| c.is_ascii_alphanumeric() || matches!(c, '.' | '+' | '_' | '~' | '-'))", "        && chars.all(|c| c.is_ascii_alphanumeric() || matches!(c, '.' | '+' | '_' | '~' | '-' | ',' | ' '))", U),
    # Visibility.
    ("a hidden issue explained", V, "rows::require_visible_issue(found, target_of, allowed)", "rows::require_visible_issue(found, target_of, &Visibility::Everything)", T),
    ("a CVE carried where the caller cannot see explained from that issue", V, ".find(|issue| permits(allowed, target_of(issue)))", ".next()", T),
    # The model.
    ("an unknown provider read as OpenAI", R, "if java::to_lower_root(java::trim(value)) == \"openai\" { AiProvider::OpenAi } else { AiProvider::Ollama }", "if java::to_lower_root(java::trim(value)) == \"ollama\" { AiProvider::Ollama } else { AiProvider::OpenAi }", U),
    ("the model asked with the review off", R, "        if self.is_enabled().await? {", "        if true {", T),
    ("Ollama asked to stream", R, "json!({\"model\": model, \"messages\": messages, \"stream\": false})", "json!({\"model\": model, \"messages\": messages})", T),
    ("the fence kept", R, "        if text.starts_with(\"```\") {", "        if false {", T),
    ("the fix's default reworded", R, "            Some(fix) => format!(\"Upgrade to {fix}.\"),", "            Some(fix) => format!(\"Upgrade {fix}.\"),", T),
    ("an unnamed model listed", R, "            .filter(|name| !name.is_empty())\n", "", T),
    ("a switched-off provider asked for its models", R, "        if !self.integrations.is_enabled(provider.integration()).await.map_err(failed)? {", "        if false {", T),
]

if __name__ == "__main__":
    sys.exit(_runner.main(MUTANTS, description=__doc__))
