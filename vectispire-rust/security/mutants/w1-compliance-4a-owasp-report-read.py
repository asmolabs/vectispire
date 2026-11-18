#!/usr/bin/env python3
"""Mutation check of Phase 3, wave 1, compliance stage 4a: the OWASP report as read — the Markdown into blocks (held
to Java's reference set), the status as of now, the backlog's figures beside the report and the links from the
identifiers the model was shown — and the contract probe's reading of a method the path lacks. See README.md.
"""
import sys

import _runner

R = ["-p", "vectispire-cp-compliance", "--test", "compliance_reference_set"]
T = ["-p", "vectispire-cp-compliance", "--test", "report"]
L = ["-p", "vectispire-cp-compliance", "--lib"]
P = ["-p", "vectispire-cp-contract", "--test", "routes"]
M = "crates/cp-compliance/src/markdown.rs"
V = "crates/cp-compliance/src/review.rs"
A = "crates/cp-contract/src/axum_support.rs"

MUTANTS = [
    # The blocks.
    ("five hashes a heading", M, "    if !(1..=4).contains(&hashes) || !after.starts_with(is_space) {", "    if !(1..=5).contains(&hashes) || !after.starts_with(is_space) {", R),
    ("Unicode spaces as Java's \\s", M, "    matches!(c, ' ' | '\\t' | '\\n' | '\\u{b}' | '\\u{c}' | '\\r')", "    c.is_whitespace()", R),
    ("a line terminator read by .", M, "    (!rest.chars().any(is_terminator)).then_some(rest)", "    Some(rest)", R),
    ("a one-cell separator", M, "    cells >= 2\n", "    cells >= 1\n", R),
    ("the separator forgotten across prose", M, "        } else if !self.table.is_empty() {\n            self.flush_table();\n            self.separator_seen = false;\n        }", "        } else {\n            self.flush_table();\n            self.separator_seen = false;\n        }", R),
    ("each wrapped line a paragraph", M, "        // Consecutive lines are one paragraph, Markdown's own rule: a model hard-wraps its prose.\n", "        self.flush_paragraph();\n", R),
    ("A100 a category", M, "    if chars.next().is_some_and(|c| c.is_ascii_digit()) {\n        return None;\n    }", "", R),
    ("a heading's case kept", M, "    let upper = java::to_upper_root(java::strip(heading));", "    let upper = java::strip(heading).to_owned();", R),
    ("italics left in", M, "    let italic = replace_all(&bold, italic_at);", "    let italic = bold.clone();", R),
    ("a star beside a star italic", M, "            && !k.checked_sub(1).is_some_and(|before| is(chars, before, '*'))\n", "", R),
    ("code spans left in", M, "    let code = replace_all(&italic, code_at);", "    let code = italic.clone();", R),
    # The status as of now.
    ("the deadline itself abandoned", V, "    stored == RUNNING && deadline.is_some_and(|deadline| deadline < now)", "    stored == RUNNING && deadline.is_some_and(|deadline| deadline <= now)", R),
    ("an abandoned review still running", V, "        status: if abandoned { FAILED.to_owned() } else { row.status },", "        status: row.status,", T),
    ("an abandoned review without its reason", V, "        error: if abandoned { Some(ABANDONED.to_owned()) } else { row.error },", "        error: row.error,", T),
    # The identifiers.
    ("an unreadable column read as empty", V, "            _ => None,\n        })\n        .collect()", "            _ => Some(String::new()),\n        })\n        .collect()", L),
    ("not recorded read as none to link", V, "        let Some(shown) = shown else {\n            return Ok(None);\n        };", "        let shown = shown.unwrap_or_default();", T),
    # The figures and the links.
    ("the settled counted", V, "                unsettled: true,\n", "                unsettled: false,\n", T),
    ("another repository's counted", V, "                repository_id: Some(repository_id),\n", "                repository_id: None,\n", T),
    ("the identifier matched by case", V, "            if let Some(key) = IssueFilters::identifier_key(issue.identifier.as_deref()) {", "            if let Some(key) = issue.identifier.clone() {", T),
    ("several issues named as one", V, "            let link = IssueLink { issue_id: if ids.len() == 1 { ids.first().copied() } else { None }, count };", "            let link = IssueLink { issue_id: ids.first().copied(), count };", T),
    ("resolved issues linked", V, "        let mut filters = IssueFilters::new(allowed.clone());\n", "        let mut filters = IssueFilters::new(allowed.clone());\n        filters.state = None;\n", T),
    ("a hidden repository's report served", V, "        require_visible_repository(found, repository_id, allowed)", "        require_visible_repository(found, repository_id, &Visibility::Everything)", T),
    # The probe.
    ("the method fallback read as a handler", A, "                && !allows_another(&response, method.as_str())\n", "\n", P),
]

if __name__ == "__main__":
    sys.exit(_runner.main(MUTANTS, description=__doc__))
