#!/usr/bin/env python3
"""Mutation check of Phase 3, wave 1, compliance stage 0a: the backlog's `owasp_category` filter places issues as
Java's `IssueSpecifications.placedIn` does — a type placed by rule, or code analysis declaring the category — and not
by the column alone. See README.md.
"""
import sys

import _runner

E = ["-p", "vectispire-cp-issues", "--lib", "persistence::tests"]
D = ["-p", "vectispire-domain", "--lib", "owasp_coverage"]
R = "crates/cp-issues/src/persistence/repository.rs"
O = "crates/domain/src/owasp_coverage.rs"

MUTANTS = [
    ("placed by the column alone", R, "    if !types.is_empty() {\n        either = either.add(IssueColumn::Type.is_in(types));\n    }\n", "", E),
    ("any type declaring counts", R, "            .add(IssueColumn::Type.eq(owasp_coverage::DECLARES_ITS_CATEGORY.wire_name()))\n", "", E),
    ("anywhere is any column", R, "(owasp_coverage::types_placed_anywhere(), owasp_coverage::codes().map(str::to_owned).collect())", "(owasp_coverage::types_placed_anywhere(), vec![\"A11\".to_owned()])", E),
    ("eol not outdated", O, "    (FindingType::Eol, \"A06\"),\n", "", [D, E]),
    ("secrets placed in a02", O, "    (FindingType::Secret, \"A07\"),\n", "    (FindingType::Secret, \"A02\"),\n", D),
]

if __name__ == "__main__":
    sys.exit(_runner.main(MUTANTS, description=__doc__))
