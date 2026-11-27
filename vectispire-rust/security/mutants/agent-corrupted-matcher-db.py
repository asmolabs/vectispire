#!/usr/bin/env python3
"""Mutation check of the corrupted matcher database's replacement (branch fix/agent-corrupted-matcher-db, 2026-11-27):
a due check reads the published copy back offline first, a refused copy is replaced and never kept as a fallback, a
silent publisher or a matcher that could not run leaves a usable copy in place. Each mutant must turn the fake-matcher
suite (`crates/scanners/tests/vulnerability_database.rs`) or the Java agent's decision table
(`dependencies_reference_set.rs`, `reference/dependencies/database/decisions.json`) red. See README.md. The same guard
on the real database is `agent-real-matcher.py`'s "a refused copy kept".
"""
import sys

import _runner

D = "crates/scanners/src/vulnerability_database.rs"
T = [
    ["-p", "vectispire-scanners", "--test", "vulnerability_database"],
    ["-p", "vectispire-scanners", "--test", "dependencies_reference_set"],
]

MUTANTS = [
    ("an unusable copy decided as the check says", D,
     "    if usability == Usability::Unusable {\n        return Decision::Replace;\n    }",
     "    if false {\n        return Decision::Replace;\n    }", T),
    ("a refused copy mounted when its replacement fails", D,
     "let (Decision::Update, Some(current)) = (decision, current) else { return Err(failed) };",
     "let Some(current) = current else { return Err(failed) };", T),
    ("the copy never read back", D,
     "let usability = usability(self.read_back(generation).await.as_ref());",
     "let usability = Usability::Unanswered;", T),
    ("the publisher asked about a refused copy", D,
     "let freshness = if usability == Usability::Unusable {",
     "let freshness = if false {", T),
    ("a matcher that could not run read as a refusal", D,
     "let Some(result) = result else { return Usability::Unanswered };",
     "let Some(result) = result else { return Usability::Unusable };", T),
    ("an update available kept", D,
     "        Freshness::UpdateAvailable => Decision::Update,",
     "        Freshness::UpdateAvailable => Decision::Keep,", T),
    ("a silent publisher read as an update", D,
     "        Freshness::Current | Freshness::Unanswered => Decision::Keep,",
     "        Freshness::Current => Decision::Keep,\n        Freshness::Unanswered => Decision::Update,", T),
    ("a kept copy not marked checked", D,
     "        if let (Decision::Keep, Some(current)) = (decision, &current) {\n            self.mark_checked();",
     "        if let (Decision::Keep, Some(current)) = (decision, &current) {", T),
]

if __name__ == "__main__":
    sys.exit(_runner.main(MUTANTS))
