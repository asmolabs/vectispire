#!/usr/bin/env python3
"""Mutation check of the matcher's database on its real 3 GB database (2026-11-23): what the update path must leave —
the old generation through a failed update, nothing half-written after an interrupted download, a stale answer read as
stale; and (2026-11-27) a published copy the matcher refuses replaced, not kept. Each mutant must turn one of `crates/scanners/tests/real_matcher.rs`'s ignored tests red. See README.md.

They download the publisher's database, so they need the network, Docker and the same variables as the nightly's
`real-matcher` job: `VECTISPIRE_REAL_GRYPE_CACHE` (kept between runs) and `VECTISPIRE_REAL_MATCHER_OUT`. Some 20 minutes:
the third mutant is killed by the interruption that never comes (the watcher's 15-minute deadline).
"""
import os
import sys

import _runner

D = "crates/scanners/src/vulnerability_database.rs"


def real(test):
    return ["-p", "vectispire-scanners", "--test", "real_matcher", "--", "--ignored", test]


MUTANTS = [
    ("a failed update drops the kept generation", D,
     "let (Decision::Update, Some(current)) = (decision, current) else { return Err(failed) };",
     "let (Decision::Update, Some(current)) = (decision, current) else { return Err(failed) }; let _ = current; "
     "return Err(failed);",
     real("a_stale_database_is_kept")),
    ("a failed download leaves its staging directory", D,
     "        if outcome.is_err() {\n            delete_recursively(&staging);\n        }",
     "        if outcome.is_err() {}", real("an_interrupted_download")),
    ("the matcher's exit 100 read as current", D,
     "if result.exit_code == UPDATE_AVAILABLE {\n        return Freshness::UpdateAvailable;\n    }",
     "if result.exit_code == UPDATE_AVAILABLE {\n        return Freshness::Current;\n    }",
     real("a_stale_database_is_kept")),
    # A copy whose checksum no longer matches is "current" to the publisher's check: decided by the check alone,
    # it is kept and the test's first assertion fails, with no download (2026-11-27).
    ("a refused copy kept", D,
     "    if usability == Usability::Unusable {\n        return Decision::Replace;\n    }",
     "    if false {\n        return Decision::Replace;\n    }",
     real("a_corrupted_published_copy_is_replaced")),
]

if __name__ == "__main__":
    if "--list" not in sys.argv and "--check" not in sys.argv:
        for variable in ("VECTISPIRE_REAL_GRYPE_CACHE", "VECTISPIRE_REAL_MATCHER_OUT"):
            if not os.environ.get(variable):
                sys.exit(f"{variable} is required: these mutants run against the real database")
    sys.exit(_runner.main(MUTANTS, timeout=1500))
