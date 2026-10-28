#!/usr/bin/env python3
"""Mutation check of the lists that only shrink, one file per module: cp-contract's routes not ported
(`reference/not-yet-ported/`, routes.rs) — each file at its own ceiling, a route listed once, a module's routes off the
list, the registry and the list partitioning the document — and cp-arch-tests' edge list read from `data/edges/`.
The per-file ceilings of `golden/deferred/` (shrinking.rs) are p2-11a-replay.py's. See README.md.
"""
import sys

import _runner

ROUTES = "crates/cp-contract/src/routes.rs"
MODEL = "crates/cp-arch-tests/src/model.rs"

CONTRACT = ["-p", "vectispire-cp-contract", "--test", "routes", "--test", "embedded_contract"]
ARCH = ["-p", "vectispire-cp-arch-tests", "--test", "edges", "--test", "workspace"]

MUTANTS = [
    # ── each file of reference/not-yet-ported/ at its own ceiling ──
    ("a file above its ceiling", ROUTES, "        } else if entries > ceiling {\n            findings.push(",
     "        } else if false && entries > ceiling {\n            findings.push(", CONTRACT),
    ("a file's ceiling never lowered", ROUTES, "        } else if entries < ceiling {\n            findings.push(",
     "        } else if false && entries < ceiling {\n            findings.push(", CONTRACT),
    ("a file that lists nothing kept", ROUTES, "        if entries == 0 {\n            findings.push(",
     "        if false && entries == 0 {\n            findings.push(", CONTRACT),
    ("a route in two files", ROUTES, "if !entries.insert((method.to_ascii_uppercase(), path.to_owned())) {",
     "if !entries.insert((method.to_ascii_uppercase(), path.to_owned())) && false {", CONTRACT),
    # ── a module's own test ──
    ("a module's route still listed passes", ROUTES, "        if committed.contains(method, path) {",
     "        if false && committed.contains(method, path) {", CONTRACT),
    ("a module's test reads a broken list as fine", ROUTES, "    findings.extend(committed.malformed.iter().cloned());\n", "", CONTRACT),
    ("the module's own routes are another's", ROUTES, ".filter(|route| !served.contains(route)).collect();",
     ".collect();", CONTRACT),
    # ── the registry's partition ──
    ("a route neither served nor listed passes", ROUTES, "        } else if !listed {", "        } else if false {", CONTRACT),
    ("a route served and listed passes", ROUTES, "            if listed {\n                findings.push(Finding::AllowlistedButServed",
     "            if false {\n                findings.push(Finding::AllowlistedButServed", CONTRACT),
    # ── data/edges/ ──
    ("a stray file in edges/ skipped", MODEL, 'return Err(format!("edges/{name}: not `<module>.toml` nor `_workspace.toml`"));',
     "continue;", ARCH),
]

# Out of reach here: `served()` in crates/cp-agents/tests/golden.rs leaves out the routes a `route` line covers; the
# test it belongs to needs a recording of the Java suite (crates/cp-contract/scripts/replay-goldens.sh), so its
# mutant is run by hand with one: without the filter the Phase 3 routes still listed are replayed and fail.


if __name__ == "__main__":
    sys.exit(_runner.main(MUTANTS, timeout=900))
