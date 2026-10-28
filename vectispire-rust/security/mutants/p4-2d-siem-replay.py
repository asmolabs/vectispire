#!/usr/bin/env python3
"""Mutation check of Phase 4 task 4.2, fourth stage: what the replay of the SIEM routes brought to light — the issues'
triage decisions signalling `TRIAGE_SETTLED`, `TRIAGE_APPROVED` and `TRIAGE_REFUSED` (Java's `TriageSignals` on the
`ISSUE_TRIAGED` entry). The bulk path's statuses are held by the replay once the triage route is owed. See README.md.
"""
import sys

import _runner

ISSUES = ["-p", "vectispire-cp-issues", "--lib", "signal_tests"]
DEC = "crates/cp-issues/src/decision.rs"

MUTANTS = [
    ("triage not signalled", DEC, "Some(event) => entry.signalling(vectispire_cp_audit::Signal(event.wire_name())),", "Some(_) => entry,", ISSUES),
]

if __name__ == "__main__":
    sys.exit(_runner.main(MUTANTS, timeout=300))
