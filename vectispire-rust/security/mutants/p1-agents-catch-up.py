#!/usr/bin/env python3
"""Mutation check of the recovery plan's Phase 1, agents: the contract range (crates/domain/src/contract.rs), the
executors (crates/protocol/src/executors.rs), the claim narrowed to the kinds the executors run (cp-scanning's queue
and dispatcher), and the agent's watch (crates/agent/src/serve.rs). See README.md.

Not a mutant: the refusal's `contract::served()` replaced by `contract::VERSION` — equivalent while OLDEST_SERVED equals
CURRENT ("1" either way); `domain::contract`'s own test pins `served()`.
"""
import sys

import _runner

CONTRACT = "crates/domain/src/contract.rs"
EXECUTORS = "crates/protocol/src/executors.rs"
SERVER = "crates/protocol/src/server.rs"
QUEUE = "crates/cp-scanning/src/internal/queue.rs"
DISPATCHER = "crates/cp-scanning/src/dispatcher.rs"
SERVE = "crates/agent/src/serve.rs"
WIRE = [["-p", "vectispire-domain", "--lib", "contract"], ["-p", "vectispire-protocol", "--test", "server_wire_reference_set"]]
UNITS = ["-p", "vectispire-protocol", "--lib", "executors"]
CLAIM = ["-p", "vectispire-cp-scanning", "--test", "engines"]
AGENT = ["-p", "vectispire-agent", "--bins", "executors"]

MUTANTS = [
    # ── the range ──
    ("a leading zero read as a number", CONTRACT, "bytes.first().is_some_and(|first| (b'1'..=b'9').contains(first))", "true", WIRE),
    ("a newer agent served", CONTRACT, "(OLDEST_SERVED..=CURRENT).contains(&number)", "number >= OLDEST_SERVED", WIRE),
    ("one remedy for both", CONTRACT, "parse(announced).is_some_and(|number| number > CURRENT)", "false", WIRE),
    ("the hello's executors not read", SERVER, 'executors: coerce::last(&m, "executors", executors::read_list)?.flatten(),\n        }))', "executors: None,\n        }))", ["-p", "vectispire-protocol", "--lib", "server"]),
    # ── what the executors say ──
    ("an unavailable executor claims its kinds", EXECUTORS, ".filter(|executor| executor.available)", "", UNITS),
    ("unknown reads as nothing available", EXECUTORS, "announced.map_or_else(ExecutorTarget::every, WorkerExecutors::claimable)", "announced.map_or_else(BTreeSet::new, WorkerExecutors::claimable)", UNITS),
    ("the detail not scrubbed", EXECUTORS, 'failure_reason::scrub(executor.detail.as_deref().unwrap_or(""), [])', 'executor.detail.clone().unwrap_or_default()', UNITS),
    ("past eight executors kept", EXECUTORS, ".take(MAX_EXECUTORS)", "", UNITS),
    # ── the claim ──
    ("every kind claimed whatever the executors", QUEUE, "targets.contains(if row.repo_id.is_some() {", "true || targets.contains(if row.repo_id.is_some() {", CLAIM),
    ("the fast path whatever the kinds", QUEUE, "if exclusion.excludes_nothing() && every_kind {", "if exclusion.excludes_nothing() {", CLAIM),
    ("no executor claims as unknown", DISPATCHER, "let runnable = WorkerExecutors::claimable_of(agent.executors.as_ref());", "let runnable = WorkerExecutors::claimable_of(None);", CLAIM),
    # ── the agent's watch ──
    ("every probe reported", SERVE, "if state.unsupported || state.reported.as_ref() == Some(&current) {", "if state.unsupported {", AGENT),
    ("a 404 asked again", SERVE, "self.state().unsupported = true;", "", AGENT),
    ("the report's refusal swallowed", SERVE, "Err(fatal) if fatal.is_fatal() => return Err(fatal),\n            Err(unreachable) => tracing::warn!(", "Err(unreachable) => tracing::warn!(", AGENT),
]

if __name__ == "__main__":
    sys.exit(_runner.main(MUTANTS, timeout=900))
