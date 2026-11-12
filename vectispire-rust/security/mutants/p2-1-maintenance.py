#!/usr/bin/env python3
"""Mutation check of Phase 2 task 2.1: the shared-module rule of cp-arch-tests (model.rs, edges.rs, data/edges/ against
Java's module model) and cp-maintenance (the slots, the turns, the composition check, the one-shot jobs).
A mutant that removes a turn's guard may hang: that is a red test, killed with its process group. See README.md.
"""
import sys

import _runner

MODEL = "crates/cp-arch-tests/src/model.rs"
EDGES = "crates/cp-arch-tests/src/edges.rs"
TOML = "crates/cp-arch-tests/data/edges/"
TASK = "crates/cp-maintenance/src/task.rs"
TURNS = "crates/cp-maintenance/src/turns.rs"
COMP = "crates/cp-maintenance/src/composition.rs"
SHOT = "crates/cp-maintenance/src/one_shot.rs"
PERS = "crates/cp-maintenance/src/persistence/mod.rs"
PMY = "crates/cp-maintenance/src/persistence/mysql.rs"
PPG = "crates/cp-maintenance/src/persistence/postgres.rs"

ARCH = ["-p", "vectispire-cp-arch-tests", "--test", "edges", "--test", "layering", "--test", "workspace", "--test", "sql"]
MAINT = ["-p", "vectispire-cp-maintenance", "--test", "turns", "--test", "failure_log", "--test", "reference", "--test", "composition"]
ENG = ["-p", "vectispire-cp-maintenance", "--test", "engines"]
APP = ["-p", "vectispire-cp-app", "--test", "maintenance_composition"]

MUTANTS = [
    # ── the shared-module rule ──
    ("nothing is shared", MODEL, "self.is_shared(to) && !self.is_shared(from)\n", "false\n", ARCH),
    ("the foundation shares with itself", MODEL, "self.is_shared(to) && !self.is_shared(from)\n", "self.is_shared(to)\n", ARCH),
    ("a root use ignores sharing", MODEL, "        self.shares(from, to)\n            || self.module.get(from).is_some_and(|m| m.open || m.allowed.iter().any(|entry| entry == to))",
     "        self.module.get(from).is_some_and(|m| m.open || m.allowed.iter().any(|entry| entry == to))", ARCH),
    ("an interface use ignores sharing", MODEL, "self.shares(from, to) || self.module.get(from).is_some_and(|m| m.open || m.allowed.contains(&entry))",
     "self.module.get(from).is_some_and(|m| m.open || m.allowed.contains(&entry))", ARCH),
    ("a dependency ignores sharing", MODEL, "        self.shares(from, to)\n            || self.module.get(from).is_some_and(|m| m.open)",
     "        self.module.get(from).is_some_and(|m| m.open)", ARCH),
    ("the unlisted edges are not in the cycle check", MODEL, "                if !self.is_shared(module) {\n                    edges.extend",
     "                if false {\n                    edges.extend", ARCH),
    ("a domain may list a shared module", MODEL, "if owner.shared && !entry.shared {", "if false {", ARCH),
    ("a shared module may not list another", MODEL, "if owner.shared && !entry.shared {", "if owner.shared {", ARCH),
    ("a shared module may be open", MODEL, "if entry.open && entry.shared {", "if false {", ARCH),
    ("a list needs no reason", MODEL, "if !justified && !entry.allowed.is_empty() {", "if false {", ARCH),
    ("a sharing needs no reason", MODEL, "if !justified && entry.shared {", "if false {", ARCH),
    ("a blank reason is a reason", MODEL, "is_some_and(|reason| !reason.trim().is_empty())", "is_some()", ARCH),
    ("the foundation's violation is not told apart", EDGES, "if config.is_shared(module) && config.is_shared(&other) {", "if false {", ARCH),
    ("reporting is not shared", TOML + "reporting.toml", 'status = "pending"\nallowed = []\nshared = true\n',
     'status = "pending"\nallowed = []\n', ARCH),
    ("agents loses a line Java has", TOML + "agents.toml", 'allowed = ["access", "access::security", "rules", "scanning", "targets"]',
     'allowed = ["access", "access::security", "scanning", "targets"]', ARCH),
    ("crypto loses its foundation edge", TOML + "crypto.toml", 'allowed = ["outbound", "settings"]', 'allowed = ["settings"]', ARCH),
    # ── the slots ──
    ("an order value moves", TASK, 'slot("TRIAGE_EXPIRY", 500,', 'slot("TRIAGE_EXPIRY", 505,', MAINT),
    ("a slot on the wrong turn", TASK, 'slot("REPORT_RUN_SWEEP", 40, "reportplugins", "ReportRunSweepTask", Scheduling)',
     'slot("REPORT_RUN_SWEEP", 40, "reportplugins", "ReportRunSweepTask", Hourly)', MAINT),
    ("a slot in the wrong module", TASK, '"posture", "WeeklyDigestTask"', '"compliance", "WeeklyDigestTask"', MAINT),
    ("a task misnamed", TASK, '"SessionCleanupTask"', '"SessionsCleanupTask"', MAINT),
    ("a turn's label", TASK, 'Cadence::Scheduling => "scheduling tick",', 'Cadence::Scheduling => "scheduler tick",', MAINT),
    ("a variant out of place", TASK, "    TriageExpiry,\n    /// After the expiry: an acceptance that lapsed puts its issue back among those whose deadline counts.\n    SlaBreaches,\n",
     "    /// After the expiry: an acceptance that lapsed puts its issue back among those whose deadline counts.\n    SlaBreaches,\n    TriageExpiry,\n", MAINT),
    # ── the turns ──
    ("two tasks in one slot accepted", TURNS, "if by_slot.insert(sequence, task).is_some() {", "if by_slot.insert(sequence, task).is_none() && false {", MAINT),
    ("the composition is empty", TURNS, "        self.composition.clone()\n", "        Vec::new()\n", MAINT + APP),
    ("a task on its slot's other turn", TURNS, "grouped.entry(sequence.cadence()).or_default().push(task);",
     "grouped.entry(Cadence::Hourly).or_default().push(task);", MAINT),
    ("no guard", TURNS, "if guard.compare_exchange(false, true, Ordering::Acquire, Ordering::Relaxed).is_err() {",
     "if guard.compare_exchange(false, true, Ordering::Acquire, Ordering::Relaxed).is_err() && false {", MAINT),
    ("the guard is never released", TURNS, "self.0.store(false, Ordering::Release);", "self.0.store(true, Ordering::Release);", MAINT),
    ("a success counted as a failure", TURNS, "Ok(Ok(())) => continue,", "Ok(Ok(())) => String::new(),", MAINT),
    ("a failure ends the turn", TURNS, "            failed.push(sequence);\n", "            failed.push(sequence);\n            break;\n", MAINT),
    ("a panic is not caught", TURNS, "AssertUnwindSafe(task.run()).catch_unwind().await",
     "Ok::<_, Box<dyn std::any::Any + Send>>(task.run().await)", MAINT),
    ("the log sentence differs", TURNS, '"{}: {} failed, the turn goes on: {reason}"', '"{}: {} failed: {reason}"', MAINT),
    ("a literal panic's message lost", TURNS, 'if let Some(text) = panic.downcast_ref::<&str>() {\n        format!("panicked: {text}")',
     'if let Some(_text) = panic.downcast_ref::<&str>() {\n        "panicked".to_owned()', MAINT),
    ("a formatted panic's message lost", TURNS, '} else if let Some(text) = panic.downcast_ref::<String>() {\n        format!("panicked: {text}")',
     '} else if let Some(_text) = panic.downcast_ref::<String>() {\n        "panicked".to_owned()', MAINT),
    ("no initial delay", TURNS, "            tokio::time::sleep(intervals.initial_delay).await;\n", "", MAINT),
    ("every turn at the relay's interval", TURNS, "tokio::time::sleep(intervals.of(cadence)).await;", "tokio::time::sleep(intervals.relay).await;", MAINT),
    ("an hourly turn every half hour", TURNS, "maintenance: Duration::from_secs(60 * 60),", "maintenance: Duration::from_secs(30 * 60),", MAINT),
    ("the scheduling turn at the relay's", TURNS, "Cadence::Scheduling => self.scheduler,", "Cadence::Scheduling => self.relay,", MAINT),
    ("a shorter initial delay", TURNS, "initial_delay: Duration::from_secs(30),", "initial_delay: Duration::from_secs(20),", MAINT),
    # ── the composition check ──
    ("a missing slot passes", COMP, "            (false, false) => problems.push(", "            (false, false) if false => problems.push(", MAINT + APP),
    ("a stale deferral passes", COMP, "            (true, true) => problems.push(", "            (true, true) if false => problems.push(", MAINT),
    ("a deferral without a reason", COMP, "        if reason.is_empty() {", "        if false {", MAINT),
    ("a slot deferred twice", COMP, "        if entries.iter().any(|entry: &Deferred| entry.sequence == sequence) {", "        if false {", MAINT),
    ("comments read as entries", COMP, "if line.is_empty() || line.starts_with('#') {", "if line.is_empty() {", MAINT + APP),
    ("line numbers from zero", COMP, "let at = number.saturating_add(1);", "let at = number;", MAINT),
    ("parse problems ignored", COMP, "        Err(problems) => return problems,", "        Err(_) => Vec::new(),", MAINT),
    # ── the one-shot jobs ──
    ("the claim's instant not the clock's", SHOT, "persistence::claim(tx, name, self.clock.now()).await?;",
     "persistence::claim(tx, name, OffsetDateTime::UNIX_EPOCH).await?;", ENG),
    ("has_run inverted (MySQL)", PMY, ".is_some())", ".is_none())", ENG),
    ("has_run inverted (PostgreSQL)", PPG, ".is_some())", ".is_none())", ENG),
]


if __name__ == "__main__":
    sys.exit(_runner.main(MUTANTS, timeout=240))
