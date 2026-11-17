#!/usr/bin/env python3
"""Mutation check of wave 1, checklists stages 2 to 4: a line's current answer and what keeps it from a submission, a
proof's file name and link, a bound rule shown in the API's shape, the edge rule towards a module not ported yet, and
the replay sending a recorded binary body as recorded, and the `checklist_answer` handler in the outbox's registry. See README.md.

Killed by `cp-checklists`' unit tests, `cp-arch-tests`' workspace test and `cp-contract`'s `binary_bodies` and `cp-app`'s `maintenance_composition`. The routes'
answers themselves are held by the golden replay.
"""
import sys

import _runner

SERVICE = "crates/cp-checklists/src/project_checklists.rs"
FORMS = "crates/cp-checklists/src/forms.rs"
LINKS = "crates/cp-checklists/src/links.rs"
EDGES = "crates/cp-arch-tests/src/edges.rs"
REPLAY = "crates/cp-contract/src/recorded/replay.rs"
UNIT = ["-p", "vectispire-cp-checklists", "--lib"]
MT = "crates/cp-app/src/maintenance.rs"
MAINT = ["-p", "vectispire-cp-app", "--test", "maintenance_composition"]
WORKSPACE = ["-p", "vectispire-cp-arch-tests", "--test", "workspace"]
CONTRACT = ["-p", "vectispire-cp-contract", "--lib", "binary_bodies"]

MUTANTS = [
    ("the answers' handler not registered", MT,
     "            siem.delivery.clone(),\n            checklist_answers,\n", "            siem.delivery.clone(),\n", MAINT),
    ("a withdrawal leaves its answer standing", SERVICE,
     "            current.remove(&row.item_id);\n", "            current.insert(row.item_id, row.clone());\n", UNIT),
    ("a link proves a line asking for a file", SERVICE,
     '.filter(|proof| asked == EvidenceKind::LinkOrFile || proof.kind == "file")', ".filter(|_| true)", UNIT),
    ("a proof lapses on its last day", SERVICE,
     "days::day_of(until.0) >= today", "days::day_of(until.0) > today", UNIT),
    ("a yes without data asks for no proof", SERVICE,
     "if declared_not_measured && kind == EvidenceKind::None { EvidenceKind::LinkOrFile } else { kind }", "kind", UNIT),
    ("control characters kept in a file's name", SERVICE,
     "last.chars().filter(|c| !(*c < '\\u{20}' || *c == '\\u{7f}')).collect()", "last.chars().collect()", UNIT),
    ("a link past its ceiling", SERVICE, "if length > MAX_LINK {", "if length > MAX_LINK.saturating_add(1) {", UNIT),
    ("a link of any scheme", LINKS, 'if scheme != "https" && scheme != "http" {', "if false {", UNIT),
    ("a component present answers its versions", FORMS,
     '.map(|prefix| Writer::object([("purlPrefix", Writer::text(prefix)), ("versions", null())])),',
     '.map(|prefix| Writer::object([("purlPrefix", Writer::text(prefix)), ("versions", "[]".to_owned())])),', UNIT),
    ("an edge to a module without its crate is owed", EDGES,
     "if !used.contains(&allowed) && crates.contains(target.as_str()) {", "if !used.contains(&allowed) {", WORKSPACE),
    ("a recorded body sent whatever its length", REPLAY,
     "    if length.and_then(|length| usize::try_from(length).ok()) != Some(bytes.len()) {",
     "    if false {", CONTRACT),
]

if __name__ == "__main__":
    sys.exit(_runner.main(MUTANTS, timeout=900))
