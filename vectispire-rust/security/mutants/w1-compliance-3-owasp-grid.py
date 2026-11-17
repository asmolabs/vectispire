#!/usr/bin/env python3
"""Mutation check of Phase 3, wave 1, compliance stage 3: the OWASP grid — its reading and scope, the grid with its
declarations and as CSV, the week by week view and its window, the weekly record's six-hour gate, and the monthly
capture. See README.md.
"""
import sys

import _runner

O = ["-p", "vectispire-cp-compliance", "--test", "owasp"]
L = ["-p", "vectispire-cp-compliance", "--lib"]
C = "crates/cp-compliance/src/coverage.rs"
G = "crates/cp-compliance/src/grid.rs"
W = "crates/cp-compliance/src/weekly.rs"
K = "crates/cp-compliance/src/weekly_capture.rs"
H = "crates/cp-compliance/src/progress.rs"
F = "crates/cp-compliance/src/owasp_words.rs"

MUTANTS = [
    # The scope.
    ("both scopes accepted", C, "    if project_id.is_some() && solution_id.is_some() {", "    if false {", O),
    ("a project read as no scope", C, "            (Some(id), _) => Some(self.targets.visible_project(id, allowance).await.map_err(refusal)?),", "            (Some(_), _) => None,", O),
    ("a solution read as no scope", C, "            (None, Some(id)) => Some(self.targets.visible_solution(id, allowance).await.map_err(refusal)?),", "            (None, Some(_)) => None,", O),
    # The record.
    ("no never-scanned target", C, "                evidence.insert(target, Evidence::never_scanned(domain_target(target)));\n", "", O),
    ("images left out", C, "            .chain(containers.iter().map(|row| ScanTarget::Container(row.id)))\n", "", O),
    # The grid as served.
    ("a declaration on every line", G, "                declaration: by_category.get(line.id).cloned(),", "                declaration: by_category.values().next().cloned(),", O),
    ("the last row unterminated", G, "        csv.push_str(&row.join(\",\"));\n        csv.push_str(\"\\r\\n\");", "        csv.push_str(&row.join(\",\"));\n        if line.id != \"A10\" { csv.push_str(\"\\r\\n\"); }", O),
    ("the estate unnamed", G, "            Some(scope.map_or(\"estate\", |scope| scope.kind).to_owned()),", "            scope.map(|scope| scope.kind.to_owned()),", O),
    ("the scope read before the language", G, "        let words = AdviceLanguage::parse(language)?;\n        let scoped = self.coverage.scoped(project_id, solution_id, allowance).await?;", "        let scoped = self.coverage.scoped(project_id, solution_id, allowance).await?;\n        let words = AdviceLanguage::parse(language)?;", O),
    ("any language", F, "        AdviceLanguage::CODES.iter().find(|(known, _)| *known == asked)", "        AdviceLanguage::CODES.iter().find(|(_, _)| true)", L),
    ("the language not trimmed", F, "        let asked = java::to_lower_root(java::trim(code));", "        let asked = java::to_lower_root(code);", L),
    ("one gap or many alike", F, "        Gap::NeverScanned if count == 1 => \" n'a jamais terminé de scan\",\n", "", L),
    # The weekly window.
    ("a future to kept", W, "        if to > current {\n            to = current;\n        }", "", O),
    ("from after to accepted", W, "        if from > to {", "        if false {", O),
    ("fifty-three weeks", W, "        if count > MAX_WEEKS {", "        if count > MAX_WEEKS + 1 {", O),
    ("the window before the scope", W, "        at_most_one(request.project_id, request.solution_id)?;\n", "", O),
    ("a leap day refused", W, "        2 if leap => 29,\n", "", L),
    ("a signed four-digit year", W, "(year.len() == 4 && signed && !negative) || ", "", L),
    ("a five-digit year unsigned", W, " || (year.len() > 4 && !signed)", "", L),
    ("an unknown state counted", W, "                    state_of(&row.state).map(|state| Split {", "                    Some(state_of(&row.state).unwrap_or(State::Findings)).map(|state| Split {", L),
    ("reopenings always known", W, "            let reopened = reopenings_known.then_some(flow.reopened);", "            let reopened = Some(flow.reopened);", L),
    ("a reconstructed week settled", W, "        settled: (!reconstructed).then(|| sum(&|line| line.settled.unwrap_or(0))),", "        settled: Some(sum(&|line| line.settled.unwrap_or(0))),", L),
    # The weekly record's gate.
    ("the boundary not due", K, "        (Some(newest), Some(gate)) => newest <= gate,", "        (Some(newest), Some(gate)) => newest < gate,", O),
    ("always due", K, "        (Some(newest), Some(gate)) => newest <= gate,", "        (Some(_), Some(_)) => true,", O),
    ("the week added to", K, "        WeeklyRepository::delete_week(&mut tx, week).await?;\n", "", O),
    # The monthly capture.
    ("a second row for the month", H, "                Some(existing) => {\n                    row.id = existing.id;\n                    SnapshotRepository::update(&mut tx, &row).await?;\n                }", "                Some(_) => SnapshotRepository::insert(&mut tx, &row).await?,", O),
    ("an unmeasured month charted", H, "            if !evaluation.overall_status.measured() {", "            if false {", O),
]

if __name__ == "__main__":
    sys.exit(_runner.main(MUTANTS, description=__doc__))
