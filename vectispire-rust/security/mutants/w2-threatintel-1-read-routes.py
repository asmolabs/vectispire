#!/usr/bin/env python3
"""Mutation check of Phase 5, wave 2, threatintel stage 1: the fleet's exploitation ranking — within the caller's
allowance, settled triage and closed states left out, the measured scores and unknown left null, the counts weighing
everything and the list cut after a stable sort — and the issues' projection it reads. See README.md.
"""
import sys

import _runner

T = ["-p", "vectispire-cp-threatintel", "--test", "ranking"]
P = "crates/cp-threatintel/src/prioritization.rs"
I = "crates/cp-issues/src/persistence/aggregates.rs"

MUTANTS = [
    # What is ranked.
    ("settled triage ranked", P, "        let filters = IssueFilters { state: None, exclude_settled: true, ..IssueFilters::new(allowed.clone()) };", "        let filters = IssueFilters { state: None, exclude_settled: false, ..IssueFilters::new(allowed.clone()) };", T),
    ("another reader's issues ranked", P, "..IssueFilters::new(allowed.clone()) };", "..IssueFilters::new(Visibility::Everything) };", T),
    ("a closed state of another case ranked", P, "!row.state.eq_ignore_ascii_case(\"closed\")", "row.state != \"closed\"", T),
    ("resolved ranked", P, " && !row.state.eq_ignore_ascii_case(\"resolved\")", "", T),
    # The scores.
    ("the feed's KEV word ignored", P, "            let is_kev = issue.is_kev || record.is_some_and(|record| record.is_kev);", "            let is_kev = issue.is_kev;", T),
    ("the feed's score before the issue's", P, "            let epss_score = issue.epss_score.or_else(|| record.and_then(|record| record.epss_score));", "            let epss_score = record.and_then(|record| record.epss_score).or(issue.epss_score);", T),
    ("the identifier looked up untrimmed", P, "intel.get(&java::to_lower_root(java::trim(cve)))", "intel.get(&java::to_lower_root(cve))", T),
    ("0.20 not high", P, "                if score >= HIGH_EPSS {", "                if score > HIGH_EPSS {", T),
    ("the mean unrounded", P, "            average_fleet_epss: thousandths(average),", "            average_fleet_epss: average,", T),
    # The fallbacks and the names.
    ("no identifier said as empty", P, "                identifier: issue.identifier.clone().unwrap_or_else(|| issue.type_.clone()),", "                identifier: issue.identifier.clone().unwrap_or_default(),", T),
    ("the package skipped for a title", P, "                    .or_else(|| issue.package_name.clone())\n", "", T),
    ("an image named by its repository rule", P, "    if let Some(name) = issue.container_id.and_then(|id| containers.get(&id)) {\n        return name.clone();\n    }\n", "", T),
    # The order and the cut.
    ("ranked lowest first", P, "        ranked.sort_by_key(|issue| std::cmp::Reverse(issue.priority_score));", "        ranked.sort_by_key(|issue| issue.priority_score);", T),
    ("ranked unstably", P, "        ranked.sort_by_key(|issue| std::cmp::Reverse(issue.priority_score));", "        ranked.sort_unstable_by_key(|issue| std::cmp::Reverse(issue.priority_score));\n        ranked.reverse();\n        ranked.sort_by_key(|issue| std::cmp::Reverse(issue.priority_score));", T),
    ("the list uncut", P, "        ranked.truncate(RANKED);\n", "", T),
    ("the tiers in another order", P, "            (MEDIUM_THEORETICAL, self.medium_theoretical),\n            (HIGH_PROBABLE, self.high_probable),", "            (HIGH_PROBABLE, self.high_probable),\n            (MEDIUM_THEORETICAL, self.medium_theoretical),", T),
    # The projection.
    ("the backlog in the engine's order", I, "                IssueColumn::IsKev,\n            ])\n            .order_by(IssueColumn::Id, Order::Asc);\n        Ok(orm::fetch_all(tx, &statement).await?)\n    }\n\n    /// `rows(filters, Identified.class)`", "                IssueColumn::IsKev,\n            ])\n            .order_by(IssueColumn::Id, Order::Desc);\n        Ok(orm::fetch_all(tx, &statement).await?)\n    }\n\n    /// `rows(filters, Identified.class)`", T),
]

if __name__ == "__main__":
    sys.exit(_runner.main(MUTANTS, description=__doc__))
