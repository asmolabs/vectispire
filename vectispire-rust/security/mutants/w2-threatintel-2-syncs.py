#!/usr/bin/env python3
"""Mutation check of Phase 5, wave 2, threatintel stage 2: the two synchronisations — the catalogue promoting,
un-flagging and announcing once, refused when older; the file written beside the one in use, confirmed when the same,
refused when older or much smaller, the refused and the N-2 generations discarded; the schedule's claim; each attempt
audited — the issues' walk and targeted writes they use, and the download's same-origin rule. See README.md.
"""
import sys

import _runner

T = ["-p", "vectispire-cp-threatintel", "--test", "sync"]
D = ["-p", "vectispire-cp-outbound", "--lib", "download"]
S = "crates/cp-threatintel/src/sync.rs"
E = "crates/cp-threatintel/src/epss_feed.rs"
C = "crates/cp-issues/src/catalog.rs"
X = "crates/cp-issues/src/persistence/exploitation.rs"
O = "crates/cp-outbound/src/download.rs"

MUTANTS = [
    # The catalogue.
    ("an older catalogue applied", S, "            && read_released < in_use\n", "            && read_released > in_use\n", T),
    ("a delisted CVE kept as exploited", S, "            if row.is_kev && !listed_ids.contains(cve.as_str()) {", "            if false {", T),
    ("the flags toggled, not compared", S, "            if kev == issue.is_kev {\n                continue;\n            }\n", "", T),
    ("the identifier read untrimmed", S, "listed.contains(&java::to_upper_root(java::trim(&issue.identifier)))", "listed.contains(&java::to_upper_root(&issue.identifier))", T),
    ("a promotion not announced", S, "                self.events.raise(tx, &event).await.map_err(FeedError)?;", "                let _ = &event;", T),
    ("the CVE count said as the KEV count", S, "        sync.cve_count = i64::try_from(stored.len()).unwrap_or(i64::MAX);", "        sync.cve_count = i64::try_from(read.added.len()).unwrap_or(i64::MAX);", T),
    ("the backlog's count dropped", S, "        Ok(SyncStatus { backlog_updated_count: i64::try_from(updated).unwrap_or(i64::MAX), ..stored })", "        Ok(stored)", T),
    ("the schedule runs whatever the claim says", S, "        if !claimed && exists {", "        if !exists {", T),
    ("the file's attempt not audited", S, "        self.audit\n            .record(actor.entry(AuditOperation::ThreatIntelSynced, RESOURCE, &describe_epss(&scored, origin)))\n            .await;\n", "", T),
    # The file.
    ("an older file applied", E, "    if read < used {", "    if read > used {", T),
    ("the same file rewritten", E, "    Ok(!(read == used && in_use.epss_model_version.as_deref() == Some(header.model_version.as_str())))", "    Ok(true)", T),
    ("a much smaller file applied", E, "        if current.is_some() {", "        if current.is_none() {", T),
    ("a refused generation left behind", E, "                self.discard_quietly(generation).await;\n", "", T),
    ("N-1 discarded, not N-2", E, "            self.discard_quietly(previous).await;\n        }", "        }\n        if let Some(current) = current {\n            self.discard_quietly(current).await;\n        }", T),
    ("N-2 never discarded", E, "            self.discard_quietly(previous).await;\n", "", T),
    ("a running synchronisation run twice", E, "        if claimed == 0 {\n            return Ok(Attempt { outcome: Outcome::Busy,", "        if claimed == 0 && false {\n            return Ok(Attempt { outcome: Outcome::Busy,", T),
    ("a resolved issue rescored and re-evaluated", E, "    vec![\"closed\".to_owned(), \"resolved\".to_owned()]", "    vec![\"closed\".to_owned()]", T),
    # The backlog's side.
    ("scores grouped with another", C, "known.to_bits() == score.to_bits()", "known.to_bits() != score.to_bits()", T),
    ("the flag written inverted", X, "                .col_expr(IssueColumn::IsKev, Expr::val(kev))", "                .col_expr(IssueColumn::IsKev, Expr::val(!kev))", T),
    ("the closed issues walked", X, "            .filter(IssueColumn::State.is_not_in(closed.iter().cloned()))\n", "", T),
    # The download.
    ("a redirect to another port followed", O, "                && port(&to) == port(&from)\n", "", D),
]

if __name__ == "__main__":
    sys.exit(_runner.main(MUTANTS, description=__doc__))
