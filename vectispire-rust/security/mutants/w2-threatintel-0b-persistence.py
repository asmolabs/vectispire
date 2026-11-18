#!/usr/bin/env python3
"""Mutation check of Phase 5, wave 2, threatintel stage 0b: the three tables' statements — the catalogue's lookups,
the sync row's elections and the EPSS lease whose update count is the decision, a generation's reads and its discard
by ranges — and the reads of both feeds, which say unknown until each was read. See README.md.
"""
import sys

import _runner

L = ["-p", "vectispire-cp-threatintel", "--lib"]
R = "crates/cp-threatintel/src/persistence/repository.rs"
F = "crates/cp-threatintel/src/feeds.rs"

MUTANTS = [
    # The catalogue.
    ("a delisted entry still exploited", R, "            .filter(FeedColumn::IsKev.eq(true))\n", "", L),
    # The catalogue's election.
    ("a fresh catalogue read again", R, "            .filter(SyncColumn::LastSyncedAt.is_null().or(SyncColumn::LastSyncedAt.lt(stale_before)))\n", "", L),
    ("a failed attempt retried every turn", R, "            .filter(SyncColumn::LastAttemptAt.is_null().or(SyncColumn::LastAttemptAt.lt(retry_before)))\n", "", L),
    ("the lock-taking update moves the attempt", R, "            .col_expr(SyncColumn::LastAttemptAt, Expr::col(SyncColumn::LastAttemptAt))", "            .col_expr(SyncColumn::LastAttemptAt, value(Option::<OffsetDateTime>::None))", L),
    # The EPSS lease.
    ("a held lease taken", R, "            .filter(SyncColumn::Id.eq(id))\n            .filter(SyncColumn::EpssLeaseUntil.is_null().or(SyncColumn::EpssLeaseUntil.lt(now)))\n            .into_query();\n        Ok(orm::execute(tx, &update).await?)\n    }\n\n    /// `claimEpssScheduled`", "            .filter(SyncColumn::Id.eq(id))\n            .into_query();\n        Ok(orm::execute(tx, &update).await?)\n    }\n\n    /// `claimEpssScheduled`", L),
    ("a fresh file read again", R, "            .filter(SyncColumn::EpssSyncedAt.is_null().or(SyncColumn::EpssSyncedAt.lt(stale_before)))\n", "", L),
    ("a failed file retried every turn", R, "            .filter(SyncColumn::EpssAttemptAt.is_null().or(SyncColumn::EpssAttemptAt.lt(retry_before)))\n", "", L),
    ("the schedule takes a held lease", R, "            .filter(SyncColumn::EpssLeaseUntil.is_null().or(SyncColumn::EpssLeaseUntil.lt(now)))\n            .into_query();\n        Ok(orm::execute(tx, &update).await?)\n    }\n\n    /// `applyEpss`", "            .into_query();\n        Ok(orm::execute(tx, &update).await?)\n    }\n\n    /// `applyEpss`", L),
    ("the previous generation lost", R, "            .col_expr(SyncColumn::EpssPreviousGeneration, value(previous))", "            .col_expr(SyncColumn::EpssPreviousGeneration, value(Option::<i64>::None))", L),
    ("a lost claim applies", R, "            .filter(SyncColumn::EpssClaim.eq(generation))\n            .into_query();\n        Ok(orm::execute(tx, &update).await?)\n    }\n\n    /// `confirmEpss`", "            .into_query();\n        Ok(orm::execute(tx, &update).await?)\n    }\n\n    /// `confirmEpss`", L),
    ("a lost claim confirms", R, "            .filter(SyncColumn::EpssClaim.eq(generation))\n            .into_query();\n        Ok(orm::execute(tx, &update).await?)\n    }\n\n    /// `failEpss`", "            .into_query();\n        Ok(orm::execute(tx, &update).await?)\n    }\n\n    /// `failEpss`", L),
    ("a lost claim fails the holder", R, "            .filter(SyncColumn::EpssClaim.eq(generation))\n            .into_query();\n        Ok(orm::execute(tx, &update).await?)\n    }\n}", "            .into_query();\n        Ok(orm::execute(tx, &update).await?)\n    }\n}", L),
    # A generation.
    ("the generations kept discarded", R, "ScoreColumn::Generation.is_not_in(keep.iter().copied())", "ScoreColumn::Generation.is_in(keep.iter().copied())", L),
    ("the boundary at the start", R, "            .offset(offset)\n", "", L),
    ("the boundary row left behind", R, "            .filter(ScoreColumn::CveId.lte(up_to))", "            .filter(ScoreColumn::CveId.lt(up_to))", L),
    # The reads.
    ("a count with no file in use", F, "            total_scored: if sync.epss_generation.is_none() { 0 } else { sync.epss_count },", "            total_scored: sync.epss_count,", L),
    ("an expired lease in progress", F, "            in_progress: sync.epss_lease_until.is_some_and(|until| until > now),", "            in_progress: sync.epss_lease_until.is_some(),", L),
    ("not listed before the catalogue was read", F, "        let kev = if !catalogue_read {", "        let kev = if false {", L),
    ("never synchronised said as not listed", F, "        None if catalogue_read => \"Not listed in the CISA KEV catalogue\",", "        None => \"Not listed in the CISA KEV catalogue\",", L),
    ("an identifier keyed untrimmed", F, "            cve_ids.into_iter().filter(|id| !java::is_blank(id)).map(|id| java::to_lower_root(java::trim(id))),", "            cve_ids.into_iter().filter(|id| !java::is_blank(id)).map(java::to_lower_root),", L),
]

if __name__ == "__main__":
    sys.exit(_runner.main(MUTANTS, description=__doc__))
