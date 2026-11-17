#!/usr/bin/env python3
"""Mutation check of Phase 3, wave 1, compliance stage 0c: crates/cp-compliance — its four tables' statements, the
weekly record narrowed to a reader's targets by kind and id (cp-db's `Kinded`), the purge listeners and the retention
tasks — and the scanning reads compliance adds. See README.md.
"""
import sys

import _runner

P = ["-p", "vectispire-cp-compliance", "--lib", "persistence::tests"]
S = ["-p", "vectispire-cp-scanning", "--lib", "persistence::tests"]
R = "crates/cp-compliance/src/persistence/repository.rs"
U = "crates/cp-compliance/src/purge.rs"
T = "crates/cp-compliance/src/internal/tasks.rs"
Q = "crates/cp-db/src/query.rs"
C = "crates/cp-scanning/src/persistence/catalog_queries.rs"

MUTANTS = [
    # The statements.
    ("lapsed includes the due instant", R, ".filter(DeclarationColumn::ReviewDueAt.lt(now))", ".filter(DeclarationColumn::ReviewDueAt.lte(now))", P),
    ("lapsed most recent first", R, ".order_by(DeclarationColumn::ReviewDueAt, Order::Asc)", ".order_by(DeclarationColumn::ReviewDueAt, Order::Desc)", P),
    ("progression by framework first", R, "            .order_by(SnapshotColumn::Period, Order::Asc)\n            .order_by(SnapshotColumn::Framework, Order::Asc)", "            .order_by(SnapshotColumn::Framework, Order::Asc)\n            .order_by(SnapshotColumn::Period, Order::Asc)", P),
    ("snapshot purge includes the cutoff", R, ".filter(SnapshotColumn::CapturedAt.lt(cutoff))", ".filter(SnapshotColumn::CapturedAt.lte(cutoff))", P),
    ("latest without the key's tie-break", R, "            .order_by(ReviewColumn::Id, Order::Desc)\n            .limit(1)", "            .order_by(ReviewColumn::Id, Order::Asc)\n            .limit(1)", P),
    ("awaited past the deadline", R, ".filter(ReviewColumn::DeadlineAt.gt(now))", ".filter(ReviewColumn::DeadlineAt.gte(now))", P),
    ("a settled report swept", R, "            .filter(ReviewColumn::Status.eq(running))\n            .filter(ReviewColumn::DeadlineAt.lt(now))", "            .filter(ReviewColumn::DeadlineAt.lt(now))", P),
    ("another week rewritten", R, "delete_weekly().filter(WeeklyColumn::WeekStart.eq(week))", "delete_weekly().filter(WeeklyColumn::WeekStart.gte(week))", P),
    ("the boundary week purged", R, "delete_weekly().filter(WeeklyColumn::WeekStart.lt(week))", "delete_weekly().filter(WeeklyColumn::WeekStart.lte(week))", P),
    ("a target's rows by id alone", R, "            .filter(WeeklyColumn::TargetKind.eq(kind))\n            .filter(WeeklyColumn::TargetId.eq(id))", "            .filter(WeeklyColumn::TargetId.eq(id))", P),
    ("the range's end excluded", R, ".filter(WeeklyColumn::WeekStart.lte(to_week));", ".filter(WeeklyColumn::WeekStart.lt(to_week));", P),
    ("the newest capture is the oldest", R, ".expr_as(Func::max(Expr::col(WeeklyColumn::CapturedAt)), Alias::new(\"captured_at\"))", ".expr_as(Func::min(Expr::col(WeeklyColumn::CapturedAt)), Alias::new(\"captured_at\"))", P),
    # Visibility by kind and id.
    ("an image read as a repository", Q, "for (spelt, ids) in [(KIND_REPOSITORY, &repositories), (KIND_CONTAINER, &containers)] {", "for (spelt, ids) in [(KIND_REPOSITORY, &repositories), (KIND_REPOSITORY, &containers)] {", P),
    ("the kind not compared", Q, "                        .add(Condition::all().add(Expr::col(Alias::new(kind)).eq(spelt)).add(in_literals(id, ids)));", "                        .add(Condition::all().add(in_literals(id, ids)));", P),
    # The purges and the tasks.
    ("a deletion's rows left", U, "            WeeklyRepository::delete_by_target(tx, kind, id).await.map_err(failed)?;\n", "", P),
    ("an unknown kind swept", U, "                    _ => true,\n", "                    _ => false,\n", P),
    ("the sweep on a deletion", U, "            if !matches!(purge, TargetPurge::Orphans) {\n                return Ok(());\n            }\n", "", P),
    ("reports outlive their scans", U, "                ReviewRepository::delete_by_scan_ids(tx, batch).await.map_err(failed)?;\n", "", P),
    ("purged from the cutoff, not its Monday", T, "    let monday = week_start(Instant { epoch_second: cutoff.unix_timestamp(), nano: cutoff.nanosecond() });\n", "    let monday = Instant { epoch_second: cutoff.unix_timestamp(), nano: 0 };\n", P),
    # The scanning reads.
    ("newest without the key's tie-break", C, "        .order_by(ScanColumn::CreatedAt, Order::Desc)\n        .order_by(ScanColumn::Id, Order::Desc)\n        .to_owned();\n    Ok(orm::fetch_all(tx, &select).await?)\n}", "        .order_by(ScanColumn::CreatedAt, Order::Desc)\n        .order_by(ScanColumn::Id, Order::Asc)\n        .to_owned();\n    Ok(orm::fetch_all(tx, &select).await?)\n}", S),
    ("every status newest", C, "        .from(Scans)\n        .and_where(Expr::col(ScanColumn::Status).eq(status))\n        .order_by(ScanColumn::CreatedAt, Order::Desc)", "        .from(Scans)\n        .order_by(ScanColumn::CreatedAt, Order::Desc)", S),
]

if __name__ == "__main__":
    sys.exit(_runner.main(MUTANTS, description=__doc__))
