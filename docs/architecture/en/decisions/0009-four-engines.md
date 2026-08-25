# 0009 — Four database engines, each one measured

**Date:** 2026-08-16 · **Status:** **superseded** by [0014](0014-two-engines-and-a-test-fixture.md) on 2026-08-25 · **Supersedes:** [0008](0008-postgresql-and-mysql.md) · **Decider:** Laurent Boucher

## Context

[0008](0008-postgresql-and-mysql.md) had narrowed the set to PostgreSQL and MySQL. Two pressures
widened it again: SQLite was already what the HTTP test suite ran on, and MariaDB was being asked
for by deployments that had it and did not want a second server.

## Decision

Support PostgreSQL, MySQL, MariaDB and SQLite, with a native SQL migration set per dialect and an
integration campaign (`integrationTestAll`) that runs the whole suite against each.

## Consequences

**What it bought, and this part was real.** Running all four found portability defects that were
invisible to reading and to any single engine — a nullable parameter compared to a column, which
SQLite accepts and PostgreSQL refuses with *could not determine data type of parameter $2*; a bare
`DATETIME` on MySQL truncating to the second and breaking the audit chain's own verification.
Neither is visible in review. Both were found by running.

**What it cost, and this part was underestimated.** Every schema change had to be written four
times, and the campaign was never wired into CI — so the argument for the cost depended on somebody
remembering to run it. By August 2026 it had been failing on a stale entity count for an unknown
period, which is the shape of a guarantee nobody is checking.

**What was never established.** That all four could actually be *deployed*. SQLite could not: under
the shipped `ddl-auto: validate` it refuses to start, because its type affinities report a
timestamp column back as FLOAT. That was known inside the test profile and never reflected in the
supported set. [0014](0014-two-engines-and-a-test-fixture.md) corrects it.
