# 0014 — Two deployable engines, and SQLite as a test fixture

**Date:** 2026-08-25 · **Status:** accepted · **Supersedes:** [0009](0009-four-engines.md) · **Decider:** Laurent Boucher

## Context

The supported engine set changed three times in six days — [0004](0004-sqlite-and-postgresql-only.md)
(SQLite + PostgreSQL), [0008](0008-postgresql-and-mysql.md) (PostgreSQL + MySQL),
[0009](0009-four-engines.md) (four engines) — and none of those records says *why*. This one does,
because the reason is the only part that survives contact with the next reversal.

Two facts prompted the re-examination, and both were measured rather than reasoned about:

**SQLite cannot run the packaged application.** Booting the jar against SQLite under the shipped
`ddl-auto: validate` fails outright:

```
Schema validation: wrong column type encountered in column [created_at] in table [t_agent];
found [numeric (Types#FLOAT)], but expecting [timestamp (Types#TIMESTAMP_UTC)]
```

SQLite has type *affinities* rather than types, so it reports a `numeric` column back as FLOAT and
Hibernate rejects every timestamp. The unit suite has always known this — its profile sets
`ddl-auto: none` and says so in a comment — but the engine was still documented as one of four
supported deployments. It is not deployable at all, and calling it supported was an over-claim
rather than a decision.

**MariaDB is a fourth native migration set for a marginal difference.** Every schema change was
written four times, and the campaign that justified it does not run in CI, so it had been failing
on a stale entity count for an unknown period without anyone noticing. The cost was continuous;
the coverage was intermittent.

## Decision

**PostgreSQL and MySQL are the supported engines.** MySQL is the default — the engine
`docker-compose.yml` ships — and the engine is chosen by `VECTISPIRE_DB_URL` alone.

**SQLite stays, and is documented as what it is: the fixture the HTTP test suite runs on.** Its
migrations are kept and the campaign still applies them, because the unit suite depends on them
applying. It is not offered as a deployment.

**MariaDB is dropped**: driver, Testcontainers module, migration set and campaign task.

## Consequences

**What this costs.** A MariaDB deployment stops being possible without someone adding the set
back. Its dialect is close enough to MySQL's that most of it would work, which is exactly why it
should not be claimed: "probably compatible" is the claim this project spends a multi-engine
campaign avoiding.

**What it buys.** Every schema change is written twice instead of four times, the campaign halves,
and the supported set is now the set that has been demonstrated to boot. Both remaining engines
were verified during the audit of 2026-08-25 by starting the packaged jar against each, inserting
rows and calling the endpoints.

**What does not change.** Native SQL per dialect stays — see [0013](0013-flyway-multi-dialect-migrations.md).
The reason is `datetime(6)`: a bare `DATETIME` on MySQL truncates to the second, which makes the
audit chain fail its own integrity verification. That precision has to be declared, and declaring
it is what a migration abstraction would take away.

**H2 was considered and refused.** It is a test database nobody deploys, so adding it would repeat
the SQLite mistake with a third dialect to maintain. Worse, its compatibility modes hide precisely
the divergences the campaign exists to find — the defect that produced
`HistoryQueriesIntegrationTest` was a statement SQLite accepted and PostgreSQL refused. If the goal
were faster tests, a MySQL container starts in about six seconds.
