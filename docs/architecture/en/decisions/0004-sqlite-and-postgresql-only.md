# 0004 — Two database engines: SQLite and PostgreSQL

**Date:** 2026-08-10 · **Status:** **superseded** by [0008](0008-postgresql-and-mysql.md) on 2026-08-14

## Context & Decision

SQLite for single-instance embedded deployments, PostgreSQL for clustered production ones. The
appeal was that the smallest deployment needed no server at all.

## Why it was wrong

**SQLite was never a deployable engine, and this record is where that error entered.** Under the
shipped `ddl-auto: validate` the application refuses to start on it: SQLite has type *affinities*
rather than types, so it reports a timestamp column back as FLOAT and Hibernate rejects the
mapping. That was known inside the test profile and contradicted the supported set for fifteen
days. [0014](0014-two-engines-and-a-test-fixture.md) finally established it by running, and
demoted SQLite to what it had always actually been: the fixture the HTTP suite runs on.

[0008](0008-postgresql-and-mysql.md) replaced this record four days later for a different reason —
MySQL — and carried the SQLite error no further, but did not name it either. Nobody looked again
until the engine scope had reversed twice more.
