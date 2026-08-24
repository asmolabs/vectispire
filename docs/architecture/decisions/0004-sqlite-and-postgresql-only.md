# 0004 — Two database engines: SQLite and PostgreSQL

**Date:** 2026-08-10 · **Status:** **superseded** by [0008](0008-postgresql-and-mysql.md) on 2026-08-14

> This decision refused MySQL on measured divergences, and it was right with what was
> known then. 0008 reopens it after re-examining them by running — and drops SQLite, which
> discards `FOR UPDATE SKIP LOCKED` silently. The text below is kept as it was: it says
> what was known at that date.

## Context

Three engines were supported and tested: SQLite, PostgreSQL 16, MySQL 8.4. The
multi-backend suite existed for good reasons — six portability defects in this schema were
invisible both from SQLite and to a careful reading, all found by running.

The question asked was: should SQLite be dropped, given that its single-writer limit
complicates fleet deployment?

## Decision

No — **MySQL is what goes.**

`SUPPORTED_BACKENDS` is `("sqlite", "postgresql")`. SQLite is the single-instance
deployment; PostgreSQL is everything else. A MySQL or MariaDB URL is **refused at
configuration time**, with the reason and the migration to perform.

### Why keep SQLite

The price of multi-dialect support is already paid, and paid correctly:
`supports_skip_locked` tests the dialect instead of assuming it, `startup_guard` refuses at
boot the deployment that cannot work. There is almost nothing left to write.

Against that, SQLite buys the one thing that decides whether a free tool is adopted: **you
can try it.** Requiring a PostgreSQL before the first result moves the evaluation from a
quarter of an hour to half a day.

And dropping SQLite would not fix the problem it seems to fix: of the three obstacles to
fleet deployment, PostgreSQL removes only one: at the time of this decision, server state
stayed pinned to the instance that accepted the socket and the migration lock was per-host.
Both have since been solved — sessions live in the database and the leader lease guards the
migration — which is what made [0008](0008-postgresql-and-mysql.md) possible.

### Why MySQL goes

It filled **no role** the other two do not cover: neither the zero-configuration option
nor the deployment target. It did, however, have behaviour of its own in three places,
each found by a test and not by a reading:

- **`DATETIME` truncated to the whole second**, silently, unless a fractional precision is
  declared. The audit log hashes `timestamp.isoformat()`, so an entry re-read after being
  written landed on a different hash and **declared itself tampered with**;
- **`SKIP LOCKED` counting skipped rows against `LIMIT`**, so six claimants out of ten came
  back empty-handed while twenty scans waited;
- **`NULLS LAST` as a syntax error.**

Three per-dialect branches in code whose subject is integrity, exercised by a single CI
job. The cost was not the code: it was that a defect in that place looks like correct
behaviour everywhere you test it.

## What was rejected

**Dropping SQLite** — see above.

**Letting MySQL work without testing it.** SQLAlchemy would connect and most of Vectispire
would work, so an operator who kept their URL would meet the removal months later, in the
shape of an audit log declaring itself tampered with. A back end that is no longer tested
must fail loudly on the first line, not subtly on the hundredth.

## Consequences

What was **kept although motivated by MySQL**, and why:

- **the claim retry budget.** Almost never spent on PostgreSQL, but removing a concurrency
  safeguard in the very commit that deletes the tests meant to observe its absence would be
  the wrong way to remove it;
- **sorting on `column IS NULL` rather than `nullslast()`.** Written for MySQL, it happens
  to be what SQLite needs too: without it, issues with no EPSS score would come ahead of
  those that have one, silently, on the engine almost everybody uses.

The migrations are not rewritten: they are records of what was applied. Their MySQL
branches are dead and harmless, and touching them is what already broke a fresh install
once.
