# 0008 — Two database engines: PostgreSQL and MySQL

**Date:** 2026-08-14 · **Status:** **superseded** by [0009](0009-four-engines.md) on 2026-08-16 · **Supersedes:** [0004](0004-sqlite-and-postgresql-only.md)

> This decision dropped SQLite because its driver discards `FOR UPDATE SKIP LOCKED`
> silently, and left MariaDB unsupported for want of measurement. 0009 reopens both after
> running them. The text below is kept as it was: it says what was known at that date.

## Context

Decision 0004 kept SQLite and PostgreSQL, and **refused MySQL at configuration time**. It
was right with what was known then: three MySQL divergences had been measured that produced
no error but produced wrong data, one of which — the timestamp truncated to the second —
made **the audit log declare itself tampered with when nothing had been**.

Two things changed.

First the need: some customers do not have PostgreSQL, they have MySQL. An engine refused
at configuration time is not a technical compromise, it is an impossible deployment.

Then the re-examination: the three divergences were measured **by running** the engines,
not by re-reading an earlier analysis of them.

## Decision

`VERISCAPE_DB_DIALECT` is `postgres` or `mysql`. Both are supported and **both pass the full
integration campaign** — 249 tests, each engine started in turn by testcontainers with its
own set of migrations.

**SQLite goes.** It accepts `FOR UPDATE SKIP LOCKED` and then discards it silently: the
claim looks like a transaction, passes every test on a development machine, and hands the
same scan to two processes in production. That is the worst possible behaviour — an engine
that refuses is preferable to an engine that lies.

## What measurement corrected

**The timestamps.** `datetime(6)` is declared in the changelog, in a single place
rather than column by column, and the connection is fixed to UTC. The audit chain hashes
the ISO-serialized timestamp — hence to the millisecond — and it verifies. The defect that
had MySQL removed no longer exists, because its cause was removed and not worked around.

**The claiming.** The dialect module declared `canClaimTransactionally: false` for MySQL.
**That was wrong**, and leaving it would have ruled MySQL out for a bad reason: the campaign
shows that no row is ever handed to two claimants. The real divergence is elsewhere, and it
now has its own flag — `claimsCompleteBatches`. MySQL counts skipped rows against the
`LIMIT`, so a batch comes back short under contention; the rest goes out on the next round.
That is throughput, not correctness.

**A defect MySQL revealed on both sides.** There was no index at all on the scan queue.
MySQL said so brutally — "Lock wait timeout exceeded" — because without an index the engine
locks every row it examines. PostgreSQL tolerated the absence on a test-sized table, which
kept the defect invisible. **The cause is the same on both engines, only its manifestation
differs**, and the index is now in place on both.

## What remains true of 0004

The price of multi-dialect support is still paid the same way: capabilities are **declared**
in the changelog properties rather than guessed, and an operator learns at startup what their engine
cannot do. Nothing is forbidden silently.

## What is not decided here

**MariaDB remains unsupported**, out of caution rather than observation: it has not been
measured. Assuming it identical to MySQL would be exactly the reasoning this decision had
to correct.
