# 0008 — Two database engines: PostgreSQL and MySQL

**Date:** 2026-08-14 · **Status:** **superseded** by [0009](0009-four-engines.md) on 2026-08-16

## Context & Decision

PostgreSQL and MySQL, after MySQL's timestamp precision was re-examined and found workable:
a bare `DATETIME` truncates to the second, `datetime(6)` does not, and the audit chain needs the
millisecond it hashes. SQLite left the supported set.

## Why it was superseded — and why that turned out to be a detour

[0009](0009-four-engines.md) widened the set to four two days later, under two pressures it
records: SQLite was already what the HTTP test suite ran on, and MariaDB was being asked for by
deployments that had it.

**[0014](0014-two-engines-and-a-test-fixture.md) then returned to exactly this record's answer** —
PostgreSQL and MySQL, with SQLite named as a test fixture rather than an engine. The register
spent six days and two records to arrive back where it started.

That is worth keeping rather than tidying away. What made the return defensible was not better
judgement: it was that the four-engine campaign had been *run*, and its cost measured — every
schema change written four times, a campaign never wired into CI, and a stale assertion that had
been failing for an unknown period. The reversal this record's own supersession caused was cheap
because nobody had explained it; the reversal in 0014 was expensive to establish and is therefore
the one that should hold.
