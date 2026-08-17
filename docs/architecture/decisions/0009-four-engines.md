# 0009 — Four database engines, each one measured

**Date:** 2026-08-16 · **Status:** accepted · **Decider:** Laurent Boucher · **Supersedes:** [0008](0008-postgresql-and-mysql.md)

> Written up after the fact, from commit `337ac80`, which is where the work was done and
> the reasoning recorded; confirmed on 2026-08-17. The register requires a superseding
> page rather than an edit to 0008, and without this one the register and the code
> disagree.

## Context

Decision 0008 supported PostgreSQL and MySQL, dropped SQLite, and left MariaDB unsupported
"out of caution rather than observation". Both of those last two positions turned out to
rest on statements nobody had run.

**SQLite was a dead promise.** The dialect appeared in `SUPPORTED_DIALECTS`, `parseDialect`
accepted it, the error message listed it among the expected values, its capabilities
carried detailed comments, and document 04 sold it as *the default mode* — the one that
lets someone try Zanshin in a quarter of an hour. A probe showed its driver was not even
installed: not "the migrations fail", but no connection possible at all.

**MariaDB was announced without ever having run.** Its four capabilities were inherited
from MySQL "out of caution, not observation" — their own comment said so — and three were
wrong.

## Decision

All four engines are supported, and **all four pass the entire integration campaign**, each
with its own set of migrations: PostgreSQL, MariaDB, MySQL, SQLite.

`npm run test:integration:all` runs the four in sequence. A capability is declared only
once it has been measured on the engine it describes.

SQLite comes back as the single-instance shape, with its limits stated at startup rather
than discovered: one writer, no transactional claiming. What 0008 held against it — a
driver that discards `FOR UPDATE` silently — is not true of `better-sqlite3`, which
**refuses** it. An engine that refuses is exactly what 0008 asked for.

## What the new campaigns revealed

None of these concerned only the new engines.

**The anti-brute-force counters were wiped on every maintenance pass.** The retention
cutoff was an ISO string built character by character, without a timezone, compared
lexicographically against the stored format. PostgreSQL and MySQL return
`…T10:00:00.000Z`, SQLite `… 10:00:00.000`: the space sorts below the "T", so *every* row
looked expired. The file's own comment already named the price — "opening a window to
whoever is trying passwords".

**`since()` lied about its type.** `getRawMany` short-circuits hydration: the value
returned is the driver's. The `Promise<Date[]>` annotation was unverifiable, and the caller
hit "`at.getTime` is not a function" in the middle of the login path.

**`canClaimTransactionally` was declared and read by nobody.** The flag described a
behaviour without producing it: claiming issued `FOR UPDATE` unconditionally. It is finally
consulted — a pessimistic lock where one exists, a conditional `UPDATE` guarded by the
status elsewhere.

**MariaDB is not MySQL.** Since 10.7 it carries a native `uuid` type its driver picks on
its own: the MySQL migrations produced a schema there that the model immediately wanted to
rebuild — sixty-two statements of difference, measured, including every primary key. It has
its own set, and the length rule now applies to the **type** rather than to the engine's
name: `varchar` requires it, `uuid` refuses it, whether PostgreSQL's or MariaDB's.

Measured on two concurrent claimants and four queued scans, MariaDB returns a full batch —
like PostgreSQL, and better than MySQL, which returns an empty list. That is the second
time a capability "inherited out of caution" has turned out to be wrong; the first ruled
MySQL out for a bad reason. **An unmeasured caution is an assertion without evidence.**

**And a missing test.** `schema-parity` asks on every engine the question
`migration:generate` asks — "what would have to change for the database to look like the
entities?" — whose right answer is "nothing". It found two divergences as it was written:
the queue index enriched by a migration without being enriched on the entity, and the audit
log's index created without being declared anywhere.

## Consequences

The rule this decision leaves behind is the one that cost the most to learn twice: **a
declared capability that has not been executed against the engine it names is a comment,
not a fact.** `dialects.ts` is only trustworthy because `test:integration:all` runs.

The cost is four migration sets to keep in step, and a CI job that starts four containers.
[04](../04-runtime-and-deployment.md) records what each engine cannot do and what is said
at startup.
