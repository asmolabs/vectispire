# 0013 — Flyway with dialect-specific native migrations

**Date:** 2026-08-22 · **Status:** accepted · **Supersedes:** [0011](0011-liquibase-rather-than-flyway.md)

## Context

The port arrived with Liquibase and a database-agnostic changelog: one description of the schema,
translated per engine by the tool. The appeal is obvious — the schema is written once — and it held
until the schema needed something the abstraction could not say.

Two cases decided it, and both are load-bearing rather than cosmetic:

* **`datetime(6)` on MySQL.** A bare `DATETIME` truncates to the second. The audit chain hashes a
  timestamp canonicalised to the millisecond, so a truncated column makes the log fail *its own*
  integrity verification — a security control reporting tampering that never happened, which is
  worse than one that reports nothing.
* **Foreign keys and cascade behaviour differ enough** between the engines that the generated DDL
  had to be inspected per engine anyway. At that point the abstraction is a layer between the
  author and the statement they are already reading.

## Decision

Flyway, with a native SQL migration set per dialect under
`src/main/resources/db/migration/{vendor}/`. `ddl-auto` stays `validate`: the schema belongs to the
migrations, and Hibernate must never reconcile it at runtime.

## Consequences

**The cost is duplication, and it is real.** Every schema change is written once per supported
engine. [0014](0014-two-engines-and-a-test-fixture.md) reduced that from four sets to two, which is
the main thing that would otherwise argue for going back.

**What is bought is that the statement in the file is the statement the server runs.** No
translation step stands between a review and the DDL, and the precision the audit chain depends on
is declared where a reader can see it.

**When to revisit.** If the supported set grows again, or if a schema change turns out to be
identical across every engine for a long enough stretch that the duplication is pure ceremony. Not
before: the reason this decision exists is a control that fails silently when the abstraction gets
a type wrong.
