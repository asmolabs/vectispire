# 0013 — Flyway with dialect-specific native migrations

**Date:** 2026-08-22 · **Status:** accepted · **Decider:** Laurent Boucher

> Supersedes [0011](0011-liquibase-rather-than-flyway.md).

## Context

The previous trade attempted to maintain a single Liquibase changelog across four engines (PostgreSQL, MariaDB, MySQL, SQLite). While it reduced initial line count, it introduced impedance mismatches and traps:
1. Liquibase's `addColumn` implementation on SQLite recreates the table via temporary tables, leaving foreign keys of dependent referencing tables pointing to non-existent temporary tables.
2. Abstract type mapping obscured subtle engine divergences (such as MySQL requiring `bit(1)` for Hibernate booleans while MariaDB uses `boolean`, and SQLite needing `numeric` for epoch millisecond timestamps).
3. Writing raw SQL changesets within Liquibase resulted in maintaining fragmented chunks of XML/YAML with embedded dialect strings.

## Decision

**Migrate from Liquibase to Flyway with native SQL migrations per dialect.**

The migrations are organized under `zanshin-core/src/main/resources/db/migration/{vendor}/`:
- `sqlite/`: Native SQLite DDL with inline foreign keys and `INTEGER PRIMARY KEY AUTOINCREMENT`.
- `postgresql/`: Native PostgreSQL DDL with `BIGINT GENERATED ALWAYS AS IDENTITY`, `TIMESTAMPTZ`, and `char(36)` UUIDs.
- `mysql/`: Native MySQL DDL with `BIGINT AUTO_INCREMENT`, `DATETIME(6)`, and `BIT(1)`.
- `mariadb/`: Native MariaDB DDL with `BOOLEAN`, `BIGINT AUTO_INCREMENT`, and `DATETIME(6)`.

## Consequences

- **Full DDL control**: What is written in the SQL file is exactly what is executed against the database engine.
- **Referential integrity on SQLite**: Foreign keys are created cleanly inline and table alterations use native SQLite DDL.
- **Portability verified by automated tests**:
  - `ChangelogTest.java` validates Flyway migrations against SQLite in unit tests, asserting all 26 tables and 20 foreign keys by name.
  - `SchemaParityIntegrationTest.java` validates with Hibernate against all four engines via Testcontainers (`ddl-auto: validate`).
