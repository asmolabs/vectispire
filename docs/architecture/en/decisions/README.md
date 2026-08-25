# Architecture Decision Records (ADR) — English

This directory contains the structural Architecture Decision Records (ADRs) for Vectispire.

| ADR | Title |
|---|---|
| [0001](0001-pluggable-scan-layer.md) | Pluggable scan layer |
| [0002](0002-the-database-carries-the-queue.md) | The database carries the scan queue |
| [0003](0003-long-polling-for-agents.md) | Long polling for agents |
| [0004](0004-sqlite-and-postgresql-only.md) | SQLite and PostgreSQL support |
| [0005](0005-quality-never-blocks-the-gate.md) | Quality findings never block the gate |
| [0006](0006-semgrep-rules-written-here.md) | Bundled Semgrep rules |
| [0007](0007-none-is-not-an-empty-list.md) | None is not an empty list |
| [0008](0008-postgresql-and-mysql.md) | PostgreSQL and MySQL support |
| [0009](0009-four-engines.md) | Support four database engines |
| [0010](0010-one-scan-runner.md) | Single concrete ScanRunner |
| [0011](0011-liquibase-rather-than-flyway.md) | Liquibase, with hand-written structural DDL |
| [0012](0012-apache-2-0.md) | Licensing under Apache 2.0 |
| [0013](0013-flyway-multi-dialect-migrations.md) | Flyway multi-dialect SQL migrations |
| [0014](0014-two-engines-and-a-test-fixture.md) | Two deployable engines, and SQLite as a test fixture |
| [0015](0015-one-secrets-engine.md) | One secrets engine |
| [0016](0016-no-spdx-document.md) | CycloneDX is the generated SBOM; SPDX is not produced |

**On length.** ADRs [0004](0004-sqlite-and-postgresql-only.md),
[0008](0008-postgresql-and-mysql.md) and [0011](0011-liquibase-rather-than-flyway.md) are short
because they are **superseded** — but short is not the same as silent. Each one now says what it
decided and **what proved it wrong**, because that is the part a reader needs and the part the
record that replaced it cannot supply: a successor argues its own case, not the failure of its
predecessor. [0001](0001-pluggable-scan-layer.md) is short for the same reason.

A decision recorded without its reasoning is a changelog entry. This register had nine of those on
2026-08-25; the engine scope had reversed three times in six days precisely because no record
explained the previous reversal. All sixteen now carry their argument. The engine history is the
one worth reading end to end — [0004](0004-sqlite-and-postgresql-only.md) →
[0008](0008-postgresql-and-mysql.md) → [0009](0009-four-engines.md) →
[0014](0014-two-engines-and-a-test-fixture.md) — because it ends one engine away from where it
started, and the records now say why the return was the expensive one and therefore the one that
should hold.
