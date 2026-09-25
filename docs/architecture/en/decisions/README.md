# Architecture Decision Records (ADR) — English

This directory contains the structural Architecture Decision Records (ADRs) for Vectispire.

| ADR | Title | Status |
|---|---|---|
| [0001](0001-pluggable-scan-layer.md) | Pluggable scan layer | superseded by [0010](0010-one-scan-runner.md) |
| [0002](0002-the-database-carries-the-queue.md) | The database carries the scan queue | accepted |
| [0003](0003-long-polling-for-agents.md) | Long polling for agents | accepted |
| [0004](0004-sqlite-and-postgresql-only.md) | SQLite and PostgreSQL support | superseded by [0008](0008-postgresql-and-mysql.md) |
| [0005](0005-quality-never-blocks-the-gate.md) | Quality findings never block the gate | accepted |
| [0006](0006-semgrep-rules-written-here.md) | Bundled Semgrep rules | accepted |
| [0007](0007-none-is-not-an-empty-list.md) | None is not an empty list | accepted |
| [0008](0008-postgresql-and-mysql.md) | PostgreSQL and MySQL support | superseded by [0009](0009-four-engines.md) |
| [0009](0009-four-engines.md) | Support four database engines | superseded by [0014](0014-two-engines-and-a-test-fixture.md) |
| [0010](0010-one-scan-runner.md) | Single concrete ScanRunner | accepted |
| [0011](0011-liquibase-rather-than-flyway.md) | Liquibase, with hand-written structural DDL | superseded by [0013](0013-flyway-multi-dialect-migrations.md) |
| [0012](0012-apache-2-0.md) | Licensing under Apache 2.0 | accepted |
| [0013](0013-flyway-multi-dialect-migrations.md) | Flyway multi-dialect SQL migrations | accepted |
| [0014](0014-two-engines-and-a-test-fixture.md) | Two deployable engines, and SQLite as a test fixture | accepted |
| [0015](0015-one-secrets-engine.md) | One secrets engine | accepted |
| [0016](0016-no-spdx-document.md) | CycloneDX is the generated SBOM; SPDX is not produced | accepted |
| [0017](0017-custom-checks-as-container-images.md) | Custom checks as container images, not uploaded JARs | proposed |
| [0018](0018-the-docker-socket-is-never-mounted.md) | The Docker socket is never mounted into the control plane | accepted |
| [0019](0019-screen-text-is-translated-on-the-client.md) | The server sends a token; the screen holds the sentence | accepted |
| [0020](0020-screenshots-stay-png.md) | Screenshots stay PNG, and the trigger to change that is named | accepted |
| [0021](0021-the-docs-site-stays-on-mkdocs-1.md) | The documentation site stays on MkDocs 1, until something else can publish it in two languages | accepted |
| [0022](0022-https-clone-tokens-are-bound-to-a-host.md) | Cloning over HTTPS uses a managed token, bound to one host | accepted |

**On length.** ADRs [0004](0004-sqlite-and-postgresql-only.md),
[0008](0008-postgresql-and-mysql.md) and [0011](0011-liquibase-rather-than-flyway.md) are short
because they are **superseded** — but short is not the same as silent. Each one now says what it
decided and **what proved it wrong**, because that is the part a reader needs and the part the
record that replaced it cannot supply: a successor argues its own case, not the failure of its
predecessor. [0001](0001-pluggable-scan-layer.md) is short for the same reason.

A decision recorded without its reasoning is a changelog entry. This register had nine of those on
2026-08-25; the engine scope had reversed three times in six days precisely because no record
explained the previous reversal. Every record in this register now carries its argument. The engine history is the
one worth reading end to end — [0004](0004-sqlite-and-postgresql-only.md) →
[0008](0008-postgresql-and-mysql.md) → [0009](0009-four-engines.md) →
[0014](0014-two-engines-and-a-test-fixture.md) — because it ends one engine away from where it
started, and the records now say why the return was the expensive one and therefore the one that
should hold.
