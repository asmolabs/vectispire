# 0034 — MySQL replaces SQLite as the fixture the unit and HTTP suites run on

**Date:** 2026-10-01 · **Status:** accepted, done 2026-10-02 · **Amends:** [0014](0014-two-engines-and-a-test-fixture.md), [0027](0027-common-migrations-with-type-placeholders.md) · **Decider:** Laurent Boucher

## Context

[0014](0014-two-engines-and-a-test-fixture.md) kept SQLite as the fixture of the plain test suite —
not a deployment — for one reason, which `ApiTestBase` still states: *it needs no daemon*, so the
HTTP suite runs on every `./gradlew build` instead of in a campaign somebody has to remember. The
same record refused H2, because a test database nobody deploys repeats the SQLite mistake with a
third dialect, and its compatibility modes hide the divergences the campaign exists to find. It
added: "if the goal were faster tests, a MySQL container starts in about six seconds."

What the fixture has cost since, measured on 2026-10-01:

- **A third migration set.** 41 files under `db/migration/sqlite/`; since V40 every migration whose
  structure diverges is written three times ([0027](0027-common-migrations-with-type-placeholders.md)),
  and `MigrationDialect` spells every type placeholder a third way.
- **Production code that exists for a test engine.** `SqliteForeignKeys` and `SqliteWriteAheadLog`
  in `core/config/`, and `SQLITE_BUSY` handling or reasoning in `ScanQueue`, `AuditLogService`,
  `AgentRepository` and `ScimProvisioningService` — single-writer locking that neither deployed
  engine has. Fifty-seven main sources mention SQLite.
- **The HTTP suite does not validate the schema.** `application-apitest.yaml` sets `ddl-auto: none`
  because SQLite reports every timestamp back as FLOAT; the 120 `ApiTestBase` classes run against a
  schema Hibernate never checked. Only the campaign does, and it does not run on every push.
- **A defect class the suite cannot see.** Behaviour that differs between SQLite and the engines —
  a statement SQLite accepts and PostgreSQL refuses (`HistoryQueriesIntegrationTest`), the bind
  limit, locking — is invisible to the 278 classes of the plain suite, whatever they assert.
- **It blocks infrastructure written for the deployed engines.** Spring Modulith's JDBC event
  registry does not start on SQLite ([0033](0033-internal-reactions-leave-through-the-outbox.md)).

## Decision

**The plain test suite runs on MySQL, the default deployed engine, in a container.** MySQL rather
than PostgreSQL because it is the engine `docker-compose.yml` ships, and the one whose defaults have
already produced a defect here — a bare `DATETIME` truncating to the second broke the audit chain's
own verification (0014). PostgreSQL stays in the campaign.

- **Locally**, one container per Gradle run through Testcontainers with reuse, a fresh database per
  test JVM as `ApiTestBase` does today with a temporary SQLite file.
- **In CI**, the `jvm` job runs in `eclipse-temurin:25-jdk`; a `services: mysql` beside it shares
  its network, so the suite reaches `mysql:3306` without Testcontainers or a Docker socket.
- **`ddl-auto: validate` in the HTTP suite**, as in production.
- **SQLite goes**: its migration set, its `MigrationDialect` entry, the driver and community dialect,
  `SqliteForeignKeys`, `SqliteWriteAheadLog`, and the `SQLITE_BUSY` workarounds once each is shown to
  be SQLite's alone. `MigrationLayoutTest` and `check-doc-facts.py` count two engines.
- **The campaign keeps PostgreSQL and MySQL** under `integrationTestAll`; its SQLite leg is removed.
- **The browser suite moves too** (2026-10-02): the `e2e` jobs of `ci.yml` and `nightly.yml` start
  the control plane on a `services: mysql` under `validate`, and the suite's helpers
  (`e2e/support/fixture.ts`) reach it through `mysql2` instead of opening the SQLite file.

**H2 stays refused**, for 0014's reasons: replacing one engine nobody deploys by another would keep
every cost above and add a compatibility mode that hides what the campaign looks for.

## What it costs

- **Docker becomes a prerequisite of `./gradlew build`**, which is exactly the property 0014 kept
  SQLite for. A machine without a daemon can still compile and run the architecture tests; the
  context and HTTP suites refuse to start, and say why — never skip silently (AGENTS.md).
- **Time.** About six seconds of container start per Gradle run, and MySQL's per-test cleanup is
  slower than deleting a file; to be measured in the first lot against the current suite's duration,
  and the move stops if the suite more than doubles.
- **One lot of migration work, L-sized**: the fixture swap, the configuration, the CI service, the
  removal of the SQLite set and code, and the documentation in both languages — then a nightly green
  on the result before the next release.

## What it buys

- Two migration sets instead of three for every structural change, and a dialect less in
  `MigrationDialect`.
- The HTTP suite validates the schema and exercises the deployed engine's locking and limits on every
  push, not only in the campaign.
- Production code no longer carries locking workarounds for an engine it is never deployed on.
- The obstacle to Modulith's registry that was SQLite disappears. The others remain, and
  [0033](0033-internal-reactions-leave-through-the-outbox.md) does not depend on this record.

## Alternatives considered

- **Keep SQLite** — the status quo; every cost in the context continues.
- **H2** — refused, see above and 0014.
- **PostgreSQL as the fixture** — equally real, but not the engine shipped by default.
- **Testcontainers in CI too** — needs the Docker socket inside the `jvm` job's container; a job
  service is the mechanism GitHub provides for exactly this.

## Amends

- [0014](0014-two-engines-and-a-test-fixture.md): "SQLite stays … as the fixture the HTTP test suite
  runs on" no longer holds; the supported engines are unchanged.
- [0027](0027-common-migrations-with-type-placeholders.md): a diverging migration is written twice,
  under `db/migration/{postgresql,mysql}/`.

## Done (2026-10-02)

A note after the record, not an edit of it.

- **The suites.** The context and HTTP suites run on MySQL through `TestDatabase`: one `mysql:9.4`
  container per test JVM, or the server `VECTISPIRE_TEST_DB_URL` names — CI's `jvm` job has it as a
  service. `ddl-auto: validate`; without a server the suites fail with a sentence saying how to give
  them one. `:vectispire-core:test`, measured on the same machine: 124 s on SQLite, 170 s on MySQL
  (1.37×), under the stop at 2×.
- **SQLite is gone**: `db/migration/sqlite` (41 files), `MigrationDialect.SQLITE`, `sqlite-jdbc` and
  `hibernate-community-dialects`, `SqliteForeignKeys`, `SqliteWriteAheadLog`, the campaign's
  `integrationTestSqlite`. `MigrationLayoutTest` and `check-doc-facts.py` count two engines, and the
  second fails when the campaign's engines and the migration directories disagree.
- **No `SQLITE_BUSY` workaround turned out to be SQLite's alone.** The audit entry's retry on a
  refused lock also answers MySQL's deadlock victim and lock-wait timeout; the claim's row write and
  the sync row's update take the row lock on both engines; an audit entry written after the commit
  still keeps an entry from describing a write that rolls back. The logic stays and the comments give
  the reason that holds.
- **What the move found.** The first evidence bundle of an installation without
  `vectispire.signing.key` answered 500: the key was created inside the bundle's read-only
  transaction, which SQLite ignored. And MySQL 9 honours an inline `references`, so on the
  `mysql:9.4` the suites run V1's inline foreign keys exist twice, InnoDB's beside V19's — the shipped
  composition's `mysql:8` discards them. Recorded here, then settled by V65 (2026-10-02): the 24
  twins are dropped, and `t_mfa_challenge.user_id` — inline in V23, so never a key on MySQL 8 — gets
  a named one; both majors now end with the same 33 keys.
- **The container kept across runs (2026-10-03).** "Locally, one container … with reuse" had been
  written and not delivered: `withReuse` was set, but nothing named or labelled the container, two
  JVMs starting together each made one, and nothing removed the databases a killed JVM left. Where the
  machine enables Testcontainers' reuse, `TestDatabase` now keeps `vectispire-test-mysql` (label
  `com.asmolabs.vectispire.test=mysql`) for every run and worktree, the name serving as the lock
  Testcontainers' reuse lacks; the databases carry their creation instant
  (`vectispire_test_<epoch>_<hex>`), are dropped at JVM exit and swept after a day. Without the
  setting nothing changes, and CI keeps its job service. The campaign keeps a fresh server per class.
  How to enable and remove it: `vectispire-java/README.md`, "One MySQL kept across runs".

