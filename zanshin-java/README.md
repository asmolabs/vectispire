# Zanshin on the JVM

Zanshin's control plane and its remote agent: **Spring Boot 4.1 / JDK 25**, built with Gradle.
The Angular interface lives in [`zanshin-angular/`](../zanshin-angular/) and reaches this over
HTTP.

```bash
./gradlew build                      # compile + unit tests + architecture suite
./gradlew :zanshin-common:integrationTest   # the scanner containers, needs Docker
./gradlew integrationTest            # one engine, needs Docker (default: postgres)
./gradlew integrationTest -Pdialect=mariadb
./gradlew integrationTestAll         # all four
```

## Three modules, and why three

```
  zanshin-core  ──┐
                  ├──►  zanshin-common     domain calculations + scan execution
  zanshin-agent ──┘
```

`zanshin-common` holds what both sides must agree on: the calculations that *decide* — issue
fingerprint, gate verdict, audit chain, export formats — and the scan execution that turns a
checkout into artifacts. Both halves are needed by both sides: the agent fingerprints the
findings it reports, and the control plane runs the same scanners in its built-in worker. Two
copies of the fingerprint rule would be two answers to "is this the same issue", which is the
one question this system may not get wrong twice.

**The split is a security boundary, not packaging.** `zanshin-agent` does not depend on
`zanshin-core`, so no JDBC driver, no Hibernate and no Spring Data is on its compile
classpath. An agent holding a database connection would also need `ENCRYPTION_KEY`, which is
enough to decrypt *every* deployment key Zanshin holds; the property that justifies the
agent's existence is precisely what it does not have ([decision
0003](../docs/architecture/decisions/0003-long-polling-for-agents.md)). It is a fact about
the build graph rather than a rule somebody enforces: the violation does not fail review, it
fails to compile.

**What that costs.** The layers *inside* `zanshin-core` — `persistence`, `repositories`,
`services`, `api` — can no longer be expressed by the module graph, so `ArchitectureTest`
enforces them with ArchUnit. That is a genuine step down: an ArchUnit rule can be deleted by
the same commit that violates it; a missing dependency cannot.

## What is checked, and where

| Guarantee | Enforced by |
|---|---|
| The agent cannot reach the database | the module graph, plus `AgentIsolationTest` |
| Layering inside the control plane | `ArchitectureTest` (ArchUnit) |
| The domain depends on no framework, and no Docker client | `ArchitectureTest` |
| `cap_drop`, `network: none` and read-only mounts reach the daemon | `ContainerRunnerIntegrationTest` |
| Only `repositories` speaks SQL | `ArchitectureTest` |
| The fingerprint's identity rules hold | `IssueFingerprintTest` |
| The audit chain detects tampering, not concurrency | `AuditChainTest` |
| A caller can only tighten a gate policy, never relax it | `PolicyGateTest` |
| The metadata endpoint is refused however it is spelled | `OutboundUrlGuardTest` |
| A ciphertext moved to another row does not decrypt | `SecretCipherTest` |
| The key can come from a secret file, and a failed mount stops the application | `EncryptionKeyFileTest`, `EncryptionKeyFileDatabaseTest` |
| Entities agree with the schema, on four engines | `SchemaParityIntegrationTest` |
| An expired session, a reset password and a role change all close the sessions | `UsersController` |
| The session store holds no usable token, only its hash | `AuthDatabaseTest`, `SessionsTest` |
| The content security policy is sent, whole, on every response | `SecurityHeadersTest` |
| An outbound request reaches the address that was validated | `PinnedHttpSenderTest` |
| A deleted audit entry the chain cannot see is caught by the mirror | `AuditMirrorTest` |
| Password sign-in cannot be closed when it is the only way in | `SignInMethodPolicyTest` |
| A team grants what it owns, and an account in no team sees nothing | `TeamVisibilityTest` |
| A new installation starts partitioned, an upgrade does not, and neither undoes a choice | `FirstInstallDefaultsTest`, `FirstInstallDefaultsDatabaseTest`, `BootstrapServiceTest` |
| A remediation deadline counts from the first sighting, and a rescan cannot reset it | `RemediationSlaTest` |
| The overdue figure and the list it links to count the same rows | `RemediationSlaRoutesTest` |
| A lapsed acceptance really stops dismissing, because the tick runs it | `MaintenanceJobsTest` |
| A team's findings are announced in its channel, not in everybody's | `TeamNotificationRoutingTest` |
| Deleting a team removes its channel, where the cascade would not | `TeamVisibilityTest` |
| No other class in `core` holds an HTTP client | `ArchitectureTest` |
| No third-party asset is referenced by the interface | `check-assets.mjs`, run by `npm test` |
| A `local` agent never receives a deployment key | `ScanDispatcherTest` |

### Two decisions worth knowing

**The fingerprint separator is NUL, not a vertical bar.** A file path containing `|` would
otherwise imitate a field boundary and collide with another issue. The reason this is worth
stating: **changing the separator rewrites the identity of every stored issue and destroys the
triage attached to them.** It was free to get right before any data existed; it will not be
free again.

**Closed sets are types.** `ScanTarget` is a sealed interface rather than two nullable ids that
a comment declares mutually exclusive; `FindingType` is an enum carrying `isSecurity()` rather
than seven string constants plus a hand-maintained list the constants could drift from.

### Host keys, and a trap worth naming

`StrictHostKeyChecking=accept-new` reads as "refuses a host whose key has changed" — and means
nothing at all if `UserKnownHostsFile` points at a directory created fresh for each clone and
deleted immediately after. **Every clone is then a first contact**, every host key is accepted,
and the `Host key verification failed` branch can never fire. The two halves cancel out across
forty lines and nothing says so; this is how it was, and it is why the policy is now a type.

`GitClone.HostKeyPolicy` is now a sealed choice between `AcceptNew(knownHosts)` — which detects
interception, at the cost that a rotated host key blocks scans until an operator clears the
entry — and `TrustEveryHost()`, named plainly because that is what the previous behaviour was.

### Cryptography

Passwords go through **Argon2id**; everything else hashes through `Digests`. Both are
**BouncyCastle**'s lightweight API rather than the JCA.

**Argon2id and not bcrypt**, for one reason worth stating because it is easy to reintroduce:
bcrypt silently ignores everything past 72 bytes. Two passphrases sharing their first 72 are
the same password, which forces a validation rule refusing long ones rather than letting
anybody believe they are protected. Argon2id needs neither the truncation nor the rule.

The JCA is avoided for a separate reason. The JCA resolves an algorithm from whatever providers the JVM was started with, so
what actually ran becomes a property of the host — unacceptable for a hash that decides whether
an audit log was tampered with. Calling the engine directly also avoids registering a provider,
which is global mutable state in a process that also serves HTTP.

## Liquibase, and the check that has to stay

The schema is one changelog rather than one migration set per dialect. That is the requested
trade: less duplication, at the price of hiding where engines actually disagree — `tinyint(1)`
against `tinyint`, `timestamptz` against `datetime` — which is where every divergence found so
far has been.

The caveat proved out, and the executed checks are what caught it — six times over: SQLite silently creating no foreign keys,
`int` against `Long` identifiers, MySQL and MariaDB disagreeing with *each other* about
booleans, SQLite refusing `AUTOINCREMENT` on anything but `INTEGER PRIMARY KEY`, a SQLite
timestamp that wrote fine and failed to read back — that one invisible to any comparison of
type names — and the trap below, which has now fired three times.

Written the tidy way — `addForeignKeyConstraint` after the tables — the changelog applies
**without complaint** on
SQLite and creates no constraint at all: referential integrity on three engines out of four,
and nothing saying so. `ChangelogTest` caught it in a second by running the thing, and now
asserts the twenty foreign keys are really there.

**The rule to know before writing changeset 008.** On SQLite, `addColumn` makes Liquibase
**recreate** the table — and the recreation leaves every foreign key *pointing at it* aimed at a
`<table>_temporary` that does not exist. Adding one nullable column to `t_team` was enough to
destroy referential integrity on `t_team_member` and `t_team_target`, which are access-control
tables. It applies cleanly, on every engine, and says nothing.

So: **do not add a column to a table other tables reference.** Two ways out, in order of
preference.

Add a **table** instead — a new one has nothing pointing at it yet, and the extra join is
cheaper than the class of defect. `t_team_webhook` exists for exactly this reason, and gained a
second one on the way: a webhook URL is a bearer capability that has no business being carried by
every query over teams.

When a column really is the right shape, write the **SQL by hand** rather than `addColumn`:

```yaml
# What runs is what is written — which is the one property this trap costs, and the reason
# the alternative to Liquibase was weighed and rejected. See decision 0011.
- changeSet:
    id: 008-example
    author: zanshin
    changes:
      - sql:
          dbms: sqlite
          sql: alter table t_team add column example varchar(50)
      - sql:
          dbms: "postgresql,mysql,mariadb"
          sql: alter table t_team add column example varchar(50)
```

SQLite performs that natively and leaves every referencing key intact — measured, not assumed.
And whichever way out is taken, the assertion in `ChangelogTest` is what tells you: it lists the
keys **by name**, which is why it asserts keys rather than columns, and why a new referencing
table has to be added to that list rather than left to be covered "by the count".

This is the one place where the single-changelog trade bites hardest — the tidy change is the
dangerous one, and only running it on SQLite says so. Why the trade is kept anyway, and what
Flyway would and would not have prevented, is
[decision 0011](../docs/architecture/decisions/0011-liquibase-rather-than-flyway.md).

**Strict parity is split in two, deliberately.** `ChangelogTest` proves the changelog applies
and that the twenty foreign keys exist, on SQLite, in a second. It does not compare column types
against the entities: a first attempt did that on SQLite and was abandoned deliberately —
SQLite has no types, only affinities, so `datetime` is stored as TEXT and a type-name comparison
there measures Liquibase's naming choices rather than whether the mapping works. Strict
validation belongs on the three engines that have real types, and SQLite's mapping is better
proven by writing a row and reading it back.

`SchemaParityIntegrationTest` puts the remaining difference back where it can fail: it asks Hibernate to
validate the entities against the schema the changelog really built, on all four engines
through Testcontainers. **There is no "skip if Docker is missing" guard, deliberately** — a
suite that skips itself reports green without having checked anything.

## What the suites cover

`./gradlew build` runs the unit suites, the architecture suite and the HTTP suite against a
real SQLite database. `./gradlew integrationTestAll` runs the schema and concurrency checks on
all four engines through Testcontainers — **not run by CI**, because it needs Docker and ten
minutes; run it before a release and after any change to the changelog.

`ArchitectureTest` no longer runs with `withOptionalLayers` or `allowEmptyShould`: every layer
is populated, so an empty one now means a package was renamed or deleted, and that rule going
quiet is exactly how it would go unnoticed.

### Defects fixed rather than reproduced

Each of these was found by reading closely or by running the thing, and each would have been
easy to carry forward unnoticed. The reasoning lives in the code; this is the index.

| | |
|---|---|
| `mustChangePassword` was enforced by the Angular client alone — a direct API call ignored it, and the bootstrap password stayed a valid SUPERUSER credential with no expiry | `PasswordChangeInterceptor` |
| Resetting a password did not close the account's sessions, so a stolen token kept working for twelve hours while the screen confirmed the change | `UsersController` |
| The dispatcher consulted the transport and not the agent's `credentialsMode`, so an agent declared `local` received every repository's decrypted deployment key | `ScanDispatcher` |
| A malformed notification threshold fell back to `UNKNOWN`, which ranks last — the threshold silently let everything through | `NotificationService` |
| The quality screen's "rule count" was the length of its own top-8 list, so it always said 8 | `QualityController` |
| The backlog grouping took a column name as a string parameter | `Issues` |
| `ScanTask.Target` is a sealed interface, which tells a JSON parser nothing: a task handed to a remote agent deserialized into an exception | `ScanTask` |
| Every `@Modifying` repository query now carries `@Transactional` — Spring Data does not add it, so an omission works whenever a caller happens to have a transaction open | `repositories/package-info.java` |

### Shapes chosen deliberately

| | |
|---|---|
| The agent's long poll parks a `DeferredResult` instead of sleeping in a service; a servlet container cannot afford a thread per idle agent | `AgentJobPoller` |
| Transaction boundaries called from inside a class use `TransactionTemplate`, not `@Transactional` — the proxy is bypassed there, and the annotation reads as a guarantee while protecting nothing | `ScanDispatcher`, `OutboxService` |
| Settings are read through the `Setting` catalog, not by key plus a caller-supplied default that could drift from the screen's | `SettingsService` |
| Spring Boot 4 auto-configures Jackson **3**; this codebase is annotated for Jackson 2, so the mapper is declared explicitly on both sides of the agent protocol | `CoreConfiguration` |
