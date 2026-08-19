# Zanshin on the JVM

A port of the NestJS control plane to **Spring Boot 4.1 / JDK 25**, built with Gradle.

It runs **alongside** `backend/`, not instead of it. The port is complete — every service,
every route and the remote agent — but the NestJS tree stays until somebody has run this one
against a real deployment. Deleting the reference implementation before that would remove the
only thing to compare a surprise against.

**It is not a transliteration.** No instance of Zanshin has been run, so there is no stored
data to stay compatible with, and byte-for-byte fidelity is not a goal. Several constraints in
the TypeScript exist only because it had to match a Python implementation and a live database;
those are void. Where the original documents a compromise it was forced into, this port does
the right thing instead and says so. The reasoning in the comments is what carries over — not
the bytes.

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
0003](../docs/architecture/decisions/0003-long-polling-for-agents.md)). The NestJS tree
asserted this with a test that read the import graph. Here it is a fact about the build
graph: the violation does not fail review, it fails to compile.

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
| Entities agree with the schema, on four engines | `SchemaParityIntegrationTest` |
| An expired session, a reset password and a role change all close the sessions | `UsersController` |
| A `local` agent never receives a deployment key | `ScanDispatcherTest` |

### Two things the original could not fix, fixed here

**The fingerprint separator is NUL, not a vertical bar.** The NestJS version carried a note
saying the collision — a file path containing `|` imitating a field boundary — must *not* be
repaired, because changing the separator rewrites the identity of every stored issue and
destroys the triage attached to them. With no data, it costs nothing. This was the last moment
at which it was free.

**Closed sets are types.** `ScanTarget` is a sealed interface rather than two nullable ids that
a comment declares mutually exclusive; `FindingType` is an enum carrying `isSecurity()` rather
than seven string constants plus a hand-maintained list the constants could drift from.

### One defect found while porting the clone

The original passed `StrictHostKeyChecking=accept-new` and explained that this "refuses a host
whose key has changed" — while pointing `UserKnownHostsFile` at a directory created fresh for
each clone and deleted immediately after. **Every clone was a first contact**, so every host
key was accepted, and the `Host key verification failed` branch of its error translation could
never fire. The two halves cancelled out across forty lines, and nothing said so.

`GitClone.HostKeyPolicy` is now a sealed choice between `AcceptNew(knownHosts)` — which detects
interception, at the cost that a rotated host key blocks scans until an operator clears the
entry — and `TrustEveryHost()`, named plainly because that is what the previous behaviour was.

### Cryptography

Passwords go through **Argon2id**; everything else hashes through `Digests`. Both are
**BouncyCastle**'s lightweight API rather than the JCA.

Argon2id replaces bcrypt, which the NestJS version used only to stay readable by a Python
implementation. That constraint dragged a real defect behind it: **bcrypt silently ignores
everything past 72 bytes**, so two passphrases sharing their first 72 were the same password,
and a validation rule had to refuse long ones rather than let anybody believe they were
protected. Both the truncation and the rule are gone.

The JCA is avoided for a separate reason. The JCA resolves an algorithm from whatever providers the JVM was started with, so
what actually ran becomes a property of the host — unacceptable for a hash that decides whether
an audit log was tampered with. Calling the engine directly also avoids registering a provider,
which is global mutable state in a process that also serves HTTP.

## Liquibase, and the check that has to stay

The schema is one changelog rather than one migration set per dialect. That is the requested
trade: less duplication, at the price of hiding where engines actually disagree — `tinyint(1)`
against `tinyint`, `timestamptz` against `datetime` — which is where every divergence found so
far has been.

The caveat proved out, and the executed checks are what caught it — five times over: SQLite silently creating no foreign keys,
`int` against `Long` identifiers, MySQL and MariaDB disagreeing with *each other* about
booleans, SQLite refusing `AUTOINCREMENT` on anything but `INTEGER PRIMARY KEY`, and a SQLite
timestamp that wrote fine and failed to read back — that last one invisible to any comparison
of type names.

Written the tidy way — `addForeignKeyConstraint` after the tables — the changelog applies
**without complaint** on
SQLite and creates no constraint at all: referential integrity on three engines out of four,
and nothing saying so. `ChangelogTest` caught it in a second by running the thing, and now
asserts the twelve foreign keys are really there.

**Strict parity is split in two, deliberately.** `ChangelogTest` proves the changelog applies
and that the twelve foreign keys exist, on SQLite, in a second. It does not compare column types
against the entities: a first attempt did that on SQLite and was abandoned deliberately —
SQLite has no types, only affinities, so `datetime` is stored as TEXT and a type-name comparison
there measures Liquibase's naming choices rather than whether the mapping works. Strict
validation belongs on the three engines that have real types, and SQLite's mapping is better
proven by writing a row and reading it back.

`SchemaParityIntegrationTest` puts the remaining difference back where it can fail: it asks Hibernate to
validate the entities against the schema the changelog really built, on all four engines
through Testcontainers. **There is no "skip if Docker is missing" guard, deliberately** — a
suite that skips itself reports green without having checked anything.

## State of the port

Complete. `backend/src` has a counterpart everywhere, and the suite that proves it runs on four
engines.

| | |
|---|---|
| Build, three modules, architecture suite | done |
| `zanshin-common/domain` and `zanshin-common/scanning` | done |
| `zanshin-core` — schema, entities, repositories | done |
| `zanshin-core` — services | done |
| `zanshin-core` — API, security, agent protocol | done |
| `zanshin-agent` | done |

`ArchitectureTest` no longer runs with `withOptionalLayers` or `allowEmptyShould`: every layer
is populated, so an empty one now means a package was renamed or deleted, and that rule going
quiet is exactly how it would go unnoticed.

### What the port changed on purpose

Each of these is a place where the TypeScript documented a compromise it could not escape, or
where reading it closely turned up something nobody had noticed. The reasoning lives in the
code; this is the index.

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

### Where the port is deliberately different in shape

| | |
|---|---|
| The agent's long poll parks a `DeferredResult` instead of sleeping in a service; a servlet container cannot afford a thread per idle agent | `AgentJobPoller` |
| Transaction boundaries called from inside a class use `TransactionTemplate`, not `@Transactional` — the proxy is bypassed there, and the annotation reads as a guarantee while protecting nothing | `ScanDispatcher`, `OutboxService` |
| Settings are read through the `Setting` catalog, not by key plus a caller-supplied default that could drift from the screen's | `SettingsService` |
| Spring Boot 4 auto-configures Jackson **3**; this codebase is annotated for Jackson 2, so the mapper is declared explicitly on both sides of the agent protocol | `CoreConfiguration` |
