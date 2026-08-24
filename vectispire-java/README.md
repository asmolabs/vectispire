# Vectispire on the JVM

Vectispire's control plane and its remote agent: **Spring Boot 4.1 / JDK 25**, built with Gradle.
The Angular interface lives in [`vectispire-angular/`](../vectispire-angular/) and reaches this over
HTTP.

```bash
./gradlew build                      # compile + unit tests + architecture suite
./gradlew :vectispire-common:integrationTest   # the scanner containers, needs Docker
./gradlew integrationTest            # one engine, needs Docker (default: postgres)
./gradlew integrationTest -Pdialect=mariadb
./gradlew integrationTestAll         # all four
```

## Three modules, and why three

```
  vectispire-core  ──┐
                    ├──►  vectispire-common     domain calculations + scan execution
  vectispire-agent ──┘
```

`vectispire-common` holds what both sides must agree on: the calculations that *decide* — issue
fingerprint, gate verdict, audit chain, export formats — and the scan execution that turns a
checkout into artifacts. Both halves are needed by both sides: the agent fingerprints the
findings it reports, and the control plane runs the same scanners in its built-in worker. Two
copies of the fingerprint rule would be two answers to "is this the same issue", which is the
one question this system may not get wrong twice.

**The split is a security boundary, not packaging.** `vectispire-agent` does not depend on
`vectispire-core`, so no JDBC driver, no Hibernate and no Spring Data is on its compile
classpath. An agent holding a database connection would also need `ENCRYPTION_KEY`, which is
enough to decrypt *every* deployment key Vectispire holds; the property that justifies the
agent's existence is precisely what it does not have ([decision
0003](../docs/architecture/decisions/0003-long-polling-for-agents.md)). It is a fact about
the build graph rather than a rule somebody enforces: the violation does not fail review, it
fails to compile.

**What that costs.** The layers *inside* `vectispire-core` — `persistence`, `repositories`,
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
| A stored gate policy is what the verdict applies, and an empty threshold means the rule is off | `GatePoliciesRoutesTest` |
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
| The five-field cron form the screens teach is the one the parser accepts | `CronExpressionsTest`, `SchedulerServiceTest` |
| A bulk triage is all-or-nothing, checks visibility on every id, and records each transition | `BulkTriageRoutesTest` |
| The backlog series is narrowed by visibility, like every other read | `TrendsRoutesTest`, `BacklogTrendTest` |
| The weekly report goes out once a week, and a failed send is retried rather than recorded | `PostureDigestServiceTest`, `PostureDigestDatabaseTest`, `MaintenanceJobsTest` |
| A team's findings are announced in its channel, not in everybody's | `TeamNotificationRoutingTest` |
| A webhook message is signed over the bytes actually sent, and an undecryptable secret refuses to send unsigned | `WebhookSigningTest`, `WebhookSignatureTest` |
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

## Flyway, and dialect-specific native migrations

The schema is managed by **Flyway** with native migration sets per dialect under
`vectispire-core/src/main/resources/db/migration/{vendor}/` (`postgresql`, `mariadb`, `mysql`, `sqlite`).

This native multi-dialect approach solves the impedance mismatches and table-recreation traps
historically experienced with abstractions:
- SQLite receives native DDL (`INTEGER PRIMARY KEY AUTOINCREMENT`, `NUMERIC` for epoch milliseconds, inline foreign keys).
- PostgreSQL uses native `BIGINT GENERATED ALWAYS AS IDENTITY`, `TIMESTAMPTZ`, and `char(36)` UUIDs.
- MySQL and MariaDB use their respective native types (`BIT(1)` / `BOOLEAN`, `DATETIME(6)`, `BIGINT AUTO_INCREMENT`).

`ChangelogTest` applies the Flyway migrations directly to a real SQLite file in one second, asserting
that all twenty-six tables and twenty foreign keys are created by name.

`SchemaParityIntegrationTest` validates with Hibernate against the schema Flyway built, on all four
engines through Testcontainers. **There is no "skip if Docker is missing" guard, deliberately** — a
suite that skips itself reports green without having checked anything.

See [decision 0013](../docs/architecture/decisions/0013-flyway-multi-dialect-migrations.md) for the architecture rationale.

## What the suites cover

`./gradlew build` runs the unit suites, the architecture suite and the HTTP suite against a
real SQLite database. `./gradlew integrationTestAll` runs the schema and concurrency checks on
all four engines through Testcontainers — **not run by CI**, because it needs Docker and ten
minutes; run it before a release and after any change to the changelog.

`ArchitectureTest` no longer runs with `withOptionalLayers` or `allowEmptyShould`: every layer
is populated, so an empty one now means a package was renamed or deleted, and that rule going
quiet is exactly how it would go unnoticed.

### Defects fixed rather than reproduced

**The cron format nothing accepted.** Both controllers' 400 said `Expected five fields, for example
"0 2 * * *"`, the schedule form on screen said the same — and the parser underneath was Spring's,
which requires **six**, seconds first. The example in the error message was itself rejected, so an
operator following the instructions could not save a schedule. It hid twice over: the fields were
not editable from the interface at all, and an unusable expression becomes `CronSchedule.NEVER`
rather than an error, so the target simply never ran — indistinguishable from one nobody had
scheduled. `SchedulerServiceTest.cronTakesPrecedence` passed *because* of the bug: its expression
parsed to NEVER, so the precedence it claimed to check was never exercised.


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
