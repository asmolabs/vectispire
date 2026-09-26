# Vectispire on the JVM

Vectispire's control plane and its remote agent: **Spring Boot 4.1 / JDK 25**, built with Gradle.
The Angular interface lives in [`vectispire-angular/`](../vectispire-angular/) and reaches this over
HTTP.

```bash
./gradlew build                      # compile + unit tests + architecture suite
./gradlew :vectispire-common:integrationTest   # the scanner containers, needs Docker
./gradlew integrationTest            # one engine, needs Docker (default: mysql)
./gradlew integrationTest -Pdialect=postgres
./gradlew integrationTestAll         # PostgreSQL, MySQL and the SQLite fixture
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
0003](../docs/architecture/en/decisions/0003-long-polling-for-agents.md)). It is a fact about
the build graph rather than a rule somebody enforces: the violation does not fail review, it
fails to compile.

**What that costs.** The layers *inside* `vectispire-core` — persistence, services, web — can no
longer be expressed by the module graph, so `ArchitectureTest` enforces them with ArchUnit, in every
module, and Spring Modulith verifies the boundaries between modules against the list each module
declares. That is a genuine step down: a rule, or a line in a list, can be changed by the same commit
that needs it; a missing dependency cannot.

**Inside `vectispire-core`, twenty-four modules.** The control plane is divided into domains over a
foundation every domain may use (`settings`, `outbound`, `crypto`, `audit`, `outbox`, `reporting`,
`maintenance`), with `platform` on top — the settings screen that composes four domains, the
foundation's routes, the error handler and the OpenAPI configuration; it may use any module and none
uses it. Every one is a vertical module (decisions
[0028](../docs/architecture/en/decisions/0028-vertical-modules.md) and
[0029](../docs/architecture/en/decisions/0029-core-domains-become-modules.md)), a package of its own:

```
core/<module>/              its API: the services other modules call, their views, its events, its ports
core/<module>/web/          its controllers
core/<module>/internal/     what the API is built from: port implementations, periodic tasks, configuration
core/<module>/persistence/  its entities, its repositories, and the projections their queries select into
```

Three named interfaces publish more than a root: `core/access/web/security/` (the route markers, the
principal, `Visibilities`), and `core/scanning/persistence/queries/` and `core/issues/persistence/queries/`
— the records other modules read unchanged, `IssueFilters` among them. The packages by layer are
gone; `core/config/` is the one package outside a module.

A class goes where its callers put it: anything another module or the module's own controllers call
is at the root, a public class only its services use is in `internal`. A controller calls its
module's API, never `internal` or any `persistence`; a module reaches another only through that
module's root or a named interface — reading another module's repository is exactly what the modules
exist to show, so the owner gets an API method (`TargetCatalog`, `ScanCatalog`, `IssueCatalog` answer
views) or, when it sits above you, a port. The domains form no cycle and depend in one direction:
**each module's `package-info` lists what it may use** — `@ApplicationModule(allowedDependencies = …)`,
named interfaces by name (`access::security`, `scanning::queries`), each line with its reason — and
Spring Modulith verifies it ([0030](../docs/architecture/en/decisions/0030-modulith-verifies-the-module-boundaries.md)).
New code goes into the module whose list matches what it needs, and a line that has to be added is
added in the same review, with its reason. Upwards, a lower domain declares a port and a higher one
implements it (`TargetScans`, `TargetBacklog`, `ScanIngestor.Backlog`, `GrantableTargets`,
`AuditLogService.Listener`, `TicketReferences`). **An effect across domains inside a transaction is a
synchronous event**: target deletion publishes `TargetDeleted` in its transaction, and each owning
domain purges its own rows in a listener that requires that transaction, in the order
`TargetPurge.Phase` fixes. An effect that must survive the commit leaves through the outbox. **A
periodic job is a `MaintenanceTask`** in the owner's `internal`, placed in `MaintenanceTask.Sequence`
and listed in `MaintenanceJobsTest.COMPOSITION`: the tick knows none of the work.

**Spring Modulith is the authority on the module boundaries.** `ModularityTest` calls `verify()` and
fails the build on a cycle between modules, a reach into another module's internals, or a dependency a
list does not carry; it sees twenty-five modules (the twenty-four above, seven of them shared, and
`config`) and writes their canvases and diagrams into `build/modulith-docs/`
([05](../docs/architecture/en/05-modularity.md)). `ArchitectureTest` keeps what Modulith cannot say:
the layers inside a module, and the six modules that use `access` for their routes only. A JPQL string
naming another module's entity is invisible to both, and `CrossModuleQueriesTest` lists the eleven
there are. Production carries Modulith's annotations and nothing else, which `ModulithRuntimeInertTest`
checks.

### Naming a repository

**A Spring Data repository is its entity's name without `Entity`, singular, then `Repository`**:
`IssueEntity` → `IssueRepository`, `SessionEntity` → `SessionRepository`, `OutboxMessageEntity` →
`OutboxMessageRepository`, `SemgrepRuleSetEntity` → `SemgrepRuleSetRepository`. The rule is applied
even where it reads twice — `RepositoryEntity`, a Git repository, is read by `GitRepositoryRepository`,
because `RepositoryRepository` says nothing. It sits in its module's `persistence`, and nothing else in
the control plane ends in `Repository`: a service named `…Repository` would pass for one in review and
in every search (a nested `Repository` record, the target kind, is the one exception). The fields that
hold one keep the collection's name — `private final IssueRepository issues` — which reads as what it
holds. A custom fragment keeps its own name (`IssueAggregateQueries`, `FindingGraphQueries`): Spring
Data finds its implementation as the *fragment's* name plus `Impl`, whatever the repository is called.

Until 2026-09-26 the repositories were named after the table as a collection — `Issues`, `Scans`,
`Outbox`, `Settings` — which a search could not tell from the English word or from the module of the
same name; decision records written before that date keep the names they had.
`ArchitectureTest.repositoriesAreNamedAndPlacedAsRepositories` holds the convention both ways.

## What is checked, and where

| Guarantee | Enforced by |
|---|---|
| The agent cannot reach the database | the module graph, plus `AgentIsolationTest` |
| Layering inside every module of the control plane | `ArchitectureTest` (ArchUnit) |
| The domain depends on no framework, and no Docker client | `ArchitectureTest` |
| `cap_drop`, `network: none` and read-only mounts reach the daemon | `ContainerRunnerIntegrationTest` |
| Only a module's `persistence` speaks SQL | `ArchitectureTest` |
| Every repository write — `@Modifying` or a derived `deleteBy…` — carries `@Transactional` | `ArchitectureTest` |
| A repository is named `<Entity>Repository` and sits in its module's `persistence`; nothing else takes the suffix | `ArchitectureTest` |
| The modules form no cycle; a module reaches another only through its root or a named interface, and uses only what its `package-info` lists; nothing uses `platform` or `config` | `ModularityTest` (Spring Modulith's `verify()`) |
| Every module but `platform` declares its list, and each list is exactly what the module uses — the edges between foundation modules included, which `verify()` allows wholesale | `ModularityTest` |
| The six modules that use `access` for their routes use it nowhere else | `ArchitectureTest` |
| A query string naming another module's table is listed with its reason, and one against the modules' direction says so | `CrossModuleQueriesTest` |
| Every class sits in a module's root, `web`, `internal` or `persistence`, or in `config`; a controller calls its own module's API | `ArchitectureTest` |
| The gate's verdicts and the compliance captures are purged by one dial, not the payload window, and a failed purge skips only its table | `EvidenceRetentionTest` |
| The running application contributes exactly the periodic tasks the tick is tested with, in their order | `MaintenanceCompositionTest`, `MaintenanceJobsTest` |
| Deleting a target takes every row that names it and nobody else's, children before parents, atomically | `TargetDeletionTest`, `TargetPurgeOrderTest`, `TargetDeletionIntegrationTest` (MySQL, PostgreSQL) |
| Production carries Spring Modulith's annotations and nothing else — no runtime, no moments, no ArchUnit — and no Modulith bean activates | `ModulithRuntimeInertTest` |
| No controller names a persistence type — an entity, a repository or a published query record — the principal included; services answer with `…View` records | `ArchitectureTest` |
| The fingerprint's identity rules hold | `IssueFingerprintTest` |
| The audit chain detects tampering, not concurrency | `AuditChainTest` |
| A caller can only tighten a gate policy, never relax it | `PolicyGateTest` |
| A stored gate policy is what the verdict applies, and an empty threshold means the rule is off | `GatePoliciesRoutesTest` |
| The metadata endpoint is refused however it is spelled | `OutboundUrlGuardTest` |
| The Docker daemon and every host of the datasource URL are reserved destinations, and an address whose hosts cannot be read stops the start instead of reserving nothing | `OutboundUrlGuardTest`, `OutboundGuardWiringTest` |
| No file of a scanned repository can pin a worker in the API discovery: its patterns read within a budget per character, and the discovery within a deadline | `AnalysisBudgetTest`, `ApiDiscoveryScannerTest` |
| A ciphertext moved to another row does not decrypt | `SecretCipherTest` |
| The key can come from a secret file, and a failed mount stops the application | `EncryptionKeyFileTest`, `EncryptionKeyFileDatabaseTest` |
| Entities agree with the schema, on both engines and the SQLite fixture | `SchemaParityIntegrationTest` |
| A migration version lives in `common` once or in every engine's directory, and a common one names no engine | `MigrationLayoutTest` |
| Each type placeholder is what the engine declares and keeps (`datetime(6)`, identity never reused) | `MigrationPlaceholdersIntegrationTest` |
| An expired session, a reset password and a role change all close the sessions; a reset also revokes the account's integration keys | `AccountAdministrationService`, `ApiKeyIntegrationRoutesTest` |
| The session store holds no usable token, only its hash | `AuthDatabaseTest`, `SessionsTest` |
| The content security policy is sent, whole, on every response | `SecurityHeadersTest` |
| An outbound request reaches the address that was validated | `PinnedHttpSenderTest` |
| An outbound answer is read up to a ceiling and within a deadline, and a scanner's output up to a ceiling; past either the call or the step fails | `PinnedHttpSenderTest`, `ContainerOutputLimitTest` |
| A deleted audit entry the chain cannot see is caught by the mirror | `AuditMirrorTest` |
| Password sign-in cannot be closed when it is the only way in | `SignInMethodPolicyTest` |
| A team grants what it owns, and an account in no team sees nothing | `TeamVisibilityTest` |
| A project grant covers the project's repositories as they are at each request, and no project grant asks nothing | `VisibilityServiceTest`, `SolutionsRoutesTest` |
| A partial grant sees a partial project and says so; no grant, no project | `SolutionsRoutesTest` |
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
| A raw socket is opened by the syslog sender alone, to the address the guard pinned | `ArchitectureTest`, `SyslogSenderTest` |
| A syslog collector is judged by the same address rules as a URL, reserved endpoints included | `OutboundUrlGuardTest`, `SiemRoutesTest` |
| The SIEM export reaches a private collector only by its own, administrator-only setting, and its test route answers an outcome, never the socket's error | `SiemRoutesTest` |
| A SIEM event leaves after its transaction commits, is retried, and the relay knows its type | `SiemExportRoutesTest` |
| Each security event is emitted by the gesture that causes it, and by nothing quieter | `SiemSignalsRoutesTest` |
| A SIEM signature identifier does not change meaning | `SecurityEventTypeTest` |
| A username cannot forge a second CEF event or a field | `CefEventTest`, `SiemSignalsRoutesTest` |
| A controller writes no audit entry; the service performing the action does | `ArchitectureTest` |
| No third-party asset is referenced by the interface | `check-assets.mjs`, run by `npm test` |
| A `local` agent never receives a deployment key | `ScanDispatcherTest` |
| An agent never holds more scans than its `max_concurrent`, even with two polls at once, and a lapsed lease does not count | `ScanQueueIntegrationTest` (MySQL, PostgreSQL), `AgentConcurrencyRoutesTest` |
| An agent runs its limit in parallel, not one more, and a stop waits for the running scans | `AgentLoopConcurrencyTest` |

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

The schema is managed by **Flyway** with native SQL, read from two locations:
`vectispire-core/src/main/resources/db/migration/common/`, then the engine's own
`db/migration/{vendor}/` (`postgresql`, `mysql`, `sqlite`).

**Once, or three times — never in between** ([decision
0027](../docs/architecture/en/decisions/0027-common-migrations-with-type-placeholders.md)). From V40
on, a migration that differs between engines only by its column types is written once in `common`,
with the placeholders `MigrationDialect` spells per engine and `MigrationPlaceholders` hands to
Flyway: `${ts}`, `${id}` (the whole identity column, `primary key` included — SQLite accepts
`autoincrement` only on the exact phrase `integer primary key`), `${bool}`, `${true}`, `${false}`,
`${text}`, `${double}`. A migration whose structure diverges — a foreign key, a column change, date
arithmetic, a data repair — is written in each vendor directory. `MigrationLayoutTest` fails the
build when a version sits in one or two vendor directories, in both places, or under a name Flyway
would skip, and refuses an engine token in `common`. **V1 to V39 stay where they are**: Flyway
checks the checksum of every applied migration, and a moved or edited file stops every existing
installation.

The vendor sets use each engine's native DDL:

This native multi-dialect approach solves the impedance mismatches and table-recreation traps
historically experienced with abstractions:
- SQLite receives native DDL (`INTEGER PRIMARY KEY AUTOINCREMENT`, `NUMERIC` for epoch milliseconds, inline foreign keys).
- PostgreSQL uses native `BIGINT GENERATED ALWAYS AS IDENTITY`, `TIMESTAMPTZ`, and `char(36)` UUIDs.
- MySQL uses its native types (`BIT(1)`, `DATETIME(6)`, `BIGINT AUTO_INCREMENT`). The declared
  precision is not decoration: a bare `DATETIME` truncates to the second, and the audit chain
  hashes a millisecond timestamp — see [decision 0013](../docs/architecture/en/decisions/0013-flyway-multi-dialect-migrations.md).
  `${ts}` is `datetime(6)` for the same reason, pinned by `MigrationLayoutTest`.

`MigrationsTest` applies the Flyway migrations directly to a real SQLite file in one second, asserting
that all forty-one tables are created by name, and that the twenty-seven foreign keys of the
seventeen tables that carry one really exist.

`SchemaParityIntegrationTest` validates with Hibernate against the schema Flyway built, on
PostgreSQL and MySQL through Testcontainers and on the SQLite fixture. `MigrationPlaceholdersIntegrationTest`
applies a test-only common migration using every placeholder, through the application's own Flyway,
and reads back on each engine the declared types and the behaviour — a millisecond kept, an identity
never reused. **There is no "skip if Docker is missing" guard, deliberately** — a
suite that skips itself reports green without having checked anything.

See [decision 0013](../docs/architecture/en/decisions/0013-flyway-multi-dialect-migrations.md) for the architecture rationale.

## What the suites cover

`./gradlew build` runs the unit suites, the architecture suite and the HTTP suite against a
real SQLite database. `./gradlew integrationTestAll` runs the schema and concurrency checks on
PostgreSQL and MySQL through Testcontainers, and on the SQLite fixture. CI runs it in two places.
On push and pull request, the `engines` job of [`ci.yml`](../.github/workflows/ci.yml) runs it
**when anything engine-sensitive changed** — a migration, a module's `core/<module>/persistence/`
(every query, `Specification` and entity lives there, which `ArchitectureTest` enforces),
`core/config/`, the integration sources, or the dependency catalogue and lockfiles — or when the diff
range cannot be resolved.
It used to watch migrations only, and a concurrency fix in `ScanQueue` reached `main` green before
the nightly found it failing on SQLite. Every night, the `databases` job of
[`nightly.yml`](../.github/workflows/nightly.yml) runs it unconditionally. A green push pipeline
that touched none of those paths still says nothing about portability: a service passing an
existing query new parameters is the nightly's to catch. Do not release on a nightly
that has not been green, and remember that the schedule fires from `main` only.

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
| Resetting a password did not close the account's sessions, so a stolen token kept working for twelve hours while the screen confirmed the change | `AccountAdministrationService` |
| The dispatcher consulted the transport and not the agent's `credentialsMode`, so an agent declared `local` received every repository's decrypted deployment key | `ScanDispatcher` |
| A malformed notification threshold fell back to `UNKNOWN`, which ranks last — the threshold silently let everything through | `NotificationService` |
| The quality screen's "rule count" was the length of its own top-8 list, so it always said 8 | `QualityQueryService` |
| The backlog grouping took a column name as a string parameter | `IssueRepository` |
| `ScanTask.Target` is a sealed interface, which tells a JSON parser nothing: a task handed to a remote agent deserialized into an exception | `ScanTask` |
| No remote agent could hand back a result: `ScanArtifacts` is a record of `Optional`s, neither mapper registered Jackson 2's `jdk8` module, and every test of the protocol mocked the transport or sent `{}` | `AgentWireFormatTest`, `AgentResultWireTest` |
| Every `@Modifying` repository query now carries `@Transactional` — Spring Data does not add it, so an omission works whenever a caller happens to have a transaction open. The convention lived in `core.repositories`' package-info; when step 5 emptied the package it became a rule, which found fifteen derived `deleteBy…` methods in five modules without it | `ArchitectureTest.everyRepositoryWriteIsTransactional` |
| A write that must arbitrate — claiming a scan, taking the leader lease, superseding a rule set — is a conditional statement whose row count names the winner, never a `save`, which reads then writes and lets whoever wrote last win | `ScanQueue`, `LeaderElection`, `SemgrepRuleSetRepository` |
| `max_concurrent` was stored, shown and sent to every agent, and nothing applied it: the claim took a scan whatever the agent held, and the agent ran one at a time. The count and the take now commit behind the agent's row — without that lock, two polls reading different candidates both count below the limit | `ScanQueue.claimWithin` |
| The agent's stop raised a flag and returned; the JVM halts when its shutdown hooks do, so the scan its javadoc promised would finish was cut off mid-run | `AgentRunner.stop` |
| A revoked key on a claim was logged as a failed claim and retried every ten seconds for ever | `AgentLoop.claim` |
| A repository or image with any triage history could not be deleted: the purge queued its child rows' removal, the bulk delete of the issues ran first, the cascade took the children, and the commit failed on rows already gone. No test had ever deleted a target carrying history | `IssueRepository.deleteByIdIn`, `ScanRepository.deleteByIdIn`, `TargetDeletionTest` |
| `known_hosts` was prepared by check-then-create: two first clones in parallel, and the second failed its scan | `GitClone.prepareKnownHosts` |
| The NestJS prefix pattern backtracked in the cube of a run of spaces — two seconds for 2,000 of them — and the Spring parser searched the whole file once per annotation: one committed file held a scan worker, in the built-in worker the control plane's own process | `ApiDiscoveryScanner`, `AnalysisBudget` |

### Shapes chosen deliberately

| | |
|---|---|
| The agent's long poll parks a `DeferredResult` instead of sleeping in a service; a servlet container cannot afford a thread per idle agent | `AgentJobPoller` |
| Transaction boundaries called from inside a class use `TransactionTemplate`, not `@Transactional` — the proxy is bypassed there, and the annotation reads as a guarantee while protecting nothing | `ScanDispatcher`, `OutboxService` |
| SIEM events are outbox rows, not calls: queued in the transaction that caused them, sent by the relay after it commits — the `@Async` exporter ran synchronously inside the caller's transaction, there being no `@EnableAsync` ([decision 0025](../docs/architecture/en/decisions/0025-siem-events-leave-through-the-outbox.md)) | `SiemEvents`, `SiemDelivery` |
| The audit log tells its listeners after the entry's commit, so a listener that fails cannot cost the entry | `AuditLogService` |
| Settings are read through the `Setting` catalog, not by key plus a caller-supplied default that could drift from the screen's | `SettingsService` |
| Spring Boot 4 auto-configures Jackson **3**; this codebase is annotated for Jackson 2, so the mapper is declared explicitly on both sides of the agent protocol | `CoreConfiguration` |
