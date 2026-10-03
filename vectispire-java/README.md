# Vectispire on the JVM

Vectispire's control plane and its remote agent: **Spring Boot 4.1 / JDK 25**, built with Gradle.
The Angular interface lives in [`vectispire-angular/`](../vectispire-angular/) and reaches this over
HTTP.

```bash
./gradlew build                      # compile + unit, architecture and HTTP suites (on MySQL: Docker)
./gradlew :vectispire-common:integrationTest   # the scanner containers, needs Docker
./gradlew integrationTest            # one engine, needs Docker (default: mysql)
./gradlew integrationTest -Pdialect=postgres
./gradlew integrationTestAll         # PostgreSQL and MySQL
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

**Inside `vectispire-core`, twenty-six modules.** The control plane is divided into domains over a
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
list does not carry; it sees twenty-seven modules (the twenty-six above, seven of them shared, and
`config`) and writes their canvases and diagrams into `build/modulith-docs/`
([05](../docs/architecture/en/05-modularity.md)). `ArchitectureTest` keeps what Modulith cannot say:
the layers inside a module, and the six modules that use `access` for their routes only. A JPQL string
naming another module's entity is invisible to both, and `CrossModuleQueriesTest` lists the four
there are — the orphan sweeps, each with its reason. Production carries Modulith's annotations and nothing else, which `ModulithRuntimeInertTest`
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
| The vulnerability matcher's database is downloaded once per host under a lock, published whole by an atomic rename, checked hourly, mounted read-only by a matcher with no network, and every file of it is this process's to delete | `VulnerabilityDatabaseTest`, `VulnerabilityDatabaseIntegrationTest`, `DependencyScannerTest` |
| Only a module's `persistence` speaks SQL | `ArchitectureTest` |
| Every repository write — `@Modifying` or a derived `deleteBy…` — carries `@Transactional` | `ArchitectureTest` |
| A repository is named `<Entity>Repository` and sits in its module's `persistence`; nothing else takes the suffix | `ArchitectureTest` |
| The modules form no cycle; a module reaches another only through its root or a named interface, and uses only what its `package-info` lists; nothing uses `platform` or `config` | `ModularityTest` (Spring Modulith's `verify()`) |
| Every module but `platform` declares its list, and each list is exactly what the module uses — the edges between foundation modules included, which `verify()` allows wholesale | `ModularityTest` |
| The six modules that use `access` for their routes use it nowhere else | `ArchitectureTest` |
| A query string naming another module's table is listed with its reason, and one against the modules' direction says so | `CrossModuleQueriesTest` |
| Every class sits in a module's root, `web`, `internal` or `persistence`, or in `config`; a controller calls its own module's API | `ArchitectureTest` |
| The gate's verdicts, the compliance captures and the weekly OWASP record are purged by one dial, not the payload window, zero purging none, and a failed purge skips only its table; a week of the OWASP record stays while any of it is inside the window, and the view answers a purged week as reconstructed | `EvidenceRetentionTest`, `OwaspWeeklyRetentionDatabaseTest`, `MaintenanceJobsTest` |
| The weekly OWASP record holds one row per target, ISO week (Monday 00:00 UTC) and category — never-scanned targets included, not measured with the findings the grid counts beside a scanned target, settled findings counted apart — rewrites the current week only, at most every six hours, and goes with a deleted target; two instances capturing one week at once leave one complete capture, the loser reporting the race rather than a failure | `OwaspCoverageSplitTest`, `OwaspWeeklyCoverageDatabaseTest`, `OwaspWeeklyCoverageConcurrencyIntegrationTest` (MySQL, PostgreSQL) |
| The weekly OWASP view states only what was recorded: a captured week combines its targets' recorded lines by the grid's rule — a never-scanned target's findings counted only beside a measured one — so its current week reads what the live grid reads, for the same reader, an estate with an unscanned target included, an earlier week is reconstructed from the issues' dates at half-open week boundaries with `state` and `settled` null — the triage history misses reopenings before V68 and decisions before V3, so settled at a past date is not guessed — and a reopened issue's earlier resolution, recorded by its reopening, is not open and is its week's resolution, by the backlog's own `open_at` and resolved clauses; a reader sums their visible targets only, a scope they see nothing of is a 404 like an absent one, 52 weeks at most; the backlog's `owasp_category` filter places as the grid does — `any` by the same rule over the ten, so a week's total opened, resolved, reopened and reconstructed open figures are the lengths of the lists they open — and a date filter lifts the default `state=open` so a since-resolved issue is listed; `reopened` counts the recorded reopenings of a week, an issue once, and is null — never zero — on a week that began before V68 was applied (Flyway's history, a day's margin for its zoneless column), the backlog's `reopened_from`/`_to` listing what it counted | `OwaspPlacementTest`, `OwaspWeeklyCoverageRoutesTest`, `OwaspWeeklyHistoryIntegrationTest` (MySQL, PostgreSQL — a reader of 70,000 targets included) |
| The running application contributes exactly the periodic tasks the tick is tested with, in their order | `MaintenanceCompositionTest`, `MaintenanceJobsTest` |
| Deleting a target takes every row that names it and nobody else's, children before parents, atomically | `TargetDeletionTest`, `TargetPurgeOrderTest`, `TargetDeletionIntegrationTest` (MySQL, PostgreSQL) |
| Production carries Spring Modulith's annotations and nothing else — no runtime, no moments, no ArchUnit — and no Modulith bean activates | `ModulithRuntimeInertTest` |
| No controller names a persistence type — an entity, a repository or a published query record — the principal included; services answer with `…View` records | `ArchitectureTest` |
| The fingerprint's identity rules hold | `IssueFingerprintTest` |
| The audit chain detects tampering, and concurrent writers — threads of one instance, or several instances with clocks apart — never fork it: each entry takes the chain's lock (V66) and is dated after the head it chains onto | `AuditChainTest`, `AuditChainConcurrencyIntegrationTest` (MySQL, PostgreSQL) |
| A caller can only tighten a gate policy, never relax it | `PolicyGateTest` |
| A stored gate policy is what the verdict applies, and an empty threshold means the rule is off | `GatePoliciesRoutesTest` |
| The metadata endpoint is refused however it is spelled | `OutboundUrlGuardTest` |
| The Docker daemon and every host of the datasource URL are reserved destinations, and an address whose hosts cannot be read stops the start instead of reserving nothing | `OutboundUrlGuardTest`, `OutboundGuardWiringTest` |
| No file of a scanned repository can pin a worker in the API discovery: its patterns read within a budget per character, and the discovery within a deadline | `AnalysisBudgetTest`, `ApiDiscoveryScannerTest` |
| A ciphertext moved to another row does not decrypt | `SecretCipherTest` |
| The key can come from a secret file, and a failed mount stops the application | `EncryptionKeyFileTest`, `EncryptionKeyFileDatabaseTest` |
| Entities agree with the schema, on both engines — and at every context start of the HTTP suite, on MySQL | `SchemaParityIntegrationTest` |
| A migration version lives in `common` once or in every engine's directory, and a common one names no engine | `MigrationLayoutTest` |
| Each type placeholder is what the engine declares and keeps (`datetime(6)`, identity never reused, bytes whole past 64 KiB) | `MigrationPlaceholdersIntegrationTest` |
| A checklist template's workbook is kept byte for byte in the engine's binary type, never a large object, and every change to a version is a conditional statement on the revision its writer read | `ChecklistTemplateStorageIntegrationTest` (MySQL, PostgreSQL) |
| A checklist template version is a draft until a person confirms its layout, and, with four-eyes on, is published or retired by none of the accounts that wrote it, at the revision its publisher reviewed | `ChecklistTemplatesRoutesTest` |
| A project's checklist is read and written only by a caller who sees the whole project — everything, the project granted as such, or every one of its repositories and at least one — and anybody else is answered "Project not found."; the guard is its service's, and its proof is minted by the guard alone | `ProjectChecklistsRoutesTest`, `RowVisibilityTest`, `ArchitectureTest.routesLeaveTheRefusalToTheirServices`, `ArchitectureTest.visibleTargetsAreMintedByTheGuard` |
| A checklist's answers are never rewritten, every write names the edition its writer read, a carried answer onto a changed line waits for confirmation, and, with four-eyes on, none of a revision's authors signs it off | `ProjectChecklistsRoutesTest` |
| One open checklist per project is a key on the engines, several closed revisions under it; its conditional statements arbitrate every transition; deleting a project takes its checklists, answers, proofs and files in its transaction | `ChecklistStorageIntegrationTest` (MySQL, PostgreSQL) |
| A checklist line's measurement is never a pass on data nobody looked at: no repository, a step absent in every scan within the age, scans from before `examined_types`, a plugin not applicable anywhere, stale evidence each answer "no data" with its reason, and one repository without data is enough; a threshold is judged on the whole backlog only, settled triage out and a status this version does not know in | `RuleEvaluationTest`, `ChecklistMeasurementsRoutesTest` |
| A static analysis line (`builtin:sast`, `builtin:quality`, a plugin) counts a repository examined only where the scan it rests on read the tree's languages — by that scan's census, the languages of the SAST rules its task carried (written when the task is built) and the manifest it named; a source language no rule read, or languages unrecorded, is "no data", and Vectispire's automatic yes is withdrawn | `RuleEvaluationTest`, `ScanDispatcherTest`, `ChecklistAutomaticAnswersRoutesTest`, `DetectedLanguagesIntegrationTest` (MySQL, PostgreSQL) |
| A binding is part of its line's digest and follows its key; a "yes" against a failing measurement is refused at submission, a "yes" without data needs a comment and a proof, an answer rests only on the measurement its person read, and a sign-off whose measurement changed since the submission is refused and freezes the rest | `ChecklistTemplatesRoutesTest`, `ChecklistMeasurementsRoutesTest` |
| The owners' questions a measurement asks — the newest analysed scan and its SBOM, the scans within an age, each plugin's state, a scope's backlog, the import carrying a tool (its key escaped), an SBOM's components — answer past 70,000 identifiers | `MeasurementQueriesIntegrationTest` (MySQL, PostgreSQL) |
| An expired session, a reset password and a role change all close the sessions; a reset also revokes the account's integration keys | `AccountAdministrationService`, `ApiKeyIntegrationRoutesTest` |
| The session store holds no usable token, only its hash | `AuthDatabaseTest`, `SessionsTest` |
| The content security policy is sent, whole, on every response | `SecurityHeadersTest` |
| An outbound request reaches the address that was validated | `PinnedHttpSenderTest` |
| Every request body is read up to a ceiling — the route's own where it has one, never clamped to the default, and the default everywhere else — counted while it is read, whatever its declared length | `RequestBodyLimitFilterTest`, `RequestBodyLimitRoutesTest` |
| An outbound answer is read up to a ceiling and within a deadline, and a scanner's output up to a ceiling; past either the call or the step fails | `PinnedHttpSenderTest`, `ContainerOutputLimitTest` |
| A deleted audit entry the chain cannot see is caught by the mirror | `AuditMirrorTest` |
| Password sign-in cannot be closed when it is the only way in | `SignInMethodPolicyTest` |
| A team grants what it owns, and an account in no team sees nothing | `TeamVisibilityTest` |
| A project grant covers the project's repositories and images as they are at each request — an image leaving the project or moving to another leaves its grantees at once — and no project grant asks nothing; the granted projects are looked up a thousand at a time | `VisibilityServiceTest`, `SolutionsRoutesTest`, `ProjectContainersRoutesTest`, `ProjectBacklogIntegrationTest` |
| A partial grant sees a partial project and says so; no grant, no project | `SolutionsRoutesTest` |
| A new installation starts partitioned, an upgrade does not, and neither undoes a choice | `FirstInstallDefaultsTest`, `FirstInstallDefaultsDatabaseTest`, `BootstrapServiceTest` |
| A remediation deadline counts from the first sighting, and a rescan cannot reset it | `RemediationSlaTest` |
| The overdue figure and the list it links to count the same rows | `RemediationSlaRoutesTest` |
| A lapsed acceptance really stops dismissing, because the tick runs it | `MaintenanceJobsTest` |
| The five-field cron form the screens teach is the one the parser accepts | `CronExpressionsTest`, `SchedulerServiceTest` |
| A bulk triage is all-or-nothing, checks visibility on every id, and records each transition | `BulkTriageRoutesTest` |
| A reopening is written into the issue's triage history in the scan's transaction — the triage it left, the resolution it ended, the scan — and a sync that reopens nothing writes nothing; every rendering of the trail (detail, dossier, PDF, CSV, the screens) names it as a reopening, never as a lapse or a decision | `IssueSyncDatabaseTest`, `HistoryTest`, `issue-detail.spec.ts`, `history.spec.ts` |
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
| No outbound call runs inside a transaction: a scan's enrichment happens before its write opens, the KEV catalogue and the EPSS file are fetched before their writes, and the OWASP review's model call sits between a committed request and a second write — asked from inside the stubbed call | `EnrichmentOutsideTransactionTest`, `ScanIngestorTest`, `ThreatIntelFeedRoutesTest`, `EpssSyncRoutesTest`, `OwaspReportTest` |
| A model review a stopped process left running reads as failed past its deadline, and the hourly sweep writes it so | `OwaspReportTest`, `MaintenanceJobsTest` |
| The KEV feed is CISA's catalogue, read whole or not at all — a document without its list, empty, shorter than its `count` or older than the one in use is refused and the one in use kept; an issue is flagged when listed, un-flagged when not, announced once — the backlog walked 500 issues a transaction, each page under the sync row's lock, so a second synchronisation reads the first one's flags; one instance syncs per interval; 1,500 entries written on each engine | `KevCatalogTest`, `ThreatIntelFeedRoutesTest`, `KevCatalogueIntegrationTest`, `MaintenanceJobsTest` |
| The EPSS feed is FIRST's daily file, read whole or not at all — cut short, malformed, out of [0, 1], under 100,000 rows or nine tenths of the file in use, past 128 MiB inflated, or older than the one in use is refused and the scores in use kept; written under a generation readers never see until one conditional update switches to it, the generation replaced kept until the next file so that a reader of it never finds it gone; one synchronisation at a time under a lease, a stale one unable to apply; open issues re-scored only by a known score; 380,000 rows written on each engine | `EpssFileTest`, `EpssSyncRoutesTest`, `EpssFeedConcurrencyTest`, `EpssScoresIntegrationTest`, `OutboundDownloadTest` |
| A scan sends nothing outside the control plane to score its findings: they are scored from the stored EPSS file | `NoOutboundDuringIngestionTest` |
| Each security event is emitted by the gesture that causes it, and by nothing quieter | `SiemSignalsRoutesTest` |
| A SIEM signature identifier does not change meaning | `SecurityEventTypeTest` |
| A username cannot forge a second CEF event or a field | `CefEventTest`, `SiemSignalsRoutesTest` |
| A controller writes no audit entry; the service performing the action does | `ArchitectureTest` |
| No controller decides what a caller sees: it resolves a `Visibility` and hands the allowance to the service — it asks it nothing and tests no kind of it | `ArchitectureTest.controllersDecideNoVisibility` |
| A service serving one target refuses a hidden one itself, whoever calls it, in the words an absent one gets; only where a module's services may not use `access` does the route refuse, and then the service takes the proof (`VisibleTarget`, minted by `RowVisibility` alone), never the bare target | `ServicesRefuseHiddenTargetsTest`, `ArchitectureTest.routesLeaveTheRefusalToTheirServices`, `ArchitectureTest.visibleTargetsAreMintedByTheGuard`, `VisibilityRoutesTest` |
| An aggregate over one project or one solution — its read, compliance and score, consolidated SBOM — follows the tree's rule (everything, the project granted as such, or one of its targets visible; otherwise 404 in an absence's words), is computed over the visible targets alone and says `partial`; `targets` resolves the scope beside the read of its filing (`SolutionQueryService.visibleProject` / `visibleSolution`) and hands it on as `VisibleScope`, minted by `RowVisibility` alone | `ProjectAggregatesRoutesTest`, `ArchitectureTest.visibleTargetsAreMintedByTheGuard`, `ArchitectureTest.routesLeaveTheRefusalToTheirServices`, `ProjectScopeIntegrationTest` |
| No third-party asset is referenced by the interface | `check-assets.mjs`, run by `npm test` |
| A `local` agent never receives a deployment key | `ScanDispatcherTest` |
| A delegated credential leaves only sealed for a sealing key the agent's pinned signing key vouched for — never in the clear; an unsigned, stale or absent announcement neither replaces nor clears the accepted key | `SealingKeyAttestationTest`, `AgentSealingKeyRoutesTest`, `ScanDispatcherTest`, `AgentSealingKeyIntegrationTest` (MySQL, PostgreSQL), `AgentSealingKeyAnnouncementTest` |
| An agent never holds more scans than its `max_concurrent`, even with two polls at once, and a lapsed lease does not count | `ScanQueueIntegrationTest` (MySQL, PostgreSQL), `AgentConcurrencyRoutesTest` |
| An agent that cannot be handed a delegated credential does not claim a scan that needs one: the scan waits unclaimed and costs no attempt, the agent still takes the rest and is answered 412 when that is all there is; the one race left is requeued with its attempt refunded | `ScanDispatcherTest`, `ScanQueueIntegrationTest` (MySQL, PostgreSQL), `AgentSealingKeyRoutesTest` |
| A scan that could not run fails at once when the failure is permanent and otherwise waits 1, then 5, then 15 minutes before any claim — every selection and the take itself — whether an agent reported it, the built-in worker failed it or its lease lapsed; a clone's kind comes from types, and an unclassified failure is transient | `FailureKindTest`, `ScanQueueTest`, `CloneFailureKindTest`, `SshCloneTest`, `ScanDispatcherTest`, `AgentFailureReportRoutesTest`, `ScanQueueIntegrationTest` (MySQL, PostgreSQL) |
| The scans needing a credential that no executor able to be handed it can take are counted by a gauge with the dispatcher's own predicate, and the log says so, rate-limited, on every instance; the agents screen shows the same figure | `CredentialedBacklogTest`, `CredentialedBacklogTaskTest`, `MaintenanceJobsTest`, `RemainingContractTest` |
| An agent runs its limit in parallel, not one more, and a stop waits for the running scans | `AgentLoopConcurrencyTest` |
| A plugin runs in the scanners' closed shape — not root, no network unless declared, the analysed tree read-only and nothing else of the workspace, one writable output, no socket — and reports produced, not applicable or absent, never empty for a failure | `PluginScannerIntegrationTest`, `PluginStepsTest`, `ScanRunnerTest` |
| Through the shipped composition, in the built-in worker and on an agent, every scanner at its pinned digest runs as the workspace's owner, reads the 0700 workspace and reports what the fixture planted for it — a secret, an IaC finding, the bundled SAST rule's hit, an SBOM, and the matcher's match against a one-advisory database published in the executor's cache, mounted read-only with no network; no step may fail. A scanner put back to root fails its step and the check, on Docker Desktop too (the scans' directories live in its VM there) | `scripts/composition-scan-check.sh` (`images`; nightly `dockerfiles`, `MODE=agent`) |
| What a plugin writes is bounded by the kernel — its output holds the ceiling and 4,096 files in a tmpfs kept by a holder, no file of it exceeds the ceiling — and a plugin that filled it is absent; the host's disk is not touched, and the same holds through the socket proxy's filter | `PluginScannerIntegrationTest`, `SocketProxyIntegrationTest`, `OutputArchiveTest`, `PluginStepsTest` |
| A plugin whose manifest declares a signer runs only once cosign has verified it, before the pull; an image it does not verify is never fetched and the plugin is *refused* (`signature_unverified`), never absent. A private registry is read with the credentials the executor's pulls use, resolved by docker-java's own rule, mounted for the verifier's run alone and erased with it; a registry that still refuses is `registry_authentication_required`, never "no signature" Executors require a signer by default: an unsigned plugin is refused (`unsigned`) unless the governor's audited waiver travels with its task — which never covers a declared signer that fails | `PluginSignatureIntegrationTest`, `PrivateRegistrySignatureIntegrationTest`, `PluginStepsTest`, `RegistryLoginTest`, `PluginSignatureTest`, `PluginsRoutesTest`, `ScanningDefaultsTest`, `AgentPropertiesBindingTest` |
| A plugin's manifest is what its task named: the executor refuses one that does not hash to the digest, and a stored row edited in place is served to nobody | `PluginStepsTest`, `PluginsRoutesTest`, `AgentProtocolTest` |
| The language census reads names only, in linear time, follows no link, and an incomplete census runs every plugin | `LanguageTest`, `LanguageCensusTest` |
| A plugin's or an imported report's clean run resolves that tool's issues only — never the type's, another plugin's, an import's or a scanner's — and a new image version keeps the triage | `PluginIngestionDatabaseTest`, `ToolFingerprintTest`, `SarifImportRoutesTest` |
| SARIF is read under a size ceiling, with no link, no location outside the tree, no expansion, and a run without results or that failed is never read as clean | `SarifReportTest`, `SarifPathsTest` |
| A plugin is registered only by the platform governor and runs only for the projects it is switched on for; SARIF is imported only by a declared source's key, for its scope and its tools | `PluginsRoutesTest`, `SarifImportRoutesTest` |
| Every refusal is an RFC 9457 problem with a `detail` — Spring's own, a `ResponseStatusException`'s reason, the filter chain's 401, 403, 413 and 429 — and a 500 quotes a correlation id, never the failure | `ProblemDetailsRoutesTest`, `RefusalTypesRoutesTest`, `ApiExceptionHandlerTest` |
| A caller is refused with `InvalidInputException` (400) or `NotFoundException` (404); a bare `IllegalArgumentException` or `NoSuchElementException` in the control plane is named with the reason it fires only on a defect | `RefusalTypesTest` |
| Every plugin and dependency the build resolves — POMs and Gradle module files included — is signed by a key trusted for its group, or matches the sha256 recorded when nothing signs it; no key server is consulted, and CI refuses to build without the file rather than verifying nothing | Gradle's dependency verification over `gradle/verification-metadata.xml` and `gradle/verification-keyring.keys`; `ci.yml`'s `jvm` step and `release.yml` (`--dependency-verification=strict`, file present) |

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

**And the type still did not decide.** `AcceptNew` handed JGit's `OpenSshServerKeyDatabase` the
session's configuration, and that database decides by `StrictHostKeyChecking` read from the ssh
config — `ask` when nothing says otherwise, which refuses when there is nobody to ask. So the policy
named "accept new" accepted no new host: a first contact failed with "Server key did not validate"
unless the host was already in the file, and a `config` beside the file saying
`StrictHostKeyChecking no` would have switched the check off. The database is now handed a
configuration of the policy's own — this file only, accept-new while it can be written, match-only
when it cannot (accept-new on a read-only file accepts and records nothing, every time) — and a
keyed clone reads no ssh config at all. `SshCloneTest` runs it against a real SSH server; nothing
had, which is how both survived.

**Where the file lives is the process's home, and a container may have none.** The images run as
1000 with no passwd entry, so `user.home` is `/`: `/.ssh` cannot be created and every keyed clone
failed. The composition sets `-Duser.home` under the work directory, one per executor.

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

## Dependency verification

The wrapper is validated and its distribution pinned by `distributionSha256Sum`; everything Gradle
resolves after that — plugins, `buildSrc`'s Kotlin DSL, every configuration of the three modules, the
engine campaign's Testcontainers, JaCoCo's agent, Jib — is checked against
`gradle/verification-metadata.xml` before it is used. Before this, any artifact the resolver fetched
was trusted, and the release signed whatever it had been handed. A missing or wrong entry fails the
build naming the artifact, on a warm cache too: Gradle checks cached files on every run.

**What vouches for what** (2026-09-27, over the 983 jars, POMs and module files a clean Gradle
home downloads for the tasks CI runs):

- **A signature, for almost everything.** 100 `<trusted-key>` entries over the 115 keys of the
  keyring, each trusted for the group Gradle saw it sign — `48B086A7…` for `org.springframework`,
  `io.micrometer`, `io.projectreactor`; `FF6E2C00…` for JUnit; `7B121B76…` for BouncyCastle — and
  30 of them narrowed by Gradle to the one module and version it saw the key sign.
  Sixteen parent and BOM POMs carry a per-file `<pgp>` instead, their key trusted for that file only.
  **Trusted by group rather than by version, deliberately**: a bump signed by the same publisher
  verifies with no edit, which is what a signature buys over a checksum, while the version itself
  stays pinned by the lockfiles and Maven Central never replaces a published one. The checksum is not
  recorded beside the signature: it would catch only the same version re-signed by the same key —
  the publisher's key and the repository compromised at once — at the price of an entry per
  artifact per version.
- **A sha256, for the six artifacts nothing signs**: the Gradle Plugin Portal's Jib plugin (its jar,
  its module file, its marker POM), the Spring Boot and `kotlin-dsl` plugin markers, and
  `org.sonatype.oss:oss-parent:7`. A bump of Jib or of Spring Boot therefore always regenerates.
- **A compile-only annotation jar, trusted like the rest**: `org.immutables:value-annotations` —
  javac reads it to parse docker-java's transport types, which keep Immutables' annotations, and
  nothing of it is packaged. Its signer, `CA3DBEC9…` (Ievgen Lukash, Immutables' maintainer), is
  trusted for `org.immutables` alone.
- **Ignored keys: none.** Gradle's first generation could not download 22 of the keys and fell back
  to checksums for their artifacts, Jackson, Hibernate, Flyway and BouncyCastle among them — a failed
  download, not a missing key: all 22 were on `keyserver.ubuntu.com` minutes later. Each was fetched
  from there, its owner compared with the group it signs, and added to the keyring.
- **Key servers are off** (`<key-servers enabled="false"/>`): every key a build needs is in the
  keyring, in ASCII armour so a diff shows who was added. A build never waits on a key server, and
  a key that is not committed is a failure, not a fetch.
- **No `<trusted-artifacts>`.** An IDE's sources download verifies through the group's key where the
  sources jar is signed, and fails where it is not; that is accepted rather than exempting a file
  pattern from verification.

**Trust here is first use, and that is what the review is for.** Gradle trusts the key that signed
the artifact it downloaded; what makes that more than a checksum is that someone read which key it
was. That is why the file changes only through `gradle/update-verification-metadata.sh` — a fresh
Gradle home (a warm one records fewer parent POMs than a clean runner resolves: `jakarta.platform`'s
went missing that way, and the build failed on a clean home only), every task CI runs, key servers
on for that run alone, and a failure when a key cannot be downloaded — followed by a reading of the
diff: a new `<trusted-key>` is a publisher (its uid is in the keyring above its block when the key
server served one — 46 of the 115 came without; look the fingerprint up on `keyserver.ubuntu.com`),
a new `<sha256>` is bytes nobody signed. **Regeneration rewrites the XML and drops any comment in it**,
which is why this reasoning is here and not there.

**Dependabot updates the version and not the metadata.** A minor bump by a publisher already trusted
for its group passes as it is; one bringing a new signer or an unsigned artifact fails `jvm`, and a
person runs the script on the pull request's branch, reviews what it adds and pushes it. A workflow
regenerating on the bot's behalf was rejected: it would re-trust whatever the pull request resolves —
the attack this exists to stop — and needs a token writing to the branch in the job that runs the
pull request's Gradle code, the combination `release.yml` was split into two jobs to avoid.

## Flyway, and dialect-specific native migrations

The schema is managed by **Flyway** with native SQL, read from two locations:
`vectispire-core/src/main/resources/db/migration/common/`, then the engine's own
`db/migration/{vendor}/` (`postgresql`, `mysql`).

**Once, or twice — never in between** ([decision
0027](../docs/architecture/en/decisions/0027-common-migrations-with-type-placeholders.md), [decision
0034](../docs/architecture/en/decisions/0034-mysql-replaces-the-sqlite-fixture.md), which removed the
SQLite set). From V40
on, a migration that differs between engines only by its column types is written once in `common`,
with the placeholders `MigrationDialect` spells per engine and `MigrationPlaceholders` hands to
Flyway: `${ts}`, `${id}` (the whole identity column, `primary key` included — a shape the SQLite set
needed and the common migrations since keep), `${bool}`, `${true}`, `${false}`,
`${text}`, `${double}`, `${bytes}` (a file's bytes: `longblob`, `bytea` — mapped with an
explicit JDBC type, never `@Lob`, which is an `oid` on PostgreSQL). A migration whose structure
diverges — a foreign key, a column change, date arithmetic, a data repair — is written in each vendor
directory. `MigrationLayoutTest` fails the
build when a version sits in one vendor directory only, in both places, or under a name Flyway
would skip, and refuses an engine token in `common`. **V1 to V39 stay where they are**: Flyway
checks the checksum of every applied migration, and a moved or edited file stops every existing
installation.

The vendor sets use each engine's native DDL:

This native multi-dialect approach solves the impedance mismatches and table-recreation traps
historically experienced with abstractions:
- PostgreSQL uses native `BIGINT GENERATED ALWAYS AS IDENTITY`, `TIMESTAMPTZ`, and `char(36)` UUIDs.
- MySQL uses its native types (`BIT(1)`, `DATETIME(6)`, `BIGINT AUTO_INCREMENT`), and a foreign key
  as a named constraint: MySQL 8 discards an inline one, and MySQL 9 keeps it — V1's inline keys
  existed twice on MySQL 9 and V23's was no key on MySQL 8, both settled by V65. The declared
  precision is not decoration: a bare `DATETIME` truncates to the second, and the audit chain
  hashes a millisecond timestamp — see [decision 0013](../docs/architecture/en/decisions/0013-flyway-multi-dialect-migrations.md).
  `${ts}` is `datetime(6)` for the same reason, pinned by `MigrationLayoutTest`.

`MigrationsTest` applies the Flyway migrations to a database of their own on the suite's MySQL
(`TestDatabase.scratch`), asserting that all sixty tables are created by name, that the twenty-seven
foreign keys of the seventeen tables that carry one really exist, and that a second run changes
nothing.

`SchemaParityIntegrationTest` validates with Hibernate against the schema Flyway built, on
PostgreSQL and MySQL through Testcontainers. `MigrationPlaceholdersIntegrationTest`
applies a test-only common migration using every placeholder, through the application's own Flyway,
and reads back on each engine the declared types and the behaviour — a millisecond kept, an identity
never reused. **There is no "skip if Docker is missing" guard, deliberately** — a
suite that skips itself reports green without having checked anything.

See [decision 0013](../docs/architecture/en/decisions/0013-flyway-multi-dialect-migrations.md) for the architecture rationale.

## What the suites cover

`./gradlew build` runs the unit suites, the architecture suite and the HTTP suite against
MySQL — one container per test JVM through Testcontainers, or the server `VECTISPIRE_TEST_DB_URL`
names, as CI's `jvm` job does with a job service — and without either it fails rather than skips
(decision 0034, `TestDatabase`). `./gradlew integrationTestAll` runs the schema and concurrency checks
on PostgreSQL and MySQL through Testcontainers. CI runs it in two places.
On push and pull request, the `engines` job of [`ci.yml`](../.github/workflows/ci.yml) runs it
**when anything engine-sensitive changed** — a migration, a module's `core/<module>/persistence/`
(every query, `Specification` and entity lives there, which `ArchitectureTest` enforces),
`core/config/`, the integration sources, or the dependency catalogue, lockfiles and verification
metadata — or when the diff
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


### One MySQL kept across runs, on your machine

By default every test JVM starts its own `mysql:9.4`, and Testcontainers' reaper (Ryuk) removes it
when the JVM exits: the server's start is paid by every run. A developer's machine can keep one
instead, shared by every run and every worktree:

```bash
echo testcontainers.reuse.enable=true >> ~/.testcontainers.properties   # or TESTCONTAINERS_REUSE_ENABLE=true
```

`TestDatabase` then starts `vectispire-test-mysql` (label `com.asmolabs.vectispire.test=mysql`) once,
outside the reaper's reach, and every later run finds it running and goes straight to its own
database. What keeps the shared server clean is the database, not the container: each JVM creates
`vectispire_test_<epoch seconds>_<random>`, drops it — and any scratch database a test left open —
when it exits, and at start drops those of ours older than a day, which only a killed JVM leaves.
Nothing else on the server is touched, and a run in another worktree, whose database is minutes old,
keeps its own. Two runs starting at once race for the name: the daemon refuses the second create, and
that run waits for the first one's container instead of making a second. A container a Docker restart
stopped is replaced; one of another image or Testcontainers version — an older branch's — is left
alone, the run reuses one without the name, and the log says to remove the old one. To remove it, or
every container of ours:

```bash
docker rm -f vectispire-test-mysql
docker rm -f $(docker ps -aq --filter label=com.asmolabs.vectispire.test=mysql)
```

The reused container is not registered with Ryuk, so nothing of `./gradlew test` or `build` depends on
the reaper any more. Testcontainers still starts it — it reads `TESTCONTAINERS_RYUK_DISABLED` from the
environment only — and where it fails to start, `TESTCONTAINERS_RYUK_DISABLED=true ./gradlew build` is
safe with reuse on. Never for the integration campaign: its containers are not reused, the reaper is
what removes them, and without it they stay.
CI is unchanged: the `jvm` job names a job service with `VECTISPIRE_TEST_DB_URL`, which starts no
container at all. A server of your own works the same way, and its stale databases are swept by the
same rule: only names of exactly that form, a day old. The integration campaign does **not** reuse.
Each of its classes gets a server nobody else uses, because
`OwaspWeeklyCoverageConcurrencyIntegrationTest` counts the lock waits of the whole server, and a
neighbour's wait would pass it without its own capture having waited.

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
| The sealing key a delegated credential was sealed for came unsigned from the agent's latest `hello`, and none meant the clear over TLS — sealing was only as trustworthy as the channel it distrusts. It is now signed with the agent's pinned key, kept until a newer signed one arrives, and its absence withholds the credential ([decision 0031](../docs/architecture/en/decisions/0031-a-sealing-key-is-believed-only-on-the-pinned-key.md)) | `AgentProtocolService`, `ScanDispatcher` |
| Withholding it claimed the scan first: every poll of an agent without a verified key counted an attempt and put the scan back, so a scan nothing had tried reached a capable executor with its takeovers spent. Such an agent's selection now leaves out the repositories carrying a credential; refunding on the old path was rejected, since the same agent would have retaken the scan at every poll | `ScanDispatcher.claimForAgent`, `ScanQueue.claimWithin` |
| That selection carried its exclusions as `not in :excluded`, one bind parameter per waiting repository carrying a credential and bounded by nothing but the queue: past the PostgreSQL driver's 65,535 the claim failed at every poll. The queue is now walked a page of 256 at a time, in claim order, and only a page's repositories are asked about; the credential lookup binds 1,000 at most | `ScanQueue.claimWithin`, `TargetCatalog.carryingCredentials`, `ScanQueueIntegrationTest` |
| A reader's visibility narrowed the backlog, the home page, the quality overview, the finding graph and the attack paths with one bind parameter per target it may see — an allowance is sized by the estate, and past the PostgreSQL driver's 65,535 every one of those reads failed for that reader. Where one statement pages, ranks or counts, the identifiers are written into it as `Long` literals in sorted lists of 1,000; where a lookup can be split, it binds 1,000 at a time — and so do a purge's deletes and a scan's fingerprint lookup, sized by a target's history and a tree | `IssueSpecifications.visible`, `FindingGraphQueriesImpl`, `IssueAggregateQueries.countGrouped`, `ScanCatalog.recentWithin`, `PurgedIssues.inBatches`, `WideAllowanceIntegrationTest` |
| A grant could name a repository or an image that did not exist — only projects were checked — and was listed as "deleted target" until a renumbering restore handed the id to somebody else's target. Every kind is now checked, against the granter's visibility too, and refused as absent (404) | `GrantTargets` |
| The EPSS screen's feed sync and a change of the certified scope wrote no audit entry, though the first is the threat-intelligence sync under another route and the second moves the denominator an assessment reads | `ThreatIntelFeedService`, `CertifiedScopeService` |
| Each scan sent the CVE it had found to `api.first.org` for their EPSS scores — which repository is vulnerable to what, told to a third party the day it was scanned — and an estate without outbound access had no score at all. FIRST's daily file is now synchronised and stored whole, and a scan reads it | `EpssFeed`, `EnrichmentService` |
| The KEV re-evaluation read the open issues at the start of its transaction and saved them whole at its end, so a score the EPSS refresh — or a scan — committed in between was put back to what it had read. Each feed now writes its own column by a targeted update | `IssueCatalog.recordExploitation`, `IssueCatalog.recordEpss` |
| The KEV re-evaluation still read every open issue into memory, in the catalogue's transaction, and held the sync row's lock — SQLite's whole file — until the last flag was written. It now walks the backlog by keyset, 500 issues a transaction, and each page takes the sync row's lock before reading, which is what keeps two synchronisations from announcing the same issue twice | `ThreatIntelFeedService`, `ThreatIntelSyncRepository.holdForReevaluation`, `KevCatalogueIntegrationTest` |
| The KEV catalogue's first write was one `select` and one `insert` per CVE — `saveAll` merges an entity with an assigned key — some 3,000 round trips under the sync row's lock. New entries are now written 500 to a statement | `ThreatIntelBulkWrites` |
| Applying an EPSS file deleted the generation it replaced at once, so a scan that had read the sync row just before the switch found none of its scores: unknown, silently. The replaced generation is kept until the next file is applied | `EpssFeed`, `EpssFeedConcurrencyTest` |
| A malformed notification threshold fell back to `UNKNOWN`, which ranks last — the threshold silently let everything through | `NotificationService` |
| Thirty-seven `ResponseStatusException`s and every refusal Spring made itself reached the client as the container's `{timestamp, status, error, path}`: the sentence each carried never arrived, and the tests that checked it read `getErrorMessage()`, which MockMvc keeps and a container drops. Meanwhile every `IllegalArgumentException` answered 400 with its message, "No enum constant com.asmolabs…" and "For input string" included | `ApiExceptionHandler`, `RefusalTypesTest` |
| The quality screen's "rule count" was the length of its own top-8 list, so it always said 8 | `QualityQueryService` |
| The backlog grouping took a column name as a string parameter | `IssueRepository` |
| The agent opened a sealed credential into a task rebuilt field by field through the constructor meant for tasks without plugins, so every credentialed repository a remote agent scanned ran none of its plugins, each recorded absent. A task is now rebuilt only through its own `withTarget`, and both sides' tests compare the whole record | `ScanTask.withTarget`, `AgentProtocol.unseal`, `ScanDispatcherTest`, `AgentProtocolTest` |
| `ScanTask.Target` is a sealed interface, which tells a JSON parser nothing: a task handed to a remote agent deserialized into an exception | `ScanTask` |
| No remote agent could hand back a result: `ScanArtifacts` is a record of `Optional`s, neither mapper registered Jackson 2's `jdk8` module, and every test of the protocol mocked the transport or sent `{}` | `AgentWireFormatTest`, `AgentResultWireTest` |
| Every `@Modifying` repository query now carries `@Transactional` — Spring Data does not add it, so an omission works whenever a caller happens to have a transaction open. The convention lived in `core.repositories`' package-info; when step 5 emptied the package it became a rule, which found fifteen derived `deleteBy…` methods in five modules without it | `ArchitectureTest.everyRepositoryWriteIsTransactional` |
| A write that must arbitrate — claiming a scan, taking the leader lease, superseding a rule set — is a conditional statement whose row count names the winner, never a `save`, which reads then writes and lets whoever wrote last win | `ScanQueue`, `LeaderElection`, `SemgrepRuleSetRepository` |
| `max_concurrent` was stored, shown and sent to every agent, and nothing applied it: the claim took a scan whatever the agent held, and the agent ran one at a time. The count and the take now commit behind the agent's row — without that lock, two polls reading different candidates both count below the limit | `ScanQueue.claimWithin` |
| The agent's stop raised a flag and returned; the JVM halts when its shutdown hooks do, so the scan its javadoc promised would finish was cut off mid-run | `AgentRunner.stop` |
| A revoked key on a claim was logged as a failed claim and retried every ten seconds for ever | `AgentLoop.claim` |
| A remote agent that could not run a scan it claimed — a clone refused, a host key changed — dropped it in silence: the lease lapsed twenty minutes later, the reclaim spent an attempt, and the reason stayed in the agent's log. The agent now reports it, scrubbed and signed, and the control plane applies the lapse's rule at once for that attempt only, the reason on the scan | `AgentLoop.reportFailure`, `ScanQueue.abandon`, `AgentFailureReportRoutesTest` |
| The report then made it worse for a lone agent: the scan was back in the queue at once, the same agent took it at its next poll, and three attempts went in seconds — a changed host key and a dropped connection alike. The built-in worker, meanwhile, failed a scan for good at its first error with the raw message. A failure is now permanent (fails at once) or transient (waits 1/5/15 min, `not_before`), decided from types on the executor, and both executors share the rule and the scrubbing | `ScanQueue.afterFailure`, `GitClone.diagnose`, `ScanDispatcher.abandon`, `ScanQueueIntegrationTest` |
| A repository or image with any triage history could not be deleted: the purge queued its child rows' removal, the bulk delete of the issues ran first, the cascade took the children, and the commit failed on rows already gone. No test had ever deleted a target carrying history | `IssueRepository.deleteByIdIn`, `ScanRepository.deleteByIdIn`, `TargetDeletionTest` |
| `known_hosts` was prepared by check-then-create: two first clones in parallel, and the second failed its scan | `GitClone.prepareKnownHosts` |
| The host-key policy called accept-new accepted no new host: JGit decided by the ssh config's `StrictHostKeyChecking`, `ask` by default, which refuses with nobody to ask — every first contact failed "Server key did not validate", and a `config` beside the file could have turned the check off. The policy now hands JGit its own configuration, a read-only file is match-only, a keyed clone reads no ssh config, and a refused key is explained as one | `GitClone.AcceptNewDatabase`, `SshCloneTest` |
| No SSH clone with a deploy key ever succeeded through the shipped composition: the image has no passwd entry, `user.home` was `/`, and the known-hosts file could not be created — a diagnosis JGit wrapped, so the scan said only "the clone failed". The composition sets each executor's home under its work directory and mounts no operator's `~/.ssh` (it was never read, and would have handed every key the operator holds to the process holding `ENCRYPTION_KEY`); `scripts/composition-scan-check.sh` clones over SSH through it and changes the host key | `docker-compose.yml`, `GitClone.clone`, `scripts/composition-scan-check.sh` |
| A plugin's output was a directory of the workspace bound writable, and a bind mount carries no size: a plugin could fill the executor's disk. `HostConfig.Tmpfs` was the obvious bound and cannot be read back — the archive API does not see a container's tmpfs — so the output is a tmpfs volume declared in the create and kept by a holder, measured by the kernel's `df` | `ContainerRunner`, `ContainerRun.BoundedOutput` |
| Every scan downloaded the matcher's database into its own workspace — some 3 GB, a minute and a half, sixteen times over for sixteen scans at once — and the matcher kept the network for it. One generation per host now, fetched under a lock and mounted read-only, and the matcher runs offline | `VulnerabilityDatabase`, `DependencyScanner` |
| Once the matcher ran as the workspace's owner rather than root, it could not write its `/tmp`: the daemon copies the image's own mode onto a tmpfs, the matcher's image ships a `/tmp` only root may write, and every scan's vulnerability matching was absent ("unable to create listing temp file", then "database does not exist"). The scratch mounts are now `mode=1777` | `ContainerRunner`, `VulnerabilityDatabaseIntegrationTest` |
| The shipped `docker-compose.yml` never completed a scan. The workspaces were in the control plane's own `/tmp`, and the daemon resolves a bind's source on its host: every scanner got an empty directory it had just created ("no source providers were able to resolve the input /repo/source"). A host directory is now mounted at the same path and is the JVM's temporary directory. No job had ever run a scan through the composition — all of them start the control plane with its worker off — so `scripts/composition-scan-check.sh` now does, in `images` and in the nightly | `docker-compose.yml`, `scripts/composition-scan-check.sh` |
| With the workspace visible at last, four scanners still ran as root, on the belief that root reads any directory: with every capability dropped it has no `CAP_DAC_OVERRIDE`, and the 0700 workspace refused it. Docker Desktop's file sharing grants that access where a Linux daemon does not. Every scanner now runs as the workspace's owner | `ContainerRun.runningAsOwnerOf`, `ScannersRunAsWorkspaceOwnerTest` |
| The composition's scan check proved two scanners of five. The matcher, the IaC checker and the SAST engine were pointed at an image that does not exist — the matcher's database is 3 GB — so the root that could not read the workspace was found for those three by hand, and SAST, off on a fresh installation, would not have started anyway. They now run at their pinned digests with SAST switched on, the matcher against a database the pinned matcher imports from `composition-scan-fixture/matcher-db.py` (its own schema, one invented advisory) and publishes in the executor's cache the way a download is; the fixture servers are an image built from a digest-pinned base, no longer `apk add` at every start. On Docker Desktop the check put its scans on a shared path, where a scanner running as root read the 0700 workspace and passed — measured with the three mutated back to root; they live in its VM now | `scripts/composition-scan-check.sh`, `scripts/composition-scan-fixture/` |
| Through the socket proxy, the first daemon request after ten idle seconds went out on a connection HAProxy had closed (`timeout http-keep-alive 10s`), which docker-java's pool never validates: an image scan queued after a pause failed its pull, and a POST is not retried. Every request now asks for its connection to be closed | `OneRequestPerConnection`, `SocketProxyIntegrationTest` |
| The labels nobody serves counted the built-in worker's even when it was switched off or had no runner, so the scans waiting for ever behind such a label went unreported | `BuiltInWorker`, `UnroutableWorkerTest` |
| The NestJS prefix pattern backtracked in the cube of a run of spaces — two seconds for 2,000 of them — and the Spring parser searched the whole file once per annotation: one committed file held a scan worker, in the built-in worker the control plane's own process | `ApiDiscoveryScanner`, `AnalysisBudget` |
| A single sign-on was orchestrated by the success handler in three commits — the subject's binding, the teams its groups claimed, the session — so a session that failed to open left the account bound and its teams reconciled for somebody never signed in. The flow is the service's, those three in one transaction and the audit entry after it | `AuthenticationFlowService.completeFederatedSignIn`, `FederatedSignInTest` |
| The gate's verdict route and its policy routes each parsed a severity in their own controller, and the copies had diverged — one trimmed `" none "`, the other refused it. One reading now, in the gate's service layer | `GatePolicyFields` |
| Outside the composition the images still had `user.home` `/` — no passwd entry for 1000 — so a plain `docker run` failed every keyed clone with "The known-hosts file could not be prepared: /.ssh". They carry `HOME=/home/vectispire`, which the JDK falls back to only when the account names no home: a `-Duser.home` in Jib's `jvmFlags` would have come after `JDK_JAVA_OPTIONS` and overridden the composition's | both `build.gradle.kts`, the `images` job |
| Every start unpacked the bundled rules to a new `vectispire-bundled-rules-*` and none was ever deleted; in the composition they piled up in the host's work directory. Deleted at shutdown, and swept at start — only an unlinked directory of that prefix, this user's, older than the process, whose lock no live process holds | `BundledRules`, `BundledRulesLifetimeTest` |
| The one-shot repair of withheld claims was kept once by reading its own audit entry: two instances starting together both read none and both wrote one. The claim is an insert the primary key arbitrates, in the transaction that does the work | `OneShotJobs`, `WithheldClaimRepairIntegrationTest.twoInstancesAtOnce` |
| The claim's first version read every failed insert as "claimed elsewhere" — on SQLite the key's refusal is not even a `DataIntegrityViolationException` — and on CI's SQLite the winner's audit entry was lost: the loser's refused insert still held the write lock, and a transaction that has read is answered `SQLITE_BUSY` at once, its busy timeout never consulted. The row decides a lost claim after the rollback; an entry refused a lock is tried again | `OneShotJobs.hasRun`, `AuditLogService.record`, `WithheldClaimRepairIntegrationTest.aFailedClaimIsNotALostOne` |
| `BundledRulesLifetimeTest` passed on macOS and failed on every Linux runner: the JDK derives a Linux process's start instant from a boot time counted in whole seconds, so it reads up to a second early and a leftover written just before a start is not "older" than it. The sweep keeps it for the next start, which errs the safe way; the test starts its next child past the second | `BundledRulesLifetimeTest.inRealProcesses` |
| Two refusals made before the application were not problems: the firewall's (`//`, an encoded `..`) reached the error page and came back `application/json`, and a URI Tomcat could not decode (a lone `%`) got Tomcat's HTML page. The chain answers the first, the host's error valve the second, both as `application/problem+json`; tested through a real connector, since MockMvc has none | `SecurityConfiguration.requestRejectedHandler`, `ProblemErrorReportValve`, `ServerRefusalsTest` |
| The first evidence bundle of an installation without `vectispire.signing.key` answered 500: the signing key is created by the first document signed, the bundle is signed in a read-only transaction, and the key's insert joined it — refused on MySQL and PostgreSQL, accepted by SQLite, which the HTTP suite ran on. The internal setting is now read and written outside the caller's transaction, which a read-back inside a `REPEATABLE READ` snapshot needs too. Found by moving the suite to MySQL | `SettingsService.storeInternalIfAbsent`, `SigningKeyServiceTest` |
| Concurrent audit writers forked the chain, and the verification then reported a break in a log nobody touched — an "audit chain broken" alarm and a SIEM event for nothing. An entry read the newest entry and chained onto it with no lock, so two that read the same head before either committed both chained onto it: eight threads of one instance did it on MySQL and PostgreSQL, and so did two instances. Every audit test had written from one thread. Each entry now locks `t_audit_chain_head` first (V66), across instances since the lock is the database's, and is dated after the head, since the lock orders the writers but not their clocks. Found while asking whether decision 0033's fourth lot could write an entry inside a scan's transaction | `AuditLogService`, `AuditChainHeadRepository`, `AuditChainConcurrencyIntegrationTest` |
| A scan that found a resolved issue again reopened it and cleared its `fixed` decision with no entry in the triage history: the trail ended on "fixed by …" for an issue standing open under review again, and the resolution it had was lost with the column that held it. The reopening is an entry of origin `reopen`, actor null, carrying the triage it left, the resolution it ended (`previous_resolved_at`, V68) and the scan; the exceptions register does not read it as a grant, and a dossier's decision count leaves it out | `IssueSyncDatabaseTest`, `HistoryTest`, `ExceptionReviewTest` |

### Shapes chosen deliberately

| | |
|---|---|
| The agent's long poll parks a `DeferredResult` instead of sleeping in a service; a servlet container cannot afford a thread per idle agent | `AgentJobPoller` |
| Transaction boundaries called from inside a class use `TransactionTemplate`, not `@Transactional` — the proxy is bypassed there, and the annotation reads as a guarantee while protecting nothing | `ScanDispatcher`, `OutboxService` |
| SIEM events are outbox rows, not calls: queued in the transaction that caused them, sent by the relay after it commits — the `@Async` exporter ran synchronously inside the caller's transaction, there being no `@EnableAsync` ([decision 0025](../docs/architecture/en/decisions/0025-siem-events-leave-through-the-outbox.md)) | `SiemEvents`, `SiemDelivery` |
| The audit log tells its listeners after the entry's commit, so a listener that fails cannot cost the entry | `AuditLogService` |
| Settings are read through the `Setting` catalog, not by key plus a caller-supplied default that could drift from the screen's | `SettingsService` |
| Spring Boot 4 auto-configures Jackson **3**; this codebase is annotated for Jackson 2, so the mapper is declared explicitly on both sides of the agent protocol | `CoreConfiguration` |
