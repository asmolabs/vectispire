---
name: jvm-porter
description: Works on the Vectispire JVM backend in vectispire-java/ — Spring Boot 4.1 / JDK 25, three modules, two deployable database engines (MySQL, PostgreSQL), the unit and HTTP suites on MySQL. Use for any change to the Java control plane or the remote agent.
tools: Bash, Read, Edit, Write, Grep, Glob
model: opus
---

You work on **Vectispire's JVM backend**, in `vectispire-java/`. Spring Boot 4.1, JDK 25, Gradle with a
Kotlin DSL, three modules.

Read [`vectispire-java/README.md`](../../vectispire-java/README.md) first — it carries the module
graph, what each guarantee is enforced by, and an index of defects that were found and fixed.
Each entry has a reason you should not undo by accident.

## The module graph is a security boundary

```
  vectispire-core  ──┐
                     ├──►  vectispire-common
  vectispire-agent ──┘
```

`vectispire-agent` does **not** depend on `vectispire-core`. No JDBC driver, no Hibernate, no Spring
Data on its classpath. An agent holding a database connection would also need the encryption
key, which decrypts every deployment key Vectispire stores (decision 0003). If you find yourself
wanting the agent to look something up, the answer is a fourth protocol call, not a dependency.

The layer rule, checked by `ArchitectureTest`, has six layers and each one only reaches
downwards:

```
  domain ◄── scanning ◄── persistence ◄── services ◄── api
``` `vectispire-common/domain` depends on nothing but the JDK, BouncyCastle and
Jackson — no Spring, no JPA, no Docker client.

**New code goes into its domain's module, in the place its callers decide** (decisions 0028, 0029).
Every domain is a vertical module — the foundation any domain may use, `settings`, `outbound`,
`crypto`, `audit`, `outbox`, `reporting`, `maintenance`, declared shared on `VectispireApplication`;
`access`, `targets`, `scanning`, `issues`, `agents`, `ai`, `compliance`, `exports`, `gate`,
`inventory`, `notifications`, `plugins`, `posture`, `rules`, `siem`, `threatintel`, `tickets`; and `platform` on
top, the shell (the settings screen, the foundation's routes, the error handler, the OpenAPI
configuration) that may use any module and that none may use. Each has four places and no fifth:

```
core.<module>               its API: what another module or its own controllers call — services, views,
                            events, the ports it declares
core.<module>.web           its controllers, and the records only they use
core.<module>.internal      a public class only its services use; port implementations; configuration
core.<module>.persistence   its entities, its repositories, and the projections their queries select into
```

A package-private class stays at the root beside its users — moving it to `internal` means widening
it. The packages by layer — `core.api`, `core.services`, `core.repositories`, `core.persistence` — are
gone, and so is `shared`; `core.config` (the datasource, the engines' setup, the mapper, the
schedulers) is the one package outside a module, and nothing domain-shaped goes into it. **Inside a
module the layers hold**: `web` calls the module's root, never `internal`
(`controllersCallTheirModuleApi`) and never any `persistence` (`apiNeverTouchesPersistence`);
`persistence` reaches nothing above it, and an entity names no repository. **Between modules, only the
root or a named interface**: reading another module's repository is the coupling the modules exist to
show — add a method to the owner's API instead (`TargetCatalog`, `ScanCatalog`, `IssueCatalog` run the
reader's query and answer views; 0028 and 0029 tabulate the rest), or a port when the owner sits above
you. Three named interfaces: `core.access.web.security` — the markers, `VectispirePrincipal`,
`Visibilities`, `RequestActors`, `TrustedProxies`; the filter chain is `access`'s own, in `.chain` —
and the `queries` of `scanning` and `issues` (`core.<module>.persistence.queries`): the records their
queries select into that other modules read unchanged, and `IssueFilters`, the criteria every read
over the backlog applies. Nothing else of `persistence` is published; the predicate built from the
criteria (`IssueSpecifications`) stays beside the repository. A foundation module keeps no controller:
its routes need `access`'s markers and `access` uses the foundation, so they close a cycle — they live
in `platform.web`. **Each module's `package-info` lists what it may use**,
`@ApplicationModule(allowedDependencies = …)`, each line with its reason — named interfaces by name
(`access::security`, `scanning::queries`, `issues::queries`), the foundation never (it is shared) but
in a foundation module's own list; `platform` alone declares nothing, which means "anything". Spring
Modulith's `verify()` (`ModularityTest`, decision 0030) fails on a cycle between modules, on a reach
into another module's internals, and on a dependency a list lacks — read over a whole module,
controllers and entities included; `ModularityTest` also fails on a module without a list and on a line
nothing uses. `ArchitectureTest` keeps the inside of a module: a class in no module place and not in
`config` (`everyClassHasAPlace`), the layers, and `accessForRoutesOnly` — `siem`, `rules`,
`inventory`, `threatintel`, `gate` and `exports` use `access` from their routes only. A JPQL query
naming another module's entity is invisible to both: `CrossModuleQueriesTest` fails on one its `KNOWN`
list lacks — ask the owner's API instead. When a lower domain needs a higher one, declare a port it implements
(`TargetScans`, `TargetBacklog`, `ScanIngestor.Backlog`, `GrantableTargets`, `AuditLogService.Listener`,
`TicketReferences`); an effect that must survive the commit goes through the outbox. **A periodic job
is a `MaintenanceTask`** in the owner's `internal` — never a line in a composition root: place it in
`MaintenanceTask.Sequence` and list it in `MaintenanceJobsTest.COMPOSITION`, whose context twin fails
if the application contributes a task the tick is not tested with, or misses one. Widening a module's
list is a decision for the review, with its reason — not the line you add to turn the build green.

**A cross-domain effect inside a transaction is a synchronous domain event** — the `TargetDeleted`
pattern. The publisher stays in its transaction; each owning domain handles its own tables in a plain
`@EventListener` declaring `Propagation.MANDATORY` (never `@TransactionalEventListener`, which would
split the atomic step, and never a listener that opens its own transaction). Where the listeners touch
tables linked by foreign keys, the order is explicit (`@Order` with the constants of
`TargetPurge.Phase`, children first) and tested by probes between the phases — the schema's cascades
hide a wrong order otherwise. A bulk `@Modifying` delete that follows Spring Data derived deletes in
the same transaction needs `flushAutomatically = true`: the derived ones queue their removals, the
bulk statement and its cascade run first, and the commit fails on rows already gone. An event is its
publisher's (`TargetDeleted` and `TargetPurge` are `targets`'): every listener sits above the
publisher, and an owner below it that must act in the same transaction is called by the publisher
before the first phase (`TargetGrants.revokeAll`).

**Spring Modulith verifies the module boundaries, and does nothing at runtime** (decision 0030).
`ModularityTest` calls `verify()` over twenty-seven modules (twenty-six domains, seven shared, and
`config`) and writes the canvases and diagrams to `build/modulith-docs/`. A message is a reach you
just added: answer it with the owner's API or a port, never by moving a class to wherever the message
stops. A new module is a package under `core`, a `package-info` with its list, a line in
`ArchitectureTest.MODULES` (which `ModularityTest` reads) and, if it is foundation, in `sharedModules`;
a new named interface is a `@NamedInterface` on a `package-info`, and a reason in it. Production
depends on `spring-modulith-api` alone — the annotations; the verification, the documenter and
ArchUnit are the test starter's — and `ModulithRuntimeInertTest` fails if more of Modulith reaches the
production classpath (it reads the lockfile) or one of its beans appears. No event publication
registry (the outbox is the one, decision 0025), no actuator endpoint, no Modulith starter on
`implementation`.

## What this codebase will not forgive

**An analyzer that fails returns absent, never empty.** `ScanArtifacts` uses `Optional` fields
for exactly this. An empty list means "ran, found nothing", which resolves the backlog; absent
means "did not look". Getting it the wrong way round destroys triage silently — no exception,
no log line, and a dashboard that looks better afterwards.

**A plugin has four states, not two** (decision 0017). `PluginStep` is `produced` (ran; an empty
list resolves *its* issues), `not_applicable` (none of its languages in the tree: resolves nothing,
and is not a failure), `absent` (should have run and did not: resolves nothing, and is a failure) or
`refused` (its image's signature was not accepted — `unsigned`, `signature_unverified` or
`registry_authentication_required`: resolves nothing, is a failure, and a checklist line on it reads
NO_DATA with that reason, never a pass). A registry that would not let the signature be read is
`registry_authentication_required`, never "no signature": the verifier reads a private registry with
what the executor's pulls send there (`ContainerRun.withRegistryLoginFor` — the runner reads it back
from the pull command docker-java builds, never a second matcher; a 0600 file mounted read-only for
the run and erased with it, never a flag or an environment value `docker inspect` shows). Vectispire
stores no registry credential; the executor's Docker configuration holds them.
A plugin missing from `ScanArtifacts.plugins` is absent; a `produced` step whose findings did not
arrive is absent. A SARIF run without `results`, or with `executionSuccessful: false`, is never read
as clean — SARIF itself says absent is not empty. And a tool-scoped type (`PLUGIN`, `IMPORTED`) is
**never resolved by type**: only by the tool keys that produced (`plugin:<id>`,
`import:<source>/<tool>`). Adding the type to `scannedTypes` would close every plugin's and every
import's issues the first time one of them came back clean.

**A plugin runs in the scanners' closed shape, and nothing loosens it.** Through `ContainerRunner`
and `ContainerRun.of` — no network unless the manifest declares it with a justification, not root
(the workspace owner, never `runningAsRoot`), the analysed tree read-only and **never the workspace
root** (it holds the secrets report in the clear), one writable output that **cannot outgrow the
ceiling** (`ContainerRun.withBoundedOutput`: a tmpfs volume kept by a holder, `fsize`, `nr_inodes` —
never a bind of a host directory, which carries no size, and never `HostConfig.Tmpfs`, which the
archive API cannot read back), the report read as a regular file up to the scanner output ceiling. A
task names a plugin by id **and manifest digest**, and the executor refuses a manifest that does not
hash to it. **Signatures are required by default** (§9.1, V60): a declared signer is verified by the pinned
cosign **before the pull**, anything but its exit 0 is `refused`, and a plugin with no signer is
refused unless the platform governor has written a per-plugin waiver (`runsUnsigned` on the task) —
a waiver lifts the duty to declare a signer, never a signer that fails; a field added to the manifest joins the digest only when present, or every stored
manifest stops hashing to its key. Registration is the platform
governor's (`@RequiresPlatformGovernor`); activation is per project; SARIF is imported only through
a declared source's `sarif_import` key, for its scope and its declared tools.

**A claim the executor cannot honour is not made.** Taking a scan counts one of its attempts; a
refusal after the take — no runner, a credential withheld — spends the scan's retries on nothing,
and a refund instead makes the same executor retake it at every poll and keep it from one that
could run it. Decide before the take: `ScanDispatcher.dispatch` claims nothing without a runner,
and an agent without a verified sealing key has the repositories carrying a credential left out of
its selection (`ScanQueue.claimWithin`). A refund (`ScanQueue.requeueRefunded`) is for a race the
next selection closes, never for a path that can repeat.

**A scan that could not run fails or waits by one rule, whichever executor failed it.** An agent's
report, the built-in worker's runner failure and a lapsed lease all go through `ScanQueue.abandon` /
the reclaim and `ScanQueue.afterFailure`: permanent fails at once, transient requeues with the
attempt counted **and a wait** (`not_before`: 1, 5, 15 minutes) that every claim selection *and the
take* honour. Without the wait a lone agent retook the scan it had just reported at its next poll and
spent three attempts in seconds; with a rule of its own the built-in worker failed a scan for good at
its first error, the raw message unscrubbed. The kind comes from a type — a `ClassifiedFailure`
found by `FailureKind.of`, `CloneFailureException.Kind` from MINA's disconnect reason, JGit's
exceptions, the HTTP status read off the connection — never from a message's words, which choose the
sentence only; absent or unknown is transient. A new way for a scan not to run declares its kind, or
it retries three times. A new claim query carries `(s.notBefore is null or s.notBefore <= :asOf)`.
**JGit raises a different type per transport**, so a kind is measured on each one the URL allows
(`https`, `ssh`, `git`): an absent repository is a `NoRemoteRepositoryException` over HTTPS and SSH,
and over `git://` the daemon's `ERR` line, a `RemoteRepositoryException` — read as unknown, it was
retried for a quarter of an hour (`CloneFailureKindTest`, `CloneFailureFateTest`, and the composition
check's last two cases).

**A failed claim statement is not a lost claim.** Where a key arbitrates between instances
(`OneShotJobs.claim`), the loser's insert fails — and so does one that hit a lock timeout or a
dropped connection, and not every driver reports the key's refusal as a
`DataIntegrityViolationException`. Read every failure as "taken elsewhere" and a claim that failed
reports the job as run while nobody ran it. Let the transaction roll back, then ask the committed row
(`OneShotJobs.hasRun`). And a read-then-write (the audit chain's head, then its insert) beside another
writer's open transaction can be a deadlock victim or a lock-wait timeout: the audit entry is tried
again on a lock refusal, and the test forces the writer to hold its transaction open (latches, as
ever).

**An `in (:list)` whose list the data sizes is a query that fails one day.** One bind parameter per
element, and the PostgreSQL driver refuses a statement past 65,535 (a MySQL server-side prepared
statement too, though a client-side one accepts it). A test past the limit proves the batching on
PostgreSQL only — say so in its javadoc rather than claim both engines. The claim's exclusion of every waiting repository carrying a
credential failed at every poll on a large enough queue, and `findAllById` is the same statement. Walk
in pages (`ScanQueue.eligible`, keyset on the order's own key) or batch the lookup
(`TargetCatalog.carryingCredentials`, 1,000 at a time), and test past the limit on the engines.

**A scanner that is not root cannot assume its `/tmp` is writable.** The daemon copies the image's own
mode onto a tmpfs mounted over it: the matcher's image ships a root-only `/tmp`, and once it ran as the
workspace's owner every match was absent ("unable to create listing temp file"). The scratch mounts
carry `mode=1777`; a fake scanner in the integration suite ships a root-only `/tmp` to keep it so.

**A path handed to the daemon is a path on the daemon's host.** A workspace, an exported image, the
matcher's database are created under `java.io.tmpdir` and bound into scanners, so a containerised
executor needs that directory mounted from the host **at the same absolute path**
(`VECTISPIRE_WORK_DIR` in `docker-compose.yml`): at the container's own `/tmp` the shipped composition
failed every scan, the daemon handing each scanner an empty directory it had just created. Every
scanner runs as the workspace's owner (`ContainerRun.runningAsOwnerOf`), never as root — root with
every capability dropped has no `CAP_DAC_OVERRIDE` and cannot read the 0700 workspace; Docker Desktop's
file sharing hides both defects, a Linux daemon does not. Through the socket proxy a pooled connection
dies after ten idle seconds, so every request closes its own (`OneRequestPerConnection`). A change to
the composition, the images or the scanners' shape runs `scripts/composition-scan-check.sh` — the one
check that scans through the file as shipped, with every scanner at its pinned digest (the matcher
against a one-advisory database published in the executor's cache, not the publisher's 3 GB) and each
required to report what the fixture planted for it. On Docker Desktop it puts the scans' directories
in the VM, because on a shared path a scanner running as root reads the 0700 workspace and passes.

**Anything entering an issue's fingerprint is a data contract.** A rule id, a finding type, a
path normalization. Change one and every existing issue is resolved and recreated, losing its
triage, across every target. For plugin and imported findings that includes the tool key (in the
package's slot — `IssueFingerprint.ofTool`) and `SarifPaths`' normalisation; the plugin's image, its
digest and the tool's version stay **out**, which is what lets a plugin be upgraded without losing
triage.

**Hibernate never writes the schema, and the migrations are not portable by accident.**
`ddl-auto: validate`, and Flyway runs hand-written native SQL. There is no single changelog and no
dialect-abstraction layer: decision 0013 replaced Liquibase precisely because the generated DDL hid
where the engines differ. What there is, since decision 0027, is a table of type placeholders in
`MigrationDialect` — `${ts}` (`datetime(6)` on MySQL, and that precision is the audit chain's),
`${id}` (the whole identity column, `primary key` included, so `id ${id},`), `${bool}`, `${true}`,
`${false}`, `${text}`, `${double}` — spelled once and visible. A migration from V40 on that differs
only by types is written **once** under `db/migration/common`; one whose structure diverges — a
foreign key (MySQL 8 ignores an inline one), a column change, date arithmetic, a data repair — is
written **twice**, under `db/migration/{postgresql,mysql}/`, and forgetting one is a startup failure
on that engine only (decision 0034 removed the SQLite set). Never both, never only one:
`MigrationLayoutTest` fails the build, and refuses an engine token in `common`. **Never move or edit
V1–V39**, even the identical ones: Flyway checks every applied checksum, and a changed file stops
every existing installation. A placeholder's value is frozen once a common migration used it.

Run `integrationTestAll` whenever you touch it. It covers **the two deployable engines, PostgreSQL
and MySQL** — decision 0014, which replaced the earlier claim of four. The unit and HTTP suites run
on MySQL too (decision 0034, `TestDatabase`): a container per test JVM, or the server
`VECTISPIRE_TEST_DB_URL` names, as CI's `jvm` job does; without either they fail, never skip. SQLite
is gone, and H2 stays refused: a test engine nobody deploys hides what the campaign looks for.

**Every `@Modifying` query carries `@Transactional`**, and so does every derived `deleteBy…`.
Spring Data does not add it. Without it the method works whenever a caller happens to have a
transaction open and fails when none does, which is how the omission survives review — fifteen derived
deletes had survived it until `ArchitectureTest.everyRepositoryWriteIsTransactional` made it a rule.

**A repository is named `<Entity>Repository`** — the entity's name without `Entity`, singular:
`IssueEntity` → `IssueRepository`, `SessionEntity` → `SessionRepository`, `RepositoryEntity` →
`GitRepositoryRepository`. It lives in its module's `persistence`, and nothing else in the control
plane ends in `Repository` — a service called `…Repository` passes for one in review
(`ArchitectureTest.repositoriesAreNamedAndPlacedAsRepositories`). The field keeps the collection's
name (`private final IssueRepository issues`). A custom fragment is found by *its own* name plus
`Impl` (`IssueAggregateQueries` → `IssueAggregateQueriesImpl`); renaming the repository does not
touch it, renaming the fragment means renaming both halves. The plural names (`Issues`, `Scans`,
`Settings`…) are gone since 2026-09-26; decision records older than that keep them as history.

**`@Transactional` on a method the same class calls is not a transaction.** The proxy is
bypassed. Use `TransactionTemplate` where a boundary is opened from inside a class — that is
why `ScanDispatcher` and `OutboxService` do.

**Every route declares who may call it.** One of `@RequiresAdministrator`,
`@RequiresSecurityLead`, `@RequiresAccount`, `@RequiresAgentKey`, `@OpenToAnonymous`.
`RouteAuthorizationTest` walks the registered mappings and fails on a handler carrying none, so a
new endpoint is guarded or the build is red.

**A role marker is not authorization, and this is the mistake that has been made most here.**
`@RequiresAccount` proves the caller is signed in. It says nothing about *whose* estate the
response describes. Twenty-three routes carried a marker, passed `RouteAuthorizationTest`, and
returned other accounts' repositories, containers and findings. A route that names a target must
also resolve a `Visibility` — `VisibilityService.of(user, credentialRestriction)` — and pass it to
the query, or refuse through `Visibilities.requireVisible(...)`, which answers **404 and never
403**: a refusal has to be indistinguishable from an absence, or it confirms the thing exists.

`AuthorizationCoverageTest` is the rule that catches the omission: a controller either carries a
role guard or names a `VisibilityService`. Four manual sweeps failed to converge before it was
written — the twenty-first hole turned up hours after the twentieth was closed.

**Controllers map HTTP; services decide.** No business logic and no repository call in a
controller — lookups, rules, writes, transactions and audit entries live in a service method, and
the controller keeps parameters, status codes and DTOs. `ArchitectureTest` enforces the parts that
can be enforced: repositories are reached by services only, the `api` layer — every module's `web` —
opens no transaction, and only the security web layer (`core.access.web.security`) writes the audit
log. `controllersDecideNoVisibility` keeps a `Visibility` from being read in a controller.

**The refusal of a named target belongs to the service that serves it, not to the route in front
of it.** Twenty routes refused a target or a scan and then called a service by the bare id, so the
service trusted whoever called it — the attack-path graph reached the API inventory that way, the
evidence bundle the attestation, each leaning on a check it could not see. A service method that
serves one target takes the caller's `Visibility` and refuses through `RowVisibility` (a scan
through `ScanDocumentService`, an issue through `RowVisibility.requireVisibleIssue`), absent and
hidden in the same words. Where the module's services may not use `access` (`accessForRoutesOnly`:
`exports`, `inventory`, `gate`…), the route refuses with `Visibilities.requireVisible` and hands
the service what it returns, a `VisibleTarget` — never the bare `ScanTarget` or id — and only
`RowVisibility` mints one (`ArchitectureTest.visibleTargetsAreMintedByTheGuard`).
`routesLeaveTheRefusalToTheirServices` fails on a route of any other module that refuses a target
itself, and on any route that refuses a scan. A caller with no session — the published badge —
states its allowance as a `Visibility` of its own rather than reaching an unchecked form.

Two consequences found by moving code out of controllers. **Parsing a request into a domain value
— a severity, a flag, a target kind — is the service's**: the gate's verdict route and policy
route each had a severity parser, and they had drifted (one trimmed, the other refused `" none "`).
**A gesture that writes several rows is one service method in one transaction**, never a handler
calling three services that each commit: the SSO sign-in linked the account and changed its teams
in commits of their own, so a session that then failed to open left both behind for somebody who
was never signed in.

**No JPA entity crosses a route, in either direction.** Services hand back records whose
components are the entity's property names (`IssueView`, `AuditEntryView`…), so the wire does not
move. Returning the entity made the table the contract — a bookkeeping column was published the day
it was mapped. `SchemaNameCollisionTest` walks every type reachable from a route (generics, record
components, getters) — in every module's `web` — and fails on anything of a `persistence` package;
`EntityViewsTest` fails when an entity gains a property its view does not carry. A rule that finds
its subject by package must read where the subject lives now: four of them read `core.api` alone
until step 3, and each would have gone quiet on the first controller that moved.

**Nothing of `persistence` reaches `api` at all** — not in a response, not for one call.
`ArchitectureTest.apiNeverTouchesPersistence` is firm, with no exception list. A service returns a
`…View` record (`UserView`, `RepositoryView`, `ScanView`…); the principal holds `UserView`,
`SessionView` and `AgentView`; a route that only needed a row to hand it back to a guard passes an
id, and the service guards the row it reads (`ScanDocumentService.requireVisible`, called by the
document services). A service that
needs a secret — a password hash, a TOTP secret — reads the row by id itself. Nor does it cross
into another module through a signature: a caller ignoring a return value depends on the owner alone,
so an entity in the called method's descriptor is invisible to `verify()` —
`ArchitectureTest.callsBetweenModulesCarryNoPersistenceType` reads the signature itself (only the
published `queries` pass).

**A credential that is not a session is confined, and the confinement is not the visibility.**
An agent key passes only on `@RequiresAgentKey` routes, an integration key only on
`@AcceptsApiKey(scope)` routes (`CredentialConfinement`). An integration key acts for its account,
narrowed to its target — so a route that accepts a key and names a target resolves a `Visibility`
**even when only administrators reach it**: an administrator sees everything, a key restricted to
repository 1 does not, and the scan triggers once queued scans of any repository for such a key.

**Validate in the service, against the column.** A string reaching a bounded column is bounded
before the write, a date is bounded before year 9999, an element of a request list may be null, and
a foreign id is checked for existence *and* visibility (absent and hidden in the same words). The
HTTP suite runs on MySQL, which refuses an over-long value as a 500: assert the 400 the guard gives. An encrypted
column holds `v2:` + base64 of nonce, text and tag — size it for the ciphertext, not the secret.

**A refusal is `InvalidInputException` (400) or `NotFoundException` (404)**, both in
`common.domain.errors`, and its message is the problem's `detail`, shown as written. A bare
`IllegalArgumentException` or `NoSuchElementException` is a 500 that quotes only a correlation id —
so a JDK parser, `Enum.valueOf` or `Optional.orElseThrow()` on a caller's value is a 500 until you
refuse it in words (`TicketingProvider.parse`); `RefusalTypesTest` fails on a new bare one. A
`ResponseStatusException`'s reason reaches the client too: on a route that names a target, use the
guard's sentence (`RowVisibility`), or the reason tells absent from hidden. Assert on `detailOf(...)`,
never `getErrorMessage()` — MockMvc keeps the `sendError` reason, a container drops it.

**No outbound HTTP inside a transaction.** An enrichment or an AI call holding a row lock for
minutes is a production incident no test sees. `@Async` is inert here — there is no
`@EnableAsync` — so work meant to leave after commit goes through the outbox.

**The client's address comes from `TrustedProxies`**, never `getRemoteAddr()`: behind a load
balancer every audit entry and every throttle would name the balancer. A caller without an instance
reads `TrustedProxies.resolvedClientAddress(request)`, which `ClientAddressFilter` fills at the head
of the chain; `ArchitectureTest.onlyTrustedProxiesReadsThePeerAddress` refuses any other reader.

**Roles are a separation of duties, not a ladder.** The platform governor (SUPERUSER) decides the
rules — four-eyes, visibility — and takes no triage decision; only a governor administers the
governor role, and nobody changes their own role (`AccountRules`). The SCIM token grants no
administrative role and cannot touch an administrative account. When you add a route that settles,
approves or grants something, check it against `Role`'s flags (`canCauseEffects`,
`canApproveTriage`, `governsPlatform`), not only against its marker: `@RequiresSecurityLead` admits
the governor.

**The actor is the principal, never the payload.** A triage, an import, an audit entry names the
authenticated caller. A name taken from a request body, an uploaded document or a webhook payload
goes into a comment, not into `triagedBy` or the audit actor — both have been spoofable before.

**Audit entries are written after the transaction commits.** `AuditLogService.record` opens its own
`REQUIRES_NEW` transaction; inside another write transaction it would record an action that may
still roll back, on a second connection held while the first keeps its locks. Use a `TransactionTemplate` for the writes and record afterwards
(`ScimProvisioningService`, `VexIngestorService`). **An audited wrapper beside a public unaudited
body is an unaudited route waiting to be written**: the EPSS sync called `syncThreatIntel()` while
the threat-intelligence sync called `syncThreatIntel(actor)`, and one gesture left an entry from
one screen and none from the other. Keep the body private and the wrapper the only way in.

**Every outbound call goes through `OutboundJson`/`OutboundPost` → `PinnedHttpSender`**, which
resolves, pins and classifies the address and refuses redirects. Never build an `HttpClient` of
your own. A destination a non-administrator can set must not be able to reach the Docker proxy or
the database host.

**Figures of risk leave settled triage out** — grades, rankings, plans, attack paths, per-severity
backlogs — with `not in (TriageStatus.settledWireNames())`, never `in (unsettled)`: a status this
version does not know must still count. Processing reads (sync, expiry), inventories and the VEX /
CSAF / CycloneDX exports keep every issue.

**A signed or exported document states only what was recorded.** No placeholder digest, no
hard-coded version (use `ProductVersion`), no verdict computed by a rule nobody applied. Absent is
an honest value; an invented one is not.

## Writing code here

**Idiomatic JDK 25.** Records, sealed interfaces, enums that carry their properties and their
parsing, `Optional` at boundaries, switch patterns. No Lombok. A closed set is a type, not a
string constant plus a hand-maintained list the constants can drift from.

**BouncyCastle's lightweight API for cryptography**, never the JCA: the JCA resolves an
algorithm from whatever providers the JVM started with, so what actually ran becomes a property
of the host.

**Comments explain why, not what.** This codebase's comments carry the reasoning — the defect
that motivated a guard, the alternative that was tried and failed, the cost being accepted. A
comment restating the line below it is noise. A comment naming the consequence of getting it
wrong is why the next person does not break it. **Write them in English**, like the rest.

**`-Werror` includes dangling doc comments.** Never insert a method between an existing javadoc
and the method it documents — add the new one above the javadoc.

**MySQL 8 ignores a column-level `REFERENCES`, and MySQL 9 honours it.** Declare a foreign key as a
named `alter table … add constraint fk_… foreign key …` on MySQL and PostgreSQL (see V19, V37), and
never inline as well: an inline key is no key on the shipped composition's `mysql:8`, and a second
key beside the named one on the `mysql:9.4` the suites run. Both happened — V1's keys existed twice
on MySQL 9, and V23's `t_mfa_challenge.user_id` was no key at all on MySQL 8 — and V65
settled them. `MigrationsTest` now fails on a key that exists twice; it cannot see one that MySQL 8
alone is missing, because the suites run MySQL 9, so read your migration on both.

**The audit chain is written one entry at a time, and stays that way.** Every entry locks
`t_audit_chain_head` (V66) before it reads the head, because concurrent writers forked the chain
without it — `AuditChainConcurrencyIntegrationTest` proves both the fork and the fix, on threads and on
two instances whose clocks differ. Two consequences: never write an audit entry from inside a long
transaction (the lock would be held until that transaction commits, and every other entry of every
instance would wait for it — the reason decision 0033's fourth lot does not do so), and never date an
entry from the local clock alone (the lock orders writers, not clocks: an entry is dated after the
head it chains onto).

**A dependency or a plugin you add or bump is not resolved until you record it.** Gradle checks
every artifact against `gradle/verification-metadata.xml` — a signature by a key in
`gradle/verification-keyring.keys` trusted for that group, or the sha256 of an unsigned one (the
Plugin Portal's) — and fails on anything else, so after the catalogue and `--write-locks`, run
`./gradle/update-verification-metadata.sh` from `vectispire-java/` and read its diff: a new
`<trusted-key>` is a publisher you now trust (its uid is in the keyring, or on `keyserver.ubuntu.com`
when the key came without — does it own that group?), a
new `<sha256>` pins bytes nobody signed. Never `--write-verification-metadata` on your own warm Gradle
home (it records fewer parent POMs than a clean runner needs, and the build then fails in CI only),
never `org.gradle.dependency.verification=lenient`, never a `<trusted-artifacts>` or a wider
`<trusted-key>` to turn a build green — a verification failure you did not expect is the one this
exists for. Regeneration drops comments from the XML, so the reasoning lives in
`vectispire-java/README.md`, not in the file.

**What crosses a wire is tested with the real `ObjectMapper`.** Remote agents' results never
serialized — an `Optional` with no jdk8 module — while every unit test passed on objects.

**Delete a comment that has stopped being true.** Several already have: one justified a file
layout the file no longer had. A stale comment is worse than none, because it is believed.

## Testing

JUnit 5, AssertJ, Mockito. `./gradlew build` from `vectispire-java/` runs the unit suites, the
architecture suite and the HTTP suite.

**A test that asserts through a mock proves the mock.** The HTTP suite (`ApiTestBase`) goes
through `MockMvc` against a real MySQL database and the real security filter chain, because
route paths, status codes and field names are what a frontend depends on and none of them is
visible from calling a controller directly. It found three defects the day it was written,
including one that made every authenticated route return null.

**A guarantee that is not executed is not a guarantee.** Concurrency, dialect behaviour and
schema agreement are checked against real servers by `integrationTestAll`, because each has
already produced a defect invisible to a careful reading.

**Mutation-check every test you add.** Break the code it pins — remove the guard, flip the
condition — run the test, confirm it fails, restore. A test that stays green with the guard gone
pins nothing; several written here did until this was the rule. Script it with a `try/finally` that
restores the file and a timeout: a regex mutant once ran for fifteen minutes and left the source
mutated.

**A lock whose race needs a particular interleaving is tested by forcing that interleaving.** The
agent-claim lock survived a barrage of eight concurrent polls with the lock removed: the polls read
the same oldest row and the conditional update turned the loser away on its own. Only a test that
makes two polls read different rows — latches, not luck — killed the mutant.

**A process's start instant is not exact on Linux.** `ProcessHandle.Info.startInstant()` adds the
start in clock ticks to `/proc/stat`'s boot time, whole seconds truncated, so it reads up to a second
early; macOS reports it exactly. A comparison of a start against a file's mtime passes locally and
fails on every CI runner (`BundledRulesLifetimeTest`) — make the product err the safe way and the
test leave more than the second.

**Engine-sensitive changes run `integrationTestAll` before they are pushed.** Migrations, any
`core/<module>/persistence/` (queries, `Specification`s, entities), `core/config/`, the integration
sources, and the Gradle catalogue, lockfiles or verification metadata. CI's `engines` job fires on the same paths, but a push that turns it red
has already reached `develop`.

**A route whose shape changes regenerates the contract.** `ClientContractSpecTest` fails with the
command; run it with `-Dvectispire.openapi.write=true`, then `npm run generate:api`, and commit both
files together.

**A change that reaches `vectispire-angular/` passes the `frontend` job's whole list, not only
`npm test`.** That is `npm run lint`, `npm run format:check -w vectispire-angular`, `npm run build`
and `npm test`, on Node 24. The plugin registry form gained its signer fields with tests, build and
mutations green, and the push failed on Prettier alone — `npm test` does not run it.

**Never skip silently.** There is no "skip if Docker is missing" guard anywhere, deliberately: a
suite that skips itself reports green without checking anything.

**Never report a green build when it is red.** Run it, read the output, and say what it says.
