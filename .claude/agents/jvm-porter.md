---
name: jvm-porter
description: Works on the Vectispire JVM backend in vectispire-java/ — Spring Boot 4.1 / JDK 25, three modules, two deployable database engines and a SQLite test fixture. Use for any change to the Java control plane or the remote agent.
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
  domain ◄── scanning ◄── persistence ◄── repositories ◄── services ◄── api
``` `vectispire-common/domain` depends on nothing but the JDK, BouncyCastle and
Jackson — no Spring, no JPA, no Docker client.

**New code goes into its domain's module, in the place its callers decide** (decision 0028). Nineteen
of the twenty-four domains (decision 0026) are vertical modules — the foundation any domain may use,
`settings`, `outbound`, `crypto`, `audit`, `outbox`, `reporting`, declared shared on
`VectispireApplication`, and `access`, `agents`, `ai`, `compliance`, `exports`, `gate`, `inventory`,
`notifications`, `posture`, `rules`, `siem`, `threatintel`, `tickets`. Each has four places and no
fifth:

```
core.<module>               its API: what another module or its own controllers call — services, views,
                            events, the ports it declares
core.<module>.web           its controllers, and the records only they use
core.<module>.internal      a public class only its services use; port implementations; configuration
core.<module>.persistence   its entities, its repositories, and the projections their queries select into
```

A package-private class stays at the root beside its users — moving it to `internal` means widening
it. `issues`, `scanning`, `targets`, `platform` and `shared` are still packaged by layer (`core.api`,
`core.services.<domain>`, `core.repositories`, `core.persistence`) until step 5; new code for them
goes there, in its domain's sub-package, never into `core.services` itself, and nothing new goes into
`shared`. **Inside a module the layers hold**: `web` calls the module's root, never `internal`
(`controllersCallTheirModuleApi`) and never any `persistence` (`apiNeverTouchesPersistence`);
`persistence` reaches nothing above it, and an entity names no repository. **Between modules, only the
root or a named interface**: reading another module's repository is the coupling the modules exist to
show — add a method to the owner's API instead (the nine that were needed are tabulated in 0028), or a
port when the owner sits above you. The one named interface is `core.access.web.security` —
the markers, `VectispirePrincipal`, `Visibilities`, `RequestActors`, `TrustedProxies`; the filter
chain is `access`'s own, in `.chain`. A foundation module keeps no controller: its routes need
`access`'s markers and `access` uses the foundation, so they close a cycle (`AuditLogController` and
`CryptoController` wait in `core.api`). `ArchitectureTest` fails on a class in no module place or
layered package (`everyClassHasAPlace`), on any cycle between domains (sliced by domain, modules and
`core.services` alike; `KNOWN_CYCLES` is empty and only shrinks), on a reach into another module's
internals (`modulesMeetAtTheirApi`), and on a dependency the `MAY_USE` table does not allow — read
over a whole module, controllers and entities included; any module's `web` may use `access`. When a lower domain needs a higher
one, declare a port it implements (`ScanIngestor.Enricher`, `AuditLogService.Listener`,
`TicketReferences`); an effect that must survive the commit goes through the outbox. Widening the
table is a decision for the review, with its reason — not the line you add to turn the build green;
nothing new goes into `shared`.

**A cross-domain effect inside a transaction is a synchronous domain event** — the `TargetDeleted`
pattern. The publisher stays in its transaction; each owning domain handles its own tables in a plain
`@EventListener` declaring `Propagation.MANDATORY` (never `@TransactionalEventListener`, which would
split the atomic step, and never a listener that opens its own transaction). Where the listeners touch
tables linked by foreign keys, the order is explicit (`@Order` with the constants of
`TargetPurge.Phase`, children first) and tested by probes between the phases — the schema's cascades
hide a wrong order otherwise. A bulk `@Modifying` delete that follows Spring Data derived deletes in
the same transaction needs `flushAutomatically = true`: the derived ones queue their removals, the
bulk statement and its cascade run first, and the commit fails on rows already gone. An event type the
listeners of lower domains must see lives where they can see it (`TargetDeleted` is in
`common.domain.targets`, because `targets` uses `access` and `scanning`).

**Spring Modulith is present in observation mode.** `ModularityObservationTest` writes what it sees
to `build/modulith-docs/` and fails on nothing — twenty-four modules since step 4, the nineteen domains
and the five layered packages, with every remaining violation a reach into `core.services` or a cycle
through it (docs/architecture 05). A new module goes into `ArchitectureTest.MODULES`, the test's list
and, if it is foundation, `sharedModules`; a new named interface is a `@NamedInterface` on a
`package-info`, and a reason in it. It does nothing at runtime: no event publication registry (the outbox is the one, decision
0025), no actuator endpoint, its "moments" auto-configuration excluded; `ModulithRuntimeInertTest`
fails if one of its beans appears. Do not add a Modulith starter or turn the test into `verify()`
outside the migration plan's steps.

## What this codebase will not forgive

**An analyzer that fails returns absent, never empty.** `ScanArtifacts` uses `Optional` fields
for exactly this. An empty list means "ran, found nothing", which resolves the backlog; absent
means "did not look". Getting it the wrong way round destroys triage silently — no exception,
no log line, and a dashboard that looks better afterwards.

**Anything entering an issue's fingerprint is a data contract.** A rule id, a finding type, a
path normalization. Change one and every existing issue is resolved and recreated, losing its
triage, across every target.

**Hibernate never writes the schema, and the migrations are not portable by accident.**
`ddl-auto: validate`, and Flyway runs hand-written native SQL. There is no single changelog and no
dialect-abstraction layer: decision 0013 replaced Liquibase precisely because the generated DDL hid
where the engines differ. What there is, since decision 0027, is a table of type placeholders in
`MigrationDialect` — `${ts}` (`datetime(6)` on MySQL, and that precision is the audit chain's),
`${id}` (the whole identity column, `primary key` included, so `id ${id},`), `${bool}`, `${true}`,
`${false}`, `${text}`, `${double}` — spelled once and visible. A migration from V40 on that differs
only by types is written **once** under `db/migration/common`; one whose structure diverges — a
foreign key (MySQL ignores an inline one, SQLite cannot add one later), a column change, date
arithmetic, a data repair — is written **three times** under `db/migration/{postgresql,mysql,sqlite}/`,
and forgetting one is a startup failure on that engine only. Never both, never one or two:
`MigrationLayoutTest` fails the build, and refuses an engine token in `common`. **Never move or edit
V1–V39**, even the identical ones: Flyway checks every applied checksum, and a changed file stops
every existing installation. A placeholder's value is frozen once a common migration used it.

Run `integrationTestAll` whenever you touch it. It covers **two deployable engines, PostgreSQL and
MySQL, plus SQLite as a test fixture** — decision 0014, which replaced the earlier claim of four.
SQLite is not a deployment target; do not add behaviour that only it can satisfy.

**Every `@Modifying` query carries `@Transactional`.** Spring Data does not add it. Without it
the method works whenever a caller happens to have a transaction open and fails when none does,
which is how the omission survives review.

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
can be enforced: repositories are reached by services only, the `api` layer — `core.api` and every
module's `web` — opens no transaction, and only the security web layer (`core.access.web.security`)
writes the audit log.

**No JPA entity crosses a route, in either direction.** Services hand back records whose
components are the entity's property names (`IssueView`, `AuditEntryView`…), so the wire does not
move. Returning the entity made the table the contract — a bookkeeping column was published the day
it was mapped. `SchemaNameCollisionTest` walks every type reachable from a route (generics, record
components, getters) — in `core.api` and every module's `web` — and fails on a JPA mapping;
`EntityViewsTest` fails when an entity gains a property its view does not carry. A rule that finds
its subject by package must read both packagings: four of them read `core.api` alone until step 3,
and each would have gone quiet on the first controller that moved.

**Nothing of `persistence` reaches `api` at all** — not in a response, not for one call.
`ArchitectureTest.apiNeverTouchesPersistence` is firm, with no exception list. A service returns a
`…View` record (`UserView`, `RepositoryView`, `ScanView`…); the principal holds `UserView`,
`SessionView` and `AgentView`; a route that only needed a row to hand it back to a guard passes an
id (`ScanDocumentService.requireVisible`, `TicketLinkService.requireVisibleIssue`). A service that
needs a secret — a password hash, a TOTP secret — reads the row by id itself.

**A credential that is not a session is confined, and the confinement is not the visibility.**
An agent key passes only on `@RequiresAgentKey` routes, an integration key only on
`@AcceptsApiKey(scope)` routes (`CredentialConfinement`). An integration key acts for its account,
narrowed to its target — so a route that accepts a key and names a target resolves a `Visibility`
**even when only administrators reach it**: an administrator sees everything, a key restricted to
repository 1 does not, and the scan triggers once queued scans of any repository for such a key.

**Validate in the service, against the column.** A string reaching a bounded column is bounded
before the write, a date is bounded before year 9999, an element of a request list may be null, and
a foreign id is checked for existence *and* visibility (absent and hidden in the same words). SQLite
enforces no length, so the HTTP suite passes where MySQL and PostgreSQL answer 500. An encrypted
column holds `v2:` + base64 of nonce, text and tag — size it for the ciphertext, not the secret.

**No outbound HTTP inside a transaction.** An enrichment or an AI call holding a row lock for
minutes is a production incident no test sees. `@Async` is inert here — there is no
`@EnableAsync` — so work meant to leave after commit goes through the outbox.

**The client's address comes from `TrustedProxies`**, never `getRemoteAddr()`: behind a load
balancer every audit entry and every throttle would name the balancer.

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
`REQUIRES_NEW` transaction; inside another write transaction it waits on SQLite's file lock until it
times out. Use a `TransactionTemplate` for the writes and record afterwards
(`ScimProvisioningService`, `VexIngestorService`).

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

**MySQL ignores a column-level `REFERENCES`.** Declare a foreign key as a named
`alter table … add constraint fk_… foreign key …` on MySQL and PostgreSQL (see V19, V37).

**What crosses a wire is tested with the real `ObjectMapper`.** Remote agents' results never
serialized — an `Optional` with no jdk8 module — while every unit test passed on objects.

**Delete a comment that has stopped being true.** Several already have: one justified a file
layout the file no longer had. A stale comment is worse than none, because it is believed.

## Testing

JUnit 5, AssertJ, Mockito. `./gradlew build` from `vectispire-java/` runs the unit suites, the
architecture suite and the HTTP suite.

**A test that asserts through a mock proves the mock.** The HTTP suite (`ApiTestBase`) goes
through `MockMvc` against a real SQLite database and the real security filter chain, because
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

**Engine-sensitive changes run `integrationTestAll` before they are pushed.** Migrations,
`core/repositories/`, `core/persistence/`, any `core/<module>/persistence/`, `core/config/`, the
integration sources, and the Gradle catalogue or lockfiles. CI's `engines` job fires on the same paths, but a push that turns it red
has already reached `develop`.

**A route whose shape changes regenerates the contract.** `ClientContractSpecTest` fails with the
command; run it with `-Dvectispire.openapi.write=true`, then `npm run generate:api`, and commit both
files together.

**Never skip silently.** There is no "skip if Docker is missing" guard anywhere, deliberately: a
suite that skips itself reports green without checking anything.

**Never report a green build when it is red.** Run it, read the output, and say what it says.
