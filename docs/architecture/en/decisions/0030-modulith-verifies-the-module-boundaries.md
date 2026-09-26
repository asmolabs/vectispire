# 0030 — Spring Modulith verifies the module boundaries, and ArchUnit keeps the layers

**Date:** 2026-09-26 · **Status:** accepted · **Supersedes:** [0026](0026-services-are-grouped-by-domain.md) · **Decider:** Laurent Boucher

> Step 6 of the migration to Spring Modulith. The module shape and the foundation are
> [0028](0028-vertical-modules.md)'s, the owners and the ports [0029](0029-core-domains-become-modules.md)'s;
> neither is replaced. What this record replaces is 0026's answer to "who checks the boundaries":
> 0026 rejected Modulith *for now* and made an ArchUnit table the reference. What Modulith sees is
> in [05 — Modularity](../05-modularity.md).

## Context

After step 5, Spring Modulith saw twenty-five modules — twenty-four domains, seven of them shared,
and `config` — and `verify()` would have reported nothing. The boundary between modules was checked
twice: by Modulith in observation, which failed on nothing, and by four ArchUnit rules that did fail
the build — a cycle rule sliced by module with its `KNOWN_CYCLES`, `modulesMeetAtTheirApi` (another
module's root or a named interface, nothing else), and `domainsDependOnlyWhereAllowed` reading the
`MAY_USE` table of 0026, 0028 and 0029.

Two authorities for one boundary is the situation `ddl-auto: validate` exists to avoid in the
schema: they agree today, and the day they disagree the one that runs second wins silently. 0026 had
rejected Modulith for three reasons. The first — the code was packaged by layer, so Modulith would
see layers — is gone: step 5 emptied the layered packages, and 0026 named exactly that as the
condition to reconsider. The second — its event registry would duplicate the outbox — still holds,
and is not what is taken here. The third — verification was already covered — is the duplication
this record ends.

## Decision

**`ModularityTest` calls `ApplicationModules.verify()` and fails the build on any violation.** It
replaces `ModularityObservationTest`, and still writes the module canvases and the C4 component
diagrams into `build/modulith-docs/`.

### Each module declares what it may use

The table moves next to what it constrains: every module but `platform` carries
`@ApplicationModule(allowedDependencies = …)` on its `package-info`, and the reason for each line —
the ones `MAY_USE` carried in comments — is written in that `package-info`'s javadoc. Three
properties of Modulith's reading decide how the lists are written:

- **A missing list means "anything"**, not "nothing": the default is open. `ModularityTest` fails
  on a module whose `package-info` declares none, `platform` excepted — the shell may use any module
  (0029), and says so by declaring nothing. Nothing may use `platform`, which needs no rule of its
  own: every other list is closed, and none names it.
- **A named interface is listed by name.** `"scanning"` allows the module's root, and only it;
  `"scanning::queries"` allows the published query records. So the lists say which modules read
  `issues::queries`, `scanning::queries` and `access::security`, which the table never did.
- **Shared modules are allowed to every module without being listed**, the foundation's own
  included. A domain does not list the foundation. A foundation module lists the foundation modules
  it uses (`crypto` → `outbound`, `settings`; `outbox` → `maintenance`), and since `verify()` would let
  `settings` use `audit`, `ModularityTest.eachModuleDeclaresExactlyWhatItUses` holds each list to
  the code in both directions: a use the list lacks, and a line no use needs. The second half is
  also what keeps the lists "the code as it stands", as 0026 said of its table: a line left behind
  is a dependency the next change takes without a review noticing.

**One line of the table could not become a list.** `MAY_USE` let any module's `web` use `access` —
every route needs the principal and its marker, and a route naming a target resolves a
`Visibility` — while six modules' services never did: `siem`, `rules`, `inventory`, `threatintel`,
`gate`, `exports`. A list is one per module. Those whose routes call `VisibilityService` list
`access`, and `ArchitectureTest.accessForRoutesOnly` keeps their root, `internal` and `persistence`
off it. `access::security` needs no such rule: the layer rule already keeps every service layer off
every `web` package.

### What ArchUnit keeps, and what it gave up

| Rule | Now | Replaced by |
|---|---|---|
| `domainsFormNoCycle`, `knownCyclesAreStillThere`, `KNOWN_CYCLES` | **retired** | `verify()`'s cycle detection, over every module and `config` |
| `modulesMeetAtTheirApi` | **retired** | `verify()`'s non-exposed type check: root package or `@NamedInterface`, nothing else |
| `domainsDependOnlyWhereAllowed`, `MAY_USE`, `FOUNDATION`, `EVERY_ROUTE_USES` | **moved** to each `package-info` | `verify()`'s allowed dependencies; `eachModuleDeclaresExactlyWhatItUses` for the foundation's edges and stale lines; `accessForRoutesOnly` for the routes-only clause |
| `layersOnlyReachDownwards` | kept | Modulith reads a module whole; the layers inside one are not its subject |
| `everyClassHasAPlace` | kept | a module's four places or `config`; Modulith accepts any sub-package |
| `controllersCallTheirModuleApi` | kept | inside one module |
| `entitiesReachNoRepository`, `persistenceHasNoWebOrService` | kept | inside one module |
| `apiNeverTouchesPersistence` | kept | covers a module's own `persistence` and the published `queries`, which `verify()` allows |
| `apiOpensNoTransaction`, `controllersWriteNoAuditEntry` | kept | layer rules |
| `domainIsPure`, `onlyRepositoriesReachTheDatabase` | kept | libraries, not modules |
| `onlyTheOutboundDoorSpeaksHttpOutwards`, `onlySyslogSenderOpensSockets` | kept | one class allowed a library |
| `everyRepositoryWriteIsTransactional`, `caseIsFoldedWithoutTheHostLocale` | kept | conventions on methods |
| `findsSomethingToCheck`, `MODULES`, `OUTSIDE_MODULES = {config}` | kept | the kept rules read them; `ModularityTest.detectsModules` holds the same list against Modulith's model. A module's root must hold a class besides its `package-info`, which every root now has |
| — | **new**: `accessForRoutesOnly` | the one line of the table a module's list cannot express |

Every kept or moved rule was mutation-checked against a violation built for it, and each retired
rule's violation — a reach into another module's `persistence` or `internal`, a cycle, a module a list
lacks, a named interface a list lacks, `platform` or `config` used by a module — fails `verify()`.

### The coupling neither sees: query strings

Modulith and ArchUnit read the classes the compiler produced; a JPQL query naming another module's
entity is a string. `CrossModuleQueriesTest` reads every `@Query` and `@NativeQuery` of every
repository, resolves entity names, table names and fully qualified class names to the module that
owns them, and fails on a reference to another module its `KNOWN` list does not carry, and on an entry
no query makes any more. It found exactly what 0029 listed:

| Query | Names | Why one statement |
|---|---|---|
| `Issues.findOrphanedIds`, `Scans.findOrphanedIds` | `targets`' `RepositoryEntity`, `ContainerEntity` | the orphan sweep: rows whose target is gone are an absence in another table |
| `Components.search`, `versionsOf`, `distinctRepositoriesWithComponents`, `distinctContainersWithComponents`, `distinctPurlsByTarget` | `scanning`'s `ScanEntity` | a component carries its scan's id; its target is the scan's |
| `AiReviewResults.latestForRepository` | `scanning`'s `ScanEntity` | a review carries its scan's id, not its repository's |
| `Scans.findWithSbomButNoComponents` | `inventory`'s `ComponentEntity` | **against the direction**: `scanning` may not use `inventory` |

An entry pointing to a module its origin's list does not name must say so, and the last one does:
the inventory's backfill selects scans by the absence of component rows from inside `scanning`. It is
the one to move — into `inventory`, over its own table, asking `ScanCatalog` for the scans that hold
an SBOM.

### Dependencies

Production code uses Modulith's annotations and nothing else — `@Modulithic`, `@ApplicationModule`,
`@NamedInterface` — so the main classpath takes `spring-modulith-api`, and the test classpath
`spring-modulith-starter-test` (the verification, the documenter and ArchUnit). The core starter, its
runtime model, its "moments", its annotation processor, jMolecules and ArchUnit leave the production
jar — 122,379,585 bytes to 117,310,636 — and so does the `application-modules.json` the processor
generated for a runtime that is not there; the auto-configuration exclusions that kept the moments
off go with them. Nothing is added, so no licence changes (`spring-modulith-api` is Apache-2.0, like
the starter it replaces). The application boots on SQLite with the same 208 request mappings (206 handler methods and Boot's two error routes) and the
same startup log, timestamps and the order of the mappings aside. `ModulithRuntimeInertTest` still boots the context — on the
test classpath, which carries Modulith's core — and now also reads the lockfile's
`productionRuntimeClasspath`, which is what the jar is built from.

Still not taken: the event publication registry (the outbox is the one, 0025), the actuator
endpoint, `@ApplicationModuleTest`.

## Consequences

- A cycle can no longer be recorded and kept: `verify()` has no `KNOWN_CYCLES`. The list had been
  empty since step 1; a cycle found in review is broken in that review, by a port or an event.
- A new module is a package under `core`, a `package-info` with its list, and a line in
  `ArchitectureTest.MODULES` and `ModularityTest.MODULES` (and `sharedModules` if it is foundation).
- A new dependency between modules is a line in the origin's `package-info`, with its reason, in the
  review that needs it — the same discipline as a line of `MAY_USE`, next to the code it constrains.
  It can still be added by the commit that needs it; what changed is that it is one place to read.
- **Nothing may name `config`** any more: the table ignored it as a target, a closed list does not.
  No module did.
- `ArchitectureTest` is about the inside of a module. A rule that finds its subject by package still
  has to read where the subject lives, and still goes quiet when it does not; `findsSomethingToCheck`
  and `ModularityTest.detectsModules` are what notice.
