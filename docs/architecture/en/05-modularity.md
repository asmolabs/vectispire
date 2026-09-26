# 05 — Modularity as Spring Modulith sees it

> **Verified since 2026-09-26, step 6 of the migration to Spring Modulith**, with the step-2
> observation kept as the baseline. [`ModularityTest`](../../../vectispire-java/vectispire-core/src/test/java/com/asmolabs/vectispire/core/ModularityTest.java)
> builds Modulith's model of the control plane, **fails the build on any violation** —
> `ApplicationModules.verify()` — and writes the module model and the generated diagrams into
> `vectispire-java/vectispire-core/build/modulith-docs/` ([decision 0030](decisions/0030-modulith-verifies-the-module-boundaries.md)).
> Production carries Modulith's annotations and nothing else; `ModulithRuntimeInertTest` fails if more
> of it reaches the jar or one of its beans becomes active. The layers inside a module stay
> [`ArchitectureTest`](../../../vectispire-java/vectispire-core/src/test/java/com/asmolabs/vectispire/core/ArchitectureTest.java)'s.

## What Modulith detects: twenty-four domains and `config`

Modulith takes the packages directly under the application class, `com.asmolabs.vectispire.core`, as
its modules. Step 2 found five, the layers of a code base packaged by layer — `api`, `services`,
`repositories`, `persistence`, `config` — and nothing about the domains, which were one module's
internals.

Steps 3 to 5 moved every domain into a package of its own ([0028](decisions/0028-vertical-modules.md),
[0029](decisions/0029-core-domains-become-modules.md)): `core.<domain>` for the API, `.web` for the
controllers, `.internal` for the implementation, `.persistence` for the entities and repositories.
Modulith now finds **25 modules**, and the layered packages are gone:

| Module | Kind | Other domains it depends on |
|---|---|---|
| `settings`, `outbound`, `crypto`, `audit`, `outbox`, `reporting`, `maintenance` | foundation, **shared** | `crypto` uses `outbound` and `settings`; `outbox` uses `maintenance` |
| `access` | domain | — |
| `siem` | domain | `access` |
| `targets` | domain | `access` |
| `scanning` | domain | `access`, `targets` |
| `inventory` | domain | `access`, `scanning`, `targets` |
| `issues` | domain | `access`, `scanning`, `targets` |
| `ai` | domain | `access`, `issues` |
| `notifications` | domain | `access`, `issues`, `targets` |
| `rules` | domain | `access`, `inventory`, `issues`, `scanning` |
| `threatintel` | domain | `access`, `issues`, `scanning`, `siem`, `targets` |
| `agents` | domain | `access`, `rules`, `scanning`, `targets` |
| `gate` | domain | `access`, `issues`, `rules`, `scanning`, `siem`, `targets` |
| `exports` | domain | `access`, `gate`, `issues`, `scanning`, `targets` |
| `posture` | domain | `access`, `gate`, `inventory`, `issues`, `notifications`, `scanning`, `targets` |
| `tickets` | domain | `access`, `gate`, `issues`, `targets` |
| `compliance` | domain | `access`, `ai`, `exports`, `gate`, `inventory`, `issues`, `posture`, `rules`, `scanning`, `targets` |
| `platform` | the shell | any; used by none |
| `config` | infrastructure | — |

Each row is also what the module's `package-info` declares, in `@ApplicationModule(allowedDependencies
= …)`, with the named interfaces it reads (`access::security`, `issues::queries`, `scanning::queries`)
and the reason for each line; `verify()` fails on a dependency a list lacks, and `ModularityTest` on a
line nothing uses. `access` appears in most rows through the controllers: every route needs its markers
and resolves a `Visibility`. The foundation is declared shared (`@Modulithic(sharedModules = …)` on
`VectispireApplication`) and stays closed: its `internal` and `persistence` packages are hidden like any
other module's. Three named interfaces are published: `access`'s `security` (the route markers, the
principal and the helpers every module's controllers use), and the `queries` of `scanning` and
`issues` — the records their queries select into and other modules read unchanged (`LatestScanRow`,
`PackageImpact`; `IssueFilters`, `IssueRows`, `IssueAggregates`).

`vectispire-common` is outside the application's package and is read as a library: a dependency on
`common.domain` is invisible to Modulith. Since step 5 no event lives there to be seen by lower
modules: `TargetDeleted` and `TargetPurge` are `targets`', and every listener sits above it.

## What `verify()` rejects

| | Before step 3 (step 2) | After step 4 | After step 5 | Step 6 |
|---|---|---|---|---|
| Modules | 5, all layers | 24: 19 domains (6 shared), 5 layers | 25: 24 domains (7 shared), `config` | the same 25 |
| Messages | **1,304** | **554** | **0** | **0 — and the build fails on the first** |
| `api` → non-exposed types of `services` (layered → layered) | 1,304 (208 types) | 278 (50 types) | — | — |
| a module → non-exposed types of `services` (module → layered) | — | 201 | — | — |
| a layered package → non-exposed types of a module | — | 18 | — | — |
| a module → non-exposed types of another module | — | **0** | **0** | **0** |
| cycles | 0 | 57, every one through `services` | **0** | **0** |
| a dependency the module's list does not declare | — | — | — | **0** (lists declared in step 6) |

**`verify()` passes, and is the gate.** Every message step 5 left was the layered packaging's, and the
packaging is gone: the controllers moved with their domains, every read of another module's tables
became a call to the owner's API or a port, and the 57 cycles — one artefact, `services` seen as one
module, over a handful of real two-way dependencies — were broken one by one, each in the direction the
domain gives (0029 has the table). Step 6 made the check blocking and gave it the table: the cycle rule,
`modulesMeetAtTheirApi` and `MAY_USE` left `ArchitectureTest` (0030 lists rule by rule what went and
what stayed).

**Two things a module's list cannot say** stay outside `verify()`. The foundation is shared, and Modulith
allows every shared module to every module, the foundation's own included: `ModularityTest` holds each
foundation module's list to what it uses. And six modules use `access` for their routes only — `siem`,
`rules`, `inventory`, `threatintel`, `gate`, `exports` — which a list, one per module, cannot express:
`ArchitectureTest.accessForRoutesOnly` keeps their services off it.

**The couplings neither Modulith nor ArchUnit can count are strings**: JPQL queries that name another
module's entity. `CrossModuleQueriesTest` reads every repository query, resolves the entities, tables and
classes it names to their module, and fails on one its list does not carry. It finds eleven — the orphan
sweeps of `Issues` and `Scans` (`targets`' tables), the inventory's five joins to the scans that saw each
component, `AiReviewResults.latestForRepository` (the scans), and `Scans.findWithSbomButNoComponents`,
which reads `inventory` from `scanning`, against the modules' direction, and says so. Each is one
statement over two tables, cheaper than two queries and a set difference; the last is the one to move.

## What changed before this observation (step 1)

The step-2 observation was taken after the knots decision 0026 had recorded were untied, so that what
Modulith would later verify started from a graph with no known exception:

- **The two recorded cycles are gone.** `audit` → `siem`: the chain verification publishes an
  `AuditChainBroken` event the SIEM listens to, instead of calling it — a plain synchronous listener,
  because the verification opens no transaction and an after-commit listener would drop the alarm.
  `issues` → `tickets`: `issues` declares a `TicketReferences` port, and `tickets` implements it.
  `ArchitectureTest.KNOWN_CYCLES` is empty.
- **Target deletion is an event.** `TargetDeletionService` used to delete rows in seven domains'
  tables. It now publishes `TargetDeleted` inside the deletion transaction, and each owning domain
  purges its own rows in a synchronous listener that requires that transaction — the purge and the
  deletion commit together or not at all. The order is explicit, children before parents
  (`TargetPurge.Phase`), so the purge does not depend on a cascade SQLite honours only while a pragma
  is issued. Writing the test for it found that a repository with any triage history could not be
  deleted; that is fixed.
- **`ReportCursor` left `shared`** for a `reporting` foundation domain; `ReachabilityAnalyzer`, a
  service nothing called, was deleted.

## What steps 3 and 4 changed

- **Nineteen domains became modules**, the foundation first; 262 classes, with their controllers,
  entities, repositories and tests.
- **`core.api.security` became part of `access`**: `core.access.web.security`, the named interface, and
  `.chain` beneath it for the filters.
- **Nine reads of another module's tables became API calls or ports**, and six dependencies the layered
  packaging hid became lines of `MAY_USE`, each with its reason.

## What step 5 changed

- **`targets`, `scanning` and `issues` are modules**, and each owns its tables: the others ask
  `TargetCatalog`, `ScanCatalog` and `IssueCatalog`, which run the same queries and answer the views the
  routes already return. `agents` owns the agent row and `gate` the stored policies, each read from
  below through a port. Three modules rather than one: the named query interfaces publish five types
  out of 118 classes, and a handful of defined operations cross between the three (0029 counts them).
- **`platform` is dissolved.** The periodic tick is a port — `maintenance.MaintenanceTask`, contributed
  by thirteen tasks from the modules that own the work, including the evidence purges `access` used to
  run for `gate` and `compliance` — and `platform` is the shell that is left: the settings screen, the
  foundation's routes, the exception handler, the SPA forwarding and the OpenAPI configuration.
  `shared` is gone: `TargetNaming` went to `targets`.
- **`core.api`, `core.services`, `core.repositories` and `core.persistence` are empty.** `core.config`
  is the one package outside a module. The contract did not move (`openapi.json` regenerates
  identical), and the application boots with the same 206 handler methods.
- **Every rule reads one packaging**: the layer rule has lost its `repositories` layer, the places are
  a module's four or `config`, and the repositories' write convention became a rule,
  `everyRepositoryWriteIsTransactional` — which found fifteen derived deletes without `@Transactional`.

## What step 6 changed

- **`ModularityObservationTest` became `ModularityTest`**, which calls `verify()` and fails the build;
  it still writes the canvases and the C4 component diagrams.
- **Each module declares what it may use**, on its `package-info`, with the reasons `MAY_USE` carried;
  `platform` alone declares nothing, which to Modulith means "anything". Named interfaces are listed by
  name, so the lists say which modules read `issues::queries`, `scanning::queries` and
  `access::security`.
- **`ArchitectureTest` keeps the inside of a module**: the layers, the four places, what a controller,
  an entity or a repository may touch. Retired, each replaced by `verify()`: the cycle rule with
  `KNOWN_CYCLES`, `modulesMeetAtTheirApi`, `domainsDependOnlyWhereAllowed` with `MAY_USE`.
- **Query strings are checked** (`CrossModuleQueriesTest`), with the list above.
- **Production depends on `spring-modulith-api` alone**: the core starter, its runtime model, its
  moments, its annotation processor, jMolecules and ArchUnit left the jar (122,379,585 bytes to
  117,310,636), and the application boots with the same 208 request mappings.
