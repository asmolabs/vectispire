# 05 — Modularity as Spring Modulith sees it

> **Observed on 2026-09-26, after steps 3 and 4 of the migration to Spring Modulith**, with the step-2
> observation kept as the baseline. Modulith is in the build to be asked questions, not to enforce
> answers: `ModularityObservationTest` builds its model of the control plane, writes the report and the
> generated diagrams into `vectispire-java/vectispire-core/build/modulith-docs/`, and fails on nothing it
> finds. At runtime it does nothing — `ModulithRuntimeInertTest` fails if one of its beans becomes
> active. The rules that *are* enforced are still [`ArchitectureTest`](../../../vectispire-java/vectispire-core/src/test/java/com/asmolabs/vectispire/core/ArchitectureTest.java)'s,
> as decisions [0026](decisions/0026-services-are-grouped-by-domain.md) and
> [0028](decisions/0028-vertical-modules.md) describe them.

## What Modulith detects: nineteen domains, and five layers left

Modulith takes the packages directly under the application class, `com.asmolabs.vectispire.core`, as
its modules. Step 2 found five, the layers of a code base packaged by layer — `api`, `services`,
`repositories`, `persistence`, `config` — and nothing about the domains, which were one module's
internals.

Steps 3 and 4 moved nineteen domains into packages of their own
([0028](decisions/0028-vertical-modules.md)): `core.<domain>` for the API, `.web` for the controllers,
`.internal` for the implementation, `.persistence` for the entities and repositories. Modulith now
finds **24 modules**:

| Module | Kind | Other domains it depends on | Layered packages it uses |
|---|---|---|---|
| `settings`, `outbound`, `crypto`, `audit`, `outbox`, `reporting` | foundation, **shared** | — (`crypto` uses `outbound` and `settings`) | — |
| `siem` | domain | `access` | — |
| `rules` | domain | `access`, `inventory` | `repositories` |
| `ai` | domain | `access` | `persistence`, `repositories` |
| `threatintel` | domain | `access`, `siem` | all three |
| `tickets` | domain | `access` | all three |
| `agents` | domain | `access`, `rules` | all three |
| `notifications` | domain | `access` | all three |
| `exports` | domain | `access`, `gate` | all three |
| `gate` | domain | `access`, `rules`, `siem` | all three |
| `inventory` | domain | `access` | all three |
| `posture` | domain | `access`, `gate`, `inventory`, `notifications` | all three |
| `compliance` | domain | `access`, `ai`, `exports`, `gate`, `inventory`, `posture`, `rules` | all three |
| `access` | domain | — | all three |
| `api`, `services`, `repositories`, `persistence`, `config` | layered packaging | — | step 5 empties them |

"All three" is `services`, `repositories` and `persistence`: the layered packages where
`issues`, `scanning`, `targets`, `platform` and `shared` still live. The foundation is declared shared
(`@Modulithic(sharedModules = …)` on `VectispireApplication`) and stays closed: its `internal` and
`persistence` packages are hidden like any other module's. `access` publishes one named interface,
`security` — the route markers, the principal and the helpers every module's controllers use.

`vectispire-common` is outside the application's package and is read as a library: a dependency on
`common.domain` is invisible to Modulith, which is worth remembering for the shared types that live
there — `ScanTarget`, and since step 1 the `TargetDeleted` event.

## What `verify()` would reject

| | Before step 3 (step 2) | After step 4 |
|---|---|---|
| Modules | 5, all layers | 24: 19 domains (6 shared), 5 layers |
| Messages | **1,304** | **554** |
| `api` → non-exposed types of `services` (layered → layered) | 1,304 (208 types) | 278 (50 types) |
| a module → non-exposed types of `services` (module → layered) | — | 201 |
| a layered package → non-exposed types of a module | — | 18 |
| a module → non-exposed types of another module | — | **0** |
| cycles | 0 | 57, **every one through `services`** |

As before, one message is counted per offending dependency — a constructor parameter, a field, each
call — so the numbers measure lines of code more than problems. What each remaining kind means:

- **`api` → `services`, 278.** The controllers of `issues`, `targets`, `scanning` and `platform` still in
  `core.api`, calling services in sub-packages of `core.services`. They move with their domains in step
  5.
- **Module → `services`, 201.** A module calling `issues`, `scanning` or `targets` services, or
  `shared.TargetNaming`: `posture` and `compliance` read `SlaService`, `exports` imports VEX through
  `issues`, `notifications` and `threatintel` implement `scanning`'s ports. Each is listed as a step-5
  finding in 0028.
- **Layered → module, 18.** `core.services` reaching a module's internals — the settings screen reads
  `access`'s `Users`, solution administration writes `access`'s grants, the scan platform's metrics
  count through `outbox`'s repository, the dispatcher takes `rules`' entity — and `ApiExceptionHandler`
  mapping an exception nested in `access`'s filter chain.
- **Cycles, 57.** `services` is one module to Modulith, so a module that uses `issues` and is used by
  `platform` — `posture`, `compliance`, `access`… — closes a cycle through it. None runs between two
  domains without passing through `services`, which `ArchitectureTest`'s own cycle rule — sliced by
  domain, `core.services.issues` and `core.access` alike — confirms: it has no cycle to report.

**The count that matters is the zero.** No module reaches into another module's `internal`,
`persistence` or `web` package: where one did — nine readers of another domain's repository — the read
became a call to the owner's API or a port, and `ArchitectureTest.modulesMeetAtTheirApi` holds it
there. What is left is the layered packaging's, and is step 5's to remove.

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
  service nothing called, was deleted. `TargetNaming` stays in `shared`: nine other domains read names
  through it, among them `access` and `scanning`, which `targets` itself uses, so moving it into
  `targets` would close two cycles.

## What steps 3 and 4 changed

- **Nineteen domains are modules**, the foundation first; 262 classes, four of them new, with their controllers,
  entities, repositories and tests. The HTTP contract did not change (`openapi.json` regenerates
  identical), and the application boots with the same 206 handler methods mapped.
- **`core.api.security` became part of `access`**: `core.access.web.security`, the named interface, and
  `.chain` beneath it for the filters.
- **Nine reads of another module's tables became API calls or ports** — the table is in 0028 — and six
  dependencies the layered packaging hid are now lines of `MAY_USE`, each with its reason.
- **Every rule that found its subject by package reads both packagings**: the layer rule, the domain
  rules, the route lints, the schema walk, the coverage gate and CI's `engines` path filter.

## What step 5 changes

`issues`, `scanning` and `targets` become modules; `platform` dissolves into the modules it composes
(each module's periodic job, retention rule and settings contribution) and `shared` into `targets`.
Then Modulith's `services`, `api`, `repositories` and `persistence` modules are empty, every cycle it
reports today disappears with them, and the report is the list of domains reaching into each other —
which step 6 turns into a failing `verify()`. Decision 0028 lists what has to be decided on the way:
who owns the agent row and the stored gate policies, where the foundation's routes and the SBOM
comparison go, and the two types that cross a boundary without any rule seeing them.
