# 0029 — The core domains become modules, and the layered packages are gone

**Date:** 2026-09-26 · **Status:** accepted · **Decider:** Laurent Boucher

> Completes [0028](0028-vertical-modules.md), which it does not supersede: the module shape, the shared
> foundation and the rules that hold a module together are 0028's. This record is step 5 of the
> migration to Spring Modulith — `targets`, `scanning` and `issues` become modules, `platform` and
> `shared` are dissolved, and `core.api`, `core.services`, `core.repositories` and `core.persistence` are
> emptied. What Modulith sees before and after is in [05 — Modularity](../05-modularity.md).
>
> Since step 6 ([0030](0030-modulith-verifies-the-module-boundaries.md)), `MAY_USE` and the rules this
> record names between modules — `modulesMeetAtTheirApi`, the cycle rule — are Spring Modulith's: each
> module declares its allowed dependencies on its `package-info`, and `verify()` fails the build.

## Context

After step 4, nineteen domains were modules and five packages were still the layers of the old
packaging. `issues`, `scanning`, `targets`, `platform` and `shared` lived in `core.services`, their
controllers in `core.api`, their tables in `core.persistence` and `core.repositories`. To Modulith,
`services` was one module: 554 messages, 57 cycles, every cycle through it. 0028 listed what step 5 had
to settle: who owns the tables every module read (issues, scans, findings, repositories, containers,
the agent row, the gate policies), how `targets` could stop calling `access` and `scanning` while both
read targets, where the foundation's routes and the periodic tick go, and two types that crossed a
boundary unseen.

The step came with a stop criterion: if the three core domains could only be separated by publishing
essentially all of their persistence as named query interfaces, they are one domain, and should be one
module.

## Decision

### Every table has an owner, and the others ask it

| Owner | Tables | What other modules call |
|---|---|---|
| `targets` | repositories, containers, projects and solutions, git tokens, SSH keys | `TargetCatalog` (views, by id, lists, the two columns other modules decide: certified scope, badge token), `TargetNaming`, `CloneCredentials` (still encrypted), `SolutionAdministrationService` |
| `scanning` | scans, findings, the leader lease, processed messages | `ScanCatalog` (`ScanView`, `ScanFindingView`, grouped counts as maps), `ScanIngestor` and its ports, `PurgedScans`, the dispatcher and the trigger; `LatestScanRow` and `PackageImpact` as the `queries` named interface |
| `issues` | issues, triage events (SLA and exceptions are computed over them) | `IssueCatalog` (counts and lists by criteria, aggregates, one issue as `IssueView`, the two writes others made: a ticket attached, the threat feed's exploitation figures), `PurgedIssues`, the triage and decision services; `IssueFilters`, `IssueRows`, `IssueAggregates` as the `queries` named interface |
| `agents` | the agent row | `AgentDirectory` (a port of `access`: which agent holds this key) and `AgentClaimLock` (a port of `scanning`: the claim's row lock), both implemented in `agents.internal` |
| `gate` | stored policies (with the verdict register it already owned) | `ActiveGatePolicies` — the row-to-policy conversion that lived in `IssueViews`, and the map of active policies by scope `GateService` and the ticket sweep each built |

Each API method runs the query the reader ran on the repository, with the same parameters and the same
order, and answers the `…View` record the routes already return, whose components are the entity's
property names — a reader changed `getStatus()` for `status()` and nothing else. A row array does not
cross: a grouped count is a map, a pair of target columns a `ScanOfTarget`, a finding with its scan a
`FindingOnScan`.

**The criteria cross, the predicate does not.** `IssueFilters` was a specification builder that
modules composed with predicates of their own, naming the issue entity to do so. It is pure criteria
now — visibility included, and the two conditions modules added by hand (`touching`, `onlyCves`) are
criteria too. The one translation into a JPA predicate is `IssueSpecifications`, beside the repository,
in `persistence`, where a change to it runs the engine campaign on push. The criteria record is
published with the rows (`issues.persistence.queries`): it names no JPA type, so publishing it is
publishing the question, not the table.

### Three modules, not one — the stop criterion, measured

What the three modules expose to the rest of the application:

| | classes | at the root | in `persistence.queries` | read by other modules outside the root |
|---|---|---|---|---|
| `targets` | 38 | 18 | 0 | nothing |
| `scanning` | 41 | 17 | 2 (`LatestScanRow`, `PackageImpact`) | `LatestScanRow` |
| `issues` | 39 | 20 | 3 (`IssueFilters`, `IssueRows`, `IssueAggregates`) | all three |

And what crosses between them — types, not messages:

- `scanning` → `targets`, ten types: the views, `TargetCatalog`, `CloneCredentials`, `TargetNaming`,
  `CronExpressions`, the purge event and its phases, and `TargetScans`, the port it implements;
- `issues` → `targets`, seven: the views, `TargetCatalog`, `TargetNaming`, the purge event, `TargetBacklog`,
  the port it implements;
- `issues` → `scanning`, seven: `ScanCatalog`, the two views, `ObservedFinding`, `ScanIngestor` (whose
  `Backlog` port it implements), `PurgedScans`, and `LatestScanRow`;
- nothing from `targets` to either, nothing from `scanning` to `issues`.

Five published query types out of 118 classes, and a handful of defined operations between the three —
the dispatch reads, the backlog's port, the figures and trigger ports, the names, the history and the
sightings, the purge. That is not "essentially everything", so **the three stay separate modules**. The
one kind of coupling left between their tables is the JPQL of the orphan sweeps and the inventory's
component joins, which name another module's entity by name in a query string; no rule sees it, and it
is listed below.

### How the cycles were broken

The 57 cycles Modulith counted were one packaging artefact — `services` as one module — over a handful
of real two-way dependencies between domains. Each was broken in the direction the domain sense gives:
a scan and an issue are *of* a target and must hear its deletion, so `scanning` and `issues` use
`targets`, never the reverse.

| Two-way dependency | Direction kept | How the other half goes |
|---|---|---|
| `targets` ↔ `scanning` (listings read scans, "scan now"; the dispatcher reads targets) | `scanning` → `targets` | `TargetScans`, a port `targets` declares and `scanning` implements (`TargetScanFigures`) |
| `targets` ↔ `issues` (listing figures; issues belong to targets) | `issues` → `targets` | `TargetBacklog`, a port `targets` declares and `issues` implements (`TargetBacklogFigures`) |
| `targets` ↔ `access` (grants written by solutions; visibility reads projects) | `targets` → `access` | `access` declares `GrantableTargets`, implemented by `targets.internal.TargetsForAccess`; grants are revoked through `TargetGrants`, `access`'s API |
| `shared.TargetNaming` read by `access` and `scanning`, used by `targets` | into `targets` | once `targets` used only `access`, the names went home; `shared` is gone |
| `TargetDeleted`/`TargetPurge` in `common.domain` so that lower modules could listen | into `targets` | every listener sits above `targets` now; the one owner below, `access`, revokes grants by a call just before the first phase, in the same transaction |
| `scanning` ↔ `issues` (ingestion wrote issues; the backlog read scans) | `issues` → `scanning` | `ScanIngestor.Backlog`, implemented by `issues.internal.IssueBacklog`; what crosses is `ObservedFinding`, the finding's whole values, never a row |
| `scanning` ↔ `inventory` | `inventory` → `scanning` | `ScanIngestor.InventorySink`, implemented by `inventory` |
| `scanning` ↔ `notifications`, `threatintel` (ports carried rows) | they use `issues`/`scanning`, not the reverse | `ScanDelta.Sink`, a port of `issues`; the enricher answers scores for identifiers |
| `scanning` → `rules` → `inventory` → `scanning` (latent) | `rules` → `scanning` | `ScanRuleSets`, declared by `scanning`, implemented by `rules.internal.RuleSetsForScans` |
| `access`, `scanning` ↔ `agents` (the agent row) | `agents` → both | `AgentDirectory` and `AgentClaimLock` |
| `issues`, `tickets` read gate's policies below `gate` | `tickets` → `gate`; `issues` no longer reads them | `ActiveGatePolicies` |
| `platform` used everything and `access` purged gate's and compliance's evidence | nothing uses `platform` | the `maintenance` port (below); each owner purges its own evidence |

The target purge stays synchronous and ordered: one transaction, `TargetPurge.Phase` children first,
probes between the phases (`TargetDeletionTest`). The findings phase has two listeners on one table:
`scanning` takes a target's findings by scan, `issues` by issue through `PurgedScans`.

### The findings of 0028

| Finding | Resolution |
|---|---|
| `AuditLogController`, `CryptoController` in `core.api` | `platform.web` — `platform` sits above `access` |
| `SbomDiffController` in `core.api` | `inventory.web`, now that `inventory` may use `scanning` |
| `OutboxService.enqueue` returned the message entity | returns the message's `UUID` |
| `RuleSetSummary`, a projection on the wire | a record at `rules`' root, same components and names; the projection is `RuleSetRow`; `SchemaNameCollisionTest` refuses anything of a `persistence` package on a route |
| The settings screen read `access`'s `Users` | `TriageApprovers.anyActive` |
| Solution administration wrote `access`'s grants | `TargetGrants.revokeAll`, `MANDATORY` |
| The scan metrics counted through `outbox`'s repository | `OutboxService.counts()`; the agents' gauges moved to `agents` |
| The dispatcher took `rules`' entity | the `ScanRuleSets` port |
| `ApiExceptionHandler` mapped an exception nested in the filter chain | `RequestBodyTooLargeException`, top-level in the `security` named interface |
| The agent row, the stored gate policies | owned by `agents` and `gate` (above) |
| Where the evidence cleanup belongs | each owner's own periodic task: `VerdictRetentionTask`, `SnapshotRetentionTask`, same dial (`evidence_retention_days`), same position in the turn, a failure still skipping only its own table |

### `platform` dissolved: a port for the tick, a shell for the rest

**The periodic tick is a port.** `MaintenanceJobs` named ten services of eight domains, and was the
reason `platform` had to be allowed to use anything. `maintenance`, a new foundation module, declares
`MaintenanceTask` (a cadence and a `run`); each domain with a periodic job contributes one from its
`internal` package — thirteen, from scan retention to the orphaned target rows. The tick runs a
cadence's tasks in their `@Order` (`MaintenanceTask.Sequence`), which keeps the old sequence and says
why two positions matter; a task that throws still ends its turn, as it did when the turn was one
method. `MaintenanceJobsTest` runs the tick over the tasks built on mocks and asserts each call in
order; `MaintenanceCompositionTest` asserts that the running application contributes exactly those
tasks — the level at which a missing caller is visible (the `expireStale` defect). `outbox` →
`maintenance` is the one new foundation edge. `RetentionService` went to `scanning`, whose table it
purges.

**`platform` is the shell.** What is left composes several domains for one screen or serves the whole
API: the settings screen (the credentials and checks of `ai`, `tickets`, `notifications` and
`access`), the audit-log and crypto routes the foundation may not keep, the exception handler, the SPA
forwarding and the OpenAPI configuration. It is a module above everything — it may use any domain, and
nothing may use it, which `ArchitectureTest` enforces.

### What stays outside a module

**`core.config`**, and nothing else: the Jackson mapper, the clock, the task schedulers, the SQLite
pragmas, Flyway's type placeholders, the mail sender, and the policies the pure rules of
`common.domain` are bound to. It serves every module and decides nothing any domain owns; Modulith sees
it as a module with no dependency. The test sources keep `core.api` (the HTTP suite, which exercises
routes of every module), `core.persistence` (the migration and foreign-key tests) and `core.services`
(two cross-module read-back tests) as test packages; no rule reads test classes.

### The rules, rewritten for one packaging

`ArchitectureTest` no longer reads two packagings. The places are a module's four or `core.config`
(`everyClassHasAPlace`), so a class dropped back into `core.services` fails; `everyServiceLivesInAKnownDomain`
went with the package it guarded. The layer rule has five layers with no `repositories`. And the write
convention `core.repositories`' package-info carried — every write, derived deletes included, carries
`@Transactional` — became a rule when its package went, `everyRepositoryWriteIsTransactional`. It found
fifteen derived deletes in five modules without the annotation, each working only because every caller
happened to have a transaction open; they carry it now.

## Consequences

- **Modulith reports no violation**: 25 modules (24 domains, 7 of them shared, and `config`), 0
  messages instead of 554, 0 cycles instead of 57. `verify()` would pass today; step 6 turns
  `ModularityObservationTest` into it.
- The HTTP contract did not move (`openapi.json` regenerates identical) and the application boots with
  the same 206 handler methods.
- New code goes into its domain's module; a new periodic job is a `MaintenanceTask` in the owner's
  `internal`, placed in `Sequence` and in `MaintenanceJobsTest.COMPOSITION`.
- CI's `engines` path filter reads `core/<module>/persistence/`; `core/repositories/` is gone from it.
- **Left, and not seen by any rule**: JPQL strings that name another module's entity (the orphan sweeps,
  the inventory's joins to scans, `AiReviewResults`, `Scans.findWithSbomButNoComponents`) — one
  statement across two tables, cheaper than two queries and a set difference, but a coupling Modulith
  cannot count. `ProcessedMessageEntity` is mapped and never read.
