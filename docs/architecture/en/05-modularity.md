# 05 — Modularity as Spring Modulith sees it

> **Observed on 2026-09-26, at step 2 of the migration to Spring Modulith.** Modulith is in the
> build to be asked questions, not to enforce answers: `ModularityObservationTest` builds its model
> of the control plane, writes the report and the generated diagrams into
> `vectispire-java/vectispire-core/build/modulith-docs/`, and fails on nothing it finds. At runtime
> it does nothing — `ModulithRuntimeInertTest` fails if one of its beans becomes active. The rules
> that *are* enforced are still [`ArchitectureTest`](../../../vectispire-java/vectispire-core/src/test/java/com/asmolabs/vectispire/core/ArchitectureTest.java)'s,
> as [decision 0026](decisions/0026-services-are-grouped-by-domain.md) describes them.

## What Modulith detects: the layers, not the domains

Modulith takes the packages directly under the application class, `com.asmolabs.vectispire.core`,
as its modules. The control plane is packaged by layer, so it finds five:

| Module | Base package | Depends on |
|---|---|---|
| `api` | `core.api` | `services` |
| `services` | `core.services` | `persistence`, `repositories` |
| `repositories` | `core.repositories` | `persistence` |
| `persistence` | `core.persistence` | — |
| `config` | `core.config` | — |

**This is the expected finding, and the reason for steps 3 to 5.** The twenty-four domains of
decision 0026 — `issues`, `scanning`, `access`, `targets`… — are sub-packages of `services`, so to
Modulith they are the internals of one module. The graph above is the layer rule, which
`ArchitectureTest` already checks; it carries no information about the domains.

`vectispire-common` is outside the application's package and is read as a library: a dependency on
`common.domain` is invisible to Modulith, which is worth remembering for the shared types that live
there — `ScanTarget`, and since step 1 the `TargetDeleted` event.

## What `verify()` would reject

**1,304 messages, of a single kind: `api` depends on non-exposed types of `services`**, 208
distinct types. A module exposes the types of its base package; every service lives in a domain
sub-package, which Modulith treats as internal. Each controller's use of its service is therefore a
violation — a constructor parameter, a field and every call counted apart, which is why the number
measures lines of code more than it measures problems. There is no cycle between the five modules,
and nothing reported between `services`, `repositories` and `persistence`: those are flat packages,
whose every type is exposed.

None of it is a defect of the code. It is what verification says of a layered packaging, and it is
why the test observes instead of verifying.

## What changed before this observation (step 1)

The observation was taken after the knots decision 0026 had recorded were untied, so that what
Modulith would later verify starts from a graph with no known exception:

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

## What step 3 changes

Step 3 starts packaging by feature: a domain becomes a top-level package owning its controllers,
services, repositories and entities (`issues/api`, `issues/services`, `issues/persistence`…), so
that Modulith's modules are the domains. The report is then expected to move from five layer
modules and one kind of violation to one module per domain and violations that mean something — a
domain reaching into another's internals — which is what step 6 turns into a failing `verify()`.
Three things are known to need a decision on the way:

- **Where the cross-domain types live.** `TargetDeleted` sits in `common.domain` because `targets`
  depends on `access` and `scanning`, which listen to it. Once `targets` stops calling them (a
  visibility port, a scan-request event), the event can move into the `targets` module's API.
- **`TargetNaming`**, for the same reason: it belongs to `targets` once `targets` is below the
  domains that read names.
- **The `platform` composition roots** — the maintenance tick, retention, the settings screen — which
  dissolve into the modules they call.

The regenerated report is the measure of each step: the counts above are the baseline.
