# 0028 — The domains become vertical modules, and the foundation is shared

**Date:** 2026-09-26 · **Status:** accepted (completed by [0029](0029-core-domains-become-modules.md)) · **Decider:** Laurent Boucher

> Builds on [0026](0026-services-are-grouped-by-domain.md), which it does not supersede: the domains,
> the foundation and the table of who may use whom are 0026's. This record is steps 3 and 4 of the
> migration to Spring Modulith — what a domain looks like once it owns its packages, what moved, what
> could not yet, and what step 5 has to settle. What Modulith sees before and after is in
> [05 — Modularity](../05-modularity.md).
>
> Since step 6 ([0030](0030-modulith-verifies-the-module-boundaries.md)), `MAY_USE` and the rules this
> record names between modules — `modulesMeetAtTheirApi`, the cycle rule — are Spring Modulith's: each
> module declares its allowed dependencies on its `package-info`, and `verify()` fails the build.

## Context

After decision 0026 the service layer was split by domain, but the code was still packaged by layer:
`core.api`, `core.services.<domain>`, `core.repositories`, `core.persistence`. Spring Modulith, added in
observation mode, took the packages under the application class for its modules and saw five layers —
`api`, `services`, `repositories`, `persistence`, `config` — and 1,304 violations of one kind, every
controller reaching a service in a sub-package of `services`. None of it was about the domains, because
to Modulith the domains were one module's internals.

Worse than invisible to Modulith, the layered packaging hid from `ArchitectureTest` the dependencies
that mattered: `MAY_USE` constrained services calling services, and nothing else. A service reading
another domain's repository, or a controller calling another domain's service, belonged to no domain
and was checked by nothing. Moving each domain into a package of its own is what makes those edges
visible, and is what 0026 said would make Modulith worth asking.

## Decision

**A domain becomes a module: `com.asmolabs.vectispire.core.<domain>`, with a fixed shape.**

```
core.<domain>               its API — the services other modules and its controllers call, their
                            views, its events and the ports it declares
core.<domain>.web           its controllers (and the records only they use)
core.<domain>.internal      what the API is built from: helpers, port implementations, configuration
core.<domain>.persistence   its entities, its repositories, and the projections their queries select into
```

Where a class goes is decided by who calls it, not by what it is called: anything another module or
the module's own controllers call is at the root; a public class only the module's services use is in
`internal`; a package-private class stays at the root beside the classes that use it — Java already
hides it, and moving it would mean widening it. Class names do not change: an OpenAPI schema is named
after its record, and the contract (`vectispire-angular/openapi.json`) did not move by a byte.

**The layers hold inside every module**, and `ArchitectureTest` defines each layer over both
packagings: `web` is the `api` layer, the root and `internal` are the `services` layer, `persistence`
holds the entities and repositories — one layer, with `entitiesReachNoRepository` keeping the order
`core.persistence` → `core.repositories` gave for free. A controller calls its module's API, never its
`internal` (`controllersCallTheirModuleApi`) and never any `persistence` package
(`apiNeverTouchesPersistence`, extended to every module's `web`). The places are closed: a class in
`core.audit.helpers` or in a new top-level package fails `everyClassHasAPlace`, so no class escapes the
layer rule by sitting where it names nothing.

**A module reaches another only through that module's root or a named interface**
(`modulesMeetAtTheirApi`, read from the `@NamedInterface` annotations themselves so it cannot disagree
with step 6's `verify()`). `MAY_USE` now reads a module whole — controllers and entities included — and
the domain slices for the cycle rule are assigned by domain, modules and `core.services` alike.

### Shared, not open

The foundation — `settings`, `outbound`, `crypto`, `audit`, `outbox`, `reporting` — is declared on
`VectispireApplication` with `@Modulithic(sharedModules = …)`. A shared module is what the foundation
already was in 0026: an allowed dependency of every module, always bootstrapped with a module under
test. It stays **closed**. An open module (`@ApplicationModule(type = OPEN)`) exposes all its types and
leaves the cycle check: declared open, the audit log would have published its repository to every
domain, which is precisely the coupling this move takes away — two readers of `t_audit_log` had to be
given API methods because of it.

### The one named interface: `access`'s security web layer

`core.api.security` — the route markers, the principal, the filter chain — moved into `access`, not
into a module of its own. Everything in it answers "who is calling, and what may they see": the
principal holds `access`'s views and the filters call its services. A separate security module would
have depended on `access` while `access`'s controllers depended on it — a cycle. It is split in two:

- `core.access.web.security`, published as `@NamedInterface("security")`: the markers, the principal,
  `TrustedProxies`, `Visibilities`, `RequestActors` and the exceptions the error handler maps. Every
  module's controllers need them, and they are web vocabulary — at a module's root, its service layer,
  the principal would become a parameter a service could take and an audit actor something a service
  could read off a request.
- `core.access.web.security.chain`: the filters, the interceptors, `SecurityConfiguration`,
  `OidcConfiguration`. No other module has a reason to name a filter.

`MAY_USE` lets any module's `web` use `access`: every route needs the principal and its marker, and
every route naming a target resolves a `Visibility`. It cannot close a cycle, since `access` uses
nothing above the foundation — except through a controller of a foundation module, which is why
`AuditLogController` and `CryptoController` went back to `core.api` (below).

### What owning its tables made each module change

A module takes the entities and repositories only it owns. When another module read them, the read
became a call to the owner's API — the same query, delegated, with the transaction it had before:

| Owner | Reader | Was | Now |
|---|---|---|---|
| `settings` | `crypto` (`SigningKeyService`) | `Settings` repository | `SettingsService.internalValue`, `storeInternal` |
| `audit` | `posture` (weekly digest) | `AuditLog.countBy…` | `AuditLogQueryService.countSince` |
| `audit` | `compliance` (evidence bundle) | `AuditLog.findAll…` | `AuditLogQueryService.asJsonLines` (same rows, caller's mapper) |
| `gate` | `exports` (attestation) | `GateVerdicts.findFirst…` ×4 | `GateRegisterService.lastForRepository`, `lastForContainer` |
| `gate` | `compliance` (section 09) | `GateVerdicts.findAll…` | `GateRegisterService.newest` |
| `gate`, `compliance` | `access` (cleanup pass) | `GateVerdicts`, `ComplianceSnapshots` `.deleteBefore` | port `SessionCleanupService.EvidencePurge`, implemented by both |
| `inventory` | `rules`, `compliance` | `Components` | `InventoryQueryService.distinctPurls…`, `distinct…WithComponents` |
| `access` | `agents` | `ApiKeysRepository` | `AgentKeys.issue`, `revoke` |
| `access` | `notifications` | `TeamTargets`, `TeamWebhooks` | `TeamChannels` |

Six edges surfaced that the layered packaging had hidden; each is in `MAY_USE` with its reason:
`crypto` → `settings` (the stored signing key), `rules` → `inventory` (coverage against the components
inventory), `agents` → `rules` (the agent fetches a rule set by hash, through its controller),
`exports` → `scanning` (a document route refuses an invisible scan first), `gate` → `access` (the
evidence-purge port), `notifications` → `access` (team routing). None closes a cycle.

### What moved

Step 3, the foundation: `settings`, `outbound`, `crypto`, `audit`, `outbox`, `reporting` (`shared`
could not dissolve — below). Step 4, in an order where no module reached a module still to come except
through the layered packages: `siem`, `rules`, `ai`, `threatintel`, `tickets`, `agents`,
`notifications`, `exports`, `gate`, `inventory`, `posture`, `compliance`, `access` — `gate` and
`inventory` before `posture` and `compliance`, which use them. 262 classes, four of them new (the
API methods' `AgentKeys` and `TeamChannels`, the port's `VerdictRetention` and `SnapshotRetention`): 108
at module roots, 73 in `web`, 26 in `internal`, 55 in `persistence`.

## The intermediate state

`issues`, `scanning`, `targets`, `platform` and `shared` are still packaged by layer, and so is what
they own. That is expected, and it has a price the Modulith report shows: to Modulith they are the
internals of one module, `services`, so every module calling one of them "depends on non-exposed types
of services", and every module they call closes a cycle through `services`. A module may depend on
the layered packages; each such dependency is step 5's to resolve.

Some things stayed layered for a reason of their own, and are findings too:

- **The agent row** (`AgentEntity`, `Agents`): `access` reads it to authenticate an agent key and
  holds `AgentView` for the principal, while `agents` administers it. Owned by `agents`, `access` would
  reach into it; a port in `access`, implemented by `agents`, would let it move.
- **Stored gate policies** (`GatePolicyEntity`, `GatePolicies`): read below `gate` — by `issues`
  (`IssueViews.storedPolicy`) and `tickets` (the sweep). Whether the policy store is `issues`' or `gate`
  publishes a lower port is to decide.
- **The foundation's routes** — `AuditLogController`, `CryptoController`: they need `access`'s markers,
  and `access` uses `audit` and `crypto`; inside those modules they close a cycle. They wait in
  `core.api` for a module above `access` to own them.
- **`SbomDiffController`**: it checks scans' visibility through `scanning`, which uses `inventory`;
  in `inventory` it would close a cycle. Comparing two scans is `scanning`'s route.
- **`TargetNaming`** (`shared`): `access` and `scanning` read names through it, and `targets` uses both.

## What step 5 must resolve

> Resolved by [0029](0029-core-domains-become-modules.md), which says finding by finding how, and
> what the intermediate state below became. The list is kept as it was written.

- **Move `issues`, `scanning` and `targets`** with their controllers, entities and repositories, and
  dissolve `platform` (the maintenance tick, retention and the settings screen become each module's
  contribution) and `shared` (`TargetNaming` into `targets` once `targets` no longer calls `access` and
  `scanning` directly). Every step-4 module but `siem` depends on one of the layered persistence types:
  `IssueEntity`/`Issues`, `ScanEntity`/`Scans`, `RepositoryEntity`/`GitRepositories`,
  `ContainerEntity`/`Containers`, `FindingEntity`/`Findings`, and the query projections `IssueFilters`,
  `IssueRows`, `IssueAggregates`, `LatestScanRow` — a module will need `issues`' and `scanning`'s API,
  or a named query interface, in their place.
- **The layered code reaching module internals**: `platform`'s settings screen reads `access`'s `Users`;
  `targets`' solution administration writes `access`'s `TeamTargets` and `UserTargets`; the scan
  platform's metrics count through `outbox`'s repository; the scan dispatcher and `ScanningConfiguration`
  take `rules`' `SemgrepRuleSetEntity` (which `RuleSetService` returns); `ApiExceptionHandler` maps the
  chain's `RequestBodyTooLargeException`.
- **Types that cross a boundary without a rule seeing them**: `OutboxService.enqueue` returns the
  message entity (only the outbox's own tests read it, but `siem` and `notifications` depend on the type
  through the method's descriptor, which neither ArchUnit nor Modulith counts), and `RuleSetSummary`, a
  repository projection, is on the wire inside `RuleSetListing` — as it was from `core.repositories`.
- **Where the cleanup of evidence belongs**: the authentication tables' pass purges the gate's
  register and the compliance captures through a port; with `platform` dissolved, each module's own
  retention is the natural home.

## Consequences

- Spring Modulith detects 24 modules — the nineteen domains and the five layered packages — and
  `verify()` would report 554 messages instead of 1,304: 278 from `core.api` into `core.services` (the
  step-5 controllers), 201 from modules into `core.services`, 18 from the layered packages into a
  module's internals, and 57 cycles, every one through `core.services`. **No module reaches into another
  module's internals.** `ModularityObservationTest` still fails on nothing; step 6 turns it into
  `verify()`.
- Every rule that found its subject by package reads both packagings, and each was mutation-checked
  against a moved class: `RouteAuthorizationTest` matched `core.api` handlers only, `SchemaNameCollisionTest`
  scanned `core.api` for controllers and `core.persistence` for entities, `AuthorizationCoverageTest` and
  `RouteScopingTest` walked `core/api` — each would have gone quiet on the first controller that moved.
  The coverage gate listed the four layered packages by name; it now excludes rather than includes.
  CI's `engines` job matched `/core/persistence/` and now matches a module's `persistence` too.
- New code goes into its domain's module, in the place its callers decide; a new edge between modules
  is a line in `MAY_USE`, in the review that needs it, with its reason.
- Package-private now means "this module's root". Two classes were widened by the move —
  `Visibilities` (called from every module's controllers) and `ViolationView` (shared by the gate's and
  the dashboard's routes, now at `gate`'s root) — each saying why. Where widening would have published a
  member, the class stayed at the root instead: `SiemDelivery` reads two package-private members of
  `siem`'s API classes.
