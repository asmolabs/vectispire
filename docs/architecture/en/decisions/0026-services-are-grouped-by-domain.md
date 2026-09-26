# 0026 — Services are grouped by domain, and the domains depend in one direction

**Date:** 2026-09-26 · **Status:** accepted · **Decider:** Laurent Boucher

> **See also** [05 — Modularity as Spring Modulith sees it](../05-modularity.md). Later the same
> day, step 1 of the migration to Spring Modulith broke both recorded cycles (`KNOWN_CYCLES` is
> empty), moved `ReportCursor` into a `reporting` foundation domain and made target deletion an
> event each owning domain purges; step 2 added Modulith in observation mode. The table below is
> the reference as `ArchitectureTest` now enforces it, with `reporting` in the foundation.

## Context

`core/services` held about 155 classes in one flat package. Everything could call everything, and
package-private meant "anyone in the service layer". The layer rule (`ArchitectureTest`) kept
controllers out of repositories and SQL out of services, but it said nothing about how the service
layer itself was shaped, and the reviews kept finding defects that a shape would have made visible:
an HTTP call made inside a transaction by a service three calls away from the one that opened it, a
maintenance job nobody called, an `@Async` method that ran synchronously in its caller's
transaction. None of them was a missing line; each was a dependency nobody could see.

Two ways of giving the layer a shape were considered.

**Spring Modulith.** It verifies module boundaries, documents them, and brings an event publication
registry. It was rejected *for now*, for three reasons:

- **This code is packaged by layer, and Modulith reads the packages directly under the application
  class as modules.** It would see `api`, `services`, `repositories` and `persistence` as four
  modules — which `ArchitectureTest` already verifies — rather than the domains. Making Modulith see
  domains means packaging by feature (`issues/api`, `issues/services`, `issues/persistence`…), a move
  of every class in the control plane and of every layer rule written against it.
- **Its event registry duplicates the outbox.** Effects that must survive a commit already leave
  through `t_outbox_message`, with a claim, a backoff and an abandonment the relay applies to every
  message type ([0025](0025-siem-events-leave-through-the-outbox.md)). A second, generic mechanism
  would be a second answer to "did this effect leave", and the two would drift.
- **Verification and documentation are already covered.** ArchUnit checks the rules in the build;
  the C4 model and its drift check (`c4-drift`) carry the documentation.

Reconsider it if the code is ever packaged by feature, if the outbox stops being enough (event
replay, externalized events to a broker), or if a domain is to be extracted into a service of its
own — the three situations in which what Modulith adds is no longer a duplicate.

## Decision

**`core/services` is divided into sub-packages, one per domain, and the domains form a directed
graph with no cycle but the two recorded below.** `ArchitectureTest` checks four things: that every
service class lives in a known domain, that `slices().matching("..core.services.(*)..")` is free of
cycles once the recorded ones are set aside, that each recorded cycle still exists (so the list can
only shrink), and that each domain depends only on the domains the table below allows it.

**A domain is drawn as a future module, not as a technical group.** A study to follow will plan
the move to modules *by domain* — each one owning its controllers, services, repositories and
entities. The packages are chosen so that a domain here is something that could own those too:
`issues` would take `IssuesController`, `Issues` and `IssueEntity` with it. Where the code put a
class on the wrong side of a boundary, it stays where its module would own it and the cycle it
closes is recorded, rather than being moved somewhere wrong to make the cycle disappear.

### The domains

| Domain | What it holds |
|---|---|
| `settings` | the deployment's configuration: `SettingsService`, the first-install defaults, and what Vectispire says about itself (`ProductVersion`, `ExportProperties`, `BrandingProperties`) |
| `outbound` | the one door out: `PinnedHttpSender`, `OutboundJson`, `OutboundPost`, the guard's configuration |
| `crypto` | encryption at rest, the key's sources, Vault, the signing key |
| `audit` | the audit log — writing it, its mirror, reading it back and judging its chain — and `RequestActor` |
| `outbox` | the relay: `OutboxService`, and the two contracts it dispatches to, `OutboxHandler` and `NotificationChannel`, with `GoneDestinationException` |
| `shared` | two helpers still without a domain: `TargetNaming`, `ReportCursor` |
| `access` | accounts, teams, visibility and the row guard, sessions, sign-in flows, second factors, OIDC, SCIM, API keys, bootstrap |
| `siem` | the security event stream and its delivery |
| `rules` | rule sets, the upstream catalogue, rule coverage |
| `inventory` | what targets are made of: components, SBOM diff, blast radius, licences, API contracts |
| `ai` | the model review and the advisor |
| `issues` | sync, triage, decisions, SLA, history, the exceptions register, VEX import |
| `tickets` | the tracker client, the ticket links, the tracker's webhook and the ticket sweep |
| `scanning` | the queue, dispatch, ingest, the built-in worker, scheduling, scan reads |
| `agents` | agent administration and the agent protocol |
| `targets` | repositories, containers, solutions and projects, clone credentials, deletion |
| `threatintel` | KEV/EPSS feeds, enrichment, end of life |
| `gate` | the gate, its register and its policies |
| `notifications` | what a scan's delta says, and the channels that say it |
| `exports` | VEX, CSAF, CycloneDX, attestation, the export documents |
| `posture` | figures of risk: dashboard, scorecards, debt, quality, remediation, attack paths, the weekly digest |
| `compliance` | frameworks, statement of applicability, evidence, OWASP |
| `platform` | the composition roots: the maintenance tick, retention, the settings screen |

**`shared` holds two classes and is meant to empty.** `TargetNaming` belongs to `targets`, which
owns the rows it names; it cannot go there while `targets` calls `scanning` to queue a scan and
`access` to filter by visibility, because both of those read names too — nine domains do. `ReportCursor`, the
PDF pagination four domains' reports share, has no domain of its own; a reporting module, or a copy
per module, is the study's to decide.

**`platform` is not a future module.** Its three classes reach into many domains by nature: the
maintenance tick calls every domain's periodic job, retention purges every domain's tables, and the
settings screen writes each domain's secrets. In a modular layout they dissolve into the domains
they call — a job per module, a retention rule per module, a settings contribution per module.

### Who may depend on whom

The **foundation** — `settings`, `outbound`, `crypto`, `audit`, `outbox`, `shared` — may be used by
every domain. Inside it, `crypto` uses `outbound` (Vault is reached through the guard) and nothing
else depends on anything, but for the recorded `audit` → `siem` edge.

Above the foundation, each domain may use only the domains listed:

| Domain | May also use |
|---|---|
| `access`, `siem`, `rules`, `inventory` | — |
| `ai`, `issues` | `access` |
| `tickets` | `access`, `issues` |
| `scanning` | `access`, `inventory`, `issues`, `rules` |
| `agents` | `access`, `scanning` |
| `targets` | `access`, `scanning` |
| `threatintel` | `scanning`, `siem` |
| `gate` | `issues`, `rules`, `siem` |
| `notifications` | `issues`, `scanning` |
| `exports` | `gate`, `issues` |
| `posture` | `access`, `gate`, `inventory`, `issues`, `notifications` |
| `compliance` | `access`, `ai`, `exports`, `gate`, `inventory`, `issues`, `posture`, `rules` |
| `platform` | any domain; nothing depends on it |

The table is the code as it stands, and adding a line to it is a decision: it belongs in the same
review as the dependency that needs it, with the reason.

### How domains talk

- **Downwards, a call.** A domain calls a service of a domain it may use, like any Spring bean.
- **Upwards, a port.** When a lower domain needs work done by a higher one, it declares the interface
  and the higher domain implements it: `ScanIngestor.Enricher`, `LicenseSource`, `EndOfLifeSource`
  and `NotificationSink` (implemented in `threatintel`, `scanning` and `notifications`),
  `AuditLogService.Listener` (implemented by `siem`), `OutboxHandler` (implemented by `siem`).
- **Effects that must survive the commit go through the outbox.** A message, a SIEM event, anything
  that leaves the process after a write, is a row written in the transaction that caused it and sent
  by the relay afterwards — never a direct call from inside the transaction, and never `@Async`,
  which is inert here.

### Three cycles: one broken, two recorded

The flat package hid three cycles between what became domains.

- **Broken: `outbox` ↔ `notifications`.** The relay caught `NotificationService.GoneDestinationException`,
  and notifications enqueue into the relay. The exception is the relay's contract, not the
  notifications'; it became the top-level `outbox.GoneDestinationException`, and
  `NotificationChannel`, the interface the relay dispatches notification rows to, went with it.
- **Recorded: `audit` → `siem`**, through `AuditLogQueryService` → `SiemEvents`. Verifying the
  chain publishes `AUDIT_CHAIN_BROKEN`, while the SIEM listens to the audit log it verifies. The way
  out is an application event the SIEM subscribes to — which is what a module would do, and more
  than a package move.
- **Recorded: `issues` → `tickets`**, through `IssueDecisionService` → `TicketService`. Attaching a
  ticket validates the reference against the configured tracker, while the tracker's webhook and
  the ticket sweep transition issues. The validation belongs to `tickets`; moving it is a change of
  method, not of package.

Both recorded edges are listed in `ArchitectureTest.KNOWN_CYCLES` with these reasons, exempted
from the cycle rule and the table by class — not by package — and a test fails the day either
disappears, so the list shrinks with the code.

## Consequences

- A new service goes into the domain whose table row matches what it needs; if none does, the table
  changes first, in the open.
- Package-private now means "this domain". Moving the classes widened one class — `ReportCursor`,
  and the members the PDF reports call — because its callers live in four domains; everything else
  that was package-private stayed private to its domain.
- The layer rule is unchanged: `..services..` covers the sub-packages. Decided the same day and
  enforced beside it: no class of `api` depends on `persistence` at all. Services answer with
  `…View` records, the principal holds `UserView`, `SessionView` and `AgentView` — which is why
  `agents` uses `access` — and a route that held a row only to hand it back passes an id.
- An ArchUnit rule can be deleted by the commit that violates it, as `vectispire-java/README.md`
  already says of the layers. The table in this record is the reference the rule is reviewed against.
