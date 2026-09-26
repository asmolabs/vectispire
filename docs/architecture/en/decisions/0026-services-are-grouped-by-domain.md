# 0026 — Services are grouped by domain, and the domains depend in one direction

**Date:** 2026-09-26 · **Status:** accepted · **Decider:** Laurent Boucher

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
acyclic graph.** `ArchitectureTest` checks three things: that every service class lives in a known
domain, that `slices().matching("..core.services.(*)..")` is free of cycles, and that each domain
depends only on the domains the table below allows it.

### The domains

| Domain | What it holds |
|---|---|
| `shared` | cross-cutting helpers with no decision of their own: `TargetNaming`, `RowVisibility`, `ReportCursor`, `ProductVersion`, `ExportProperties`, `BrandingProperties`, `SettingsService` |
| `outbound` | the one door out: `PinnedHttpSender`, `OutboundJson`, `OutboundPost`, the guard's configuration |
| `crypto` | encryption at rest, the key's sources, Vault, the signing key |
| `audit` | writing the audit log and its mirror, and `RequestActor` |
| `outbox` | the relay: `OutboxService`, `OutboxHandler`, `NotificationChannel`, `GoneDestinationException` |
| `access` | accounts, teams, visibility, sessions, sign-in flows, second factors, OIDC, SCIM, API keys |
| `siem` | the security event stream and its delivery |
| `rules` | rule sets, the upstream catalogue, rule coverage |
| `inventory` | what targets are made of: components, SBOM diff, blast radius, licences, API contracts |
| `ai` | the model review and the advisor |
| `tickets` | the tracker client and the ticket links |
| `issues` | sync, triage, decisions, SLA, history, exceptions, VEX import, the tracker's webhook and sweep |
| `scanning` | the queue, dispatch, ingest, the built-in worker, scheduling, scan reads |
| `agents` | agent administration and the agent protocol |
| `targets` | repositories, containers, solutions and projects, clone credentials, deletion |
| `threatintel` | KEV/EPSS feeds, enrichment, end of life |
| `gate` | the gate, its register and its policies |
| `notifications` | what a scan's delta says, and the channels that say it |
| `exports` | VEX, CSAF, CycloneDX, attestation, the export documents |
| `posture` | figures of risk: dashboard, scorecards, debt, quality, remediation, attack paths, the weekly digest |
| `compliance` | frameworks, statement of applicability, evidence, OWASP, and reading the audit trail back |
| `platform` | the composition roots: the maintenance tick, retention, bootstrap, the settings screen |

`shared` is small on purpose and stays so: a class goes there only when three or more domains need it
and it decides nothing. `SettingsService` is the one that looks out of place; it is there because
twenty-five classes across twelve domains read settings, and a `settings` domain holding it would
have to sit below all of them while the settings *screen* — which writes each domain's secrets —
sits above them.

### Who may depend on whom

The **foundation** — `shared`, `outbound`, `crypto`, `audit`, `outbox` — may be used by every
domain. Inside it, `crypto` uses `outbound` (Vault is reached through the guard) and nothing else
depends on anything.

Above the foundation, each domain may use only the domains listed:

| Domain | May also use |
|---|---|
| `access`, `siem`, `rules`, `inventory`, `ai`, `tickets` | — |
| `issues` | `tickets` |
| `scanning` | `issues`, `inventory`, `rules` |
| `agents` | `scanning` |
| `targets` | `access`, `scanning` |
| `threatintel` | `scanning`, `siem` |
| `gate` | `issues`, `rules`, `siem` |
| `notifications` | `issues`, `scanning` |
| `exports` | `gate`, `issues` |
| `posture` | `gate`, `inventory`, `issues`, `notifications` |
| `compliance` | `access`, `ai`, `exports`, `gate`, `inventory`, `issues`, `posture`, `rules`, `siem` |
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

### Three cycles broken on the way

The flat package hid three cycles between what became domains:

- `outbox` ↔ `notifications` — the relay caught `NotificationService.GoneDestinationException`,
  and notifications enqueue into the relay. The exception is the relay's contract, not the
  notifications'; it became the top-level `outbox.GoneDestinationException`, and
  `NotificationChannel`, the interface the relay dispatches notification rows to, went with it.
- `audit` ↔ `siem` — `SiemEvents` listens to the audit log, and `AuditLogQueryService` publishes a
  SIEM event when the chain is broken. Reading the trail back and judging its integrity is an
  auditor's question, so the query service and its view live in `compliance`, beside the controls
  that already verify the chain; `audit` keeps the writer every domain calls.
- `issues` ↔ `tickets` — `IssueDecisionService.attachTicket` validates a reference against the
  configured tracker, while the tracker's webhook and the ticket sweep apply issue transitions. The
  webhook and the sweep are issue gestures that involve a tracker, so they live in `issues`, and
  `tickets` keeps the tracker client and the links.

No cycle is recorded as an exception.

## Consequences

- A new service goes into the domain whose table row matches what it needs; if none does, the table
  changes first, in the open.
- Package-private now means "this domain". Moving the classes widened a handful of members that were
  package-private and used across what became a boundary; the rest stayed private to their domain.
- The layer rule is unchanged: `..services..` covers the sub-packages.
- An ArchUnit rule can be deleted by the commit that violates it, as `vectispire-java/README.md`
  already says of the layers. The table in this record is the reference the rule is reviewed against.
