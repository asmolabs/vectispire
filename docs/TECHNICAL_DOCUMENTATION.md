# Zanshin — Technical Documentation

This document describes Zanshin's internal architecture, its database schema, and the scan
pipeline's runtime flow. For features and quick start, see [`README.md`](../README.md). For
the reasoning behind the structural choices, see [`docs/architecture/`](architecture/) and
its [decision register](architecture/decisions/).

## 1. Layered architecture

Two artifacts in one npm workspace: a NestJS backend and an Angular front end that talks to
it over the same HTTP API a CI pipeline or a remote agent uses.

```mermaid
flowchart TB
    subgraph front["Angular front end — frontend/src/app/"]
        Pages["Pages<br/>dashboard, securite, qualite, depots, issues,<br/>containers, scans, ssh-keys, api-keys, agents,<br/>settings, users, audit-log"]
    end

    subgraph api["api/ — controllers, DTOs, guards"]
        Routes["16 controllers<br/>auth, scans, issues, gate, exports, quality,<br/>repositories, containers, dashboard, settings,<br/>users, ssh-keys, api-keys, audit-log,<br/>agents, agents-admin"]
    end

    subgraph services["services/ — orchestration, transactions"]
        Scan["ScanDispatcherService / ScanWorkerService<br/>ScanIngestorService"]
        Issue["IssueSyncService / IssueTriageService"]
        Enrich["EnrichmentService · EolService · LicenseService"]
        Ai["AiReviewService"]
        Notify["NotificationService · OutboxService"]
        Ticket["TicketService · TicketSweepService"]
        Ops["SchedulerService · LeaderElectionService<br/>RetentionService · MaintenanceService"]
        Auth["AuthService · PasswordService · SessionCleanupService<br/>ApiKeyAuthService · AuditLogService · SettingsService<br/>EncryptionService · BootstrapService"]
    end

    subgraph repos["repositories/ — data access, no business rules"]
        R["ScanRepository · IssueRepository · TargetRepository<br/>AuditLogRepository · SessionRepository"]
    end

    subgraph persistence["persistence/ — entities, dialects, driver types"]
        Ent["19 TypeORM entities · migrations per dialect"]
    end

    subgraph domain["domain/ — pure, depends on nothing"]
        D["fingerprint · gate · audit chain · exports · triage<br/>url-guard · crypto · retention · scheduling · …"]
    end

    subgraph scanning["scanning/ — runs containers, no database"]
        S["ScanRunner · ContainerRunner<br/>syft · grype · gitleaks · checkov · semgrep"]
    end

    Pages -->|"/api over HTTP"| Routes
    Routes --> services
    services --> repos
    repos --> persistence
    services --> scanning
    services --> domain
    repos --> domain
    scanning --> domain
```

**Dependency injection is NestJS's**, wired in
[`api/api.module.ts`](../backend/src/api/api.module.ts) and
[`persistence/persistence.module.ts`](../backend/src/persistence/persistence.module.ts).
The Python stack built an `IoCContainer` by hand, fresh per request, around a database
session; that graph is gone.

**The layering is enforced, not documented.**
[`architecture.spec.ts`](../backend/src/architecture.spec.ts) reads the import graph and
fails the suite when a layer imports from above itself, when a `domain/` file imports a
framework, or when `agent/` imports `typeorm`, `pg`, `mysql2` or `@nestjs/`. That last one
is a security property, not a style rule — see
[decision 0003](architecture/decisions/0003-long-polling-for-agents.md). A rule written
only in a document is true the day it is written and false six months later.

`domain/` is pure because it carries the calculations where a mistake raises no exception
but destroys data: an issue's fingerprint, the audit chain, the gate verdict, the three
export formats. One exemption in the test: a `*.module.ts` is wiring, and is the one kind
of file whose job is to know NestJS.

## 2. Database schema

The schema belongs to the **migrations**, under
[`persistence/migrations/<dialect>/`](../backend/src/persistence/migrations/) — one set per
engine, because the same intent is spelled differently on each. `synchronize` is `false`
and stays that way: it would modify the database from the entities, at startup, with no
trace and no review.

`ZANSHIN_DB_DIALECT` accepts `postgres` (default), `mysql`, `mariadb` and `sqlite`. All
four pass the whole integration campaign
([decision 0009](architecture/decisions/0009-four-engines.md)).
[`schema-parity.integration-spec.ts`](../backend/src/persistence/schema-parity.integration-spec.ts)
asks on each engine the question `migration:generate` asks — "what would have to change for
the database to look like the entities?" — whose right answer is "nothing".

### The scan and issue model

```mermaid
erDiagram
    REPOSITORY ||--o{ SCAN : "is scanned by"
    CONTAINER  ||--o{ SCAN : "is scanned by"
    SCAN       ||--o{ FINDING : "produces"
    SCAN       ||--o{ ISSUE : "opens (first_seen)"
    SCAN       ||--o{ AI_REVIEW_RESULT : "carries"
    SCAN       }o--o| AGENT : "claimed by"
    ISSUE      }o--|| REPOSITORY : "concerns"
    ISSUE      }o--|| CONTAINER : "concerns"
    REPOSITORY ||--o| SSH_KEY : "clones with"
    REPOSITORY ||--o| GATE_POLICY : "evaluated by"
    CONTAINER  ||--o| GATE_POLICY : "evaluated by"

    REPOSITORY {
        int id PK
        string url
        string name
        string branch
        string sub_path
        uuid ssh_key_id FK
        int scan_interval_minutes
        string scan_cron
        string required_agent_label
        datetime last_scheduled_scan_at
    }
    CONTAINER {
        int id PK
        string image
        string platform
        int scan_interval_minutes
        string scan_cron
        string required_agent_label
        datetime last_scheduled_scan_at
    }
    SCAN {
        int id PK
        int repo_id FK
        int container_id FK
        string status "queued|scanning|completed|failed"
        string branch
        json sbom "purged by retention"
        json cves "purged by retention"
        json summary "counters, kept"
        string claimed_by
        datetime claimed_at
        datetime lease_expires_at
        int attempts
        text error
        datetime created_at
    }
    FINDING {
        int id PK
        int scan_id FK
        string type "vulnerability|secret|iac|license|eol|sast|quality|ai_review"
        string severity
        string identifier "CVE or rule id"
        string purl
        string package_name
        string package_version
        bool is_direct_dependency
        string file_path
        int line
        float cvss_score
        float epss_score
        bool is_kev
        string fix_state
        string fix_versions
        text description
        string source
    }
    ISSUE {
        int id PK
        string fingerprint UK "unique per target"
        int repo_id FK
        int container_id FK
        string state "open|resolved"
        string triage_status "VEX vocabulary"
        string triage_justification
        text triage_comment
        string triaged_by
        datetime triaged_at
        datetime triage_expires_at
        int times_seen
        datetime first_seen_at
        datetime last_seen_at
        string ticket_ref
        string ticket_url
    }
    AI_REVIEW_RESULT {
        int id PK
        int scan_id FK
        string model
        string status
        text content
        text error
    }
    GATE_POLICY {
        int id PK
        string target_kind "global|repository|container"
        int target_id
        int version
        bool is_active
        string fail_on_severity
        bool fail_on_kev
        bool fixable_only
        bool include_triaged
        bool include_ai_review
        string note
        string created_by
    }
    AGENT {
        uuid id PK
        string name
        string kind "embedded|remote"
        string labels "comma-separated"
        string credentials_mode "local|delegated"
        bool enabled
        int max_concurrent
        uuid api_key_id FK
        string hostname
        string platform
        string version
        text sealing_public_key
        datetime last_seen_at
    }
```

### The service tables

Outside the main model, and each one load-bearing:

| Table | What it holds | Why it exists |
|---|---|---|
| `user` | accounts, bcrypt password, role, `must_change_password` | — |
| `session` | opaque token, `created_at`, `last_seen_at`, `expires_at`, IP, user agent | a **revocable** session: the Reflex token could not be invalidated, so nobody could be logged out |
| `login_attempt` | `counter_key`, `occurred_at` | anti-stuffing counted per user **and** per client; one axis alone is defeatable |
| `api_key` | bcrypt hash, prefix for display, scopes, target restriction, expiry | the raw secret is returned once and never stored |
| `ssh_key` | AES-GCM ciphertext bound to its row by associated data | without the binding, key A's ciphertext copied into row B decrypts cleanly |
| `setting` | key/value | the catalog in `domain/settings/catalog.ts` decides what is exposed |
| `audit_log` | entry hash, previous hash, IP, user agent | chained: makes **selective** editing detectable |
| `outbox_message` | payload, `status`, `attempts`, `next_attempt_at` | written in the transaction that produces the result, so a crash before the POST loses nothing |
| `processed_message` | `message_id` UK, `agent_id` | deduplicates an at-least-once agent report; the fingerprint alone would still inflate `times_seen` |
| `leader_lease` | `name`, `holder`, `expires_at` | one instance holds the periodic tick; a table rather than an advisory lock because it is **observable** |

## 3. Scan pipeline

Triggering does not execute. A trigger inserts a `queued` row and returns; a worker loop
claims and runs it. That is what lets a remote agent, or a second instance, take the work
([decision 0002](architecture/decisions/0002-the-database-carries-the-queue.md)).

```mermaid
sequenceDiagram
    participant T as Trigger<br/>(scheduler, UI, API)
    participant Q as scan table
    participant W as ScanWorkerService
    participant R as ScanRunner
    participant I as ScanIngestorService
    participant S as IssueSyncService
    participant DB as Database

    T->>Q: INSERT scan(status="queued")
    T-->>T: returns immediately
    W->>Q: claim (FOR UPDATE SKIP LOCKED + lease)
    W->>R: run(task)
    R->>R: clone (depth 1) or export the image
    R->>R: syft → grype → gitleaks → checkov → semgrep
    R-->>W: ScanArtifacts (null = did not run)
    W->>I: ingest
    I->>DB: INSERT findings, UPDATE scan(summary)
    I->>S: sync from scan
    S->>S: fingerprint, reconcile, open / resolve
    S->>DB: outbox row, in the same transaction
    Note over W,DB: A scanner that fails records a failure on the scan<br/>and leaves its artifact null. The scan still completes.
```

Points that are not obvious from the diagram:

- **`null` is not `[]`.** In `ScanArtifacts`, `[]` is the positive claim *"the step ran and
  found nothing"*, which **resolves** that type's issues; `null` means it did not run, and
  the backlog is left alone. A port that normalized nulls into empty lists would silently
  resolve hundreds of security issues with no error anywhere
  ([decision 0007](architecture/decisions/0007-none-is-not-an-empty-list.md)).
- **Failure does not only show in the exit code.** A Semgrep run where most files timed out
  exits 0 with a short list. `errors[]` and `paths.scanned` are inspected, and past a 25%
  error ratio the result is `null`.
- **Semgrep produces two finding types from one pass.** Each rule's `metadata.category`
  decides: `security` becomes a `sast` finding, gated like any vulnerability; anything else
  becomes `quality`, which no policy can let into a verdict
  ([decision 0005](architecture/decisions/0005-quality-never-blocks-the-gate.md)). Both
  come from the same run, so they enter the scanned-types list together.
- **The analyzers' configuration comes from Zanshin, never from the target.** gitleaks
  falls back to the scanned repository's `.gitleaks.toml` when given no `--config`, and
  Semgrep honours the analyzed tree's `.gitignore` unless told otherwise — in both cases
  the audited repository would decide what is looked for in it.
- **Rules are copied into the scan's workspace.** Counter-intuitive but mandatory: volume
  paths are resolved by the Docker *daemon*, so a directory inside Zanshin's own image is
  invisible to the sibling scanner container. See
  [`scanning/bundled-rules.ts`](../backend/src/scanning/bundled-rules.ts), which also
  merges the operator's `ZANSHIN_SEMGREP_RULES_DIR`.
- **Secrets, IaC and SAST never run on a container image.** They look in source code;
  declaring them scanned would silently resolve that target's whole history for those
  types. They stay `null`.

## 4. The scanners

Each is an ephemeral container, pinned **by digest**, with `cap_drop: ALL`,
`no-new-privileges`, memory and PID caps, and the network cut off when the tool has nothing
to fetch.

| Step | Image | Network | Produces |
|---|---|---|---|
| SBOM | `anchore/syft` | open (registry) | component inventory |
| Vulnerabilities | `anchore/grype` | open (vulnerability database) | `vulnerability` findings |
| Secrets | `gitleaks` | **cut off** | `secret` findings |
| IaC | `bridgecrew/checkov` | **cut off** | `iac` findings |
| Source code | `semgrep/semgrep` | **cut off** | `sast` and `quality` findings |
| Licenses | *(none)* | — | derived from the SBOM |
| End of life | endoflife.date | outbound, opt-in | `eol` findings |
| AI review | local Ollama | local, opt-in | `ai_review` findings |

There is **one** runner, [`ScanRunner`](../backend/src/scanning/scan-runner.ts), and it runs
Docker. The Python stack had a `ScannerEngine` interface with three implementations; the
port kept only the Docker one and
[decision 0010](architecture/decisions/0010-one-scan-runner.md) abandons the seam rather
than rebuilding it around a single implementation. Moving execution elsewhere is done by
running an agent elsewhere.

**No analysis container sees the Docker socket.** The image SBOM step used to mount it so
Syft could pull the image itself — handing root on the host to a process whose input is
hostile by definition. Zanshin now pulls and exports the image, and presents the container
with a read-only archive.

### AI code review (Ollama), off by default

[`AiReviewService`](../backend/src/services/ai-review.service.ts) is a light complement to
the scanners, not a SAST engine: one prompt, no guaranteed reproducibility. The sample sent
is a sorted, extension-filtered concatenation of source files capped at 40,000 characters —
no chunking, so large repositories are truncated.

Three things about it are security decisions, not features:

- **The URL guard is inverted here.** This endpoint receives the scanned repository's source
  code, so the risk is not that it points inward but that it points **outward**. A
  well-formed public URL is exactly what an exfiltration channel looks like, so a public
  destination is refused unless explicitly allowed.
- **Its findings enter no gate verdict by default.** A hostile repository can steer a model
  it has been handed the code of, and an invented `critical` would fail somebody's build.
- **An LLM is not a trust boundary.** The sample is wrapped in an explicit delimiter and the
  prompt asks the model to *report* an injection attempt rather than obey it. That is a
  mitigation, and the reason its verdict blocks nothing.

The model list is read live from Ollama's `GET /api/tags`, so what the operator has actually
pulled is what becomes selectable; a two-entry fallback is shown as a *suggestion* when
Ollama is unreachable, never as installed. Parsing is defensive — a response that does not
parse yields an empty list and never raises.

## 5. Service and repository reference

| Service | Responsibility |
|---|---|
| `ScanDispatcherService` | Claims scans transactionally and hands tasks to agents; holds the credentials decision (`credentialsMode`) and the sealing. |
| `ScanWorkerService` | The built-in worker: claims, runs, ingests. |
| `ScanIngestorService` | Normalizes artifacts into `Finding` rows and updates the scan. Knows the database; runs no container. |
| `IssueSyncService` | Reconciles findings against issues across scans: fingerprint, `times_seen`, open/resolve. Writes the outbox row in the same transaction. |
| `IssueTriageService` | Applies a validated triage decision, and expires the ones past their review date. |
| `EnrichmentService` | EPSS scores and the CISA KEV catalog. Best-effort: never turns a completed scan into a failure. |
| `EolService` · `LicenseService` | End-of-life matching, and the license blocklist over SBOM data already collected. |
| `AiReviewService` | See §4. |
| `NotificationService` · `OutboxService` | Selects what deserves a message, and relays the outbox with capped backoff. |
| `TicketService` · `TicketSweepService` | Opens one tracker ticket per issue that would fail a build, under the same gate policy — no second threshold. |
| `SchedulerService` | The periodic tick: due scans, retention, triage expiry, outbox, ticket sweep. |
| `LeaderElectionService` | The lease that makes exactly one instance run that tick. |
| `RetentionService` · `MaintenanceService` | Purge of raw payloads, and periodic housekeeping. |
| `AuthService` · `PasswordService` · `SessionCleanupService` | Login, throttling, hashing, session expiry. |
| `ApiKeyAuthService` | Key verification, scopes, target restriction, expiry. |
| `AuditLogService` | Chained audit entries. Recording never raises: a logging failure must not break the action being audited. |
| `EncryptionService` | AES-GCM at rest, with the context bound to the row, and multi-key rotation. |
| `SettingsService` · `BootstrapService` | Key/value settings, and first-run account creation. |

Five repositories only — `Scan`, `Issue`, `Target`, `AuditLog`, `Session` — each a thin
wrapper around the queries its callers actually need. There is no generic base repository.
A service writes no SQL, and a repository holds no business rule;
`architecture.spec.ts` enforces both.

## 6. The front end

Angular 21 with [Optimus UI](https://github.com/openng/optimus-ui), the community fork of
PrimeNG v21 — PrimeTek archived PrimeNG and moved v22 to a commercial license. The shell
comes from the Sakai template (MIT). `primeicons` is pinned to exactly `7.0.0`: 8.0.0
followed PrimeNG under a proprietary license, which is what moving to Optimus was meant to
avoid. See [`frontend/README.md`](../frontend/README.md).

The view models the browser receives are typed and computed server-side
([`core/api.models.ts`](../frontend/src/app/core/api.models.ts)): finished values, not
arithmetic. In particular the gate verdict shown on the Security screen is the one
`POST /api/v1/gate` returns, because both go through `domain/gate/policy-gate.ts` — not a
second implementation in SQL, which would agree today and diverge the first time a policy
flag was added.

`npm test` starts with `scripts/check-assets.mjs`, which refuses any reference to a
third-party domain in `index.html` and `styles.scss` and verifies the declared fonts exist
and are real `woff2`. Not zeal: the CSP refuses third-party stylesheets, and such a
reference breaks nothing visible — the request is blocked, the page falls back to the system
font, and nothing reports it. That is exactly how the Reflex version's typography never
reached production.

## 7. Testing approach

The unit suite runs with no database: `npm test`.

The integration suites start a real engine through **testcontainers**, apply every
migration, and roll each test back in its own transaction — so the schema under test is the
one production will receive, and the cases cannot see each other.

```bash
npm run test:integration --workspace @zanshin/backend       # PostgreSQL
npm run test:integration:all --workspace @zanshin/backend   # all four engines
```

Two rules the harness enforces on itself:

- **It does not skip when Docker is missing.** A run that verifies nothing must fail loudly.
  That is a defect this harness once had.
- **A concurrency guarantee not executed against a real server is not a guarantee.** Ten
  concurrent claimants against a real engine is what revealed that six of them came back
  empty-handed while twenty scans waited — invisible on SQLite and to a careful reading.
