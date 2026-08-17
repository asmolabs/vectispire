# 01 — Overview

## What Zanshin does

Zanshin watches the security of a set of **targets** — Git repositories and container
images — by periodically putting them through a battery of analyzers, and tracks what it
finds **from one scan to the next**.

That last point is what separates it from a script that runs Grype in CI. A scanner
returns a list; Zanshin returns a **backlog**: what appeared, what was triaged and by
whom, what has been sitting there for six scans, what has gone away. A report says what
exists today; a backlog says what changed, which is the only information anyone acts on.

The second use is the **compliance verdict**: `POST /api/v1/gate` tells a build pipeline
whether a target passes, according to an explicit policy. This is where Zanshin stops
being a dashboard and becomes a decision.

Three principles shape everything else.

**Everything is local.** The analyzers run in ephemeral containers on the same machine,
with the network cut off when the tool has nothing to fetch. No source code leaves. This
is not a constraint endured: it is what makes the tool deployable where application
security is actually a question, and it is why the Semgrep rules are bundled rather than
downloaded ([decision 0006](decisions/0006-semgrep-rules-written-here.md)).

**The default deployment is one process and one file.** A single `docker run` and the
tool is up. Everything distributed — several instances, remote agents, PostgreSQL — is
possible, and refused at startup when the configuration does not allow it
([04](04-runtime-and-deployment.md)).

**What was not observed is not clean.** An analyzer that crashes has found nothing, and
mistaking its silence for an empty result declares the target fixed. This distinction
runs through the whole codebase
([decision 0007](decisions/0007-none-is-not-an-empty-list.md)).

## The pieces

```mermaid
flowchart TB
    subgraph proc["Zanshin backend (NestJS)"]
        API["HTTP API<br/>backend/src/api/"]
        SVC["Services<br/>backend/src/services/"]
        REPO["Repositories<br/>backend/src/repositories/"]
        SCHED["Scheduler<br/>scheduler.service.ts — periodic tick"]
    end

    UI["Angular UI<br/>frontend/src/app/"]
    DB[("Database<br/>PostgreSQL, MySQL, MariaDB or SQLite")]
    DOCKER["Docker daemon<br/>ephemeral analysis containers"]
    AGENT["Remote agent<br/>four-route protocol"]
    FEEDS["Public feeds<br/>EPSS, CISA KEV, endoflife.date"]
    HOOK["Webhook / ticket tracker"]

    UI -->|"/api over HTTP"| API
    API --> SVC
    SCHED --> SVC
    SVC --> REPO
    REPO --> DB
    SVC --> DOCKER
    SVC -.->|"outbound, opt-in"| FEEDS
    SVC -.->|"through the outbox"| HOOK
    AGENT -->|"HTTP long-polling<br/>never the database"| API
    AGENT --> DOCKER
```

**Two artifacts, one API.** The port split the single Reflex process into a NestJS
backend and an Angular front end; the browser now talks to the same HTTP API that a CI
pipeline or a remote agent talks to. The API keys finally have a consumer that is not
the UI itself — under Reflex they could be issued and served no purpose.

**Dependency injection is NestJS's**, wired in
[`backend/src/api/api.module.ts`](../../backend/src/api/api.module.ts). The Python stack
built its own `IoCContainer` per request around a database session; that hand-rolled
graph is gone.

### The layers, and the rule that holds them

```
api/ ──► services/ ──► repositories/ ──► persistence/ ──► database
           │                                  │
           └──────────────┬───────────────────┘
                          ▼
                       domain/          (pure, depends on nothing)
```

One rule, and it is what makes the whole thing testable: **a layer only knows the one
below it.** In particular, a service writes no SQL — it goes through a repository — and a
repository holds no business rule.

Unlike the Python stack, this rule is not merely written down:
`backend/src/architecture.spec.ts` reads the import graph and fails the suite when a
layer imports from above itself, or when a domain file imports a framework. See
[`backend/README.md`](../../backend/README.md) for the full table.

Two practical consequences:

- The UI and a CI pipeline are two clients of the **same** endpoint. The verdict shown on
  the Security screen is the one `POST /api/v1/gate` returns, because both go through
  `domain/gate/policy-gate.ts` — not because someone was careful. A SQL aggregate that
  reimplemented the verdict would agree today and diverge the first time a policy flag
  was added.
- The UI's view models
  ([`frontend/src/app/core/api.models.ts`](../../frontend/src/app/core/api.models.ts))
  are typed and computed server-side. The browser receives finished values, not
  arithmetic.

## The path of a scan

```mermaid
sequenceDiagram
    participant D as Trigger<br/>(scheduler, UI, API)
    participant Q as Queue (scan table)
    participant R as ScanRunner
    participant I as ScanIngestor
    participant S as IssueSync

    D->>Q: inserts a "queued" row
    Note over Q: returns immediately
    R->>Q: claims (lease + owner)
    R->>R: clone / resolve the image
    R->>R: SBOM, vulnerabilities, secrets, IaC, SAST
    R-->>I: ScanArtifacts (null = did not run)
    I->>I: normalizes into Finding
    I->>S: syncs from the scan
    S->>S: fingerprints, reconciles, opens / resolves
```

**Triggering does not execute.** A trigger inserts a `queued` row and returns. A worker
loop claims and executes. That is what lets a remote agent, or a second instance, take
the work — and what removed the in-memory queue held by whichever process received the
request ([decision 0002](decisions/0002-the-database-carries-the-queue.md)).

**Two separated responsibilities.** `ScanRunner` runs the analyzers and knows nothing of
the database; `ScanIngestor` reads the artifacts and writes. The cut is not cosmetic: it
is what lets a remote agent execute the first half with no database access
([decision 0003](decisions/0003-long-polling-for-agents.md)), and
`architecture.spec.ts` forbids the agent from importing `typeorm`, `pg`, `mysql2` or
`@nestjs/` so the property cannot quietly lapse.

### The analyzers

Each is an ephemeral container, pinned **by digest** — these images are Zanshin's own
supply chain, and they run on a machine that has the Docker socket.

| Step | Tool | Network | Produces |
|---|---|---|---|
| SBOM | `anchore/syft` | open (registry, daemon) | component inventory |
| Vulnerabilities | `anchore/grype` | open (vulnerability database) | `vulnerability` findings |
| Secrets | `gitleaks` | **cut off** | `secret` findings |
| IaC | `bridgecrew/checkov` | **cut off** | `iac` findings |
| Source code | `semgrep/semgrep` | **cut off** | `sast` and `quality` findings |
| Licenses | *(none)* | — | derived from the SBOM |
| End of life | endoflife.date | outbound, opt-in | `eol` findings |
| AI review | local Ollama | local, opt-in | `ai_review` findings |

[`ScanRunner`](../../backend/src/scanning/scan-runner.ts) is a single concrete class here.
The Python stack had it as a `ScannerEngine` interface with three implementations —
Docker, a local side-car API, and OSV
([decision 0001](decisions/0001-pluggable-scan-layer.md)); the port carried over only the
Docker one, so the seam exists in the decision register but not in the code. See
[04](04-runtime-and-deployment.md) for what that costs.

## The periodic tick

A single rhythm carries all background work: scheduled scans, retention of raw payloads,
triage expiry, outbox relay, refreshing the built-in agent. It is taken **under a lease**
— a row in `leader_lease`, see
[`leader-election.service.ts`](../../backend/src/services/leader-election.service.ts) —
so that only one instance holds it. A holder that dies stops renewing; the next tick
takes over after expiry ([04](04-runtime-and-deployment.md)).

A lease in a table rather than an engine advisory lock: it is portable, it works
single-instance with no special case, and above all **it is observable**. When something
has stopped happening, `SELECT * FROM leader_lease` says who was supposed to do it and
until when. A `pg_advisory_lock` answers no question after the fact.

## Still open

- **No per-team partitioning at the account level.** An API key can be restricted to one
  target; a *user* sees everything. This is the most visible limit for anyone wanting to
  deploy Zanshin across several teams.
- **The pluggable scan layer is a decision without an implementation.** Only the Docker
  runner was ported, and the contract test that kept the implementations honest was lost
  with the Python tree. [Decision 0001](decisions/0001-pluggable-scan-layer.md) has not
  been superseded, so the register and the code disagree.
- **No reachability analysis** (call graph, taint). A vulnerability in a dependency that
  is never called is counted like any other. That is heavy work, deliberately out of
  scope.
