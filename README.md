# Zanshin

Zanshin is a software dependency and security tracking application built around SBOM (Software Bill of Materials) analysis. It scans Git repositories and container images, detects known vulnerabilities, hardcoded secrets, problematic licenses, and infrastructure-as-code misconfigurations, then centralizes the results in a single dashboard — in the spirit of a unified ASPM (Application Security Posture Management) platform, with a pluggable scanning layer (local Docker, local API, or cloud API depending on the analysis type).

Built with [NestJS](https://nestjs.com) and [Angular](https://angular.dev) over PostgreSQL, in a single npm workspace.

## Features

- **SCA analysis (dependencies)**: SBOM generation (Syft) and known-vulnerability detection (Grype or OSV.dev), with severity, CVE, and affected component.
- **EPSS / CISA KEV enrichment**: every vulnerability is enriched with its exploitation probability (EPSS) and "actively exploited" status (KEV catalog), to prioritize beyond the raw CVSS score.
- **Direct versus transitive dependencies**: each issue records whether the project declared the package itself or something else pulled it in, read from the SBOM's dependency graph. A critical CVE in a declared dependency is a version bump this afternoon; the same CVE four levels down waits on an upstream release. Ranked identically they produce a backlog nobody finishes, so the listing can be narrowed to what is fixable today. Unknown when the SBOM carries no dependency graph — a missing answer rather than a default one.
- **Secret detection** (gitleaks): finds hardcoded API keys, tokens, and credentials in scanned repositories.
- **License compliance**: evaluates a configurable license blocklist against data already present in the SBOM.
- **End-of-life detection** (endoflife.date): flags platforms and runtimes whose security support has ended — the container's own distribution first of all. A whole class of risk with no CVE attached: nothing will be fixed for the *next* vulnerability, whatever it turns out to be. Coverage is deliberately scoped to products (languages, runtimes, frameworks, distributions), not every library.
- **IaC scanning** (checkov): detects Terraform/Kubernetes misconfigurations in repositories.
- **Security and Quality sections.** The navigation is grouped: *Sécurité* holds an
  overview that finally shows the gate verdict per target — computed since gate policies
  existed and displayed nowhere until now — alongside the issue backlog, repositories and
  containers. *Qualité* ranks the code-quality backlog by rule, file and repository, and
  says plainly that none of it can fail a build. The overview also names the two states
  no other screen did: a target never scanned, and one whose last scan failed — both have
  an empty backlog, and an empty backlog passes every policy.
- **Source-code analysis** (Semgrep, off by default): reads the code itself — a
  concatenated SQL query, a command handed to a shell, an unverified TLS certificate —
  which no other scanner here sees. Produces two kinds of finding: *security* ones, gated
  like any vulnerability, and *quality* ones, which are visible in the backlog and can
  never fail a CI gate. Runs with the network disabled, using rules that ship with
  Zanshin; see [the rule directory](backend/src/scanning/rules/semgrep/)
  for how to add your own.
- **Issue tracking and triage**: every finding is tracked across scans as an *issue* — first seen, times seen, whether a fix exists, and a triage decision in VEX vocabulary (affected / not affected / fixed / under review) with a justification, and optionally a **review date**. A suppression is a statement about a context — "not reachable in our configuration", "not shipped in production" — and contexts change; at its review date the issue returns to *under review* with its justification and comment intact. Each scan reports what it *changed*: new issues, resolved issues.
- **Periodic rescanning**: each target carries a scan interval *or* a cron expression, honoured by a built-in scheduler — the point being that new vulnerabilities appear in code that hasn't changed. The expression wins when both are set: an interval drifts a few minutes each run, so a scan configured for the quiet hours eventually runs in the middle of the day.
- **HTTP API and CI policy gate**: trigger scans, read issues, and ask "should this build fail?" against a **stored, versioned policy** — global, or per target. The rules used to arrive in the request body, which meant each project decided its own bar; a request can now only *tighten* the stored policy, never loosen it, and the verdict says which policy it applied. Authenticated with the API keys the UI issues.
- **Tracker tickets** (GitLab, Jira): opens one ticket per problem that would fail a build, using the same policy — one threshold, defined once. The reference is kept on the issue, so a tracker outage is retried and never duplicated.
- **Notifications**: a webhook fires when a scan makes something appear or reappear — not on every scan, which is what keeps the channel readable. The message is written to an **outbox in the same transaction as the scan's results** and delivered by the scheduler with capped exponential backoff, so a crash between the commit and the POST no longer loses it silently and a briefly unreachable endpoint is retried instead of logged once.
- **Exports**: **SARIF 2.1.0** for GitHub code scanning / GitLab / Azure DevOps — which is what gets a finding out of the dashboard and onto the pull request that introduced it — plus an OpenVEX document built from the triage decisions, issues as CSV, and the stored SBOM.
- **User management** and **audit log**: roles (SUPERUSER/ADMIN/USER), guardrails (can't delete your own account or the last active superuser), traceability of sensitive actions.
- **Scanning that stays on the machine**: every scanner runs in an ephemeral container with the network disabled and a read-only mount. The OSV.dev and HTTP-sidecar backends the Python version offered are **not part of this port** — the sidecar was already documented as redundant, and OSV matching bought little that a pinned Grype image does not.

## Architecture

The pipeline is split in two along one line: **`ScanRunner` runs the scanners and never
touches the database; `ScanIngestor` reads its results and never runs a container.** That
split is what lets the same code execute inside the control plane or on a remote agent
that has no database credentials.

| Step | Tool | Image pinned by digest |
|---|---|---|
| SBOM | Syft | yes |
| Vulnerability matching | Grype | yes |
| Secrets | gitleaks | yes |
| IaC | checkov | yes |
| Source code (off by default) | Semgrep | yes |

Every scanner runs in an ephemeral container with **the network disabled**, a read-only
mount, `cap_drop: ALL` and `no-new-privileges`. Nothing about the scanned code leaves the
machine. The only outbound calls a scan makes are the EPSS and CISA KEV lookups, which
carry CVE identifiers and nothing else — and the end-of-life catalogue, which carries
product names and versions.

Results are normalized into a single `Finding` table (type, severity, identifier, package, source, EPSS/CVSS scores, KEV status, fix version), in addition to the raw JSON blobs (`Scan.sbom`, `Scan.cves`) kept for audit purposes.

A `Finding` is an *observation*, valid for one scan. Above it, an `Issue` tracks the same problem across scans — identified by a fingerprint that deliberately ignores the package version, so a dependency that stays vulnerable through three patch releases keeps one history and one triage decision. Two axes are kept strictly separate: `state` (open/resolved) is written only by the pipeline, from what the scanners observe; `triage_status` (VEX) is written only by a human. Conflating them would make "resolved" meaningless — a suppressed finding and a genuinely fixed one must not look alike. See [`backend/src/services/issue-sync.service.ts`](backend/src/services/issue-sync.service.ts).

The architecture dossier — overview, data model, security, deployment, and a decision register with the discarded alternatives — is in [`docs/architecture/`](docs/architecture/) (written in French). For diagrams of the layered architecture, the full database schema, and the scan pipeline's sequence flow, see [`docs/TECHNICAL_DOCUMENTATION.md`](docs/TECHNICAL_DOCUMENTATION.md).

### Distributed scanning: agents

A scan is executed by an **agent**. There are two kinds, and both are rows in the same
table, listed together on the `/agents` page:

- the **built-in agent** — this very web process. Created automatically at startup, no
  configuration, which is why a single-machine install works out of the box;
- **remote agents** — separate worker processes on other machines, speaking the four-route
  agent protocol (`hello`, `jobs`, `heartbeat`, `result`).

Both run the same code (`ScanRunner`), and both send back the scanners' raw output for
the control plane to normalize (`ScanIngestor`). A result produced on another machine is
therefore indistinguishable from a local one: same `Finding` rows, same EPSS/KEV
enrichment, same licence policy, same issue reconciliation.

Reasons to add a remote agent: keep the Docker socket off the host that serves the UI, reach
a repository or registry that is only routable from another network segment, or add
capacity. **Disabling the built-in agent** is how you say "run nothing here" — queued
scans then wait for a remote agent instead of quietly using the web instance.

A remote agent polls over HTTP with an API key carrying the `agent` scope, so it needs no
inbound port and **no database access**. That last point is a security property, not a
detail: an agent with a database connection would also need `ENCRYPTION_KEY`, i.e. the
ability to decrypt every deploy key Zanshin holds.

| Credentials mode | What the controller sends | When to use it |
|---|---|---|
| `local` (default) | nothing | the agent's own machine has git access. A compromised agent yields only what that machine was granted |
| `delegated` | the deploy key, per job | a trusted machine. Requires HTTPS (refused otherwise), the key is never written to disk beyond a `0600` temp file, and every delivery is audited |

```bash
# On the agent's machine — the key comes from /agents, shown once
ZANSHIN_URL=https://zanshin.internal \
ZANSHIN_AGENT_TOKEN=zsk_... \
node dist/agent/main.js
```

Or as a container, which is how it is meant to be deployed:

```bash
docker build -f Dockerfile.agent -t zanshin-agent .
docker run --rm -e ZANSHIN_URL=... -e ZANSHIN_AGENT_TOKEN=zsk_... \
  -v /var/run/docker.sock:/var/run/docker.sock zanshin-agent
```

The agent runs **the same `ScanRunner`** as the built-in worker, which is what makes a
result produced elsewhere indistinguishable from a local one. A layering test enforces
what it may import: `scanning/` and `domain/`, never `persistence/` — an agent with a
database connection would also need `ENCRYPTION_KEY`, i.e. the ability to decrypt every
deploy key Zanshin holds.

**Container image scans are distributed too**, and they carry no key at all: an image is
pulled from a registry, not cloned from git, so registry credentials belong to the Docker
configuration of whichever machine scans. Secrets, IaC and source-code analysis do not
apply to an image and stay `null` — declaring them scanned would silently resolve their
whole history for that target.

See [`docs/architecture/04-execution-et-deploiement.md`](docs/architecture/04-execution-et-deploiement.md)
for the decisions and the known limits.

**Running more than one web instance.** Most of what made that unsafe is now fixed: the
scan claim is transactional (`FOR UPDATE SKIP LOCKED`), the periodic work has exactly
one owner across the fleet, startup recovery no longer fails another worker's scans, and
and the login throttle is counted in the database rather than in process memory. What it requires:

- **PostgreSQL or MySQL** (`ZANSHIN_DATABASE_URL`, plus `ZANSHIN_DB_DIALECT=mysql` for the
  latter). Both keep a claimed scan from reaching two workers;
- **the migration as its own deployment step** (`npm --workspace backend run
  migration:run`), before the new instances start;
- nothing else. Sessions live in the database, not in process memory, so a client that
  lands on the other instance stays signed in — the Redis that the Reflex version needed
  for its state manager has no equivalent here.

The scheduler elects a single owner across the fleet, while every instance keeps claiming
work for its own built-in worker: a fleet whose instances only worked while holding the
lease would idle behind whichever one holds it.

Start it wrong and the application says so: it refuses, or warns, with the reason named.

## Quick start

Prerequisites: Node ≥ 24, Docker (for the scanners and, in development, for the database).

```bash
npm install
npm --workspace backend run start:dev     # API on http://localhost:3000
npm --workspace frontend start            # UI on http://localhost:4200
```

The schema is owned by **TypeORM migrations** — `synchronize` is off, deliberately: a
schema synthesised from the entities is not the one production will receive, and testing
against it would let a faulty migration through.

```bash
npm --workspace backend run migration:run       # apply
npm --workspace backend run migration:generate  # write one from the entities
```

### Main pages

| Route | Description |
|---|---|
| `/dashboard` | Overview |
| `/depots` | Tracked Git repositories, scan history, finding details |
| `/issues` | Issue backlog across scans, with triage (VEX) |
| `/containers` | Tracked container images |
| `/ssh-keys` | Encrypted SSH keys for cloning private repositories |
| `/api-keys` | Programmatic API keys (bcrypt hash, secret shown once) |
| `/agents` | Scan agents (built-in and remote), the queue, and leases (admin only) |
| `/settings` | Scan backend selection, enrichment toggle, license blocklist |
| `/users` | User management (admin only) |
| `/audit-log` | Audit log of sensitive actions (admin only) |
| `/api/v1/docs` | Interactive API reference (OpenAPI) |

## API and CI integration

The API is served from the same process and port as the UI, under `/api/v1`, and authenticates with a key created on the **API keys** page:

```bash
export ZANSHIN=http://localhost:3000
export ZANSHIN_KEY=zsk_...

# What can I scan?
curl -H "Authorization: Bearer $ZANSHIN_KEY" $ZANSHIN/api/v1/targets

# Scan, then poll
curl -X POST -H "Authorization: Bearer $ZANSHIN_KEY" -H 'Content-Type: application/json' \
     -d '{"repository_id": 1}' $ZANSHIN/api/v1/scans
curl -H "Authorization: Bearer $ZANSHIN_KEY" $ZANSHIN/api/v1/scans/42

# Should this build fail?
curl -X POST -H "Authorization: Bearer $ZANSHIN_KEY" -H 'Content-Type: application/json' \
     -d '{"repository_id": 1, "policy": {"fail_on_severity": "high", "fail_on_kev": true}}' \
     $ZANSHIN/api/v1/gate
```

The gate returns HTTP 200 with `{"passed": false, "violations": [...]}` when the policy is violated — a violated policy is an answer, not a transport error, and pipelines treat the two differently. Issues already triaged as *not affected* or *fixed* don't fail a build unless you ask for `include_triaged`.

The policy itself lives in the database, edited from the **Settings** page: a global default plus optional per-target overrides, each change stored as a new version with its author and an optional note. `GET /api/v1/gate/policies` lists what is in force and `.../history` every version of one scope — "which policy failed that build in March" has an answer.

A `policy` object in the request body is still accepted and can only make the rules **stricter**. Every field's strict direction is defined per field, since it does not mean "greater": a *lower* severity threshold is stricter; `fail_on_kev` and `include_triaged` are stricter when `true`; `fixable_only` is stricter when **`false`**, because `true` excludes issues with no published fix — which is exactly the case that needs a human decision, not a green build. Anything refused comes back in `policy.ignored_relaxations`, alongside the `source` and `version` actually applied.

Exports: `GET /api/v1/targets/{repository|container}/{id}/issues.sarif` (SARIF 2.1.0), `.../vex` (OpenVEX), `.../issues.csv`, and `GET /api/v1/scans/{id}/sbom` (the Syft SBOM as produced).

SARIF is the one that puts a finding in front of the developer who introduced it, annotated on the line, in the pull request:

```bash
curl -H "Authorization: Bearer $ZANSHIN_KEY" \
     -o zanshin.sarif "$ZANSHIN/api/v1/targets/repository/1/issues.sarif"
gh api -X POST /repos/{owner}/{repo}/code-scanning/sarifs \
     -f commit_sha="$GITHUB_SHA" -f ref="$GITHUB_REF" -f sarif="$(gzip -c zanshin.sarif | base64 -w0)"
```

Triaged issues are uploaded as SARIF *suppressions* rather than dropped: removing them would make the platform re-report them as new on the next upload, undoing the triage work, and the suppression carries the justification. Zanshin's own issue fingerprint travels as a `partialFingerprint`, so a platform still matches an issue after the file moves or the line shifts. Full reference at `/api/v1/docs` — which requires a key, like every other route: an anonymous map of the routes and payload shapes is a free reconnaissance step.

A key can be narrowed when it is created, and a CI key normally should be:

| Restriction | Effect |
|---|---|
| Scopes `read` / `scan` / `export` | What the key may do. A key that only publishes results needs `read`; one that queues scans needs `scan`. Missing scope → 403. |
| Target `repository:{id}` or `container:{id}` | What the key may reach — including the `/issues` listing and the exports, which are narrowed to that target. Another target → 403 (not 404: the caller already knows the id it asked for). |
| Expiry in days | After it, the key is refused as invalid. The row stays, so the listing still shows that the key existed. |

`GET /api/v1/issues` accepts `only_direct=true` to return just the packages the project declared itself — the subset a version bump fixes today, without waiting on an upstream release. Issues whose directness is unknown are excluded: a missing answer is not a positive one.

Defaults stay wide (every scope, every target, no expiry) because that is what a key granted before these existed, and because a form whose defaults break the pipeline teaches people to tick every box.

## Configuration

Runtime settings (enrichment, end-of-life, retention, notifications, licences, tracker, model review) are managed from the **Settings** page and stored in the `t_setting` table rather than as environment variables. A setting appears there only once a service actually reads it: a form that accepts a value and does nothing with it is worse than one that does not offer it.

Three things are *not* runtime settings, because they have to exist before the application can be used safely:

| Variable | Required | Purpose |
|---|---|---|
| `ENCRYPTION_KEY` | To store SSH keys | 32-byte key used to encrypt SSH private keys and tokens (AES-GCM). Without it, saving a secret is refused rather than written under something that cannot protect it. The application no longer carries a default key: it used to ship one in its own source, which meant a copy of the database file was enough to read every stored private key. |
| `ZANSHIN_SEMGREP_RULES_DIR` | To widen Semgrep's coverage | A directory of extra Semgrep rules, merged with the ones Zanshin ships. Zanshin only carries its own: the public Semgrep rule sets are not redistributable, so you install the set you choose on your own machine and point this variable at it. Fetch it once at install time — the scan itself stays offline. The Python port shipped a `fetch_semgrep_rules` helper for this; it has **not** been ported, so the download is currently manual. |
| `ZANSHIN_PREVIOUS_ENCRYPTION_KEYS` | To rotate `ENCRYPTION_KEY` | Comma-separated older keys, tried for **decryption only**. Values move to the current key as they are re-saved, and the SSH keys page marks the rows that still depend on an older one — so the variable can be dropped once none remain. Also how a value encrypted with the old published default key is read one last time; see [`docs/ROTATION_ET_PURGE.md`](docs/ROTATION_ET_PURGE.md). |
| `ZANSHIN_BOOTSTRAP_USERNAME` | First run only | Username of the initial SUPERUSER, created at startup when the `user` table is empty. |
| `ZANSHIN_BOOTSTRAP_PASSWORD` | First run only | Its password (8 characters minimum). |

Operational tuning (all optional, shown with their defaults):

| Variable | Default | Purpose |
|---|---|---|
| `ZANSHIN_DATABASE_URL` | — | PostgreSQL connection URL. Required: there is no file-backed default any more, and there is a reason for that below. |
| `ZANSHIN_DB_DIALECT` | `postgres` | One of `postgres`, `mysql`, `mariadb`, `sqlite`. Selects the migration set and the spelling of the column types, and declares at startup what the engine cannot do (see `dialects.ts`). |
| `PORT` | `3000` | HTTP port of the API. |
| `ZANSHIN_PUBLIC_URL` | — | Public base URL, used in exports and tracker tickets so a link written today still resolves tomorrow. |
| `ZANSHIN_EMBEDDED_WORKER` | `true` | `false` for a control plane that runs no scan itself. Queued scans then wait for a remote agent instead of quietly using the web instance. |
| `ZANSHIN_SCAN_MAX_CONCURRENT` | `2` | Concurrent scans for this instance's built-in worker. |
| `ZANSHIN_SCAN_LEASE_SECONDS` / `_MAX_ATTEMPTS` / `_CLAIM_ATTEMPTS` | `900` / `3` / `3` | Lease held on a claimed scan, retries before it is abandoned, and retries of the claim itself under contention. |
| `ZANSHIN_SCAN_TIMEOUT_SECONDS` | `900` | Ceiling for a single scanner container; past it the container is killed and the scan fails with a timeout instead of hanging. |
| `ZANSHIN_SCAN_MEMORY_LIMIT_MB` / `_PIDS_LIMIT` | `2048` / `512` | Memory and process ceilings per scanner container. |
| `ZANSHIN_SCHEDULER_ENABLED` | `true` | `false` for a deployment that only scans on demand. |
| `ZANSHIN_SCHEDULER_TICK_SECONDS` | `60` | How often due targets are looked for. |
| `ZANSHIN_LEADER_LEASE_SECONDS` | `180` | How long the scheduler lease is held without renewal. Comfortably longer than one tick, so a slow tick does not hand the job to somebody else; short enough that a dead leader is replaced in about two minutes. |
| `ZANSHIN_SYFT_IMAGE` / `_GRYPE_` / `_GITLEAKS_` / `_CHECKOV_` / `_SEMGREP_` | pinned digests | Scanner images. Pinned by digest, not by tag: they execute on the scanning host and read input nobody controls, so they *are* Zanshin's supply chain — whoever controls `anchore/syft:latest` controls what runs there. Update deliberately with `docker buildx imagetools inspect <image>:latest`. |
| `ZANSHIN_IMAGE_SCAN_PLATFORM` | — | Platform to pull for a container scan, e.g. `linux/amd64` — the image scanned should be the one that runs in production, not the one that matches the scanner's host. |
| `ZANSHIN_SESSION_TTL_HOURS` / `_IDLE_MINUTES` | `12` / `60` | Absolute and idle session lifetimes. |
| `ZANSHIN_VEX_AUTHOR` | `Zanshin` | Author recorded in OpenVEX documents — a VEX is an assertion about who said what, and when. |
| `ZANSHIN_SQL_LOGGING` | `false` | Logs every statement. For diagnosis, never for a running deployment. |



The database file is not part of the repository (it holds password hashes and encrypted SSH keys), so a fresh deployment starts with no accounts — hence the bootstrap variables. Once an account exists, they are ignored.

### Choosing a database

Four engines are supported — PostgreSQL, MariaDB, MySQL and SQLite — and **each is
exercised by the full integration campaign**, with its own migration set. Set
`ZANSHIN_DB_DIALECT`; PostgreSQL is the default. A portability defect is invisible to
reading and to a single engine; running all four is the only way it gets found, and it
found several.

| | PostgreSQL | MariaDB | MySQL | SQLite |
|---|---|---|---|---|
| Transactional scan claim | yes | yes | yes | **no** |
| Complete claim batch under contention | yes | yes | **no** | n/a |
| Millisecond timestamps | yes | yes | yes | yes |
| `NULLS LAST` | yes | no | no | yes |
| Concurrent writers | yes | yes | yes | **no** |

Every "no" comes from a defect found by running, and **none of them raises an error**:

- **MySQL returns short claim batches.** Rows skipped by `SKIP LOCKED` count against the
  `LIMIT`, so a worker asking for two scans may get none while the queue is not empty. No
  row is ever handed to two workers — measured, not assumed — and the rest goes out on the
  next tick. It is a throughput characteristic, not a correctness defect. MariaDB, measured
  on the same scenario, returns a complete batch like PostgreSQL.
- **SQLite has a single writer.** A second instance on the same file would not be slow, it
  would corrupt data. Its claim therefore falls back to a conditional `UPDATE` guarded by
  the status column, which is correct for threads of one process. Its driver **refuses**
  `FOR UPDATE` rather than ignoring it — the Python stack dropped it silently, producing a
  claim that looked transactional and handed the same scan to two processes in production.
- **Timestamps need declared precision on MySQL.** A bare `DATETIME` truncates to the
  second, which would make the audit chain fail its own verification and declare itself
  tampered with. `datetime(6)` is declared in `column-types.ts`, in one place rather than
  column by column, and the connection is pinned to UTC for the same reason.

PostgreSQL remains the reference engine: the one where everything is true without
reservation, and the one the code picks by default.


## Tests

```bash
npm --workspace backend test              # unit suite
npm --workspace backend run test:integration   # starts PostgreSQL via testcontainers
```

562 unit tests and 249 integration tests. **The integration suites do not skip.** They used
to begin with `const describeWithPostgres = connectionString ? describe : describe.skip`:
without a database URL, twelve files silently skipped themselves and the run reported green
having verified nothing. The harness now starts the container itself, so a missing Docker
fails loudly — which is the correct behaviour, and exactly the class of defect this project
exists to find.

Migrations rather than `synchronize`, for the same reason: the schema under test is the one
production will receive.

```bash
uvx pyright
```

The backend compiles under `strictNullChecks` and a **layering test**
(`architecture.spec.ts`) that fails the build when an import crosses the wrong way. That
test is not decoration: it is what keeps the domain layer — fingerprints, gate verdicts,
schedules — free of TypeORM and HTTP, and therefore testable without a database.

The lesson kept from the Python version's type checking still applies: a gate that fires on
noise is switched off within a week. So the rules here are the ones whose findings were all
real.

## Project structure

```
backend/src/
├── domain/            # Pure rules: fingerprint, gate, exports, schedule, payloads
├── scanning/          # Runs the scanners — no database (agent side)
├── persistence/       # TypeORM entities and migrations
├── repositories/      # Data access, no business rules
├── services/          # Orchestration: ingestion, issues, notifications, tickets
└── api/               # HTTP controllers
frontend/src/app/      # Angular: 15 screens, Sakai layout over Optimus UI
docs/architecture/     # ADR
```

The import direction is enforced by a test (`architecture.spec.ts`):
`domain ← scanning ← persistence ← repositories ← services ← api`. The domain layer knows
nothing of TypeORM or HTTP, which is what makes the rules that matter — a fingerprint, a
gate verdict, a due date — testable without a database.

