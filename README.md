# Zanshin

**[English](#english)** | **[Français](#français)**

---

## English

Zanshin is a software dependency and security tracking application built around SBOM (Software Bill of Materials) analysis. It scans Git repositories and container images, detects known vulnerabilities, hardcoded secrets, problematic licenses, and infrastructure-as-code misconfigurations, then centralizes the results in a single dashboard — in the spirit of a unified ASPM (Application Security Posture Management) platform, with a pluggable scanning layer (local Docker, local API, or cloud API depending on the analysis type).

Built in Python with [Reflex](https://reflex.dev) (server-side state and UI) and SQLAlchemy/SQLite.

### Features

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
  Zanshin; see [the rule directory](zanshin/services/scanners/rules/semgrep/README.md)
  for how to add your own.
- **Issue tracking and triage**: every finding is tracked across scans as an *issue* — first seen, times seen, whether a fix exists, and a triage decision in VEX vocabulary (affected / not affected / fixed / under review) with a justification, and optionally a **review date**. A suppression is a statement about a context — "not reachable in our configuration", "not shipped in production" — and contexts change; at its review date the issue returns to *under review* with its justification and comment intact. Each scan reports what it *changed*: new issues, resolved issues.
- **Periodic rescanning**: each target carries a scan interval *or* a cron expression, honoured by a built-in scheduler — the point being that new vulnerabilities appear in code that hasn't changed. The expression wins when both are set: an interval drifts a few minutes each run, so a scan configured for the quiet hours eventually runs in the middle of the day.
- **HTTP API and CI policy gate**: trigger scans, read issues, and ask "should this build fail?" against a **stored, versioned policy** — global, or per target. The rules used to arrive in the request body, which meant each project decided its own bar; a request can now only *tighten* the stored policy, never loosen it, and the verdict says which policy it applied. Authenticated with the API keys the UI issues.
- **Tracker tickets** (GitLab, Jira): opens one ticket per problem that would fail a build, using the same policy — one threshold, defined once. The reference is kept on the issue, so a tracker outage is retried and never duplicated.
- **Notifications**: a webhook fires when a scan makes something appear or reappear — not on every scan, which is what keeps the channel readable. The message is written to an **outbox in the same transaction as the scan's results** and delivered by the scheduler with capped exponential backoff, so a crash between the commit and the POST no longer loses it silently and a briefly unreachable endpoint is retried instead of logged once.
- **Exports**: **SARIF 2.1.0** for GitHub code scanning / GitLab / Azure DevOps — which is what gets a finding out of the dashboard and onto the pull request that introduced it — plus an OpenVEX document built from the triage decisions, issues as CSV, and the stored SBOM.
- **User management** and **audit log**: roles (SUPERUSER/ADMIN/USER), guardrails (can't delete your own account or the last active superuser), traceability of sensitive actions.
- **Interchangeable scan backends**: local Docker (default, nothing leaves the machine), OSV.dev (vulnerability matching via a free cloud API), or a self-hosted HTTP sidecar service (`scan-api/`) — selectable from the Settings page without changing the rest of the application.

### Architecture

The central design choice is the `ScannerEngine` interface (`zanshin/services/scanners/base.py`), which decouples *what* to scan from *where/how* it runs. `ScanProcessor` orchestrates the steps (clone, SBOM, vulnerability scan, secrets, IaC) without ever calling Docker directly — it delegates to whichever implementation is configured:

| Backend | SBOM / secrets / IaC generation | Vulnerability matching | Use case |
|---|---|---|---|
| `docker` (default) | Ephemeral Docker containers (Syft/gitleaks/checkov/Semgrep) | Grype (local container) | No external dependency, fully local |
| `osv` | Delegated to the local Docker backend | OSV.dev cloud API (free) | CVE matching without maintaining Grype locally |
| `local_api` | HTTP sidecar service (`scan-api/`), same host, shared disk | Same, via the sidecar | Removes Docker socket access from the main process |

Results are normalized into a single `Finding` table (type, severity, identifier, package, source, EPSS/CVSS scores, KEV status, fix version), in addition to the raw JSON blobs (`Scan.sbom`, `Scan.cves`) kept for audit purposes.

A `Finding` is an *observation*, valid for one scan. Above it, an `Issue` tracks the same problem across scans — identified by a fingerprint that deliberately ignores the package version, so a dependency that stays vulnerable through three patch releases keeps one history and one triage decision. Two axes are kept strictly separate: `state` (open/resolved) is written only by the pipeline, from what the scanners observe; `triage_status` (VEX) is written only by a human. Conflating them would make "resolved" meaningless — a suppressed finding and a genuinely fixed one must not look alike. See [`zanshin/services/issue_service.py`](zanshin/services/issue_service.py).

The architecture dossier — overview, data model, security, deployment, and a decision register with the discarded alternatives — is in [`docs/architecture/`](docs/architecture/) (written in French). The `scan-api/` sidecar has its own [README](scan-api/README.md) (deployment model, security, known limitations). For diagrams of the layered architecture, the full database schema, and the scan pipeline's sequence flow, see [`docs/TECHNICAL_DOCUMENTATION.md`](docs/TECHNICAL_DOCUMENTATION.md).

#### Distributed scanning: agents

A scan is executed by an **agent**. There are two kinds, and both are rows in the same
table, listed together on the `/agents` page:

- the **built-in agent** — this very web process. Created automatically at startup, no
  configuration, which is why a single-machine install works out of the box;
- **remote agents** — separate `python -m zanshin.agent` processes on other machines.

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
python -m zanshin.agent
```

See [`docker-compose.agent.yml`](docker-compose.agent.yml) for the containerized form, and
[`docs/architecture/04-execution-et-deploiement.md`](docs/architecture/04-execution-et-deploiement.md)
for the decisions and the known limits.

**Running more than one web instance.** Most of what made that unsafe is now fixed: the
scan claim is transactional (`FOR UPDATE SKIP LOCKED`), the periodic work has exactly
one owner across the fleet, startup recovery no longer fails another worker's scans, and
the API quota and login throttle are shared through Redis. What it requires:

- **PostgreSQL** (`ZANSHIN_DATABASE_URL`). SQLite has one writer and no `SKIP LOCKED`;
  a second instance on it is refused at startup rather than left to corrupt the file;
- **`REDIS_URL`**, both for Reflex's own state manager — without it a client that lands
  on the other instance is intermittently logged out — and for the security counters;
- **`ZANSHIN_AUTO_MIGRATE=false`**, with `alembic upgrade head` as its own deployment
  step: the migration lock is a file lock and coordinates one host only.

Start it wrong and the application says so: it refuses, or warns, with the reason named.

### Quick start

Prerequisites: Python ≥ 3.12, [uv](https://docs.astral.sh/uv/), Docker (for the default scan backend).

```bash
uv sync
uv run reflex run
```

The app starts on `http://localhost:3000` (frontend), with the backend API on Reflex's default port.

The schema is managed by **Alembic**. On startup Zanshin brings the database to the latest revision by itself; a database that predates Alembic is adopted (stamped at the baseline revision) rather than rebuilt, so upgrading an existing deployment needs no manual step. Migrations can also be driven by hand:

```bash
uv run alembic upgrade head     # apply
uv run alembic check            # fail if a model has no matching migration
uv run alembic revision --autogenerate -m "what changed"
```

#### Main pages

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

### API and CI integration

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

### Configuration

Runtime settings (`scan_backend`, `enrichment_enabled`, `license_blocklist`, `local_api` backend URL and shared directory) are managed from the **Settings** page and stored in the database (`setting` table) rather than as environment variables.

Three things are *not* runtime settings, because they have to exist before the application can be used safely:

| Variable | Required | Purpose |
|---|---|---|
| `ENCRYPTION_KEY` | To store SSH keys | 32-byte key used to encrypt SSH private keys and tokens (AES-GCM). Without it, saving a secret is refused rather than written under something that cannot protect it. The application no longer carries a default key: it used to ship one in its own source, which meant a copy of the database file was enough to read every stored private key. |
| `ZANSHIN_SEMGREP_RULES_DIR` | To widen Semgrep's coverage | A directory of extra Semgrep rules, merged with the ones Zanshin ships. Zanshin only carries its own: the public Semgrep rule sets are not redistributable, so `scripts/fetch_semgrep_rules.py` installs the set you choose on your own machine. Run once at install time — the scan itself stays offline. |
| `ZANSHIN_PREVIOUS_ENCRYPTION_KEYS` | To rotate `ENCRYPTION_KEY` | Comma-separated older keys, tried for **decryption only**. Values move to the current key as they are re-saved, and the SSH keys page marks the rows that still depend on an older one — so the variable can be dropped once none remain. Also how a value encrypted with the old published default key is read one last time; see [`docs/ROTATION_ET_PURGE.md`](docs/ROTATION_ET_PURGE.md). |
| `ZANSHIN_BOOTSTRAP_USERNAME` | First run only | Username of the initial SUPERUSER, created at startup when the `user` table is empty. |
| `ZANSHIN_BOOTSTRAP_PASSWORD` | First run only | Its password (8 characters minimum). |

Operational tuning (all optional, shown with their defaults):

| Variable | Default | Purpose |
|---|---|---|
| `ZANSHIN_DB_PATH` | `zanshin/database.sqlite` | Path to the SQLite file. The simplest way to keep the data outside the source tree; made absolute, because a relative path resolves against the working directory and that differs between `reflex run`, `alembic` and a service unit. |
| `ZANSHIN_DATABASE_URL` | derived from `ZANSHIN_DB_PATH` | Full SQLAlchemy URL, for anything that is not a local file — e.g. `postgresql+psycopg://user:password@host/zanshin`. Takes precedence over `ZANSHIN_DB_PATH`. Requires the driver: `uv sync --extra postgres`. |
| `ZANSHIN_DB_TIMEOUT_SECONDS` | `30` | SQLite only: how long a write waits for a concurrent writer before failing. Scan workers, the scheduler and requests all write, so contention is normal. |
| `ZANSHIN_DB_POOL_SIZE` / `_MAX_OVERFLOW` / `_POOL_RECYCLE_SECONDS` | `5` / `10` / `1800` | Server databases only: connection pool. Ignored for SQLite, which has no pool worth tuning. |
| `ZANSHIN_AUTO_MIGRATE` | `true` | Set to `false` for a deployment that runs `alembic upgrade head` as its own step — which is what a server database on several application hosts should do. The schema is still *checked* at startup: a database behind the code stops the application there rather than at the first query. |
| `REDIS_URL` | — | Shares the API quota and the login throttle between instances. Without it they are counted per process, which is correct for one instance and means the quota doubles for two. Reflex reads the same variable for its own state manager, which a fleet needs anyway. |
| `ZANSHIN_ALLOW_MULTI_INSTANCE_SQLITE` | `false` | Lifts the startup refusal that fires when another instance is live and the database is SQLite. Its only legitimate use is a restart under a *new* hostname within two minutes of the previous one stopping — a Kubernetes rolling restart. It does not make two instances safe on SQLite. |
| `ZANSHIN_SCAN_WORKERS` | `5` | *Default* for the "maximum concurrent scans" setting, which is now edited from the **Settings** page and applied without a restart. Scans are queued in the order they were requested; the queue lives in the database, so a request survives a restart and its place in line is answerable (`queue_position` on `GET /api/v1/scans/{id}`). |
| `ZANSHIN_SCAN_POOL_THREADS` | `32` | Hard ceiling on scan threads, and therefore on the setting above. The pool is a supply of threads, not the queue — a pool smaller than the configured limit would silently cap it. |
| `ZANSHIN_SCAN_TIMEOUT_SECONDS` | `900` | Ceiling for a single scanner container; past it, the container is killed and the scan fails with a timeout instead of hanging. |
| `ZANSHIN_SCHEDULER_ENABLED` | `true` | Set to `false` for a deployment that only scans on demand. |
| `ZANSHIN_SCHEDULER_TICK_SECONDS` | `60` | How often due targets are looked for. |
| `ZANSHIN_STALLED_SCAN_MAX_AGE_SECONDS` | `5400` | Age past which a scan still in flight is considered wedged and failed. |
| `ZANSHIN_RETENTION_INTERVAL_SECONDS` | `21600` | How often raw scanner payloads are pruned (see the **Settings** page for the thresholds themselves). |
| `ZANSHIN_SCAN_MEMORY_LIMIT` | `2g` | Memory ceiling per scanner container. |
| `ZANSHIN_SCAN_PIDS_LIMIT` | `512` | Process ceiling per scanner container. |
| `ZANSHIN_SYFT_IMAGE` / `_GRYPE_` / `_GITLEAKS_` / `_CHECKOV_` | pinned digests | Scanner images. Pinned by digest, not by tag: they run with the Docker socket mounted, so they are Zanshin's own supply chain. Update deliberately with `docker buildx imagetools inspect <image>:latest`. |
| `ZANSHIN_ALLOWED_ORIGINS` | `http://localhost:3000,http://127.0.0.1:3000` | Comma-separated origins allowed to open the websocket. Reflex's default is `*`, which lets any page a user visits create server-side state. **Set this to your real hostname when deploying anywhere but localhost** — otherwise the app's own frontend is refused. |
| `ZANSHIN_SESSION_TTL_HOURS` | `12` | A session older than this is signed out on the next page load. |
| `ZANSHIN_API_RATE_LIMIT` / `ZANSHIN_API_RATE_WINDOW_SECONDS` | `300` / `60` | Requests per key per window, before 429 with `Retry-After`. Counted in memory, per process. |
| `ZANSHIN_MIGRATION_LOCK` | next to the database | Lock file serialising `alembic upgrade` at startup. Reflex imports the app in several processes, and SQLite's DDL is not transactional: without this, two concurrent upgrades can leave the schema half-migrated. |

The sidecar (`scan-api/`) additionally requires `ZANSHIN_SCAN_API_TOKEN` (matched by the `local_scan_api_token` setting) and `ZANSHIN_SHARED_ROOT`. It refuses every request without the token, and refuses any path outside that root — see [`scan-api/README.md`](scan-api/README.md).

The database file is not part of the repository (it holds password hashes and encrypted SSH keys), so a fresh deployment starts with no accounts — hence the bootstrap variables. Once an account exists, they are ignored.

#### Choosing a database

SQLite is the default and is what this deployment is exercised against: one file, no
server, and the scan pipeline's write volume is nowhere near its limits. Point it
somewhere durable and back that up — that file is the whole installation.

```bash
ZANSHIN_DB_PATH=/var/lib/zanshin/zanshin.sqlite
```

PostgreSQL is the other supported backend, verified by tests that start a real server —
`pytest -m backends` runs the whole schema and every service that owns a column against
PostgreSQL 16 via testcontainers. They are excluded from the default run because an image
pull has no place in the loop you run on every edit. One thing to know before choosing it.

**MySQL was supported and was withdrawn.** It filled no role the other two did not: it is
neither the zero-configuration option nor the deployment target, and it had its own
behaviour in three places that matter — `DATETIME` truncated to whole seconds, so every
audit-log entry reported itself as tampered with; `SKIP LOCKED` counted skipped rows
against `LIMIT`, so concurrent scan claims came back empty; `NULLS LAST` was a syntax
error. Three dialect branches in code whose subject is integrity, for no gain. A MySQL URL
is now refused at startup with that explanation rather than half-working.

```bash
uv sync --extra postgres
ZANSHIN_DATABASE_URL=postgresql+psycopg://zanshin:...@db.internal/zanshin
ZANSHIN_AUTO_MIGRATE=false        # run `alembic upgrade head` as a deployment step
```

- **Foreign keys are enforced there and not on SQLite**, which ignores them unless
  asked per connection. This schema's cascades are declared ORM-side and
  `Issue.findings` has none, so a delete that quietly orphans rows today would raise
  on a server database. Not yet fixed — it needs `ondelete` rules and a migration.
- **Timestamps are stored as ISO-8601 strings**, not as `timestamptz`/`DATETIME`.
  That is what `SafeDateTime` does, and it is deliberate (it exists to read the
  several formats the pre-Alembic schema left behind), but it means date arithmetic
  in SQL is not available on those columns. Ordering and comparison work, because
  ISO-8601 sorts lexicographically.

Migrations run on either. `alembic` reads the same two variables as the application,
so the command line and the running app can never disagree about which database they
are looking at.

### Tests

```bash
uv run pytest
```

~82% coverage over `zanshin/`, UI layer included. The two halves of the UI are checked by different means: page loaders and event handlers by state-level tests (see the `UIHarness` in `tests/conftest.py`, which drives a Reflex state outside the server), and the component trees by `uv run reflex compile --dry`, which fails on a mistyped attribute of a typed row model. Every test runs against an in-memory SQLite database, never against `zanshin/database.sqlite`.

```bash
uv run pytest -m backends     # needs Docker
```

Additionally, a cross-backend suite starts a real PostgreSQL 16 server with testcontainers, applies every migration and pushes a row through each custom column type and each service that owns one. It is excluded from the default run (`addopts = -m 'not backends'`) because an image pull does not belong in the loop you run on every edit, and it skips itself when Docker is unavailable. It exists because every portability defect this schema had was invisible both to SQLite and to reading the code — a `BINARY` type PostgreSQL has no name for, `FROM user` resolving to a function instead of a table, `VARCHAR` without a length, a `BIGINT` foreign key onto an `INT` key, `DROP INDEX IF EXISTS`, `NULLS LAST`. Six of them, all found by running.

### Project structure

```
zanshin/
├── models/          # SQLAlchemy models
├── repositories/     # Data access
├── services/         # Business logic (scanning, enrichment, users, audit...)
│   ├── scanners/      # ScannerEngine implementations (docker, osv, local_api)
│   ├── scan_runner.py     # Runs the scanners — no database (agent side)
│   └── scan_ingestor.py   # Normalizes results — database only (controller side)
├── agent/             # The remote agent: `python -m zanshin.agent`
├── ui/                # Reflex pages, state, and typed view models
├── api/               # HTTP API (FastAPI, mounted on the Reflex app)
├── scan_contract.py   # Task/result shapes shared by runner and ingestor
├── schema.py          # Alembic bootstrap at startup
├── clock.py           # The single source of "now"
└── container.py       # Dependency injection (IoCContainer)
migrations/            # Alembic revisions
scan-api/              # HTTP sidecar service (local_api backend)
tests/                 # pytest suite
docs/architecture/     # ADR
```

---

## Français

Zanshin est une application de suivi des dépendances et de sécurité logicielle, basée sur l'analyse de SBOM (Software Bill of Materials). Elle scanne des dépôts Git et des images de conteneurs, détecte les vulnérabilités connues, les secrets codés en dur, les licences problématiques et les mauvaises configurations d'infrastructure (IaC), puis centralise les résultats dans un tableau de bord unique — dans l'esprit d'une plateforme ASPM (Application Security Posture Management) unifiée, avec une couche de scan pluggable (Docker local, API locale, ou API cloud selon le type d'analyse).

Construit en Python avec [Reflex](https://reflex.dev) (état et UI gérés côté serveur) et SQLAlchemy/SQLite.

### Fonctionnalités

- **Analyse SCA (dépendances)** : génération de SBOM (Syft) et détection de vulnérabilités connues (Grype ou OSV.dev), avec sévérité, CVE et composant concerné.
- **Enrichissement EPSS / CISA KEV** : chaque vulnérabilité est complétée par sa probabilité d'exploitation (EPSS) et son statut "activement exploitée" (catalogue KEV), pour prioriser au-delà du seul score CVSS.
- **Dépendances directes ou transitives** : chaque problème indique si le projet a déclaré le paquet lui-même ou si autre chose l'a tiré, d'après le graphe de dépendances du SBOM. Un CVE critique dans une dépendance déclarée se corrige cet après-midi ; le même quatre niveaux plus bas attend une publication amont. Classés à l'identique, ils produisent un backlog que personne ne termine — la liste peut donc être restreinte à ce qui est corrigeable aujourd'hui. Inconnu quand le SBOM ne porte aucun graphe : une réponse absente plutôt qu'une réponse par défaut.
- **Détection de secrets** (gitleaks) : recherche de clés API, tokens et identifiants codés en dur dans les dépôts scannés.
- **Conformité des licences** : évaluation d'une liste noire de licences configurable, à partir des données déjà présentes dans le SBOM.
- **Détection de fin de vie** (endoflife.date) : signale les plateformes et exécutions dont le support de sécurité est terminé — la distribution du conteneur en premier lieu. Toute une classe de risque sans CVE : aucun correctif ne sera publié pour la *prochaine* faille, quelle qu'elle soit. La couverture porte volontairement sur des produits (langages, exécutions, frameworks, distributions), pas sur chaque bibliothèque.
- **Scan IaC** (checkov) : détection de mauvaises configurations Terraform/Kubernetes dans les dépôts.
- **Rubriques Sécurité et Qualité.** La navigation est regroupée : *Sécurité* réunit une
  vue d'ensemble qui affiche enfin le verdict du gate par cible — calculé depuis
  l'apparition des politiques et montré nulle part jusqu'ici — avec le backlog, les dépôts
  et les conteneurs. *Qualité* classe les constats de qualité par règle, par fichier et par
  dépôt, et dit clairement qu'aucun ne peut faire échouer une compilation. La vue
  d'ensemble nomme aussi les deux états qu'aucun écran ne montrait : une cible jamais
  scannée, et une cible dont le dernier scan a échoué — toutes deux ont un backlog vide, et
  un backlog vide satisfait toutes les politiques.
- **Analyse du code source** (Semgrep, désactivée par défaut) : lit le code lui-même —
  requête SQL concaténée, commande passée au shell, certificat TLS non vérifié — ce
  qu'aucun autre scanner ne voit ici. Produit deux natures de constats : *sécurité*,
  traités comme toute vulnérabilité, et *qualité*, visibles dans le backlog mais
  incapables de faire échouer un gate CI. Tourne réseau coupé, avec des règles embarquées
  dans Zanshin ; voir [le répertoire de règles](zanshin/services/scanners/rules/semgrep/README.md)
  pour en ajouter.
- **Suivi et triage des problèmes** : chaque finding est suivi d'un scan à l'autre sous forme de *problème* — première détection, nombre de fois vu, existence d'un correctif, et décision de triage en vocabulaire VEX (affecté / non affecté / corrigé / à examiner) avec justification, et éventuellement une **date de révision**. Une suppression porte sur un contexte — « pas atteignable dans notre configuration », « pas livré en production » — et les contextes changent ; à l'échéance, le problème revient *à examiner*, justification et commentaire conservés. Chaque scan indique ce qu'il a **changé** : problèmes apparus, problèmes résolus.
- **Rescan périodique** : chaque cible porte un intervalle de scan, honoré par un ordonnanceur intégré — l'intérêt étant que de nouvelles vulnérabilités apparaissent dans du code qui n'a pas bougé.
- **API HTTP et *policy gate* CI** : déclencher un scan, lire les problèmes, et demander « ce build doit-il échouer ? » selon une **politique stockée et versionnée** — globale, ou par cible. Ces règles arrivaient auparavant dans le corps de la requête, donc chaque projet décidait du seuil qu'on lui appliquait ; une requête peut désormais seulement *durcir* la politique stockée, jamais l'assouplir, et le verdict indique laquelle a été appliquée. Authentifiée par les clés API émises depuis l'UI.
- **Tickets** (GitLab, Jira) : ouvre un ticket par problème qui ferait échouer un build, selon la même politique — un seul seuil, défini une seule fois. La référence est conservée sur le problème, donc une panne du gestionnaire est réessayée sans jamais dupliquer.
- **Notifications** : un webhook part quand un scan fait apparaître ou réapparaître quelque chose — pas à chaque scan, c'est ce qui garde le canal lisible. Le message est écrit dans un **outbox, dans la même transaction que les résultats du scan**, puis livré par l'ordonnanceur avec réessais espacés et plafonnés : un arrêt brutal entre la validation et l'envoi ne le perd plus en silence, et un point d'arrivée momentanément injoignable est réessayé au lieu d'être journalisé une fois.
- **Exports** : **SARIF 2.1.0** pour GitHub code scanning / GitLab / Azure DevOps — c'est ce qui sort un problème du tableau de bord pour l'amener sur la pull request qui l'a introduit — plus un document OpenVEX construit à partir des décisions de triage, les problèmes en CSV, et le SBOM stocké.
- **Gestion des utilisateurs** et **journal d'audit** : rôles (SUPERUSER/ADMIN/USER), garde-fous (impossible de supprimer son propre compte ou le dernier superutilisateur actif), traçabilité des actions sensibles.
- **Backends de scan interchangeables** : Docker local (par défaut, rien ne sort de la machine), OSV.dev (matching de vulnérabilités via API cloud gratuite) ou un service HTTP sidecar auto-hébergé (`scan-api/`) — au choix depuis la page Paramètres, sans changer le reste de l'application.

### Architecture

Le choix de conception central est l'interface `ScannerEngine` (`zanshin/services/scanners/base.py`), qui découple *quoi* scanner de *où/comment* c'est exécuté. `ScanProcessor` orchestre les étapes (clone, SBOM, scan de vulnérabilités, secrets, IaC) sans jamais appeler Docker directement — il délègue à l'implémentation configurée :

| Backend | Génération SBOM / secrets / IaC | Matching de vulnérabilités | Cas d'usage |
|---|---|---|---|
| `docker` (défaut) | Conteneurs Docker éphémères (Syft/gitleaks/checkov/Semgrep) | Grype (conteneur local) | Aucune dépendance externe, 100 % local |
| `osv` | Délégué au backend Docker local | API cloud OSV.dev (gratuite) | Matching CVE sans maintenir Grype localement |
| `local_api` | Service HTTP sidecar (`scan-api/`), même hôte, disque partagé | Idem, via le sidecar | Retire l'accès au socket Docker du processus principal |

Les résultats sont normalisés dans une table `Finding` unique (type, sévérité, identifiant, package, source, scores EPSS/CVSS, statut KEV, version corrigée) en plus des blobs JSON bruts (`Scan.sbom`, `Scan.cves`) conservés pour l'audit.

Un `Finding` est une *observation*, valable pour un seul scan. Au-dessus, un `Issue` suit le même problème d'un scan à l'autre — identifié par une empreinte qui ignore volontairement la version du paquet, pour qu'une dépendance restée vulnérable pendant trois versions correctives conserve un seul historique et une seule décision de triage. Deux axes sont maintenus strictement séparés : `state` (ouvert/résolu) n'est écrit que par le pipeline, d'après ce que les scanners observent ; `triage_status` (VEX) n'est écrit que par un humain. Les confondre viderait « résolu » de son sens — un finding masqué et un finding réellement corrigé ne doivent pas se ressembler. Voir [`zanshin/services/issue_service.py`](zanshin/services/issue_service.py).

Le dossier d'architecture — vue d'ensemble, modèle de données, sécurité, déploiement, et un registre des décisions avec les alternatives écartées — est dans [`docs/architecture/`](docs/architecture/). Le service sidecar `scan-api/` a son propre [README](scan-api/README.md) (modèle de déploiement, sécurité, limites connues). Pour les diagrammes de l'architecture en couches, le schéma complet de la base de données et le déroulé du pipeline de scan, voir [`docs/TECHNICAL_DOCUMENTATION.md`](docs/TECHNICAL_DOCUMENTATION.md).

#### Scan distribué : les agents

Un scan est exécuté par un **agent**. Il y en a deux sortes, qui sont des lignes de la
même table et apparaissent ensemble sur la page `/agents` :

- l'**agent intégré** — ce processus web lui-même. Créé automatiquement au démarrage,
  aucune configuration : c'est ce qui fait qu'une installation sur une seule machine
  fonctionne d'emblée ;
- les **agents distants** — des processus `python -m zanshin.agent` séparés, sur d'autres
  machines.

Les deux exécutent le même code (`ScanRunner`) et renvoient les sorties brutes des
outils, que le plan de contrôle normalise (`ScanIngestor`). Un résultat produit sur une
autre machine est donc indiscernable d'un résultat local : mêmes `Finding`, même
enrichissement EPSS/KEV, même politique de licences, même rapprochement des problèmes.

Raisons d'ajouter un agent distant : retirer le socket Docker de la machine qui sert
l'UI, atteindre un dépôt ou un registre joignable seulement depuis un autre segment
réseau, ou ajouter de la capacité. **Désactiver l'agent intégré** est la façon de dire
« n'exécute rien ici » : les scans en file attendent alors un agent distant au lieu
d'utiliser discrètement l'instance web.

Un agent distant interroge le contrôleur en HTTP avec une clé API à portée `agent` : il
n'a besoin d'aucun port entrant ni **d'aucun accès à la base**. Ce dernier point est une
propriété de sécurité, pas un détail : un agent ayant accès à la base aurait aussi besoin
d'`ENCRYPTION_KEY`, c'est-à-dire de quoi déchiffrer *toutes* les clés de déploiement que
Zanshin détient.

| Mode d'identifiants | Ce que le contrôleur envoie | Quand l'utiliser |
|---|---|---|
| `local` (défaut) | rien | la machine de l'agent a son propre accès git. Un agent compromis ne donne que ce qui a été accordé à cette machine |
| `delegated` | la clé de déploiement, par tâche | machine de confiance. Exige HTTPS (refus sinon), la clé n'est jamais écrite ailleurs que dans un fichier temporaire `0600`, et chaque remise est auditée |

```bash
# Sur la machine de l'agent — la clé vient de /agents, affichée une seule fois
ZANSHIN_URL=https://zanshin.interne \
ZANSHIN_AGENT_TOKEN=zsk_... \
python -m zanshin.agent
```

Voir [`docker-compose.agent.yml`](docker-compose.agent.yml) pour la variante
conteneurisée, et
[`docs/architecture/04-execution-et-deploiement.md`](docs/architecture/04-execution-et-deploiement.md)
pour les décisions et les limites connues.

**Lancer plus d'une instance web.** L'essentiel de ce qui rendait cela dangereux est
corrigé : la réclamation des scans est transactionnelle (`FOR UPDATE SKIP LOCKED`), le
travail périodique a exactement un propriétaire dans la flotte, la reprise au démarrage
ne fait plus échouer les scans d'un autre exécutant, et le quota d'API comme
l'anti-bourrage sont partagés via Redis. Ce que cela exige :

- **PostgreSQL** (`ZANSHIN_DATABASE_URL`). SQLite n'a qu'un écrivain et pas de
  `SKIP LOCKED` ; une seconde instance dessus est refusée au démarrage plutôt que
  laissée corrompre le fichier ;
- **`REDIS_URL`**, à la fois pour le gestionnaire d'état de Reflex — sans lui, un client
  qui atterrit sur l'autre instance est déconnecté par intermittence — et pour les
  compteurs de sécurité ;
- **`ZANSHIN_AUTO_MIGRATE=false`**, avec `alembic upgrade head` comme étape de
  déploiement à part : le verrou de migration est un verrou de fichier et ne coordonne
  qu'un hôte.

Mal démarrée, l'application le dit : elle refuse, ou avertit, en nommant la raison.

### Démarrage rapide

Prérequis : Python ≥ 3.12, [uv](https://docs.astral.sh/uv/), Docker (pour le backend de scan par défaut).

```bash
uv sync
uv run reflex run
```

L'application démarre sur `http://localhost:3000` (frontend) avec l'API backend sur le port par défaut de Reflex.

Le schéma est géré par **Alembic**. Au démarrage, Zanshin met la base à la dernière révision tout seul ; une base antérieure à Alembic est adoptée (marquée à la révision de référence) plutôt que reconstruite, donc la mise à jour d'un déploiement existant ne demande aucune manipulation. Les migrations se pilotent aussi à la main :

```bash
uv run alembic upgrade head     # appliquer
uv run alembic check            # échoue si un modèle n'a pas sa migration
uv run alembic revision --autogenerate -m "ce qui a changé"
```

#### Pages principales

| Route | Description |
|---|---|
| `/dashboard` | Vue d'ensemble |
| `/depots` | Dépôts Git suivis, historique des scans, détail des findings |
| `/issues` | Backlog des problèmes suivis d'un scan à l'autre, avec triage (VEX) |
| `/containers` | Images de conteneurs suivies |
| `/ssh-keys` | Clés SSH (chiffrées) pour cloner des dépôts privés |
| `/api-keys` | Clés API programmatiques (hash bcrypt, secret affiché une seule fois) |
| `/agents` | Agents de scan (intégré et distants), file d'attente et baux (admin) |
| `/settings` | Choix du backend de scan, activation de l'enrichissement, liste noire de licences |
| `/users` | Gestion des utilisateurs (admin) |
| `/audit-log` | Journal d'audit des actions sensibles (admin) |
| `/api/v1/docs` | Référence interactive de l'API (OpenAPI) |

### API and CI integration

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

### API et intégration CI

L'API est servie par le même processus et le même port que l'UI, sous `/api/v1`, et s'authentifie avec une clé créée sur la page **Clés API** :

```bash
export ZANSHIN=http://localhost:3000
export ZANSHIN_KEY=zsk_...

# Que puis-je scanner ?
curl -H "Authorization: Bearer $ZANSHIN_KEY" $ZANSHIN/api/v1/targets

# Scanner, puis interroger
curl -X POST -H "Authorization: Bearer $ZANSHIN_KEY" -H 'Content-Type: application/json' \
     -d '{"repository_id": 1}' $ZANSHIN/api/v1/scans
curl -H "Authorization: Bearer $ZANSHIN_KEY" $ZANSHIN/api/v1/scans/42

# Ce build doit-il échouer ?
curl -X POST -H "Authorization: Bearer $ZANSHIN_KEY" -H 'Content-Type: application/json' \
     -d '{"repository_id": 1, "policy": {"fail_on_severity": "high", "fail_on_kev": true}}' \
     $ZANSHIN/api/v1/gate
```

Le gate répond HTTP 200 avec `{"passed": false, "violations": [...]}` quand la politique est violée — une politique violée est une réponse, pas une erreur de transport, et les pipelines traitent les deux différemment. Les problèmes déjà triés en *non affecté* ou *corrigé* ne font pas échouer un build, sauf demande explicite via `include_triaged`.

La politique elle-même vit en base, éditée depuis la page **Paramètres** : un défaut global plus des surcharges optionnelles par cible, chaque modification étant stockée comme une nouvelle version avec son auteur et un motif facultatif. `GET /api/v1/gate/policies` liste ce qui est en vigueur et `.../history` toutes les versions d'une portée — « quelle politique a fait échouer ce build en mars » a une réponse.

Un objet `policy` dans le corps de la requête reste accepté et ne peut que **durcir** les règles. Le sens « strict » est défini champ par champ, parce qu'il ne veut pas dire « plus grand » : un seuil de sévérité *plus bas* est plus strict ; `fail_on_kev` et `include_triaged` sont plus stricts à `true` ; `fixable_only` est plus strict à **`false`**, parce que `true` exclut les problèmes sans correctif publié — précisément le cas qui demande une décision humaine, pas un build vert. Tout refus revient dans `policy.ignored_relaxations`, à côté du `source` et de la `version` réellement appliqués.

Exports : `GET /api/v1/targets/{repository|container}/{id}/issues.sarif` (SARIF 2.1.0), `.../vex` (OpenVEX), `.../issues.csv`, et `GET /api/v1/scans/{id}/sbom` (le SBOM Syft tel que produit).

SARIF est celui qui met un problème sous les yeux du développeur qui l'a introduit, annoté sur la ligne, dans la pull request :

```bash
curl -H "Authorization: Bearer $ZANSHIN_KEY" \
     -o zanshin.sarif "$ZANSHIN/api/v1/targets/repository/1/issues.sarif"
gh api -X POST /repos/{owner}/{repo}/code-scanning/sarifs \
     -f commit_sha="$GITHUB_SHA" -f ref="$GITHUB_REF" -f sarif="$(gzip -c zanshin.sarif | base64 -w0)"
```

Les problèmes triés partent en *suppressions* SARIF et non à la poubelle : les retirer ferait qu'à l'envoi suivant la plateforme les redéclare comme nouveaux, annulant le travail de triage — et la suppression porte la justification. L'empreinte d'identité Zanshin voyage en `partialFingerprint`, pour qu'un problème reste reconnu après un déplacement de fichier ou un décalage de ligne. Référence complète sur `/api/v1/docs` — qui exige une clé, comme toutes les autres routes : une carte anonyme des routes et des charges utiles est une étape de reconnaissance offerte.

Une clé peut être restreinte à sa création, et une clé de CI devrait normalement l'être :

| Restriction | Effet |
|---|---|
| Portées `read` / `scan` / `export` | Ce que la clé peut faire. Une clé qui ne fait que publier des résultats a besoin de `read` ; une qui déclenche des scans, de `scan`. Portée absente → 403. |
| Cible `repository:{id}` ou `container:{id}` | Ce que la clé peut atteindre — y compris la liste `/issues` et les exports, restreints à cette cible. Une autre cible → 403 (et non 404 : l'appelant connaît déjà l'identifiant qu'il a demandé). |
| Expiration en jours | Passée cette date, la clé est refusée comme invalide. La ligne subsiste : la liste montre encore que la clé a existé. |

`GET /api/v1/issues` accepte `only_direct=true` pour ne renvoyer que les paquets déclarés par le projet — ce qu'un changement de version corrige aujourd'hui, sans attendre un amont. Les problèmes dont la directivité est inconnue sont exclus : une réponse absente n'est pas une réponse positive.

Les valeurs par défaut restent larges (toutes les portées, toutes les cibles, sans expiration) : c'est ce qu'accordait une clé avant l'existence de ces restrictions, et un formulaire dont les défauts cassent le pipeline apprend surtout à cocher toutes les cases.

### Configuration

Les réglages runtime (`scan_backend`, `enrichment_enabled`, `license_blocklist`, URL et répertoire partagé du backend `local_api`) se gèrent depuis la page **Paramètres**, et sont stockés en base (table `setting`) plutôt que par variables d'environnement.

Trois éléments ne sont *pas* des réglages runtime, parce qu'ils doivent exister avant que l'application puisse être utilisée sans risque :

| Variable | Requise | Rôle |
|---|---|---|
| `ENCRYPTION_KEY` | Pour stocker des clés SSH | Clé de 32 octets utilisée pour chiffrer les clés SSH privées et les jetons (AES-GCM). Sans elle, l'enregistrement d'un secret est refusé, au lieu de l'écrire sous quelque chose qui ne le protège pas. L'application ne transporte plus de clé par défaut : elle en publiait une dans son propre code, si bien qu'une copie du fichier de base suffisait à lire toutes les clés privées stockées. |
| `ZANSHIN_SEMGREP_RULES_DIR` | Pour élargir la couverture de Semgrep | Un répertoire de règles Semgrep supplémentaires, fusionné avec celles que Zanshin embarque. Zanshin ne transporte que les siennes : les jeux de règles publics de Semgrep ne sont pas redistribuables, donc `scripts/fetch_semgrep_rules.py` installe sur votre machine celui que vous choisissez. À lancer une fois, à l'installation — le scan lui-même reste hors ligne. |
| `ZANSHIN_PREVIOUS_ENCRYPTION_KEYS` | Pour faire tourner `ENCRYPTION_KEY` | Anciennes clés séparées par des virgules, essayées **au déchiffrement uniquement**. Les valeurs basculent sur la clé courante au fil des réenregistrements, et la page *Clés SSH* signale les lignes qui dépendent encore d'une ancienne — la variable se retire quand il n'en reste plus. C'est aussi par là qu'une valeur chiffrée avec l'ancienne clé par défaut publiée se relit une dernière fois ; voir [`docs/ROTATION_ET_PURGE.md`](docs/ROTATION_ET_PURGE.md). |
| `ZANSHIN_BOOTSTRAP_USERNAME` | Premier démarrage | Nom du SUPERUSER initial, créé au démarrage quand la table `user` est vide. |
| `ZANSHIN_BOOTSTRAP_PASSWORD` | Premier démarrage | Son mot de passe (8 caractères minimum). |

Réglages d'exploitation (tous optionnels, valeurs par défaut indiquées) :

| Variable | Défaut | Rôle |
|---|---|---|
| `ZANSHIN_DB_PATH` | `zanshin/database.sqlite` | Chemin du fichier SQLite. La façon la plus simple de garder les données hors de l'arborescence source ; rendu absolu, parce qu'un chemin relatif se résout par rapport au répertoire courant et que celui-ci diffère entre `reflex run`, `alembic` et une unité de service. |
| `ZANSHIN_DATABASE_URL` | dérivée de `ZANSHIN_DB_PATH` | URL SQLAlchemy complète, pour tout ce qui n'est pas un fichier local — par exemple `postgresql+psycopg://utilisateur:motdepasse@hôte/zanshin`. Prend le pas sur `ZANSHIN_DB_PATH`. Nécessite le pilote : `uv sync --extra postgres`. |
| `REDIS_URL` | — | Partage le quota d'API et l'anti-bourrage entre instances. Sans lui ils sont comptés par processus : correct pour une instance, et le quota double pour deux. Reflex lit la même variable pour son gestionnaire d'état, dont une flotte a de toute façon besoin. |
| `ZANSHIN_ALLOW_MULTI_INSTANCE_SQLITE` | `false` | Lève le refus au démarrage déclenché quand une autre instance est vivante et que la base est SQLite. Son seul usage légitime : un redémarrage sous un *nouveau* nom d'hôte moins de deux minutes après l'arrêt du précédent — un rolling restart Kubernetes. Il ne rend pas deux instances sûres sur SQLite. |
| `ZANSHIN_DB_TIMEOUT_SECONDS` | `30` | SQLite uniquement : combien de temps une écriture attend un autre écrivain avant d'échouer. Les workers de scan, l'ordonnanceur et les requêtes écrivent tous, donc la contention est normale. |
| `ZANSHIN_DB_POOL_SIZE` / `_MAX_OVERFLOW` / `_POOL_RECYCLE_SECONDS` | `5` / `10` / `1800` | Bases serveur uniquement : pool de connexions. Ignoré pour SQLite, qui n'a pas de pool à régler. |
| `ZANSHIN_AUTO_MIGRATE` | `true` | `false` pour un déploiement qui exécute `alembic upgrade head` comme étape propre — ce que devrait faire une base serveur répartie sur plusieurs hôtes applicatifs. Le schéma reste *vérifié* au démarrage : une base en retard sur le code arrête l'application là, et non à la première requête. |
| `ZANSHIN_SCAN_WORKERS` | `5` | Valeur *par défaut* du réglage « scans simultanés maximum », qui s'édite désormais depuis la page **Paramètres** et s'applique sans redémarrage. Les scans sont mis en file dans l'ordre où ils ont été demandés ; la file vit en base, donc une demande survit à un redémarrage et sa place est connue (`queue_position` sur `GET /api/v1/scans/{id}`). |
| `ZANSHIN_SCAN_POOL_THREADS` | `32` | Plafond dur du nombre de threads de scan, donc du réglage ci-dessus. Le pool est une réserve de threads, pas la file — un pool plus petit que la limite configurée la bornerait silencieusement. |
| `ZANSHIN_SCAN_TIMEOUT_SECONDS` | `900` | Plafond pour un conteneur de scan ; au-delà, il est tué et le scan échoue en timeout au lieu de rester bloqué. |
| `ZANSHIN_SCHEDULER_ENABLED` | `true` | `false` pour un déploiement qui ne scanne qu'à la demande. |
| `ZANSHIN_SCHEDULER_TICK_SECONDS` | `60` | Fréquence de recherche des cibles dues. |
| `ZANSHIN_STALLED_SCAN_MAX_AGE_SECONDS` | `5400` | Âge au-delà duquel un scan encore en cours est considéré bloqué et mis en échec. |
| `ZANSHIN_RETENTION_INTERVAL_SECONDS` | `21600` | Fréquence de purge des sorties brutes des scanners (les seuils eux-mêmes sont dans la page **Paramètres**). |
| `ZANSHIN_SCAN_MEMORY_LIMIT` | `2g` | Plafond mémoire par conteneur de scan. |
| `ZANSHIN_SCAN_PIDS_LIMIT` | `512` | Plafond de processus par conteneur de scan. |
| `ZANSHIN_SYFT_IMAGE` / `_GRYPE_` / `_GITLEAKS_` / `_CHECKOV_` | digests épinglés | Images des analyseurs. Épinglées par digest et non par tag : elles s'exécutent avec le socket Docker monté, donc elles constituent la chaîne d'approvisionnement de Zanshin. À mettre à jour délibérément via `docker buildx imagetools inspect <image>:latest`. |
| `ZANSHIN_ALLOWED_ORIGINS` | `http://localhost:3000,http://127.0.0.1:3000` | Origines autorisées à ouvrir le websocket, séparées par des virgules. Reflex accepte `*` par défaut, ce qui permet à n'importe quelle page visitée de créer de l'état serveur. **À renseigner avec le vrai nom d'hôte pour tout déploiement hors localhost**, sinon le frontend de l'application est lui-même refusé. |
| `ZANSHIN_SESSION_TTL_HOURS` | `12` | Une session plus ancienne est déconnectée au chargement de page suivant. |
| `ZANSHIN_API_RATE_LIMIT` / `ZANSHIN_API_RATE_WINDOW_SECONDS` | `300` / `60` | Requêtes par clé et par fenêtre, avant un 429 avec `Retry-After`. Comptées en mémoire, par processus. |
| `ZANSHIN_MIGRATION_LOCK` | à côté de la base | Fichier de verrou sérialisant `alembic upgrade` au démarrage. Reflex importe l'application dans plusieurs processus et le DDL de SQLite n'est pas transactionnel : sans ce verrou, deux montées de version simultanées peuvent laisser le schéma à moitié migré. |

Le sidecar (`scan-api/`) exige en plus `ZANSHIN_SCAN_API_TOKEN` (à reporter dans le réglage `local_scan_api_token`) et `ZANSHIN_SHARED_ROOT`. Il refuse toute requête sans jeton, et tout chemin hors de cette racine — voir [`scan-api/README.md`](scan-api/README.md).

Le fichier de base de données ne fait plus partie du dépôt (il contient des hashes de mots de passe et des clés SSH chiffrées) : un déploiement neuf démarre donc sans aucun compte, d'où ces variables de bootstrap. Dès qu'un compte existe, elles sont ignorées.

#### Choisir une base de données

SQLite est le défaut, et c'est ce contre quoi ce déploiement est éprouvé : un fichier,
pas de serveur, et le volume d'écriture du pipeline de scan est loin de ses limites.
Placez-le à un endroit durable et sauvegardez-le — ce fichier *est* l'installation.

```bash
ZANSHIN_DB_PATH=/var/lib/zanshin/zanshin.sqlite
```

PostgreSQL est l'autre moteur pris en charge, vérifié par des tests qui démarrent un
vrai serveur — `pytest -m backends` passe tout le schéma et chaque service propriétaire
d'une colonne sur PostgreSQL 16 via testcontainers. Ils sont exclus de l'exécution par
défaut : un téléchargement d'image n'a rien à faire dans la boucle qu'on lance à chaque
modification. Une chose à savoir avant de choisir.

**MySQL a été pris en charge, puis retiré.** Il ne remplissait aucun rôle que les deux
autres ne couvrent : il n'est ni l'option sans configuration, ni la cible de déploiement,
et il avait son comportement propre à trois endroits qui comptent — `DATETIME` tronqué à
la seconde entière, donc chaque entrée du journal d'audit se déclarait falsifiée ;
`SKIP LOCKED` comptant les lignes sautées dans `LIMIT`, donc des réclamations de scan qui
revenaient vides ; `NULLS LAST` en erreur de syntaxe. Trois branches par dialecte dans du
code dont le sujet est l'intégrité, sans contrepartie. Une URL MySQL est désormais refusée
au démarrage avec cette explication, plutôt que de marcher à moitié.

```bash
uv sync --extra postgres
ZANSHIN_DATABASE_URL=postgresql+psycopg://zanshin:...@db.internal/zanshin
ZANSHIN_AUTO_MIGRATE=false        # exécuter « alembic upgrade head » comme étape de déploiement
```

- **Les clés étrangères y sont appliquées, contrairement à SQLite**, qui les ignore
  sauf demande explicite par connexion. Les cascades de ce schéma sont déclarées côté
  ORM et `Issue.findings` n'en a aucune : une suppression qui laisse aujourd'hui des
  lignes orphelines en silence lèverait une erreur sur une base serveur. Pas encore
  corrigé — cela demande des règles `ondelete` et une migration.
- **Les horodatages sont stockés en chaînes ISO-8601**, pas en `timestamptz` ni
  `DATETIME`. C'est ce que fait `SafeDateTime`, et c'est délibéré (il existe pour
  relire les différents formats laissés par le schéma antérieur à Alembic), mais cela
  signifie qu'on ne dispose pas d'arithmétique de dates en SQL sur ces colonnes. Le
  tri et les comparaisons fonctionnent, l'ISO-8601 se triant lexicographiquement.

Les migrations tournent sur l'une comme sur l'autre. `alembic` lit les deux mêmes
variables que l'application, donc la ligne de commande et l'application en marche ne
peuvent pas être en désaccord sur la base qu'elles regardent.

### Tests

```bash
uv run pytest
```

~82 % de couverture sur `zanshin/`, couche UI incluse. Les deux moitiés de l'UI sont vérifiées par des moyens différents : les loaders et handlers par des tests d'état (voir `UIHarness` dans `tests/conftest.py`, qui pilote un état Reflex hors serveur), et les arbres de composants par `uv run reflex compile --dry`, qui échoue sur un attribut inexistant d'une ligne typée. Chaque test s'exécute sur une base SQLite en mémoire, jamais sur `zanshin/database.sqlite`.

```bash
uv run pytest -m backends     # nécessite Docker
```

En complément, une suite multi-backends démarre un vrai serveur PostgreSQL 16 avec testcontainers, applique toutes les migrations et fait passer une ligne par chaque type de colonne maison et chaque service qui en possède un. Elle est exclue de l'exécution par défaut (`addopts = -m 'not backends'`), parce qu'un téléchargement d'image n'a rien à faire dans la boucle qu'on lance à chaque modification, et elle se saute d'elle-même sans Docker. Elle existe parce que tous les défauts de portabilité de ce schéma étaient invisibles à la fois pour SQLite et à la lecture : un type `BINARY` que PostgreSQL ne connaît pas, `FROM user` qui désigne une fonction au lieu d'une table, `VARCHAR` sans longueur, une clé étrangère `BIGINT` vers une clé `INT`, `DROP INDEX IF EXISTS`, `NULLS LAST`. Six, tous trouvés en exécutant.

### Structure du projet

```
zanshin/
├── models/          # Modèles SQLAlchemy
├── repositories/     # Accès aux données
├── services/         # Logique métier (scan, enrichissement, utilisateurs, audit...)
│   ├── scanners/      # Implémentations ScannerEngine (docker, osv, local_api)
│   ├── scan_runner.py     # Exécute les scanners — sans base (côté agent)
│   └── scan_ingestor.py   # Normalise les résultats — base seule (côté contrôleur)
├── agent/             # L'agent distant : `python -m zanshin.agent`
├── ui/                # Pages, état et view-models typés Reflex
├── api/               # API HTTP (FastAPI, montée sur l'app Reflex)
├── scan_contract.py   # Formes de tâche/résultat partagées entre runner et ingestor
├── schema.py          # Amorçage Alembic au démarrage
├── clock.py           # Source unique de « maintenant »
└── container.py       # Injection de dépendances (IoCContainer)
migrations/            # Révisions Alembic
scan-api/              # Service sidecar HTTP (backend local_api)
tests/                 # Suite pytest
docs/architecture/     # ADR
```
