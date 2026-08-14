# Zanshin

**[English](#english)** | **[Français](#français)**

---

## English

Zanshin is a software dependency and security tracking application built around SBOM (Software Bill of Materials) analysis. It scans Git repositories and container images, detects known vulnerabilities, hardcoded secrets, problematic licenses, and infrastructure-as-code misconfigurations, then centralizes the results in a single dashboard — in the spirit of a unified ASPM (Application Security Posture Management) platform, with a pluggable scanning layer (local Docker, local API, or cloud API depending on the analysis type).

Built with [NestJS](https://nestjs.com) and [Angular](https://angular.dev) over PostgreSQL, in a single npm workspace.

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

### Architecture

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

#### Distributed scanning: agents

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

**Known gap in this port.** The control plane serves the agent protocol in full — an agent
is declared from `/agents`, its key is issued once, and the four routes are live and
tested. What does *not* ship yet is a standalone agent binary: the Python `zanshin.agent`
process was retired with the rest of the Python tree, and its TypeScript replacement is
not written. Remote agents are therefore reachable by anything that speaks the protocol,
but Zanshin does not hand you the client. Single-machine installs are unaffected — the
built-in agent is what they use.

See [`docs/architecture/04-execution-et-deploiement.md`](docs/architecture/04-execution-et-deploiement.md)
for the decisions and the known limits.

**Running more than one web instance.** Most of what made that unsafe is now fixed: the
scan claim is transactional (`FOR UPDATE SKIP LOCKED`), the periodic work has exactly
one owner across the fleet, startup recovery no longer fails another worker's scans, and
and the login throttle is counted in the database rather than in process memory. What it requires:

- **PostgreSQL** (`ZANSHIN_DATABASE_URL`). It is the only engine whose `FOR UPDATE SKIP
  LOCKED` does what the queue assumes;
- **the migration as its own deployment step** (`npm --workspace backend run
  migration:run`), before the new instances start;
- nothing else. Sessions live in the database, not in process memory, so a client that
  lands on the other instance stays signed in — the Redis that the Reflex version needed
  for its state manager has no equivalent here.

The scheduler elects a single owner across the fleet, while every instance keeps claiming
work for its own built-in worker: a fleet whose instances only worked while holding the
lease would idle behind whichever one holds it.

Start it wrong and the application says so: it refuses, or warns, with the reason named.

### Quick start

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

Runtime settings (enrichment, end-of-life, retention, notifications, licences, tracker, model review) are managed from the **Settings** page and stored in the `t_setting` table rather than as environment variables. A setting appears there only once a service actually reads it: a form that accepts a value and does nothing with it is worse than one that does not offer it.

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
| `ZANSHIN_DATABASE_URL` | — | PostgreSQL connection URL. Required: there is no file-backed default any more, and there is a reason for that below. |
| `ZANSHIN_DB_DIALECT` | `postgres` | Declares the engine so the application can warn at startup about what that engine cannot do correctly (see `dialects.ts`). It does not make an unsupported engine work. |
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
| `ZANSHIN_SYFT_IMAGE` / `_GRYPE_` / `_GITLEAKS_` / `_CHECKOV_` / `_SEMGREP_` | pinned digests | Scanner images. Pinned by digest, not by tag: they run with the Docker socket mounted, so they *are* Zanshin's supply chain. Update deliberately with `docker buildx imagetools inspect <image>:latest`. |
| `ZANSHIN_IMAGE_SCAN_PLATFORM` | — | Platform to pull for a container scan, e.g. `linux/amd64` — the image scanned should be the one that runs in production, not the one that matches the scanner's host. |
| `ZANSHIN_SESSION_TTL_HOURS` / `_IDLE_MINUTES` | `12` / `60` | Absolute and idle session lifetimes. |
| `ZANSHIN_VEX_AUTHOR` | `Zanshin` | Author recorded in OpenVEX documents — a VEX is an assertion about who said what, and when. |
| `ZANSHIN_SQL_LOGGING` | `false` | Logs every statement. For diagnosis, never for a running deployment. |



The database file is not part of the repository (it holds password hashes and encrypted SSH keys), so a fresh deployment starts with no accounts — hence the bootstrap variables. Once an account exists, they are ignored.

#### Choosing a database

PostgreSQL is the only supported engine, and that is a narrowing from the Python
version, which defaulted to SQLite.

The reason is not preference. Three things this application does are wrong on SQLite and
**produce no error** — they produce wrong data. `FOR UPDATE SKIP LOCKED`, which makes the
scan queue safe for several workers, is accepted and then *silently dropped*: the claim
looks transactional, passes every test on a developer's machine, and hands the same scan
to two processes in production. SQLite also has a single writer, and the scheduler, the
workers and the requests all write.

MySQL and MariaDB are declared in `dialects.ts` with the three defects that would follow —
`DATETIME` truncating to the second, which makes the audit chain declare itself tampered
with; `SKIP LOCKED` counting skipped rows against the `LIMIT`; `NULLS LAST` refused — but
they are **not tested**, and no migration exists for them. Treat that entry as a warning,
not as support.


### Tests

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

### Project structure

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

---

## Français

Zanshin est une application de suivi des dépendances et de sécurité logicielle, basée sur l'analyse de SBOM (Software Bill of Materials). Elle scanne des dépôts Git et des images de conteneurs, détecte les vulnérabilités connues, les secrets codés en dur, les licences problématiques et les mauvaises configurations d'infrastructure (IaC), puis centralise les résultats dans un tableau de bord unique — dans l'esprit d'une plateforme ASPM (Application Security Posture Management) unifiée, avec une couche de scan pluggable (Docker local, API locale, ou API cloud selon le type d'analyse).

Construit avec [NestJS](https://nestjs.com) et [Angular](https://angular.dev) sur PostgreSQL, dans un unique espace de travail npm.

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
  dans Zanshin ; voir [le répertoire de règles](backend/src/scanning/rules/semgrep/)
  pour en ajouter.
- **Suivi et triage des problèmes** : chaque finding est suivi d'un scan à l'autre sous forme de *problème* — première détection, nombre de fois vu, existence d'un correctif, et décision de triage en vocabulaire VEX (affecté / non affecté / corrigé / à examiner) avec justification, et éventuellement une **date de révision**. Une suppression porte sur un contexte — « pas atteignable dans notre configuration », « pas livré en production » — et les contextes changent ; à l'échéance, le problème revient *à examiner*, justification et commentaire conservés. Chaque scan indique ce qu'il a **changé** : problèmes apparus, problèmes résolus.
- **Rescan périodique** : chaque cible porte un intervalle de scan, honoré par un ordonnanceur intégré — l'intérêt étant que de nouvelles vulnérabilités apparaissent dans du code qui n'a pas bougé.
- **API HTTP et *policy gate* CI** : déclencher un scan, lire les problèmes, et demander « ce build doit-il échouer ? » selon une **politique stockée et versionnée** — globale, ou par cible. Ces règles arrivaient auparavant dans le corps de la requête, donc chaque projet décidait du seuil qu'on lui appliquait ; une requête peut désormais seulement *durcir* la politique stockée, jamais l'assouplir, et le verdict indique laquelle a été appliquée. Authentifiée par les clés API émises depuis l'UI.
- **Tickets** (GitLab, Jira) : ouvre un ticket par problème qui ferait échouer un build, selon la même politique — un seul seuil, défini une seule fois. La référence est conservée sur le problème, donc une panne du gestionnaire est réessayée sans jamais dupliquer.
- **Notifications** : un webhook part quand un scan fait apparaître ou réapparaître quelque chose — pas à chaque scan, c'est ce qui garde le canal lisible. Le message est écrit dans un **outbox, dans la même transaction que les résultats du scan**, puis livré par l'ordonnanceur avec réessais espacés et plafonnés : un arrêt brutal entre la validation et l'envoi ne le perd plus en silence, et un point d'arrivée momentanément injoignable est réessayé au lieu d'être journalisé une fois.
- **Exports** : **SARIF 2.1.0** pour GitHub code scanning / GitLab / Azure DevOps — c'est ce qui sort un problème du tableau de bord pour l'amener sur la pull request qui l'a introduit — plus un document OpenVEX construit à partir des décisions de triage, les problèmes en CSV, et le SBOM stocké.
- **Gestion des utilisateurs** et **journal d'audit** : rôles (SUPERUSER/ADMIN/USER), garde-fous (impossible de supprimer son propre compte ou le dernier superutilisateur actif), traçabilité des actions sensibles.
- **Un scan qui reste sur la machine** : chaque scanner tourne dans un conteneur éphémère, réseau coupé et montage en lecture seule. Les backends OSV.dev et sidecar HTTP qu'offrait la version Python **ne font pas partie de ce portage** — le sidecar était déjà documenté comme redondant, et le matching OSV apportait peu face à une image Grype épinglée.

### Architecture

Le pipeline est coupé en deux le long d'une seule ligne : **`ScanRunner` exécute les
scanners et ne touche jamais la base ; `ScanIngestor` lit ses résultats et n'exécute
jamais de conteneur.** C'est cette coupure qui permet au même code de tourner dans le plan
de contrôle ou sur un agent distant qui n'a aucun identifiant de base.

| Étape | Outil | Image épinglée par empreinte |
|---|---|---|
| SBOM | Syft | oui |
| Vulnérabilités | Grype | oui |
| Secrets | gitleaks | oui |
| IaC | checkov | oui |
| Code source (désactivé par défaut) | Semgrep | oui |

Chaque scanner tourne dans un conteneur éphémère avec **le réseau coupé**, un montage en
lecture seule, `cap_drop: ALL` et `no-new-privileges`. Rien du code scanné ne quitte la
machine. Les seuls appels sortants d'un scan sont EPSS et le catalogue KEV, qui ne portent
que des identifiants de CVE — et le catalogue de fin de vie, qui ne porte que des noms de
produits et des versions.

Les résultats sont normalisés dans une table `Finding` unique (type, sévérité, identifiant, package, source, scores EPSS/CVSS, statut KEV, version corrigée) en plus des blobs JSON bruts (`Scan.sbom`, `Scan.cves`) conservés pour l'audit.

Un `Finding` est une *observation*, valable pour un seul scan. Au-dessus, un `Issue` suit le même problème d'un scan à l'autre — identifié par une empreinte qui ignore volontairement la version du paquet, pour qu'une dépendance restée vulnérable pendant trois versions correctives conserve un seul historique et une seule décision de triage. Deux axes sont maintenus strictement séparés : `state` (ouvert/résolu) n'est écrit que par le pipeline, d'après ce que les scanners observent ; `triage_status` (VEX) n'est écrit que par un humain. Les confondre viderait « résolu » de son sens — un finding masqué et un finding réellement corrigé ne doivent pas se ressembler. Voir [`backend/src/services/issue-sync.service.ts`](backend/src/services/issue-sync.service.ts).

Le dossier d'architecture — vue d'ensemble, modèle de données, sécurité, déploiement, et un registre des décisions avec les alternatives écartées — est dans [`docs/architecture/`](docs/architecture/). Pour les diagrammes de l'architecture en couches, le schéma complet de la base de données et le déroulé du pipeline de scan, voir [`docs/TECHNICAL_DOCUMENTATION.md`](docs/TECHNICAL_DOCUMENTATION.md).

#### Scan distribué : les agents

Un scan est exécuté par un **agent**. Il y en a deux sortes, qui sont des lignes de la
même table et apparaissent ensemble sur la page `/agents` :

- l'**agent intégré** — ce processus web lui-même. Créé automatiquement au démarrage,
  aucune configuration : c'est ce qui fait qu'une installation sur une seule machine
  fonctionne d'emblée ;
- les **agents distants** — des travailleurs séparés sur d'autres machines, parlant le
  protocole d'agent à quatre routes (`hello`, `jobs`, `heartbeat`, `result`), sur d'autres
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

**Lacune connue de ce portage.** Le plan de contrôle sert le protocole d'agent en entier —
un agent se déclare depuis `/agents`, sa clé est délivrée une fois, et les quatre routes
sont en place et testées. Ce qui ne suit **pas** encore, c'est un binaire d'agent autonome :
le processus Python `zanshin.agent` a été retiré avec le reste de l'arbre Python, et son
remplaçant TypeScript n'est pas écrit. Les agents distants sont donc joignables par tout ce
qui parle le protocole, mais Zanshin ne vous fournit pas le client. Les installations sur
une seule machine ne sont pas concernées : elles utilisent l'agent intégré.

Voir [`docs/architecture/04-execution-et-deploiement.md`](docs/architecture/04-execution-et-deploiement.md)
pour les décisions et les limites connues.

**Lancer plus d'une instance web.** L'essentiel de ce qui rendait cela dangereux est
corrigé : la réclamation des scans est transactionnelle (`FOR UPDATE SKIP LOCKED`), le
travail périodique a exactement un propriétaire dans la flotte, la reprise au démarrage
ne fait plus échouer les scans d'un autre exécutant, et le quota d'API comme
l'anti-bourrage sont partagés via Redis. Ce que cela exige :

- **PostgreSQL** (`ZANSHIN_DATABASE_URL`). C'est le seul moteur dont le `FOR UPDATE SKIP
  LOCKED` fait ce que la file suppose ;
- **la migration comme étape de déploiement propre** (`npm --workspace backend run
  migration:run`), avant le démarrage des nouvelles instances ;
- rien d'autre. Les sessions vivent en base et non dans la mémoire d'un processus, donc un
  client qui atterrit sur l'autre instance reste connecté.

L'ordonnanceur élit un propriétaire unique dans la flotte, tandis que chaque instance
continue de réclamer du travail pour son propre travailleur intégré : une flotte dont les
instances ne travailleraient qu'en détenant le bail resterait oisive derrière celle qui le
tient.

Mal démarrée, l'application le dit : elle refuse, ou avertit, en nommant la raison.

### Démarrage rapide

Prérequis : Node ≥ 24, Docker (pour les scanners et, en développement, pour la base).

```bash
npm install
npm --workspace backend run start:dev     # API sur http://localhost:3000
npm --workspace frontend start            # interface sur http://localhost:4200
```


Le schéma appartient aux **migrations TypeORM** — `synchronize` est désactivé, et c'est
délibéré : un schéma synthétisé depuis les entités n'est pas celui que la production
recevra, et tester contre lui laisserait passer une migration incorrecte.

```bash
npm --workspace backend run migration:run       # appliquer
npm --workspace backend run migration:generate  # en écrire une depuis les entités
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
| `ZANSHIN_DATABASE_URL` | — | PostgreSQL connection URL. Required: there is no file-backed default any more, and there is a reason for that below. |
| `ZANSHIN_DB_DIALECT` | `postgres` | Declares the engine so the application can warn at startup about what that engine cannot do correctly (see `dialects.ts`). It does not make an unsupported engine work. |
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
| `ZANSHIN_SYFT_IMAGE` / `_GRYPE_` / `_GITLEAKS_` / `_CHECKOV_` / `_SEMGREP_` | pinned digests | Scanner images. Pinned by digest, not by tag: they run with the Docker socket mounted, so they *are* Zanshin's supply chain. Update deliberately with `docker buildx imagetools inspect <image>:latest`. |
| `ZANSHIN_IMAGE_SCAN_PLATFORM` | — | Platform to pull for a container scan, e.g. `linux/amd64` — the image scanned should be the one that runs in production, not the one that matches the scanner's host. |
| `ZANSHIN_SESSION_TTL_HOURS` / `_IDLE_MINUTES` | `12` / `60` | Absolute and idle session lifetimes. |
| `ZANSHIN_VEX_AUTHOR` | `Zanshin` | Author recorded in OpenVEX documents — a VEX is an assertion about who said what, and when. |
| `ZANSHIN_SQL_LOGGING` | `false` | Logs every statement. For diagnosis, never for a running deployment. |


Le fichier de base de données ne fait plus partie du dépôt (il contient des hashes de mots de passe et des clés SSH chiffrées) : un déploiement neuf démarre donc sans aucun compte, d'où ces variables de bootstrap. Dès qu'un compte existe, elles sont ignorées.

#### Choisir une base de données

PostgreSQL est le seul moteur pris en charge, et c'est un rétrécissement par rapport à la
version Python, qui prenait SQLite par défaut.

La raison n'est pas une préférence. Trois choses que fait cette application sont fausses
sur SQLite et **ne produisent aucune erreur** — elles produisent des données fausses.
`FOR UPDATE SKIP LOCKED`, qui rend la file de scans sûre à plusieurs travailleurs, est
accepté puis *silencieusement supprimé* : la réclamation ressemble à une transaction, passe
tous les tests sur la machine d'un développeur, et remet le même scan à deux processus en
production. SQLite n'a par ailleurs qu'un seul écrivain, et l'ordonnanceur, les
travailleurs et les requêtes écrivent tous.

MySQL et MariaDB sont déclarés dans `dialects.ts` avec les trois défauts qui suivraient —
`DATETIME` tronquant à la seconde, ce qui fait que le journal d'audit se déclare falsifié ;
`SKIP LOCKED` comptant les lignes sautées dans le `LIMIT` ; `NULLS LAST` refusé — mais ils
ne sont **pas testés**, et aucune migration n'existe pour eux. Cette entrée est un
avertissement, pas une prise en charge.


### Tests

```bash
npm --workspace backend test                   # suite unitaire
npm --workspace backend run test:integration   # démarre PostgreSQL par testcontainers
```

562 tests unitaires et 249 tests d'intégration. **Les suites d'intégration ne se sautent
pas.** Elles commençaient par `const describeWithPostgres = connectionString ? describe :
describe.skip` : sans URL de base, douze fichiers se sautaient en silence et la campagne
rapportait vert sans rien avoir vérifié. Le harnais démarre désormais le conteneur
lui-même, donc l'absence de Docker échoue bruyamment — le comportement correct, et
exactement le genre de défaut que ce projet existe pour trouver.

Les migrations plutôt que `synchronize`, pour la même raison : le schéma testé est celui
que la production recevra.

```bash
uvx pyright
```

Le backend compile sous `strictNullChecks` et un **test de couches**
(`architecture.spec.ts`) qui fait échouer la compilation quand un import traverse dans le
mauvais sens. Ce test n'est pas décoratif : c'est lui qui garde la couche domaine —
empreintes, verdicts de gate, échéances — libre de TypeORM et de HTTP, donc testable sans
base.

La leçon retenue de la vérification de types de la version Python vaut toujours : une
barrière qui se déclenche sur du bruit est désactivée en une semaine. Les règles gardées ici
sont donc celles dont les constats étaient tous justes.

### Structure du projet

```
backend/src/
├── domain/            # Règles pures : empreinte, gate, exports, échéance, charges utiles
├── scanning/          # Exécute les scanners — sans base (côté agent)
├── persistence/       # Entités TypeORM et migrations
├── repositories/      # Accès aux données, aucune règle métier
├── services/          # Orchestration : ingestion, problèmes, notifications, tickets
└── api/               # Contrôleurs HTTP
frontend/src/app/      # Angular : 15 écrans, mise en page Sakai sur Optimus UI
docs/architecture/     # ADR
```

Le sens des imports est vérifié par un test (`architecture.spec.ts`) :
`domain ← scanning ← persistence ← repositories ← services ← api`. La couche domaine ignore
TypeORM comme HTTP, ce qui rend testables sans base les règles qui comptent — une empreinte,
un verdict de gate, une échéance.
