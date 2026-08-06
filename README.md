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
- **IaC scanning** (checkov): detects Terraform/Kubernetes misconfigurations in repositories.
- **Issue tracking and triage**: every finding is tracked across scans as an *issue* — first seen, times seen, whether a fix exists, and a triage decision in VEX vocabulary (affected / not affected / fixed / under review) with a justification, and optionally a **review date**. A suppression is a statement about a context — "not reachable in our configuration", "not shipped in production" — and contexts change; at its review date the issue returns to *under review* with its justification and comment intact. Each scan reports what it *changed*: new issues, resolved issues.
- **Periodic rescanning**: each target carries a scan interval, honoured by a built-in scheduler — the point being that new vulnerabilities appear in code that hasn't changed.
- **HTTP API and CI policy gate**: trigger scans, read issues, and ask "should this build fail?" against a configurable policy (severity threshold, actively-exploited, fix-available). Authenticated with the API keys the UI issues.
- **Notifications**: a webhook fires when a scan makes something appear or reappear — not on every scan, which is what keeps the channel readable.
- **Exports**: **SARIF 2.1.0** for GitHub code scanning / GitLab / Azure DevOps — which is what gets a finding out of the dashboard and onto the pull request that introduced it — plus an OpenVEX document built from the triage decisions, issues as CSV, and the stored SBOM.
- **User management** and **audit log**: roles (SUPERUSER/ADMIN/USER), guardrails (can't delete your own account or the last active superuser), traceability of sensitive actions.
- **Interchangeable scan backends**: local Docker (default, nothing leaves the machine), OSV.dev (vulnerability matching via a free cloud API), or a self-hosted HTTP sidecar service (`scan-api/`) — selectable from the Settings page without changing the rest of the application.

### Architecture

The central design choice is the `ScannerEngine` interface (`zanshin/services/scanners/base.py`), which decouples *what* to scan from *where/how* it runs. `ScanProcessor` orchestrates the steps (clone, SBOM, vulnerability scan, secrets, IaC) without ever calling Docker directly — it delegates to whichever implementation is configured:

| Backend | SBOM / secrets / IaC generation | Vulnerability matching | Use case |
|---|---|---|---|
| `docker` (default) | Ephemeral Docker containers (Syft/gitleaks/checkov) | Grype (local container) | No external dependency, fully local |
| `osv` | Delegated to the local Docker backend | OSV.dev cloud API (free) | CVE matching without maintaining Grype locally |
| `local_api` | HTTP sidecar service (`scan-api/`), same host, shared disk | Same, via the sidecar | Removes Docker socket access from the main process |

Results are normalized into a single `Finding` table (type, severity, identifier, package, source, EPSS/CVSS scores, KEV status, fix version), in addition to the raw JSON blobs (`Scan.sbom`, `Scan.cves`) kept for audit purposes.

A `Finding` is an *observation*, valid for one scan. Above it, an `Issue` tracks the same problem across scans — identified by a fingerprint that deliberately ignores the package version, so a dependency that stays vulnerable through three patch releases keeps one history and one triage decision. Two axes are kept strictly separate: `state` (open/resolved) is written only by the pipeline, from what the scanners observe; `triage_status` (VEX) is written only by a human. Conflating them would make "resolved" meaningless — a suppressed finding and a genuinely fixed one must not look alike. See [`zanshin/services/issue_service.py`](zanshin/services/issue_service.py).

The detailed decisions, discarded alternatives, and phase-by-phase implementation status are documented in [`docs/architecture/ADR-001-scanner-backends.md`](docs/architecture/ADR-001-scanner-backends.md) (written in French). The `scan-api/` sidecar has its own [README](scan-api/README.md) (deployment model, security, known limitations). For diagrams of the layered architecture, the full database schema, and the scan pipeline's sequence flow, see [`docs/TECHNICAL_DOCUMENTATION.md`](docs/TECHNICAL_DOCUMENTATION.md).

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
| `ENCRYPTION_KEY` | To store SSH keys | 32-byte key used to encrypt SSH private keys (AES-GCM). Without it, saving an SSH key is refused rather than silently falling back to the well-known default key that used to ship in this repository. Existing values encrypted with that old key still decrypt, and move to the new key when re-saved. |
| `ZANSHIN_BOOTSTRAP_USERNAME` | First run only | Username of the initial SUPERUSER, created at startup when the `user` table is empty. |
| `ZANSHIN_BOOTSTRAP_PASSWORD` | First run only | Its password (8 characters minimum). |

Operational tuning (all optional, shown with their defaults):

| Variable | Default | Purpose |
|---|---|---|
| `ZANSHIN_DATABASE_URL` | the bundled SQLite file | Points the app and the migrations at another database. |
| `ZANSHIN_SCAN_WORKERS` | `5` | Concurrent scans. Each one can hold a scanner container open. |
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

### Tests

```bash
uv run pytest
```

~82% coverage over `zanshin/`, UI layer included. The two halves of the UI are checked by different means: page loaders and event handlers by state-level tests (see the `UIHarness` in `tests/conftest.py`, which drives a Reflex state outside the server), and the component trees by `uv run reflex compile --dry`, which fails on a mistyped attribute of a typed row model. Every test runs against an in-memory SQLite database, never against `zanshin/database.sqlite`.

### Project structure

```
zanshin/
├── models/          # SQLAlchemy models
├── repositories/     # Data access
├── services/         # Business logic (scanning, enrichment, users, audit...)
│   └── scanners/      # ScannerEngine implementations (docker, osv, local_api)
├── ui/                # Reflex pages, state, and typed view models
├── api/               # HTTP API (FastAPI, mounted on the Reflex app)
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
- **Scan IaC** (checkov) : détection de mauvaises configurations Terraform/Kubernetes dans les dépôts.
- **Suivi et triage des problèmes** : chaque finding est suivi d'un scan à l'autre sous forme de *problème* — première détection, nombre de fois vu, existence d'un correctif, et décision de triage en vocabulaire VEX (affecté / non affecté / corrigé / à examiner) avec justification, et éventuellement une **date de révision**. Une suppression porte sur un contexte — « pas atteignable dans notre configuration », « pas livré en production » — et les contextes changent ; à l'échéance, le problème revient *à examiner*, justification et commentaire conservés. Chaque scan indique ce qu'il a **changé** : problèmes apparus, problèmes résolus.
- **Rescan périodique** : chaque cible porte un intervalle de scan, honoré par un ordonnanceur intégré — l'intérêt étant que de nouvelles vulnérabilités apparaissent dans du code qui n'a pas bougé.
- **API HTTP et *policy gate* CI** : déclencher un scan, lire les problèmes, et demander « ce build doit-il échouer ? » selon une politique configurable (seuil de sévérité, exploitation active, correctif disponible). Authentifiée par les clés API émises depuis l'UI.
- **Notifications** : un webhook part quand un scan fait apparaître ou réapparaître quelque chose — pas à chaque scan, c'est ce qui garde le canal lisible.
- **Exports** : **SARIF 2.1.0** pour GitHub code scanning / GitLab / Azure DevOps — c'est ce qui sort un problème du tableau de bord pour l'amener sur la pull request qui l'a introduit — plus un document OpenVEX construit à partir des décisions de triage, les problèmes en CSV, et le SBOM stocké.
- **Gestion des utilisateurs** et **journal d'audit** : rôles (SUPERUSER/ADMIN/USER), garde-fous (impossible de supprimer son propre compte ou le dernier superutilisateur actif), traçabilité des actions sensibles.
- **Backends de scan interchangeables** : Docker local (par défaut, rien ne sort de la machine), OSV.dev (matching de vulnérabilités via API cloud gratuite) ou un service HTTP sidecar auto-hébergé (`scan-api/`) — au choix depuis la page Paramètres, sans changer le reste de l'application.

### Architecture

Le choix de conception central est l'interface `ScannerEngine` (`zanshin/services/scanners/base.py`), qui découple *quoi* scanner de *où/comment* c'est exécuté. `ScanProcessor` orchestre les étapes (clone, SBOM, scan de vulnérabilités, secrets, IaC) sans jamais appeler Docker directement — il délègue à l'implémentation configurée :

| Backend | Génération SBOM / secrets / IaC | Matching de vulnérabilités | Cas d'usage |
|---|---|---|---|
| `docker` (défaut) | Conteneurs Docker éphémères (Syft/gitleaks/checkov) | Grype (conteneur local) | Aucune dépendance externe, 100 % local |
| `osv` | Délégué au backend Docker local | API cloud OSV.dev (gratuite) | Matching CVE sans maintenir Grype localement |
| `local_api` | Service HTTP sidecar (`scan-api/`), même hôte, disque partagé | Idem, via le sidecar | Retire l'accès au socket Docker du processus principal |

Les résultats sont normalisés dans une table `Finding` unique (type, sévérité, identifiant, package, source, scores EPSS/CVSS, statut KEV, version corrigée) en plus des blobs JSON bruts (`Scan.sbom`, `Scan.cves`) conservés pour l'audit.

Un `Finding` est une *observation*, valable pour un seul scan. Au-dessus, un `Issue` suit le même problème d'un scan à l'autre — identifié par une empreinte qui ignore volontairement la version du paquet, pour qu'une dépendance restée vulnérable pendant trois versions correctives conserve un seul historique et une seule décision de triage. Deux axes sont maintenus strictement séparés : `state` (ouvert/résolu) n'est écrit que par le pipeline, d'après ce que les scanners observent ; `triage_status` (VEX) n'est écrit que par un humain. Les confondre viderait « résolu » de son sens — un finding masqué et un finding réellement corrigé ne doivent pas se ressembler. Voir [`zanshin/services/issue_service.py`](zanshin/services/issue_service.py).

Le détail des décisions, alternatives écartées et le statut d'implémentation phase par phase sont documentés dans [`docs/architecture/ADR-001-scanner-backends.md`](docs/architecture/ADR-001-scanner-backends.md). Le service sidecar `scan-api/` a son propre [README](scan-api/README.md) (modèle de déploiement, sécurité, limites connues). Pour les diagrammes de l'architecture en couches, le schéma complet de la base de données et le déroulé du pipeline de scan, voir [`docs/TECHNICAL_DOCUMENTATION.md`](docs/TECHNICAL_DOCUMENTATION.md).

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
| `ENCRYPTION_KEY` | Pour stocker des clés SSH | Clé de 32 octets utilisée pour chiffrer les clés SSH privées (AES-GCM). Sans elle, l'enregistrement d'une clé SSH est refusé, au lieu de retomber silencieusement sur la clé par défaut publiée dans ce dépôt. Les valeurs déjà chiffrées avec cette ancienne clé restent déchiffrables, et basculent sur la nouvelle clé lors du prochain enregistrement. |
| `ZANSHIN_BOOTSTRAP_USERNAME` | Premier démarrage | Nom du SUPERUSER initial, créé au démarrage quand la table `user` est vide. |
| `ZANSHIN_BOOTSTRAP_PASSWORD` | Premier démarrage | Son mot de passe (8 caractères minimum). |

Réglages d'exploitation (tous optionnels, valeurs par défaut indiquées) :

| Variable | Défaut | Rôle |
|---|---|---|
| `ZANSHIN_DATABASE_URL` | le fichier SQLite fourni | Pointe l'application et les migrations vers une autre base. |
| `ZANSHIN_SCAN_WORKERS` | `5` | Scans simultanés. Chacun peut occuper un conteneur de scan. |
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

### Tests

```bash
uv run pytest
```

~82 % de couverture sur `zanshin/`, couche UI incluse. Les deux moitiés de l'UI sont vérifiées par des moyens différents : les loaders et handlers par des tests d'état (voir `UIHarness` dans `tests/conftest.py`, qui pilote un état Reflex hors serveur), et les arbres de composants par `uv run reflex compile --dry`, qui échoue sur un attribut inexistant d'une ligne typée. Chaque test s'exécute sur une base SQLite en mémoire, jamais sur `zanshin/database.sqlite`.

### Structure du projet

```
zanshin/
├── models/          # Modèles SQLAlchemy
├── repositories/     # Accès aux données
├── services/         # Logique métier (scan, enrichissement, utilisateurs, audit...)
│   └── scanners/      # Implémentations ScannerEngine (docker, osv, local_api)
├── ui/                # Pages, état et view-models typés Reflex
├── api/               # API HTTP (FastAPI, montée sur l'app Reflex)
├── schema.py          # Amorçage Alembic au démarrage
├── clock.py           # Source unique de « maintenant »
└── container.py       # Injection de dépendances (IoCContainer)
migrations/            # Révisions Alembic
scan-api/              # Service sidecar HTTP (backend local_api)
tests/                 # Suite pytest
docs/architecture/     # ADR
```
