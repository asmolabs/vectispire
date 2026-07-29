# Zanshin

**[English](#english)** | **[Français](#français)**

---

## English

Zanshin is a software dependency and security tracking application built around SBOM (Software Bill of Materials) analysis. It scans Git repositories and container images, detects known vulnerabilities, hardcoded secrets, problematic licenses, and infrastructure-as-code misconfigurations, then centralizes the results in a single dashboard — in the spirit of a unified ASPM (Application Security Posture Management) platform, with a pluggable scanning layer (local Docker, local API, or cloud API depending on the analysis type).

Built in Python with [Reflex](https://reflex.dev) (server-side state and UI) and SQLAlchemy/SQLite.

### Features

- **SCA analysis (dependencies)**: SBOM generation (Syft) and known-vulnerability detection (Grype or OSV.dev), with severity, CVE, and affected component.
- **EPSS / CISA KEV enrichment**: every vulnerability is enriched with its exploitation probability (EPSS) and "actively exploited" status (KEV catalog), to prioritize beyond the raw CVSS score.
- **Secret detection** (gitleaks): finds hardcoded API keys, tokens, and credentials in scanned repositories.
- **License compliance**: evaluates a configurable license blocklist against data already present in the SBOM.
- **IaC scanning** (checkov): detects Terraform/Kubernetes misconfigurations in repositories.
- **VEX (Vulnerability Exploitability eXchange)**: manual vulnerability triage (affected / not affected / fixed / under review) with justification.
- **User management** and **audit log**: roles (SUPERUSER/ADMIN/USER), guardrails (can't delete your own account or the last active superuser), traceability of sensitive actions.
- **Interchangeable scan backends**: local Docker (default, nothing leaves the machine), OSV.dev (vulnerability matching via a free cloud API), or a self-hosted HTTP sidecar service (`scan-api/`) — selectable from the Settings page without changing the rest of the application.

### Architecture

The central design choice is the `ScannerEngine` interface (`zanshin/services/scanners/base.py`), which decouples *what* to scan from *where/how* it runs. `ScanProcessor` orchestrates the steps (clone, SBOM, vulnerability scan, secrets, IaC) without ever calling Docker directly — it delegates to whichever implementation is configured:

| Backend | SBOM / secrets / IaC generation | Vulnerability matching | Use case |
|---|---|---|---|
| `docker` (default) | Ephemeral Docker containers (Syft/gitleaks/checkov) | Grype (local container) | No external dependency, fully local |
| `osv` | Delegated to the local Docker backend | OSV.dev cloud API (free) | CVE matching without maintaining Grype locally |
| `local_api` | HTTP sidecar service (`scan-api/`), same host, shared disk | Same, via the sidecar | Removes Docker socket access from the main process |

Results are normalized into a single `Finding` table (type, severity, identifier, package, source, EPSS score, KEV status), in addition to the raw JSON blobs (`Scan.sbom`, `Scan.cves`) kept for audit purposes.

The detailed decisions, discarded alternatives, and phase-by-phase implementation status are documented in [`docs/architecture/ADR-001-scanner-backends.md`](docs/architecture/ADR-001-scanner-backends.md) (written in French). The `scan-api/` sidecar has its own [README](scan-api/README.md) (deployment model, security, known limitations). For diagrams of the layered architecture, the full database schema, and the scan pipeline's sequence flow, see [`docs/TECHNICAL_DOCUMENTATION.md`](docs/TECHNICAL_DOCUMENTATION.md).

### Quick start

Prerequisites: Python ≥ 3.12, [uv](https://docs.astral.sh/uv/), Docker (for the default scan backend).

```bash
uv sync
uv run reflex run
```

The app starts on `http://localhost:3000` (frontend), with the backend API on Reflex's default port. On first startup, missing tables are created automatically in `zanshin/database.sqlite` (`Base.metadata.create_all` — never alters existing tables; see the limitation documented in the ADR: no migration tool yet, so a column change requires a manual migration).

#### Main pages

| Route | Description |
|---|---|
| `/dashboard` | Overview |
| `/depots` | Tracked Git repositories, scan history, finding details |
| `/containers` | Tracked container images |
| `/ssh-keys` | Encrypted SSH keys for cloning private repositories |
| `/api-keys` | Programmatic API keys (bcrypt hash, secret shown once) |
| `/settings` | Scan backend selection, enrichment toggle, license blocklist |
| `/users` | User management (admin only) |
| `/audit-log` | Audit log of sensitive actions (admin only) |

### Configuration

Runtime settings (`scan_backend`, `enrichment_enabled`, `license_blocklist`, `local_api` backend URL and shared directory) are managed from the **Settings** page and stored in the database (`setting` table) rather than as environment variables.

### Tests

```bash
uv run pytest
```

The suite covers the entire services/repositories/scanners layer (~93% coverage on `zanshin/`, excluding the Reflex UI layer — `rx.State` classes are exercised through Reflex's own test harness, not plain pytest; see `pyproject.toml`). Every test runs against an in-memory SQLite database, never against `zanshin/database.sqlite`.

### Project structure

```
zanshin/
├── models/          # SQLAlchemy models
├── repositories/     # Data access
├── services/         # Business logic (scanning, enrichment, users, audit...)
│   └── scanners/      # ScannerEngine implementations (docker, osv, local_api)
├── ui/                # Reflex pages and state
└── container.py       # Dependency injection (IoCContainer)
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
- **Détection de secrets** (gitleaks) : recherche de clés API, tokens et identifiants codés en dur dans les dépôts scannés.
- **Conformité des licences** : évaluation d'une liste noire de licences configurable, à partir des données déjà présentes dans le SBOM.
- **Scan IaC** (checkov) : détection de mauvaises configurations Terraform/Kubernetes dans les dépôts.
- **VEX (Vulnerability Exploitability eXchange)** : triage manuel des vulnérabilités (affectée / non affectée / corrigée / en cours de revue) avec justification.
- **Gestion des utilisateurs** et **journal d'audit** : rôles (SUPERUSER/ADMIN/USER), garde-fous (impossible de supprimer son propre compte ou le dernier superutilisateur actif), traçabilité des actions sensibles.
- **Backends de scan interchangeables** : Docker local (par défaut, rien ne sort de la machine), OSV.dev (matching de vulnérabilités via API cloud gratuite) ou un service HTTP sidecar auto-hébergé (`scan-api/`) — au choix depuis la page Paramètres, sans changer le reste de l'application.

### Architecture

Le choix de conception central est l'interface `ScannerEngine` (`zanshin/services/scanners/base.py`), qui découple *quoi* scanner de *où/comment* c'est exécuté. `ScanProcessor` orchestre les étapes (clone, SBOM, scan de vulnérabilités, secrets, IaC) sans jamais appeler Docker directement — il délègue à l'implémentation configurée :

| Backend | Génération SBOM / secrets / IaC | Matching de vulnérabilités | Cas d'usage |
|---|---|---|---|
| `docker` (défaut) | Conteneurs Docker éphémères (Syft/gitleaks/checkov) | Grype (conteneur local) | Aucune dépendance externe, 100 % local |
| `osv` | Délégué au backend Docker local | API cloud OSV.dev (gratuite) | Matching CVE sans maintenir Grype localement |
| `local_api` | Service HTTP sidecar (`scan-api/`), même hôte, disque partagé | Idem, via le sidecar | Retire l'accès au socket Docker du processus principal |

Les résultats sont normalisés dans une table `Finding` unique (type, sévérité, identifiant, package, source, score EPSS, statut KEV) en plus des blobs JSON bruts (`Scan.sbom`, `Scan.cves`) conservés pour l'audit.

Le détail des décisions, alternatives écartées et le statut d'implémentation phase par phase sont documentés dans [`docs/architecture/ADR-001-scanner-backends.md`](docs/architecture/ADR-001-scanner-backends.md). Le service sidecar `scan-api/` a son propre [README](scan-api/README.md) (modèle de déploiement, sécurité, limites connues). Pour les diagrammes de l'architecture en couches, le schéma complet de la base de données et le déroulé du pipeline de scan, voir [`docs/TECHNICAL_DOCUMENTATION.md`](docs/TECHNICAL_DOCUMENTATION.md).

### Démarrage rapide

Prérequis : Python ≥ 3.12, [uv](https://docs.astral.sh/uv/), Docker (pour le backend de scan par défaut).

```bash
uv sync
uv run reflex run
```

L'application démarre sur `http://localhost:3000` (frontend) avec l'API backend sur le port par défaut de Reflex. Au premier démarrage, les tables manquantes sont créées automatiquement dans `zanshin/database.sqlite` (`Base.metadata.create_all` — ne modifie jamais les tables existantes, voir la limite documentée dans l'ADR : pas d'outil de migration, une évolution de colonne nécessite une intervention manuelle).

#### Pages principales

| Route | Description |
|---|---|
| `/dashboard` | Vue d'ensemble |
| `/depots` | Dépôts Git suivis, historique des scans, détail des findings |
| `/containers` | Images de conteneurs suivies |
| `/ssh-keys` | Clés SSH (chiffrées) pour cloner des dépôts privés |
| `/api-keys` | Clés API programmatiques (hash bcrypt, secret affiché une seule fois) |
| `/settings` | Choix du backend de scan, activation de l'enrichissement, liste noire de licences |
| `/users` | Gestion des utilisateurs (admin) |
| `/audit-log` | Journal d'audit des actions sensibles (admin) |

### Configuration

Les réglages runtime (`scan_backend`, `enrichment_enabled`, `license_blocklist`, URL et répertoire partagé du backend `local_api`) se gèrent depuis la page **Paramètres**, et sont stockés en base (table `setting`) plutôt que par variables d'environnement.

### Tests

```bash
uv run pytest
```

La suite couvre l'intégralité de la couche services/repositories/scanners (~93 % de couverture sur `zanshin/`, hors couche UI Reflex — les classes `rx.State` s'exercent via le harnais de test propre à Reflex, pas via pytest classique, voir `pyproject.toml`). Chaque test s'exécute sur une base SQLite en mémoire, jamais sur `zanshin/database.sqlite`.

### Structure du projet

```
zanshin/
├── models/          # Modèles SQLAlchemy
├── repositories/     # Accès aux données
├── services/         # Logique métier (scan, enrichissement, utilisateurs, audit...)
│   └── scanners/      # Implémentations ScannerEngine (docker, osv, local_api)
├── ui/                # Pages et état Reflex
└── container.py       # Injection de dépendances (IoCContainer)
scan-api/              # Service sidecar HTTP (backend local_api)
tests/                 # Suite pytest
docs/architecture/     # ADR
```
