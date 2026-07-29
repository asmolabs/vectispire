# Zanshin — Getting Started / Launch Guide

**[English](#english)** | **[Français](#français)**

---

## English

This document covers everything needed to run Zanshin locally: prerequisites, installation, environment configuration, and how to start both the main application and the optional `scan-api` sidecar. For features, see [`README.md`](../README.md); for architecture and database schema, see [`TECHNICAL_DOCUMENTATION.md`](TECHNICAL_DOCUMENTATION.md).

### 1. Prerequisites

| Requirement | Why |
|---|---|
| **Python ≥ 3.12** | Pinned in `pyproject.toml` (`requires-python = ">=3.12"`) and `.python-version`. |
| **[uv](https://docs.astral.sh/uv/)** | Dependency manager used by this project (`uv.lock` is checked in). |
| **Docker**, running and reachable | Required by the default `docker` scan backend: Zanshin runs Syft, Grype, gitleaks, and checkov as ephemeral containers via the Docker socket. Not needed if you only use the `osv` or `local_api` backend (see §5 and [`TECHNICAL_DOCUMENTATION.md`](TECHNICAL_DOCUMENTATION.md) §4). |
| **Git** | Used both to clone this repo and, internally, by Zanshin itself (GitPython) to clone the repositories it scans. |

Node.js is **not** a separate prerequisite: Reflex compiles the frontend itself (a `.web/` directory with its own bundled `node_modules` is generated on first run).

### 2. Install

```bash
git clone <this-repo-url>
cd Zanshin
uv sync
```

`uv sync` installs both runtime dependencies (Reflex, SQLAlchemy, cryptography, docker SDK, GitPython, bcrypt, httpx, ...) and the dev dependencies (`pytest`, `pytest-cov`) from `pyproject.toml`.

### 3. Configuration

Zanshin has almost no environment-variable configuration — most runtime settings (which scan backend to use, whether enrichment is enabled, the license blocklist, ...) live in the database (`setting` table) and are edited from the **Settings** page after the app is running (see §6). There is one environment variable worth knowing about before your first run:

| Variable | Default |
|---|---|
| `ENCRYPTION_KEY` | `"my-secret-encryption-key-32bytes"` (hardcoded fallback, kept for backward compatibility with previously encrypted data) |

`ENCRYPTION_KEY` is the AES-GCM key `EncryptionService` uses to encrypt SSH private keys at rest (`SSHKey.private_key`). **Set this explicitly to a real secret in any environment beyond local experimentation** — the default is public (it's in this repo's source code) and offers no real protection. Changing it after keys have already been encrypted will make them undecryptable, so set it once, before first use.

```bash
export ENCRYPTION_KEY="a-real-32-byte-secret-value-here"
```

### 4. Database

The SQLite database file is `zanshin/database.sqlite` and is **checked into this repository** — it predates the current codebase and is carried forward with its existing data (repositories, containers, users, scan history, VEX decisions, ...). You do not need to create it or seed it from scratch for a normal clone of this repo.

On every startup, `Base.metadata.create_all()` runs automatically (`zanshin/zanshin.py`) and creates any table that doesn't exist yet (this is how newer tables like `finding`, `audit_logs`'s model, and `api_key`'s new columns were introduced without a migration tool). It never alters or drops an existing table — see [`ADR-001`](architecture/ADR-001-scanner-backends.md) for why there's no migration tool yet, and treat any future column change as something requiring a manual, hand-written migration.

**If you're starting from a genuinely empty database** (e.g. a fresh environment without the tracked `database.sqlite`, or one you deleted on purpose): there is no self-registration page, so you'll need to create the first user directly, once, via a Python shell:

```bash
uv run python
```

```python
from zanshin.database import SessionLocal
from zanshin.services.auth_service import AuthService
from zanshin.repositories.user_repository import UserRepository
from zanshin.models.user import User
from datetime import datetime

db = SessionLocal()
user_repo = UserRepository(db)
auth = AuthService(user_repo)

user = User(
    username="admin",
    password=auth.hash_password("change-me-immediately"),
    display_name="Admin",
    role="SUPERUSER",
    is_active=True,
    created_at=datetime.utcnow(),
)
db.add(user)
db.commit()
db.close()
```

Log in with those credentials, then change the password from the app (or directly reset it later via the `/users` admin page once at least one `SUPERUSER` exists).

### 5. Launching the application

```bash
uv run reflex run
```

This starts both halves of the app: the frontend dev server (default `http://localhost:3000`) and the backend API Reflex's event handlers talk to (default port `8000`) — both configurable in `rxconfig.py` if needed. Open `http://localhost:3000/login` and sign in.

For a production-style run: `uv run reflex run --env prod` builds an optimized frontend bundle first. There is no `Dockerfile` or `docker-compose.yml` for the main Zanshin app in this repository yet — only for the optional `scan-api` sidecar (§6) — so containerized production deployment of the main app itself is not yet set up.

### 6. Optional: the `scan-api` sidecar (`local_api` backend)

Skip this section unless you specifically want the `local_api` scan backend (it removes the need for Zanshin's own process to access the Docker socket — see [`TECHNICAL_DOCUMENTATION.md`](TECHNICAL_DOCUMENTATION.md) §4). The default `docker` backend needs no separate service.

```bash
cd scan-api
pip install -r requirements.txt
# plus: install syft, grype, gitleaks, checkov on PATH — see each tool's own install docs,
# or build the provided Dockerfile which does this for you.
uvicorn main:app --host 0.0.0.0 --port 8686
```

Then, from Zanshin's **Settings** page, set:

- Scan backend: `local_api`
- Service URL: e.g. `http://localhost:8686`
- Shared directory: a filesystem path both Zanshin and `scan-api` can read/write at the **same path** (this backend passes file paths, never uploads — both processes must see the same disk)

Full deployment details (Docker image, shared-volume requirement, security warning about the lack of authentication on this service) are in [`scan-api/README.md`](../scan-api/README.md).

### 7. Running the tests

```bash
uv run pytest
```

Runs entirely against an in-memory database; never touches `zanshin/database.sqlite`. See [`TECHNICAL_DOCUMENTATION.md`](TECHNICAL_DOCUMENTATION.md) §6 for the testing approach.

### 8. Troubleshooting

- **`docker.errors.DockerException` / permission denied on the Docker socket**: the user running Zanshin needs access to the Docker socket (`/var/run/docker.sock` on Linux/macOS with Docker Desktop). On Linux, add the user to the `docker` group or run with sufficient privileges.
- **First scan is slow**: the `docker` backend pulls `anchore/syft`, `anchore/grype`, `zricethezav/gitleaks`, and `bridgecrew/checkov` images on demand the first time each is used — subsequent scans reuse the cached images.
- **"Identifiants incorrects ou compte inactif" on login**: either the credentials are wrong, or the account's `is_active` flag is `false` — check via `/users` (needs an existing admin) or query the `user` table directly.
- **Changed `ENCRYPTION_KEY` and now SSH key decryption fails**: expected — AES-GCM decryption requires the exact same key used to encrypt. There's no key-rotation mechanism; re-add affected SSH keys after changing the key.

---

## Français

Ce document couvre tout ce qui est nécessaire pour lancer Zanshin en local : prérequis, installation, configuration de l'environnement, et démarrage de l'application principale ainsi que du sidecar optionnel `scan-api`. Pour les fonctionnalités, voir [`README.md`](../README.md) ; pour l'architecture et le schéma de base de données, voir [`TECHNICAL_DOCUMENTATION.md`](TECHNICAL_DOCUMENTATION.md).

### 1. Prérequis

| Prérequis | Pourquoi |
|---|---|
| **Python ≥ 3.12** | Fixé dans `pyproject.toml` (`requires-python = ">=3.12"`) et `.python-version`. |
| **[uv](https://docs.astral.sh/uv/)** | Gestionnaire de dépendances utilisé par ce projet (`uv.lock` est versionné). |
| **Docker**, en cours d'exécution et accessible | Requis par le backend de scan par défaut (`docker`) : Zanshin exécute Syft, Grype, gitleaks et checkov comme conteneurs éphémères via le socket Docker. Pas nécessaire si vous utilisez uniquement le backend `osv` ou `local_api` (voir §5 et [`TECHNICAL_DOCUMENTATION.md`](TECHNICAL_DOCUMENTATION.md) §4). |
| **Git** | Utilisé pour cloner ce dépôt, et en interne par Zanshin lui-même (GitPython) pour cloner les dépôts qu'il scanne. |

Node.js n'est **pas** un prérequis séparé : Reflex compile lui-même le frontend (un répertoire `.web/` avec son propre `node_modules` est généré au premier lancement).

### 2. Installation

```bash
git clone <url-de-ce-dépôt>
cd Zanshin
uv sync
```

`uv sync` installe à la fois les dépendances d'exécution (Reflex, SQLAlchemy, cryptography, SDK docker, GitPython, bcrypt, httpx, ...) et les dépendances de développement (`pytest`, `pytest-cov`) définies dans `pyproject.toml`.

### 3. Configuration

Zanshin n'a presque aucune configuration par variable d'environnement — la plupart des réglages runtime (backend de scan à utiliser, activation de l'enrichissement, liste noire de licences, ...) vivent en base (table `setting`) et se modifient depuis la page **Paramètres** une fois l'application lancée (voir §6). Il y a une seule variable d'environnement à connaître avant le premier lancement :

| Variable | Défaut |
|---|---|
| `ENCRYPTION_KEY` | `"my-secret-encryption-key-32bytes"` (valeur de repli codée en dur, conservée pour compatibilité avec des données déjà chiffrées) |

`ENCRYPTION_KEY` est la clé AES-GCM utilisée par `EncryptionService` pour chiffrer les clés privées SSH au repos (`SSHKey.private_key`). **À définir explicitement avec un vrai secret dans tout environnement au-delà d'une expérimentation locale** — la valeur par défaut est publique (elle figure dans le code source de ce dépôt) et n'offre aucune protection réelle. La changer après que des clés ont déjà été chiffrées les rendra indéchiffrables : définissez-la une fois, avant la première utilisation.

```bash
export ENCRYPTION_KEY="une-vraie-valeur-secrete-de-32-octets"
```

### 4. Base de données

Le fichier de base de données SQLite est `zanshin/database.sqlite` et est **versionné dans ce dépôt** — il précède le code actuel et est repris avec ses données existantes (dépôts, conteneurs, utilisateurs, historique de scans, décisions VEX, ...). Vous n'avez pas besoin de le créer ou de l'initialiser depuis zéro pour un clone normal de ce dépôt.

À chaque démarrage, `Base.metadata.create_all()` s'exécute automatiquement (`zanshin/zanshin.py`) et crée toute table qui n'existe pas encore (c'est ainsi que des tables plus récentes comme `finding`, le modèle d'`audit_logs`, et les nouvelles colonnes d'`api_key` ont été introduites sans outil de migration). Il ne modifie et ne supprime jamais une table existante — voir [`ADR-001`](architecture/ADR-001-scanner-backends.md) pour comprendre pourquoi il n'y a pas encore d'outil de migration, et considérez tout futur changement de colonne comme nécessitant une migration manuelle écrite à la main.

**Si vous partez d'une base réellement vide** (par exemple un environnement neuf sans le `database.sqlite` versionné, ou supprimé volontairement) : il n'y a pas de page d'auto-inscription, il faut donc créer le premier utilisateur directement, une seule fois, via un shell Python :

```bash
uv run python
```

```python
from zanshin.database import SessionLocal
from zanshin.services.auth_service import AuthService
from zanshin.repositories.user_repository import UserRepository
from zanshin.models.user import User
from datetime import datetime

db = SessionLocal()
user_repo = UserRepository(db)
auth = AuthService(user_repo)

user = User(
    username="admin",
    password=auth.hash_password("a-changer-immediatement"),
    display_name="Admin",
    role="SUPERUSER",
    is_active=True,
    created_at=datetime.utcnow(),
)
db.add(user)
db.commit()
db.close()
```

Connectez-vous avec ces identifiants, puis changez le mot de passe depuis l'application (ou réinitialisez-le plus tard directement depuis la page admin `/users` une fois qu'au moins un `SUPERUSER` existe).

### 5. Lancer l'application

```bash
uv run reflex run
```

Cela démarre les deux moitiés de l'application : le serveur de développement frontend (par défaut `http://localhost:3000`) et l'API backend à laquelle parlent les gestionnaires d'événements de Reflex (port par défaut `8000`) — les deux configurables dans `rxconfig.py` si besoin. Ouvrez `http://localhost:3000/login` et connectez-vous.

Pour un lancement de type production : `uv run reflex run --env prod` construit d'abord un bundle frontend optimisé. Il n'y a pas encore de `Dockerfile` ni de `docker-compose.yml` pour l'application Zanshin principale dans ce dépôt — seulement pour le sidecar optionnel `scan-api` (§6) — le déploiement conteneurisé en production de l'application principale elle-même n'est donc pas encore en place.

### 6. Optionnel : le sidecar `scan-api` (backend `local_api`)

Ignorez cette section sauf si vous voulez spécifiquement le backend de scan `local_api` (il supprime le besoin, pour le processus Zanshin lui-même, d'accéder au socket Docker — voir [`TECHNICAL_DOCUMENTATION.md`](TECHNICAL_DOCUMENTATION.md) §4). Le backend `docker` par défaut ne nécessite aucun service séparé.

```bash
cd scan-api
pip install -r requirements.txt
# plus : installer syft, grype, gitleaks, checkov sur le PATH — voir la doc
# d'installation de chaque outil, ou construire le Dockerfile fourni qui s'en charge.
uvicorn main:app --host 0.0.0.0 --port 8686
```

Puis, depuis la page **Paramètres** de Zanshin, définissez :

- Backend de scan : `local_api`
- URL du service : par ex. `http://localhost:8686`
- Répertoire partagé : un chemin du système de fichiers que Zanshin et `scan-api` peuvent tous deux lire/écrire au **même chemin** (ce backend transmet des chemins de fichiers, jamais des uploads — les deux processus doivent voir le même disque)

Le détail complet du déploiement (image Docker, exigence de volume partagé, avertissement de sécurité sur l'absence d'authentification de ce service) se trouve dans [`scan-api/README.md`](../scan-api/README.md).

### 7. Lancer les tests

```bash
uv run pytest
```

S'exécute entièrement sur une base en mémoire ; ne touche jamais `zanshin/database.sqlite`. Voir [`TECHNICAL_DOCUMENTATION.md`](TECHNICAL_DOCUMENTATION.md) §6 pour l'approche de test.

### 8. Dépannage

- **`docker.errors.DockerException` / permission refusée sur le socket Docker** : l'utilisateur qui lance Zanshin doit avoir accès au socket Docker (`/var/run/docker.sock` sous Linux/macOS avec Docker Desktop). Sous Linux, ajoutez l'utilisateur au groupe `docker` ou lancez avec les privilèges suffisants.
- **Le premier scan est lent** : le backend `docker` télécharge les images `anchore/syft`, `anchore/grype`, `zricethezav/gitleaks` et `bridgecrew/checkov` à la demande lors de leur première utilisation — les scans suivants réutilisent les images en cache.
- **« Identifiants incorrects ou compte inactif » à la connexion** : soit les identifiants sont erronés, soit le champ `is_active` du compte est à `false` — vérifiez via `/users` (nécessite un admin existant) ou interrogez directement la table `user`.
- **`ENCRYPTION_KEY` changée et le déchiffrement des clés SSH échoue désormais** : comportement attendu — le déchiffrement AES-GCM nécessite exactement la même clé que celle utilisée au chiffrement. Il n'y a pas de mécanisme de rotation de clé ; réajoutez les clés SSH concernées après avoir changé la clé.
