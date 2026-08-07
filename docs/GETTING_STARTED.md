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
| `ENCRYPTION_KEY` | *none* — saving a secret is refused until it is set |
| `ZANSHIN_PREVIOUS_ENCRYPTION_KEYS` | *none* — comma-separated older keys, tried for decryption only |

`ENCRYPTION_KEY` is the AES-GCM key `EncryptionService` uses to encrypt SSH private keys at rest (`SSHKey.private_key`) and ticket tokens. **There is no default.** There used to be one, hardcoded in this repository's source, which meant a copy of the database file was enough to read every stored private key; it has been removed, and the application will refuse to write a secret rather than write one it cannot protect.

```bash
export ENCRYPTION_KEY="$(python -c 'import base64,os; print(base64.b64encode(os.urandom(32)).decode())')"
```

Changing it later no longer strands what is already stored: list the old key in `ZANSHIN_PREVIOUS_ENCRYPTION_KEYS` and existing values keep decrypting while new ones are written under the current key. The **SSH keys** page shows which rows still depend on an older key, so you can tell when the old one can be dropped. A value encrypted with the removed default key is a different matter — its plaintext is public, so it must be replaced at the provider, not re-encrypted; see [`ROTATION_ET_PURGE.md`](ROTATION_ET_PURGE.md).

### 4. Database

The SQLite database file is `zanshin/database.sqlite` and is **checked into this repository** — it predates the current codebase and is carried forward with its existing data (repositories, containers, users, scan history, VEX decisions, ...). You do not need to create it or seed it from scratch for a normal clone of this repo.

On every startup, Zanshin brings the database to the latest Alembic revision (`zanshin/schema.py`): a fresh database is built from the migrations, and a database that predates Alembic is *adopted* — stamped at the baseline revision rather than rebuilt — so no manual step is needed when upgrading. Column changes are ordinary migrations; generate one with `uv run alembic revision --autogenerate -m "..."` and check for drift with `uv run alembic check`.

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

### 7. Optional: AI code review (Ollama)

An additional, disabled-by-default option: a local LLM, run via [Ollama](https://ollama.com), that reviews source code with a "security architect" prompt as a lightweight complement to Grype/gitleaks/checkov — not a replacement. When enabled, it runs automatically on repository scans; its narrative result and normalized findings (severity/title/file) show up in the scan detail dialog. See `AiReviewService`'s docstring and [`TECHNICAL_DOCUMENTATION.md`](TECHNICAL_DOCUMENTATION.md) §4bis for how it's wired in.

Ollama can be run either natively or in Docker — Zanshin talks to it over plain HTTP either way (`ai_review_ollama_url`, default `http://localhost:11434`), and the choice is purely about where/how Ollama itself runs. This is selectable in Settings ("Mode de déploiement d'Ollama"), for documentation/UI purposes only.

**Native install (recommended, especially on Apple Silicon Macs)** — see [ollama.com/download](https://ollama.com/download). Gets full GPU acceleration: Metal on Apple Silicon, CUDA/ROCm on Linux with the right drivers.

```bash
ollama pull gemma4:12b-it-qat   # ~7.2GB, ~9-10GB RAM/VRAM — recommended default
ollama pull gemma4:e4b-it-qat   # ~6.1GB, lighter/faster, lower review quality
```

**Docker** — simpler to reproduce across machines, but on **Apple Silicon Macs, Docker Desktop has no GPU/Metal passthrough**, so the container runs CPU-only and inference is noticeably slower than the native app. On Linux with an NVIDIA GPU (+ nvidia-container-toolkit), GPU acceleration is still possible in the container. A ready-made compose file is provided at the repository root:

```bash
docker compose -f docker-compose.ollama.yml up -d
docker exec -it zanshin-ollama ollama pull gemma4:12b-it-qat
docker exec -it zanshin-ollama ollama pull gemma4:e4b-it-qat   # optional, lighter alternative
```

(Uncomment the `deploy` section in `docker-compose.ollama.yml` for NVIDIA GPU passthrough on Linux.)

Then, from Zanshin's **Settings** page, under "Revue de code par IA": pick a deployment mode (informational — see above), toggle the feature on, set the Ollama URL (default `http://localhost:11434`, unchanged whether Ollama runs natively or via the provided compose file since the container publishes the same port to the host), and pick a model from the dropdown — the list is read live from Ollama's own `/api/tags` endpoint (whatever you've actually pulled shows up there), not a hardcoded list. If Ollama isn't reachable yet, the dropdown falls back to showing the two models above as suggestions rather than being empty.

### 8. Running the tests

```bash
uv run pytest
```

Runs entirely against an in-memory database; never touches `zanshin/database.sqlite`. See [`TECHNICAL_DOCUMENTATION.md`](TECHNICAL_DOCUMENTATION.md) §6 for the testing approach.

### 9. Troubleshooting

- **`docker.errors.DockerException` / permission denied on the Docker socket**: the user running Zanshin needs access to the Docker socket (`/var/run/docker.sock` on Linux/macOS with Docker Desktop). On Linux, add the user to the `docker` group or run with sufficient privileges.
- **First scan is slow**: the `docker` backend pulls `anchore/syft`, `anchore/grype`, `zricethezav/gitleaks`, and `bridgecrew/checkov` images on demand the first time each is used — subsequent scans reuse the cached images.
- **"Identifiants incorrects ou compte inactif" on login**: either the credentials are wrong, or the account's `is_active` flag is `false` — check via `/users` (needs an existing admin) or query the `user` table directly.
- **Changed `ENCRYPTION_KEY` and now SSH key decryption fails**: list the previous key in `ZANSHIN_PREVIOUS_ENCRYPTION_KEYS` (comma-separated). Existing values then decrypt again, and move to the new key as they are re-saved — the **Clés SSH** page marks the rows that still depend on the old one.
- **An SSH key shows "Illisible" after upgrading**: no configured key reads it, most likely because it predates any `ENCRYPTION_KEY` and was encrypted with the default that used to ship in this repository. That default has been removed. Its private half is public, so replace the key pair at your git provider rather than trying to recover it; [`ROTATION_ET_PURGE.md`](ROTATION_ET_PURGE.md) has the procedure.
- **AI review model dropdown only shows the two suggestions**: Ollama isn't reachable at the configured URL — check it's running (`ollama list` if native, `docker ps` / `docker compose -f docker-compose.ollama.yml ps` if containerized) and that the URL/port match, then click "Rafraîchir la liste" on the Settings page.
- **AI review works but feels slow**: expected if Ollama is running in Docker on an Apple Silicon Mac (no GPU/Metal passthrough — CPU-only inference). Switch to a native install for GPU acceleration, or use the lighter `gemma4:e4b-it-qat` model.

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
| `ENCRYPTION_KEY` | *aucun* — l'enregistrement d'un secret est refusé tant qu'elle n'est pas définie |
| `ZANSHIN_PREVIOUS_ENCRYPTION_KEYS` | *aucun* — anciennes clés séparées par des virgules, essayées au déchiffrement uniquement |

`ENCRYPTION_KEY` est la clé AES-GCM utilisée par `EncryptionService` pour chiffrer au repos les clés privées SSH (`SSHKey.private_key`) et les jetons de ticket. **Il n'y a pas de valeur par défaut.** Il y en avait une, codée en dur dans le source de ce dépôt, si bien qu'une copie du fichier de base suffisait à lire toutes les clés privées stockées ; elle a été retirée, et l'application refuse d'écrire un secret plutôt que d'en écrire un qu'elle ne peut pas protéger.

```bash
export ENCRYPTION_KEY="$(python -c 'import base64,os; print(base64.b64encode(os.urandom(32)).decode())')"
```

La changer ensuite ne condamne plus ce qui est déjà stocké : listez l'ancienne clé dans `ZANSHIN_PREVIOUS_ENCRYPTION_KEYS` et les valeurs existantes continuent de se déchiffrer, tandis que les nouvelles sont écrites sous la clé courante. La page **Clés SSH** indique les lignes qui dépendent encore d'une ancienne clé, ce qui permet de savoir quand la retirer. Une valeur chiffrée avec l'ancienne clé par défaut est un autre sujet : son contenu en clair est public, elle est donc à remplacer chez le fournisseur et non à rechiffrer — voir [`ROTATION_ET_PURGE.md`](ROTATION_ET_PURGE.md).

### 4. Base de données

Le fichier de base de données SQLite est `zanshin/database.sqlite` et est **versionné dans ce dépôt** — il précède le code actuel et est repris avec ses données existantes (dépôts, conteneurs, utilisateurs, historique de scans, décisions VEX, ...). Vous n'avez pas besoin de le créer ou de l'initialiser depuis zéro pour un clone normal de ce dépôt.

À chaque démarrage, Zanshin met la base à la dernière révision Alembic (`zanshin/schema.py`) : une base vierge est construite depuis les migrations, une base antérieure à Alembic est *adoptée* — estampillée à la révision de référence plutôt que reconstruite — donc aucune manipulation n'est nécessaire lors d'une mise à jour. Les changements de colonne sont des migrations ordinaires : `uv run alembic revision --autogenerate -m "..."` pour en générer une, `uv run alembic check` pour détecter une dérive.

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

### 7. Optionnel : revue de code par IA (Ollama)

Une option supplémentaire, désactivée par défaut : un LLM local, exécuté via [Ollama](https://ollama.com), qui relit le code source avec un prompt "security architect", en complément léger de Grype/gitleaks/checkov — pas un remplacement. Une fois activée, elle s'exécute automatiquement sur les scans de dépôt ; son résultat narratif et ses findings normalisés (sévérité/titre/fichier) apparaissent dans la fenêtre de détail du scan. Voir la docstring d'`AiReviewService` et [`TECHNICAL_DOCUMENTATION.md`](TECHNICAL_DOCUMENTATION.md) §4bis pour le détail de l'intégration.

Ollama peut tourner soit nativement, soit en Docker — Zanshin lui parle en HTTP dans les deux cas (`ai_review_ollama_url`, défaut `http://localhost:11434`), le choix ne concerne que la façon dont Ollama lui-même est lancé. Ce choix est disponible dans les Réglages ("Mode de déploiement d'Ollama"), à titre informatif/documentaire.

**Installation native (recommandée, surtout sur Mac Apple Silicon)** — voir [ollama.com/download](https://ollama.com/download). Bénéficie de l'accélération GPU complète : Metal sur Apple Silicon, CUDA/ROCm sous Linux avec les bons pilotes.

```bash
ollama pull gemma4:12b-it-qat   # ~7,2 Go, ~9-10 Go RAM/VRAM — défaut recommandé
ollama pull gemma4:e4b-it-qat   # ~6,1 Go, plus léger/rapide, qualité de revue moindre
```

**Docker** — plus simple à reproduire d'une machine à l'autre, mais **sur Mac Apple Silicon, Docker Desktop n'a pas d'accès GPU/Metal** : le conteneur tourne alors en CPU uniquement, nettement plus lent que l'application native. Sous Linux avec un GPU NVIDIA (+ nvidia-container-toolkit), l'accélération GPU reste possible en conteneur. Un fichier compose prêt à l'emploi est fourni à la racine du dépôt :

```bash
docker compose -f docker-compose.ollama.yml up -d
docker exec -it zanshin-ollama ollama pull gemma4:e4b-it-qat   # optionnel, alternative plus légère
docker exec -it zanshin-ollama ollama pull gemma4:12b-it-qat

```

(Décommentez la section `deploy` de `docker-compose.ollama.yml` pour le passthrough GPU NVIDIA sous Linux.)

Puis, depuis la page **Paramètres** de Zanshin, section "Revue de code par IA" : choisissez un mode de déploiement (informatif — voir ci-dessus), activez la fonctionnalité, définissez l'URL d'Ollama (par défaut `http://localhost:11434`, inchangée qu'Ollama tourne nativement ou via le fichier compose fourni puisque le conteneur publie le même port sur l'hôte), et choisissez un modèle dans la liste déroulante — la liste est lue en direct sur l'API `/api/tags` d'Ollama (ce que vous avez réellement téléchargé y apparaît), pas une liste figée. Si Ollama n'est pas encore joignable, la liste propose les deux modèles ci-dessus à titre de suggestion plutôt que d'être vide.

### 8. Lancer les tests

```bash
uv run pytest
```

S'exécute entièrement sur une base en mémoire ; ne touche jamais `zanshin/database.sqlite`. Voir [`TECHNICAL_DOCUMENTATION.md`](TECHNICAL_DOCUMENTATION.md) §6 pour l'approche de test.

### 9. Dépannage

- **`docker.errors.DockerException` / permission refusée sur le socket Docker** : l'utilisateur qui lance Zanshin doit avoir accès au socket Docker (`/var/run/docker.sock` sous Linux/macOS avec Docker Desktop). Sous Linux, ajoutez l'utilisateur au groupe `docker` ou lancez avec les privilèges suffisants.
- **Le premier scan est lent** : le backend `docker` télécharge les images `anchore/syft`, `anchore/grype`, `zricethezav/gitleaks` et `bridgecrew/checkov` à la demande lors de leur première utilisation — les scans suivants réutilisent les images en cache.
- **« Identifiants incorrects ou compte inactif » à la connexion** : soit les identifiants sont erronés, soit le champ `is_active` du compte est à `false` — vérifiez via `/users` (nécessite un admin existant) ou interrogez directement la table `user`.
- **`ENCRYPTION_KEY` changée et le déchiffrement des clés SSH échoue désormais** : indiquez la clé précédente dans `ZANSHIN_PREVIOUS_ENCRYPTION_KEYS` (valeurs séparées par des virgules). Les valeurs existantes se déchiffrent à nouveau et basculent sur la nouvelle clé au fil des réenregistrements — la page **Clés SSH** signale celles qui dépendent encore de l'ancienne.
- **Une clé SSH affiche « Illisible » après une mise à jour** : aucune clé configurée ne la déchiffre, le plus souvent parce qu'elle est antérieure à toute `ENCRYPTION_KEY` et qu'elle a été chiffrée avec la clé par défaut autrefois publiée dans ce dépôt. Cette valeur par défaut a été retirée. Sa moitié privée est publique : remplacez la paire chez votre fournisseur git plutôt que de chercher à la récupérer ; la marche à suivre est dans [`ROTATION_ET_PURGE.md`](ROTATION_ET_PURGE.md).
- **La liste des modèles IA n'affiche que les deux suggestions** : Ollama n'est pas joignable à l'URL configurée — vérifiez qu'il tourne (`ollama list` en natif, `docker ps` / `docker compose -f docker-compose.ollama.yml ps` en conteneur) et que l'URL/le port correspondent, puis cliquez sur "Rafraîchir la liste" dans la page Paramètres.
- **La revue IA fonctionne mais semble lente** : normal si Ollama tourne en Docker sur un Mac Apple Silicon (pas de passthrough GPU/Metal — inférence CPU uniquement). Passez à une installation native pour l'accélération GPU, ou utilisez le modèle plus léger `gemma4:e4b-it-qat`.
