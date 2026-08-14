# Zanshin — Getting Started / Launch Guide

**[English](#english)** | **[Français](#français)**

---

## English

This document covers everything needed to run Zanshin locally: prerequisites, installation, environment configuration, and how to start the application. For features, see [`README.md`](../README.md); for architecture and database schema, see [`TECHNICAL_DOCUMENTATION.md`](TECHNICAL_DOCUMENTATION.md).

### 1. Prerequisites

| Requirement | Why |
|---|---|
| **Node ≥ 24** | The workspace targets the current LTS. |
| **Docker**, running and reachable | Zanshin runs Syft, Grype, gitleaks, checkov and Semgrep as ephemeral containers through the Docker socket. It is also what starts PostgreSQL in development and in the integration tests. |
| **PostgreSQL** | The only supported engine — see the README for why that is a narrowing and not a preference. In development, a container is enough. |
| **Git** | To clone this repository, and used by Zanshin itself to clone what it scans. |

### 2. Install

```bash
git clone <this-repo-url>
cd Zanshin
npm install
```

One install for the whole workspace: `backend/` (NestJS) and `frontend/` (Angular) share
a single lockfile.

### 3. Configuration

Most runtime settings — enrichment, end-of-life, retention, notifications, licences,
tracker, model review — live in the database and are edited from the **Settings** page once
the application runs. A setting appears there only once a service actually reads it.

Three environment variables matter before the first run:

| Variable | Default |
|---|---|
| `ZANSHIN_DATABASE_URL` | *none* — required, e.g. `postgres://zanshin:zanshin@localhost:5432/zanshin` |
| `ENCRYPTION_KEY` | *none* — saving a secret is refused until it is set |
| `ZANSHIN_PREVIOUS_ENCRYPTION_KEYS` | *none* — comma-separated older keys, tried for decryption only |


### 4. Database

PostgreSQL, and only PostgreSQL. In development a container is the shortest path:

```bash
docker run -d --name zanshin-db -p 5432:5432 \
  -e POSTGRES_USER=zanshin -e POSTGRES_PASSWORD=zanshin -e POSTGRES_DB=zanshin \
  postgres:16-alpine
```

The schema belongs to **TypeORM migrations**, applied as an explicit step:

```bash
npm --workspace backend run migration:run       # apply
npm --workspace backend run migration:generate  # write one from the entities
```

`synchronize` is off, deliberately: a schema synthesised from the entities is not the one
production will receive, and testing against it would let a faulty migration through.

There is no self-registration page, so the first account comes from the bootstrap
variables — set them before the first start and the SUPERUSER is created when the user
table is empty:

```bash
ZANSHIN_BOOTSTRAP_USERNAME=admin
ZANSHIN_BOOTSTRAP_PASSWORD=<at least 8 characters>
```


### 5. Launching the application

```bash
npm --workspace backend run migration:run   # bring the schema up to date
npm --workspace backend run start:dev       # API on http://localhost:3000
npm --workspace frontend start              # UI on http://localhost:4200
```

The first start creates a SUPERUSER from `ZANSHIN_BOOTSTRAP_USERNAME` and
`ZANSHIN_BOOTSTRAP_PASSWORD` when the user table is empty. Once an account exists, both
variables are ignored.


### 6. Optional: AI code review (Ollama)

An additional, disabled-by-default option: a local LLM, run via [Ollama](https://ollama.com), that reviews source code with a "security architect" prompt as a lightweight complement to Grype/gitleaks/checkov — not a replacement. When enabled, it runs automatically on repository scans; its narrative result and normalized findings (severity/title/file) show up in the scan detail dialog. See `AiReviewService`'s docstring and [`TECHNICAL_DOCUMENTATION.md`](TECHNICAL_DOCUMENTATION.md) §4bis for how it's wired in.

Ollama can be run either natively or in Docker — Zanshin talks to it over plain HTTP either way (`ai_review_ollama_url`, default `http://localhost:11434`), and the choice is purely about where/how Ollama itself runs. The Python version carried a *Mode de déploiement* setting here; it changed nothing about how Zanshin called Ollama, so it is not part of this port.

**Native install (recommended, especially on Apple Silicon Macs)** — see [ollama.com/download](https://ollama.com/download). Gets full GPU acceleration: Metal on Apple Silicon, CUDA/ROCm on Linux with the right drivers.

```bash
ollama pull gemma4:12b-it-qat   # ~7.2GB, ~9-10GB RAM/VRAM — recommended default
ollama pull gemma4:e4b-it-qat   # ~6.1GB, lighter/faster, lower review quality
```

**Docker** — simpler to reproduce across machines, but on **Apple Silicon Macs, Docker Desktop has no GPU/Metal passthrough**, so the container runs CPU-only and inference is noticeably slower than the native app. On Linux with an NVIDIA GPU (+ nvidia-container-toolkit), GPU acceleration is still possible in the container. A ready-made compose file is provided at the repository root:

```bash
docker run -d --name ollama -p 11434:11434 -v ollama:/root/.ollama ollama/ollama
docker exec -it zanshin-ollama ollama pull gemma4:12b-it-qat
docker exec -it zanshin-ollama ollama pull gemma4:e4b-it-qat   # optional, lighter alternative
```

(Add `--gpus all` for NVIDIA passthrough on Linux.)

Then, from Zanshin's **Settings** page, under "Revue de code par IA": toggle the feature on, set the Ollama URL (default `http://localhost:11434`, unchanged whether Ollama runs natively or via the provided compose file since the container publishes the same port to the host), and pick a model from the dropdown — the list is read live from Ollama's own `/api/tags` endpoint (whatever you've actually pulled shows up there), not a hardcoded list. If Ollama isn't reachable yet, the dropdown falls back to showing the two models above as suggestions rather than being empty.

### 7. Running the tests

```bash
npm --workspace backend test                    # unit suite
npm --workspace backend run test:integration    # starts PostgreSQL via testcontainers
```

The integration suites start their own database and **do not skip** when one is missing:
a run without Docker fails loudly rather than reporting green having verified nothing.


### 8. Troubleshooting

- **`docker.errors.DockerException` / permission denied on the Docker socket**: the user running Zanshin needs access to the Docker socket (`/var/run/docker.sock` on Linux/macOS with Docker Desktop). On Linux, add the user to the `docker` group or run with sufficient privileges.
- **First scan is slow**: the `docker` backend pulls `anchore/syft`, `anchore/grype`, `zricethezav/gitleaks`, `bridgecrew/checkov` and `semgrep/semgrep` images on demand the first time each is used — subsequent scans reuse the cached images.
- **"Identifiants incorrects ou compte inactif" on login**: either the credentials are wrong, or the account's `is_active` flag is `false` — check via `/users` (needs an existing admin) or query the `user` table directly.
- **Changed `ENCRYPTION_KEY` and now SSH key decryption fails**: list the previous key in `ZANSHIN_PREVIOUS_ENCRYPTION_KEYS` (comma-separated). Existing values then decrypt again, and move to the new key as they are re-saved — the **Clés SSH** page marks the rows that still depend on the old one.
- **An SSH key shows "Illisible" after upgrading**: no configured key reads it, most likely because it predates any `ENCRYPTION_KEY` and was encrypted with the default that used to ship in this repository. That default has been removed. Its private half is public, so replace the key pair at your git provider rather than trying to recover it; [`ROTATION_ET_PURGE.md`](ROTATION_ET_PURGE.md) has the procedure.
- **AI review model dropdown only shows the two suggestions**: Ollama isn't reachable at the configured URL — check it's running (`ollama list` if native, `docker ps` if containerized) and that the URL/port match, then click "Rafraîchir la liste" on the Settings page.
- **AI review works but feels slow**: expected if Ollama is running in Docker on an Apple Silicon Mac (no GPU/Metal passthrough — CPU-only inference). Switch to a native install for GPU acceleration, or use the lighter `gemma4:e4b-it-qat` model.

---

## Français

Ce document couvre tout ce qui est nécessaire pour lancer Zanshin en local : prérequis, installation, configuration de l'environnement, et démarrage de l'application. Pour les fonctionnalités, voir [`README.md`](../README.md) ; pour l'architecture et le schéma de base de données, voir [`TECHNICAL_DOCUMENTATION.md`](TECHNICAL_DOCUMENTATION.md).

### 1. Prérequis

| Prérequis | Pourquoi |
|---|---|
| **Node ≥ 24** | L'espace de travail vise la version LTS courante. |
| **Docker**, démarré et joignable | Zanshin exécute Syft, Grype, gitleaks, checkov et Semgrep en conteneurs éphémères via le socket Docker. C'est aussi ce qui démarre PostgreSQL en développement et dans les tests d'intégration. |
| **PostgreSQL** | Le seul moteur pris en charge — voir le README pour la raison, qui est un rétrécissement et non une préférence. En développement, un conteneur suffit. |
| **Git** | Pour cloner ce dépôt, et utilisé par Zanshin lui-même pour cloner ce qu'il scanne. |

### 2. Installation

```bash
git clone <url-de-ce-depot>
cd Zanshin
npm install
```

Une seule installation pour tout l'espace de travail : `backend/` (NestJS) et `frontend/`
(Angular) partagent un unique fichier de verrouillage.

### 3. Configuration

La plupart des réglages — enrichissement, fin de vie, rétention, notifications, licences,
gestionnaire de tickets, revue par modèle — vivent en base et s'éditent depuis l'écran
**Paramètres** une fois l'application lancée. Un réglage n'y apparaît qu'une fois qu'un
service le lit vraiment.

Trois variables d'environnement comptent avant le premier démarrage :

| Variable | Défaut |
|---|---|
| `ZANSHIN_DATABASE_URL` | *aucun* — obligatoire, p. ex. `postgres://zanshin:zanshin@localhost:5432/zanshin` |
| `ENCRYPTION_KEY` | *aucun* — l'enregistrement d'un secret est refusé tant qu'elle est absente |
| `ZANSHIN_PREVIOUS_ENCRYPTION_KEYS` | *aucun* — anciennes clés séparées par des virgules, essayées en déchiffrement seulement |


### 4. Base de données

PostgreSQL, et lui seul. En développement, un conteneur est le chemin le plus court :

```bash
docker run -d --name zanshin-db -p 5432:5432 \
  -e POSTGRES_USER=zanshin -e POSTGRES_PASSWORD=zanshin -e POSTGRES_DB=zanshin \
  postgres:16-alpine
```

Le schéma appartient aux **migrations TypeORM**, appliquées comme une étape explicite :

```bash
npm --workspace backend run migration:run       # appliquer
npm --workspace backend run migration:generate  # en écrire une depuis les entités
```

`synchronize` est désactivé, délibérément : un schéma synthétisé depuis les entités n'est
pas celui que la production recevra, et tester contre lui laisserait passer une migration
incorrecte.

Il n'y a pas de page d'auto-inscription : le premier compte vient donc des variables
d'amorçage — posez-les avant le premier démarrage et le SUPERUSER est créé quand la table
des utilisateurs est vide :

```bash
ZANSHIN_BOOTSTRAP_USERNAME=admin
ZANSHIN_BOOTSTRAP_PASSWORD=<au moins 8 caractères>
```


### 5. Lancer l'application

```bash
npm --workspace backend run migration:run   # mettre le schéma à jour
npm --workspace backend run start:dev       # API sur http://localhost:3000
npm --workspace frontend start              # interface sur http://localhost:4200
```

Le premier démarrage crée un SUPERUSER depuis `ZANSHIN_BOOTSTRAP_USERNAME` et
`ZANSHIN_BOOTSTRAP_PASSWORD` quand la table des utilisateurs est vide. Une fois un compte
créé, les deux variables sont ignorées.


### 6. Optionnel : revue de code par IA (Ollama)

Une option supplémentaire, désactivée par défaut : un LLM local, exécuté via [Ollama](https://ollama.com), qui relit le code source avec un prompt "security architect", en complément léger de Grype/gitleaks/checkov — pas un remplacement. Une fois activée, elle s'exécute automatiquement sur les scans de dépôt ; son résultat narratif et ses findings normalisés (sévérité/titre/fichier) apparaissent dans la fenêtre de détail du scan. Voir la docstring d'`AiReviewService` et [`TECHNICAL_DOCUMENTATION.md`](TECHNICAL_DOCUMENTATION.md) §4bis pour le détail de l'intégration.

Ollama peut tourner soit nativement, soit en Docker — Zanshin lui parle en HTTP dans les deux cas (`ai_review_ollama_url`, défaut `http://localhost:11434`), le choix ne concerne que la façon dont Ollama lui-même est lancé. La version Python portait ici un réglage *Mode de déploiement* ; il ne changeait rien à la façon dont Zanshin appelait Ollama, il ne fait donc pas partie de ce portage.

**Installation native (recommandée, surtout sur Mac Apple Silicon)** — voir [ollama.com/download](https://ollama.com/download). Bénéficie de l'accélération GPU complète : Metal sur Apple Silicon, CUDA/ROCm sous Linux avec les bons pilotes.

```bash
ollama pull gemma4:12b-it-qat   # ~7,2 Go, ~9-10 Go RAM/VRAM — défaut recommandé
ollama pull gemma4:e4b-it-qat   # ~6,1 Go, plus léger/rapide, qualité de revue moindre
```

**Docker** — plus simple à reproduire d'une machine à l'autre, mais **sur Mac Apple Silicon, Docker Desktop n'a pas d'accès GPU/Metal** : le conteneur tourne alors en CPU uniquement, nettement plus lent que l'application native. Sous Linux avec un GPU NVIDIA (+ nvidia-container-toolkit), l'accélération GPU reste possible en conteneur. Un fichier compose prêt à l'emploi est fourni à la racine du dépôt :

```bash
docker run -d --name ollama -p 11434:11434 -v ollama:/root/.ollama ollama/ollama
docker exec -it zanshin-ollama ollama pull gemma4:e4b-it-qat   # optionnel, alternative plus légère
docker exec -it zanshin-ollama ollama pull gemma4:12b-it-qat

```

(Ajoutez `--gpus all` pour le passthrough GPU NVIDIA sous Linux.)

Puis, depuis la page **Paramètres** de Zanshin, section "Revue de code par IA" : choisissez un mode de déploiement (informatif — voir ci-dessus), activez la fonctionnalité, définissez l'URL d'Ollama (par défaut `http://localhost:11434`, inchangée qu'Ollama tourne nativement ou via le fichier compose fourni puisque le conteneur publie le même port sur l'hôte), et choisissez un modèle dans la liste déroulante — la liste est lue en direct sur l'API `/api/tags` d'Ollama (ce que vous avez réellement téléchargé y apparaît), pas une liste figée. Si Ollama n'est pas encore joignable, la liste propose les deux modèles ci-dessus à titre de suggestion plutôt que d'être vide.

### 7. Lancer les tests

```bash
npm --workspace backend test                    # suite unitaire
npm --workspace backend run test:integration    # démarre PostgreSQL par testcontainers
```

Les suites d'intégration démarrent leur propre base et **ne se sautent pas** quand elle
manque : une campagne sans Docker échoue bruyamment plutôt que de rapporter vert sans rien
avoir vérifié.


### 8. Dépannage

- **`docker.errors.DockerException` / permission refusée sur le socket Docker** : l'utilisateur qui lance Zanshin doit avoir accès au socket Docker (`/var/run/docker.sock` sous Linux/macOS avec Docker Desktop). Sous Linux, ajoutez l'utilisateur au groupe `docker` ou lancez avec les privilèges suffisants.
- **Le premier scan est lent** : le backend `docker` télécharge les images `anchore/syft`, `anchore/grype`, `zricethezav/gitleaks`, `bridgecrew/checkov` et `semgrep/semgrep` à la demande lors de leur première utilisation — les scans suivants réutilisent les images en cache.
- **« Identifiants incorrects ou compte inactif » à la connexion** : soit les identifiants sont erronés, soit le champ `is_active` du compte est à `false` — vérifiez via `/users` (nécessite un admin existant) ou interrogez directement la table `user`.
- **`ENCRYPTION_KEY` changée et le déchiffrement des clés SSH échoue désormais** : indiquez la clé précédente dans `ZANSHIN_PREVIOUS_ENCRYPTION_KEYS` (valeurs séparées par des virgules). Les valeurs existantes se déchiffrent à nouveau et basculent sur la nouvelle clé au fil des réenregistrements — la page **Clés SSH** signale celles qui dépendent encore de l'ancienne.
- **Une clé SSH affiche « Illisible » après une mise à jour** : aucune clé configurée ne la déchiffre, le plus souvent parce qu'elle est antérieure à toute `ENCRYPTION_KEY` et qu'elle a été chiffrée avec la clé par défaut autrefois publiée dans ce dépôt. Cette valeur par défaut a été retirée. Sa moitié privée est publique : remplacez la paire chez votre fournisseur git plutôt que de chercher à la récupérer ; la marche à suivre est dans [`ROTATION_ET_PURGE.md`](ROTATION_ET_PURGE.md).
- **La liste des modèles IA n'affiche que les deux suggestions** : Ollama n'est pas joignable à l'URL configurée — vérifiez qu'il tourne (`ollama list` en natif, `docker ps` en conteneur) et que l'URL/le port correspondent, puis cliquez sur "Rafraîchir la liste" dans la page Paramètres.
- **La revue IA fonctionne mais semble lente** : normal si Ollama tourne en Docker sur un Mac Apple Silicon (pas de passthrough GPU/Metal — inférence CPU uniquement). Passez à une installation native pour l'accélération GPU, ou utilisez le modèle plus léger `gemma4:e4b-it-qat`.
