# Zanshin — Getting Started / Launch Guide

This document covers everything needed to run Zanshin locally: prerequisites, installation, environment configuration, and how to start the application. For features, see [`README.md`](../README.md); for architecture and database schema, see [`TECHNICAL_DOCUMENTATION.md`](TECHNICAL_DOCUMENTATION.md).

## 1. Prerequisites

| Requirement | Why |
|---|---|
| **Node ≥ 24** | The workspace targets the current LTS. |
| **Docker**, running and reachable | Zanshin runs Syft, Grype, gitleaks, checkov and Semgrep as ephemeral containers through the Docker socket. It is also what starts PostgreSQL in development and in the integration tests. |
| **PostgreSQL or MySQL 8** | Both are supported and exercised by the integration campaign. SQLite is not — see the README for the measured reason. In development, a container is enough. |
| **Git** | To clone this repository, and used by Zanshin itself to clone what it scans. |

## 2. Install

```bash
git clone <this-repo-url>
cd Zanshin
npm install
```

`npm` covers the interface alone. The control plane is a Gradle build in `zanshin-java/` and
shares nothing with it but the HTTP contract.

## 3. Configuration

Most runtime settings — enrichment, end-of-life, retention, notifications, licences,
tracker, model review — live in the database and are edited from the **Settings** page once
the application runs. A setting appears there only once a service actually reads it.

Three environment variables matter before the first run:

| Variable | Default |
|---|---|
| `ZANSHIN_DATABASE_URL` | *none* — required, e.g. `postgres://zanshin:zanshin@localhost:5432/zanshin` |
| `ENCRYPTION_KEY` | *none* — saving a secret is refused until it is set |
| `ZANSHIN_PREVIOUS_ENCRYPTION_KEYS` | *none* — comma-separated older keys, tried for decryption only |


## 4. Database

PostgreSQL or MySQL 8. In development a container is the shortest path:

```bash
docker run -d --name zanshin-db -p 5432:5432 \
  -e POSTGRES_USER=zanshin -e POSTGRES_PASSWORD=zanshin -e POSTGRES_DB=zanshin \
  postgres:16-alpine
```

The schema belongs to a **Liquibase changelog**, applied at startup:

```bash
# Liquibase applies the changelog at startup — there is no separate command to run.
# A new change is a new changeset in zanshin-core/src/main/resources/db/changelog/.
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


## 5. Launching the application

```bash
# Liquibase brings the schema up to date at startup; nothing to run by hand.
cd zanshin-java && ./gradlew :zanshin-core:bootRun   # API on http://localhost:8000
npm --workspace @zanshin/frontend start              # UI on http://localhost:4200
```

The first start creates a SUPERUSER from `ZANSHIN_BOOTSTRAP_USERNAME` and
`ZANSHIN_BOOTSTRAP_PASSWORD` when the user table is empty. Once an account exists, both
variables are ignored.


## 6. Optional: AI code review (Ollama)

An additional, disabled-by-default option: a local LLM, run via [Ollama](https://ollama.com), that reviews source code with a "security architect" prompt as a lightweight complement to Grype/gitleaks/checkov — not a replacement. When enabled, it runs automatically on repository scans; its narrative result and normalized findings (severity/title/file) show up in the scan detail dialog. See `AiReviewService`'s docstring and [`TECHNICAL_DOCUMENTATION.md`](TECHNICAL_DOCUMENTATION.md) §4bis for how it's wired in.

Ollama can be run either natively or in Docker — Zanshin talks to it over plain HTTP either way (`ai_review_ollama_url`, default `http://localhost:11434`), and the choice is purely about where/how Ollama itself runs. There is deliberately no setting for it: where Ollama runs changes nothing about how Zanshin calls it.

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

## 7. Running the tests

```bash
cd zanshin-java && ./gradlew build              # unit, architecture and HTTP suites
cd zanshin-java && ./gradlew integrationTest    # starts PostgreSQL via testcontainers
```

The integration suites start their own database and **do not skip** when one is missing:
a run without Docker fails loudly rather than reporting green having verified nothing.


## 8. Troubleshooting

- **`docker.errors.DockerException` / permission denied on the Docker socket**: the user running Zanshin needs access to the Docker socket (`/var/run/docker.sock` on Linux/macOS with Docker Desktop). On Linux, add the user to the `docker` group or run with sufficient privileges.
- **First scan is slow**: the `docker` backend pulls `anchore/syft`, `anchore/grype`, `zricethezav/gitleaks`, `bridgecrew/checkov` and `semgrep/semgrep` images on demand the first time each is used — subsequent scans reuse the cached images.
- **"Identifiants incorrects ou compte inactif" on login**: either the credentials are wrong, or the account's `is_active` flag is `false` — check via `/users` (needs an existing admin) or query the `user` table directly.
- **Changed `ENCRYPTION_KEY` and now SSH key decryption fails**: list the previous key in `ZANSHIN_PREVIOUS_ENCRYPTION_KEYS` (comma-separated). Existing values then decrypt again, and move to the new key as they are re-saved — the **Clés SSH** page marks the rows that still depend on the old one.
- **An SSH key shows "Illisible" after upgrading**: no configured key reads it, most likely because it predates any `ENCRYPTION_KEY` and was encrypted with the default that used to ship in this repository. That default has been removed. Its private half is public, so replace the key pair at your git provider rather than trying to recover it; [`ROTATION_AND_PURGE.md`](ROTATION_AND_PURGE.md) has the procedure.
- **AI review model dropdown only shows the two suggestions**: Ollama isn't reachable at the configured URL — check it's running (`ollama list` if native, `docker ps` if containerized) and that the URL/port match, then click "Rafraîchir la liste" on the Settings page.
- **AI review works but feels slow**: expected if Ollama is running in Docker on an Apple Silicon Mac (no GPU/Metal passthrough — CPU-only inference). Switch to a native install for GPU acceleration, or use the lighter `gemma4:e4b-it-qat` model.

