# Vectispire — Getting Started / Launch Guide

This document covers everything needed to run Vectispire locally: prerequisites, installation, environment configuration, and how to start the application. For features, see [`README.md`](../README.md); for architecture and database schema, see [`TECHNICAL_DOCUMENTATION.md`](TECHNICAL_DOCUMENTATION.md).

## 1. Prerequisites

| Requirement | Why |
|---|---|
| **Node ≥ 24** | The workspace targets the current LTS. |
| **Docker**, running and reachable | Vectispire runs Syft, Grype, gitleaks, checkov and Semgrep as ephemeral containers through the Docker socket. It is also what starts PostgreSQL in development and in the integration tests. |
| **PostgreSQL or MySQL 8** | Both are supported and exercised by the integration campaign. SQLite is not — see the README for the measured reason. In development, a container is enough. |
| **Git** | To clone this repository, and used by Vectispire itself to clone what it scans. |

## 2. Install

```bash
git clone <this-repo-url>
cd Vectispire
npm install
```

`npm` covers the interface alone. The control plane is a Gradle build in `vectispire-java/` and
shares nothing with it but the HTTP contract.

## 3. Configuration

Most runtime settings — enrichment, end-of-life, retention, notifications, licences,
tracker, model review — live in the database and are edited from the **Settings** page once
the application runs. A setting appears there only once a service actually reads it.

Three environment variables matter before the first run:

| Variable | Default |
|---|---|
| `VECTISPIRE_DB_URL` | `jdbc:postgresql://localhost:5432/vectispire` — a **JDBC** URL, e.g. `jdbc:mysql://localhost:3306/vectispire` |
| `VECTISPIRE_DB_USER` / `VECTISPIRE_DB_PASSWORD` | `vectispire` / empty |
| `ENCRYPTION_KEY` | *none* — saving a secret is refused until it is set. In production prefer `ENCRYPTION_KEY_FILE` |
| `ENCRYPTION_KEY_FILE` | *none* — a path to a file holding the key instead, which is what a Docker or Kubernetes secret mounts. Keeps the value out of `/proc/<pid>/environ`, `docker inspect` and an orchestrator's logs. Setting it *and* `ENCRYPTION_KEY` is refused; a path that does not resolve stops the application rather than starting with no key |
| `VECTISPIRE_PREVIOUS_ENCRYPTION_KEYS` | *none* — comma-separated older keys, tried for decryption only |
| `VECTISPIRE_PREVIOUS_ENCRYPTION_KEYS_FILE` | *none* — the same list from a file, comma- or newline-separated, so a rotation does not have to put the old key back into the environment |
| `VECTISPIRE_PASSWORD_LOGIN` | `true`. `false` delegates authentication to the identity provider entirely — the second factor is then the realm's. Ignored, loudly, when no `VECTISPIRE_OIDC_ISSUER` is set: it would leave no way in |
| `VECTISPIRE_AUDIT_MIRROR` | *none* — a path where each audit entry is appended as one JSON line, outside the database it watches. Off means the log has one copy, and the verification screen says so |


## 4. Database

PostgreSQL or MySQL 8. In development a container is the shortest path:

```bash
docker run -d --name vectispire-db -p 5432:5432 \
  -e POSTGRES_USER=vectispire -e POSTGRES_PASSWORD=vectispire -e POSTGRES_DB=vectispire \
  postgres:16-alpine
```

The schema belongs to **Flyway migrations**, applied at startup:

```bash
# Flyway applies migrations at startup — there is no separate command to run.
# A new change is a new migration script in vectispire-core/src/main/resources/db/migration/<dialect>/.
```

`ddl-auto` is `validate`, deliberately: a schema synthesised from the entities is not the one
production will receive, and testing against it would let a faulty migration through.

There is no self-registration page, so the first account comes from the bootstrap
variables — set them before the first start and the SUPERUSER is created when the user
table is empty:

```bash
VECTISPIRE_BOOTSTRAP_USERNAME=admin
VECTISPIRE_BOOTSTRAP_PASSWORD=<at least 8 characters>
```


## 5. Launching the application

```bash
# Flyway brings the schema up to date at startup; nothing to run by hand.
cd vectispire-java && ./gradlew :vectispire-core:bootRun --args='--server.port=3180'   # API on http://localhost:3180 (for Angular dev proxy)
npm --workspace @vectispire/frontend start                                         # UI on http://localhost:4280 (proxies /api to 3180)
```

The first start creates a SUPERUSER from `VECTISPIRE_BOOTSTRAP_USERNAME` and
`VECTISPIRE_BOOTSTRAP_PASSWORD` when the user table is empty. Once an account exists, both
variables are ignored.

### 5.1 Docker Compose Deployment (All-in-One)

You can launch the complete Vectispire stack (PostgreSQL + Control Plane + Optional Remote Agent) in a single command:

```bash
# 1. Copy and adjust environment variables
cp .env.example .env

# 2. Launch PostgreSQL + Vectispire Control Plane on http://localhost:3180
docker compose up -d

# 3. Optional: Launch with a dedicated remote agent
docker compose --profile with-agent up -d
```

**Building Container Images:**
```bash
npm run docker:build          # or docker build -t vectispire:latest .
npm run docker:build:agent    # or docker build -f Dockerfile.agent -t vectispire-agent:latest .
```


## 6. Optional: AI code review (Ollama)

An additional, disabled-by-default option: a local LLM, run via [Ollama](https://ollama.com), that reviews source code with a "security architect" prompt as a lightweight complement to Grype/gitleaks/checkov — not a replacement. When enabled, it runs automatically on repository scans; its narrative result and normalized findings (severity/title/file) show up in the scan detail dialog. See `AiReviewService`'s docstring and [`TECHNICAL_DOCUMENTATION.md`](TECHNICAL_DOCUMENTATION.md) §4bis for how it's wired in.

Ollama can be run either natively or in Docker — Vectispire talks to it over plain HTTP either way (`ai_review_ollama_url`, default `http://localhost:11434`), and the choice is purely about where/how Ollama itself runs. There is deliberately no setting for it: where Ollama runs changes nothing about how Vectispire calls it.

**Native install (recommended, especially on Apple Silicon Macs)** — see [ollama.com/download](https://ollama.com/download). Gets full GPU acceleration: Metal on Apple Silicon, CUDA/ROCm on Linux with the right drivers.

```bash
ollama pull gemma4:12b-it-qat   # ~7.2GB, ~9-10GB RAM/VRAM — recommended default
ollama pull gemma4:e4b-it-qat   # ~6.1GB, lighter/faster, lower review quality
```

**Docker** — simpler to reproduce across machines, but on **Apple Silicon Macs, Docker Desktop has no GPU/Metal passthrough**, so the container runs CPU-only and inference is noticeably slower than the native app. On Linux with an NVIDIA GPU (+ nvidia-container-toolkit), GPU acceleration is still possible in the container. A ready-made compose file is provided at the repository root:

```bash
docker run -d --name ollama -p 11434:11434 -v ollama:/root/.ollama ollama/ollama
docker exec -it vectispire-ollama ollama pull gemma4:12b-it-qat
docker exec -it vectispire-ollama ollama pull gemma4:e4b-it-qat   # optional, lighter alternative
```

(Add `--gpus all` for NVIDIA passthrough on Linux.)

Then, from Vectispire's **Settings** page, under "Revue de code par IA": toggle the feature on, set the Ollama URL (default `http://localhost:11434`, unchanged whether Ollama runs natively or via the provided compose file since the container publishes the same port to the host), and pick a model from the dropdown — the list is read live from Ollama's own `/api/tags` endpoint (whatever you've actually pulled shows up there), not a hardcoded list. If Ollama isn't reachable yet, the dropdown falls back to showing the two models above as suggestions rather than being empty.

## 7. Running the tests

```bash
cd vectispire-java && ./gradlew build              # unit, architecture and HTTP suites
cd vectispire-java && ./gradlew integrationTest    # starts PostgreSQL via testcontainers
```

The integration suites start their own database and **do not skip** when one is missing:
a run without Docker fails loudly rather than reporting green having verified nothing.


## 8. Verifying a release

Each release carries four files: the jar, its SBOM, and a Sigstore bundle for each. Verify before
running anything — a security tool you took on trust is a contradiction.

```bash
cosign verify-blob \
  --bundle vectispire-1.0.0.jar.cosign.bundle \
  --certificate-identity "https://github.com/Asmo1973/Vectispire/.github/workflows/release.yml@refs/tags/v1.0.0" \
  --certificate-oidc-issuer https://token.actions.githubusercontent.com \
  vectispire-1.0.0.jar
```

**Each part of that command pins something, and dropping any of them gives back most of what
signing was for.**

- `--certificate-identity` names the **workflow file and the tag**, not the repository. Matching
  the repository alone would accept a signature minted by any workflow anybody can add to it,
  including one added in a pull request.
- `--certificate-oidc-issuer` says the identity came from GitHub's token service. Without it, an
  identity string that merely *looks* like the one above is enough.
- The `--bundle` carries the certificate and the signature together, so there is no second file to
  lose and no step at which an unverified certificate is substituted.

Replace the tag in both places when verifying another version: the identity is per-tag by design,
so a bundle from one release does not verify a file from another.

There is **no signing key** — Sigstore keyless signs with the workflow's own OIDC identity. That is
the property worth understanding: there is no key in anybody's custody to steal, rotate, or explain,
and what a signature attests is "this workflow, in this repository, on this tag". A stolen
repository secret cannot produce one. A change to `release.yml` itself can, which is why the
identity a verifier pins includes its path.

The same command with the SBOM's filenames verifies the SBOM. It is worth doing: an SBOM is what
somebody feeds to their own scanner, and an unsigned one is a list of dependencies anybody can
rewrite before you read it.

## 9. Troubleshooting

- **`docker.errors.DockerException` / permission denied on the Docker socket**: the user running Vectispire needs access to the Docker socket (`/var/run/docker.sock` on Linux/macOS with Docker Desktop). On Linux, add the user to the `docker` group or run with sufficient privileges.
- **First scan is slow**: the `docker` backend pulls `anchore/syft`, `anchore/grype`, `zricethezav/gitleaks`, `bridgecrew/checkov` and `semgrep/semgrep` images on demand the first time each is used — subsequent scans reuse the cached images.
- **"Identifiants incorrects ou compte inactif" on login**: either the credentials are wrong, or the account's `is_active` flag is `false` — check via `/users` (needs an existing admin) or query the `user` table directly.
- **Changed `ENCRYPTION_KEY` and now SSH key decryption fails**: list the previous key in `VECTISPIRE_PREVIOUS_ENCRYPTION_KEYS` (comma-separated). Existing values then decrypt again, and move to the new key as they are re-saved — the **Clés SSH** page marks the rows that still depend on the old one.
- **An SSH key shows "Illisible" after upgrading**: no configured key reads it, most likely because it predates any `ENCRYPTION_KEY` and was encrypted with the default that used to ship in this repository. That default has been removed. Its private half is public, so replace the key pair at your git provider rather than trying to recover it; [`ROTATION_AND_PURGE.md`](ROTATION_AND_PURGE.md) has the procedure.
- **AI review model dropdown only shows the two suggestions**: Ollama isn't reachable at the configured URL — check it's running (`ollama list` if native, `docker ps` if containerized) and that the URL/port match, then click "Rafraîchir la liste" on the Settings page.
- **AI review works but feels slow**: expected if Ollama is running in Docker on an Apple Silicon Mac (no GPU/Metal passthrough — CPU-only inference). Switch to a native install for GPU acceleration, or use the lighter `gemma4:e4b-it-qat` model.

## 10. REST API Documentation & Swagger UI

- **Official REST Reference**: Consult the [REST API Reference Documentation](api/rest_api_reference.md) for full descriptions of authentication schemes (`Bearer JWT`, `X-API-Key`, `X-Agent-Key`), endpoints, and `curl` examples.
- **Swagger UI (Development & Staging)**:
  Swagger UI is disabled by default in production. You can activate it in local development environments:
  ```bash
  export VECTISPIRE_SWAGGER_UI_ENABLED=true
  export VECTISPIRE_API_DOCS_ENABLED=true
  ```
  Access the interactive console at `http://localhost:3180/swagger-ui.html`.


