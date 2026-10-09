# Vectispire — Getting Started / Launch Guide

This document covers everything needed to run Vectispire locally: prerequisites, installation, environment configuration, and how to start the application. For features, see [`README.md`](../../README.md); for architecture and database schema, see [`TECHNICAL_DOCUMENTATION.md`](TECHNICAL_DOCUMENTATION.md).

## 1. Prerequisites

| Requirement | Why |
|---|---|
| **JDK 25** | The Gradle toolchain of `vectispire-java/` asks for 25; only needed to build or run from source. |
| **Node 24 (LTS)** | Pinned by `.nvmrc`. Angular 22 refuses Node 25. |
| **Docker**, running and reachable | Vectispire runs Syft, Grype, gitleaks, checkov and Semgrep as ephemeral containers through a Docker daemon — in the shipped composition through a `docker-socket-proxy`, never the socket itself. It is also what starts MySQL in development and for the test suites. |
| **MySQL 8** (default) **or PostgreSQL** | Both are supported and exercised by the integration campaign; MySQL is what `VECTISPIRE_DB_URL` points at when unset and what `docker-compose.yml` ships. SQLite is not supported, and is no longer in the build at all ([ADR 0034](../architecture/en/decisions/0034-mysql-replaces-the-sqlite-fixture.md)). In development, a container is enough. |
| **Git** | To clone this repository, and used by Vectispire itself to clone what it scans. |

## 2. Install

```bash
git clone <this-repo-url>
cd vectispire
npm ci                                  # the interface; respects the lockfile
cd vectispire-java && ./gradlew build   # the control plane: compile, unit, architecture and HTTP suites (needs Docker)
```

`npm` covers the interface alone. The control plane is a Gradle build in `vectispire-java/` and
shares nothing with it but the HTTP contract.

## 3. Configuration

Most runtime settings — enrichment, end-of-life, retention, notifications, licences,
tracker, model review — live in the database and are edited from the **Settings** page once
the application runs. A setting appears there only once a service actually reads it.

The environment variables that matter before the first run:

| Variable | Default |
|---|---|
| `VECTISPIRE_DB_URL` | `jdbc:mysql://localhost:3306/vectispire` — a **JDBC** URL; for PostgreSQL, `jdbc:postgresql://localhost:5432/vectispire` |
| `VECTISPIRE_DB_USER` / `VECTISPIRE_DB_PASSWORD` | `vectispire` / empty |
| `ENCRYPTION_KEY` | *none* — saving a secret is refused until it is set. In production prefer `ENCRYPTION_KEY_FILE` |
| `ENCRYPTION_KEY_FILE` | *none* — a path to a file holding the key instead, which is what a Docker or Kubernetes secret mounts. Keeps the value out of `/proc/<pid>/environ`, `docker inspect` and an orchestrator's logs. Setting it *and* `ENCRYPTION_KEY` is refused; a path that does not resolve stops the application rather than starting with no key |
| `VECTISPIRE_PREVIOUS_ENCRYPTION_KEYS` | *none* — comma-separated older keys, tried for decryption only |
| `VECTISPIRE_PREVIOUS_ENCRYPTION_KEYS_FILE` | *none* — the same list from a file, comma- or newline-separated, so a rotation does not have to put the old key back into the environment |
| `VECTISPIRE_PASSWORD_LOGIN` | `true`. `false` delegates authentication to the identity provider entirely — the second factor is then the realm's. Ignored, loudly, when no `VECTISPIRE_OIDC_ISSUER` is set: it would leave no way in |
| `VECTISPIRE_AUDIT_MIRROR` | *none* — a path where each audit entry is appended as one JSON line, outside the database it watches. Off means the log has one copy, and the verification screen says so |
| `VECTISPIRE_BRAND_NAME` | `Vectispire` — custom company or instance name displayed across the header, reports (PDF), and exports (SARIF, VEX, CSAF) |
| `VECTISPIRE_GITLAB_URL` | `https://github.com/asmolabs/vectispire` — upstream repository URL displayed alongside the "Powered by Vectispire" footer mention. The variable name predates the move to GitHub and is kept because it is part of the public branding response |


## 4. Database

MySQL 8 by default — the engine `docker-compose.yml` ships and the one
`VECTISPIRE_DB_URL` points at when nothing overrides it. PostgreSQL is the other supported engine;
the engine is read from the URL and there is no separate dialect setting.

```bash
docker run -d --name vectispire-db -p 127.0.0.1:3306:3306 \
  -e MYSQL_ROOT_PASSWORD=root -e MYSQL_DATABASE=vectispire \
  -e MYSQL_USER=vectispire -e MYSQL_PASSWORD=vectispire \
  mysql:8
```

For PostgreSQL instead, point `VECTISPIRE_DB_URL` at it — nothing else changes:

```bash
docker run -d --name vectispire-db -p 127.0.0.1:5432:5432 \
  -e POSTGRES_USER=vectispire -e POSTGRES_PASSWORD=vectispire -e POSTGRES_DB=vectispire \
  postgres:16-alpine
# VECTISPIRE_DB_URL=jdbc:postgresql://localhost:5432/vectispire
```

Both bind to `127.0.0.1`, not to every interface: `-p 3306:3306` publishes the port on all of the
host's addresses — Docker also writes its own firewall rules, so a host firewall does not
necessarily stop it — and these are development passwords. Vectispire, run on the same machine,
reaches `localhost` either way.

The schema belongs to **Flyway migrations**, applied at startup:

```bash
# Flyway applies migrations at startup — there is no separate command to run.
# A new change is a new migration script: once in vectispire-core/src/main/resources/db/migration/common/
# with the type placeholders when only the column types differ, or once per dialect in
# db/migration/<dialect>/ when the structure does (ADR 0027).
```

`ddl-auto` is `validate`, deliberately: a schema synthesised from the entities is not the one
production will receive, and testing against it would let a faulty migration through.

There is no self-registration page, so the first account comes from the bootstrap
variables — set them before the first start and the SUPERUSER is created when the user
table is empty:

```bash
VECTISPIRE_BOOTSTRAP_USERNAME=admin
VECTISPIRE_BOOTSTRAP_PASSWORD=<at least 12 characters>
```


## 5. Launching the application

```bash
# Flyway brings the schema up to date at startup; nothing to run by hand.
cd vectispire-java && ./gradlew :vectispire-core:bootRun --args='--server.port=3180'   # API on http://localhost:3180 (for Angular dev proxy)
npm --workspace @vectispire/frontend start                                         # UI on http://localhost:4280 (proxies /api to 3180)
```

The first start creates a SUPERUSER from `VECTISPIRE_BOOTSTRAP_USERNAME` and
`VECTISPIRE_BOOTSTRAP_PASSWORD` when the user table is empty. Once an account exists, both
variables are ignored. Open `http://localhost:4280`, sign in with that account and change its
password.

### 5.1 Docker Compose Deployment (All-in-One)

You can launch the complete Vectispire stack (MySQL + Control Plane + Optional Remote Agent) in a single command:

```bash
# 1. Copy and adjust environment variables
cp .env.example .env

# 2. Launch MySQL + Vectispire Control Plane on http://localhost:3180
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

An additional, disabled-by-default option: a local LLM, run via [Ollama](https://ollama.com), that reviews source code with a "security architect" prompt as a lightweight complement to Grype/gitleaks/checkov — not a replacement. When enabled, it runs automatically on repository scans; its narrative result and normalized findings (severity/title/file) show up in the scan detail dialog. See `AiReviewService`'s docstring and §4 of [`TECHNICAL_DOCUMENTATION.md`](TECHNICAL_DOCUMENTATION.md) for how it's wired in.

Ollama can be run either natively or in Docker — Vectispire talks to it over plain HTTP either way (`ai_review_ollama_url`, default `http://localhost:11434`), and the choice is purely about where/how Ollama itself runs. There is deliberately no setting for it: where Ollama runs changes nothing about how Vectispire calls it.

**Native install (recommended, especially on Apple Silicon Macs)** — see [ollama.com/download](https://ollama.com/download). Gets full GPU acceleration: Metal on Apple Silicon, CUDA/ROCm on Linux with the right drivers.

```bash
ollama pull gemma4:12b-it-qat   # ~7.2GB, ~9-10GB RAM/VRAM — recommended default
ollama pull gemma4:e4b-it-qat   # ~6.1GB, lighter/faster, lower review quality
```

**Docker** — simpler to reproduce across machines, but on **Apple Silicon Macs, Docker Desktop has no GPU/Metal passthrough**, so the container runs CPU-only and inference is noticeably slower than the native app. On Linux with an NVIDIA GPU (+ nvidia-container-toolkit), GPU acceleration is still possible in the container.

```bash
docker run -d --name vectispire-ollama -p 127.0.0.1:11434:11434 -v ollama:/root/.ollama ollama/ollama
docker exec -it vectispire-ollama ollama pull gemma4:12b-it-qat
docker exec -it vectispire-ollama ollama pull gemma4:e4b-it-qat   # optional, lighter alternative
```

`127.0.0.1` again, and for a stronger reason: Ollama's API has **no authentication at all**.
Published on every interface, anyone who can reach the host can run models on it, pull new ones and
delete yours.

(Add `--gpus all` for NVIDIA passthrough on Linux.)

Then, from Vectispire's **Settings → AI** tab, in the **AI Review** card: switch the review on, set the Ollama URL (default `http://localhost:11434`, unchanged whether Ollama runs natively or in the container above, since the container publishes the same port on the host's loopback), and name the model. **Test the connection** says whether Ollama answers at that URL and whether the model is among the ones it holds — read live from Ollama's own `/api/tags`, so what you have actually pulled is what counts.

**The configuration is in the database, not in the environment.** This section once described three
`VECTISPIRE_AI_REVIEW_*` variables that exist nowhere in the code: setting them did nothing. The real
settings are `ai_review_enabled`, `ai_review_ollama_url` and `ai_review_model`, set from the
interface — so a change is audited and needs no restart.

## 7. Running the tests

```bash
cd vectispire-java && ./gradlew build              # unit, architecture and HTTP suites
cd vectispire-java && ./gradlew integrationTest    # starts MySQL via testcontainers (-Pdialect= for the others)
```

The integration suites start their own database and **do not skip** when one is missing:
a run without Docker fails loudly rather than reporting green having verified nothing.


## 8. Verifying a release

Each release carries the jar and its SBOM, the CI gate script `vectispire-gate.sh` and — from the
release after 0.10.0 on — the CLI `vectispire-cli.sh` ([CI/CD integration](CI_CD_INTEGRATION.md#-getting-the-cli)),
each with a Sigstore bundle verified the same way, and signed container images — two up to 0.10.0,
three from the release after it (see below). Verify before running anything: a security tool you took
on trust is a contradiction.

```bash
cosign verify-blob \
  --bundle vectispire-0.10.0.jar.cosign.bundle \
  --certificate-identity "https://github.com/asmolabs/vectispire/.github/workflows/release.yml@refs/tags/v0.10.0" \
  --certificate-oidc-issuer https://token.actions.githubusercontent.com \
  vectispire-0.10.0.jar
```

**Each part of that command pins something, and dropping any of them gives back most of what
signing was for.**

- `--certificate-identity` names the **workflow file and the tag**, not the repository. Matching
  the repository alone would accept a signature minted by any workflow anybody can add to it,
  including one added in a pull request.
- `--certificate-oidc-issuer` says the identity came from GitHub's OIDC token service. Without it,
  an identity string that merely *looks* like the one above is enough.
- The `--bundle` carries the certificate and the signature together, so there is no second file to
  lose and no step at which an unverified certificate is substituted.

Replace the tag in both places when verifying another version: the identity is per-tag by design,
so a bundle from one release does not verify a file from another.

**Verify the SBOM the same way.** It is signed by the same run, with the same identity, and it is
the file you read to decide whether an advisory applies to you — an unsigned component list is one
anybody can rewrite:

```bash
cosign verify-blob \
  --bundle vectispire-0.10.0.cdx.json.cosign.bundle \
  --certificate-identity "https://github.com/asmolabs/vectispire/.github/workflows/release.yml@refs/tags/v0.10.0" \
  --certificate-oidc-issuer https://token.actions.githubusercontent.com \
  vectispire-0.10.0.cdx.json
```

### Running it from the published images

A release also publishes its container images, so nothing has to be compiled to run this — the
control plane and the agent:

```bash
docker pull ghcr.io/asmolabs/vectispire:0.10.0
docker pull ghcr.io/asmolabs/vectispire-agent:0.10.0
```

From the release after 0.10.0 on, a third is published beside them,
`ghcr.io/asmolabs/vectispire-report-demo` — the demonstration [report plugin](../../docs-site/administration/report-plugins.md),
signed, attested and verified the same way. 0.10.0 does not carry it.

**Verify them before running them, and verify by digest.** A tag is a mutable pointer — signing
`:0.10.0` says nothing about what `:0.10.0` resolves to next week, which is the same reason every
action in this repository is pinned by SHA:

```bash
DIGEST=$(docker buildx imagetools inspect ghcr.io/asmolabs/vectispire:0.10.0 \
           --format '{{.Manifest.Digest}}')

cosign verify \
  --certificate-identity "https://github.com/asmolabs/vectispire/.github/workflows/release.yml@refs/tags/v0.10.0" \
  --certificate-oidc-issuer https://token.actions.githubusercontent.com \
  "ghcr.io/asmolabs/vectispire@${DIGEST}"
```

Each image carries a CycloneDX SBOM as a signed attestation rather than a loose file beside it —
a component list anybody can swap is not evidence of anything:

```bash
cosign verify-attestation --type cyclonedx \
  --certificate-identity "https://github.com/asmolabs/vectispire/.github/workflows/release.yml@refs/tags/v0.10.0" \
  --certificate-oidc-issuer https://token.actions.githubusercontent.com \
  "ghcr.io/asmolabs/vectispire@${DIGEST}" | jq -r '.payload' | base64 -d | jq '.predicate.components | length'
```

**Pin the digest in whatever runs it.** `image: ghcr.io/asmolabs/vectispire@sha256:…` in a compose
file or a manifest is the deployment that matches what you verified; `:latest` is a deployment
that changes under you without a diff.

**Releases signed before 2026-08-27 carry a different identity.** The project moved from GitLab to
GitHub, and the certificate identity names the forge, the repository and the workflow file — so it
changed with the move. For a pre-move tag, verify against the old pair instead:

```
  --certificate-identity "https://gitlab.com/asmolabs_be/vectispire//.gitlab-ci.yml@refs/tags/<tag>"
  --certificate-oidc-issuer https://gitlab.com
```

That an identity is not portable across forges is the property working, not a defect: a signature
is a claim about *which workflow in which repository* produced the file, and that changed.

There is **no signing key** — Sigstore keyless signs with the workflow's own OIDC identity. That is
the property worth understanding: there is no key in anybody's custody to steal, rotate, or explain,
and what a signature attests is "this workflow, in this repository, on this tag". A stolen
repository secret cannot produce one. A change to `release.yml` itself can, which is why the
identity a verifier pins includes its path.

The same command with the SBOM's filenames verifies the SBOM. It is worth doing: an SBOM is what
somebody feeds to their own scanner, and an unsigned one is a list of dependencies anybody can
rewrite before you read it.

### Verifying the build provenance

A signature says *which workflow* produced a file. Each release after v0.9.0 also carries a
[SLSA build provenance](https://slsa.dev/spec/v1.0/provenance) attestation, for the jar and for
each image, that says *how*: the repository, the **commit** the tag pointed at when the release
ran, the workflow and the runner. A tag can be moved after the fact; the commit recorded in the
provenance cannot, and it is the one to check out if you want to read or rebuild the source that
shipped.

GitHub's CLI verifies it, with no file to download beside the artefact:

```bash
gh attestation verify vectispire-<version>.jar \
  --repo asmolabs/vectispire \
  --signer-workflow asmolabs/vectispire/.github/workflows/release.yml \
  --source-ref refs/tags/v<version>

gh attestation verify oci://ghcr.io/asmolabs/vectispire@sha256:<digest> \
  --repo asmolabs/vectispire \
  --signer-workflow asmolabs/vectispire/.github/workflows/release.yml \
  --source-ref refs/tags/v<version>
```

The image is named **by digest** — the one printed in the release notes, or the one
`docker buildx imagetools inspect ghcr.io/asmolabs/vectispire:<version> --format '{{.Manifest.Digest}}'`
returns — for the same reason the signature is. The agent image verifies the same way under
`ghcr.io/asmolabs/vectispire-agent`, and the demonstration report plugin's under
`ghcr.io/asmolabs/vectispire-report-demo`.

`--repo` alone is the command GitHub documents, and it is not enough on its own: it accepts an
attestation made by *any* workflow of the repository, on any branch. `--signer-workflow` narrows
it to the release workflow and `--source-ref` to the tag you meant to install — the same two
things `--certificate-identity` pins in the `cosign` commands above. Add `--format json` to read
the statement itself; the commit is under `buildDefinition.resolvedDependencies`.

The provenance adds to the signature and does not replace it: v0.9.0 and the releases before it
have a signature and no provenance, and the `cosign` commands above remain the check every release
supports.

## 9. Troubleshooting

- **Every step of a scan fails with a Docker client error** — `Connection refused`, or `Permission denied` on `/var/run/docker.sock` — and the scan ends *failed*, its detail listing each step with that reason: the control plane cannot reach a daemon. With the shipped composition this should not happen — no Vectispire container mounts the socket, a `docker-socket-proxy` does, and `DOCKER_HOST` points at it. Running outside compose, straight against a daemon, the user does need access to `/var/run/docker.sock` (Linux/macOS with Docker Desktop); on Linux, add it to the `docker` group.
- **First scan is slow**: the `docker` backend pulls `anchore/syft`, `anchore/grype`, `zricethezav/gitleaks`, `bridgecrew/checkov` and `semgrep/semgrep` images on demand the first time each is used — subsequent scans reuse the cached images.
- **"Invalid credentials." on login**: either the credentials are wrong, or the account is deactivated — check on the **Users** page (needs an existing administrator) or query the `t_user` table directly.
- **Changed `ENCRYPTION_KEY` and now SSH key decryption fails**: list the previous key in `VECTISPIRE_PREVIOUS_ENCRYPTION_KEYS` (comma-separated). Existing values then decrypt again, and move to the new key as they are re-saved — the **SSH keys** page marks the rows that still depend on the old one.
- **An SSH key shows "Unreadable" after upgrading**: no configured key reads it, most likely because it predates any `ENCRYPTION_KEY` and was encrypted with the default that used to ship in this repository. That default has been removed. Its private half is public, so replace the key pair at your git provider rather than trying to recover it; save the new one from the *SSH keys* page once `ENCRYPTION_KEY` is set. The [August 2026 incident note](../analysis/en/2026-08-06_credential_exposure_incident.en.md) says how that default came to be public.
- **"Test the connection" reports no answer from Ollama**: Ollama isn't reachable at the configured URL — check it's running (`ollama list` if native, `docker ps` if containerized) and that the URL and port match, then test again from **Settings → AI**. When it answers but says the model is not available, pull that model or correct its name.
- **AI review works but feels slow**: expected if Ollama is running in Docker on an Apple Silicon Mac (no GPU/Metal passthrough — CPU-only inference). Switch to a native install for GPU acceleration, or use the lighter `gemma4:e4b-it-qat` model.

## 10. REST API Documentation & Swagger UI

- **Official REST Reference**: Consult the [REST API Reference Documentation](api/rest_api_reference.md) for the authentication schemes — an opaque session token, an agent key or an integration API key, each as `Authorization: Bearer`, with `X-API-Key` accepted for a key — a curated selection of endpoints, and `curl` examples. The complete contract is the OpenAPI document, [`vectispire-angular/openapi.json`](../../vectispire-angular/openapi.json).
- **Swagger UI (Development & Staging)**:
  Swagger UI is disabled by default in production. You can activate it in local development environments:
  ```bash
  export VECTISPIRE_SWAGGER_UI_ENABLED=true
  export VECTISPIRE_API_DOCS_ENABLED=true
  ```
  Access the interactive console at `http://localhost:3180/swagger-ui.html`.

---

## 11. Integration Guides

- [CI/CD & CLI Integration (`vectispire-cli`)](CI_CD_INTEGRATION.md) — Security Quality Gates & build breaker runner for GitLab CI, GitHub Actions, Bitbucket, and Jenkins.
- [Bidirectional Ticketing](TICKETING_INTEGRATION.md) — Automatic issue creation and closure sync with Jira, GitLab, GitHub, and ServiceNow.
- [Alerts & Notifications](NOTIFICATIONS_INTEGRATION.md) — Real-time alerting for Discord, Slack, and Microsoft Teams.
- [Attack Path Visualizer](ATTACK_PATH_VISUALIZER.md) — Real-time exploit chain correlation (Ingress &rarr; API &rarr; RCE &rarr; Secret/DB).


