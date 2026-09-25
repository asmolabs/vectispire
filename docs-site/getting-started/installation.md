# Installation

Vectispire is two processes and a database: a Spring Boot control plane that serves the API
and the compiled interface, and — optionally — one or more remote agents. A single-machine
install needs neither the agent nor any agent configuration.

## Prerequisites

| Requirement | Why |
|---|---|
| **Docker**, running and reachable | Every scanner runs as an ephemeral container through the Docker socket. This is not optional: there is one scan backend and it is Docker. |
| **PostgreSQL** or **MySQL 8** | Both are supported and exercised by the integration campaign. The engine is read from the JDBC URL; there is no separate dialect setting. |
| **Git** | Vectispire clones what it scans. |
| **Node ≥ 24**, **JDK 25** | Only if you build from source rather than running the published images. |

!!! warning "Access to a Docker daemon"
    Vectispire runs its scanners as containers, so it needs to reach a daemon — but **it does
    not mount the socket**. The composition puts a `docker-socket-proxy` in front, on an
    internal network, and points the control plane at it through `DOCKER_HOST`. Nothing on
    your side to configure, and no `docker` group to join.

    Running outside compose, straight against a daemon? Then the user does need access to
    `/var/run/docker.sock`, and on Linux that usually means the `docker` group. Without it
    every scan fails at the first container.

!!! danger "One host means one blast radius"
    With the built-in worker on — the default — the process that can create containers is the
    process that holds `ENCRYPTION_KEY`, and daemon access is root on that host. The proxy
    narrows what can be asked of the daemon; it does not separate the two. For anything beyond
    a single-team installation, run a **remote agent** and set
    `VECTISPIRE_EMBEDDED_WORKER=false` on the control plane. See
    [decision 0018](https://github.com/asmolabs/vectispire/blob/main/docs/architecture/en/decisions/0018-the-docker-socket-is-never-mounted.md).

## The quickest route: Docker Compose

```bash
cp .env.example .env      # then edit it — see below
docker compose up -d
```

That brings up MySQL and the control plane on `http://localhost:3180`. To also start a
dedicated remote agent:

```bash
docker compose --profile with-agent up -d
```

!!! info "What the composition keeps apart"
    - **Secrets arrive as files.** `MYSQL_PASSWORD`, `MYSQL_ROOT_PASSWORD`, `ENCRYPTION_KEY` and
      `VECTISPIRE_BOOTSTRAP_PASSWORD` are still read from `.env`, but Compose hands them to the
      containers as files under `/run/secrets/`, not as environment: a container's environment is
      what `docker inspect` returns to anything that can talk to the daemon.
    - **The database answers the control plane only.** It sits on an internal network with the
      control plane alone and publishes no port — a port bound to `127.0.0.1` is still reachable
      from every other container on the host. For a SQL session:
      `docker compose exec db mysql -u vectispire -p vectispire`.
    - **The agent reaches the API and its own daemon proxy, nothing else** — not the database, not
      the control plane's proxy.
    - **No setting may point at the daemon's proxy or at the database.** An Ollama, webhook, SIEM
      or tracker URL naming either is refused, whatever the destination policy.

The composition pulls two published images, so nothing here needs a JDK or a Gradle cache:

```
ghcr.io/asmolabs/vectispire:0.9.0
ghcr.io/asmolabs/vectispire-agent:0.9.0
```

They are public — no login, no token. Pull one on its own with
`docker pull ghcr.io/asmolabs/vectispire:0.9.0`, and see
[Verifying a release](#verifying-a-release) before you run it.

## Before the first start

Most settings live in the database and are edited from **Settings** once the application
runs. Four things have to be right *before* the first start, because they are needed to
reach that screen at all.

### The database

```bash
VECTISPIRE_DB_URL=jdbc:postgresql://localhost:5432/vectispire
VECTISPIRE_DB_USER=vectispire
VECTISPIRE_DB_PASSWORD=…
```

For MySQL, point the same variable at it — `jdbc:mysql://localhost:3306/vectispire` — and
change nothing else.

The schema belongs to **Flyway migrations**, applied at startup. There is no separate
migration command to run, and `ddl-auto` is `validate` deliberately: a schema synthesised
from the entities is not the one production receives, so testing against it would let a
faulty migration through.

### The encryption key

Vectispire encrypts the secrets it holds — deploy keys above all. **Saving a secret is
refused until a key is set.**

```bash
ENCRYPTION_KEY_FILE=/run/secrets/vectispire-encryption-key
```

Prefer `ENCRYPTION_KEY_FILE` over `ENCRYPTION_KEY` in production: a file is what a Docker
or Kubernetes secret mounts, and it keeps the value out of `/proc/<pid>/environ`,
`docker inspect` and your orchestrator's logs. Setting both is refused. A path that does
not resolve stops the application rather than starting with no key.

See [Rotation and purge](../administration/maintenance.md) for changing it later.

### The first account

There is no self-registration page. The first account comes from bootstrap variables, and
the SUPERUSER is created when the user table is empty:

```bash
VECTISPIRE_BOOTSTRAP_USERNAME=admin
VECTISPIRE_BOOTSTRAP_PASSWORD=<at least 8 characters>
```

Once any account exists, both variables are ignored. Change that password at first login.

## Where to run it

**Vectispire is built for an internal network, not for the public internet.** It is an
operations console for a team that already has access to the code it scans, and its design
assumes that everyone who can reach the login page is somebody you would have given a login
to anyway.

That assumption is load-bearing, so it is worth stating plainly rather than leaving it to be
inferred from the defaults:

- The control plane publishes port `3180` on **every interface** of its host. That is
  deliberate — you have to reach the interface — but it means a host with a public address
  serves Vectispire to the internet the moment it starts. The database, by contrast, is
  published on loopback only; the difference is intentional and visible in
  `docker-compose.yml`.
- A signed-in user who can register a repository can make the control plane clone a URL they
  chose. That is the product working as intended, and it is also why *who can sign in* is the
  boundary that matters most.

If the host is reachable from outside your network, put it behind something — a VPN, an
identity-aware proxy, or a firewall rule — before anything else. If you terminate TLS in front
of it, name the proxy in `vectispire.security.trusted-proxies`; left empty, the rate limiter
counts the proxy's address rather than the caller's and stops protecting anyone.

### Two settings that change with the size of the install

| Setting | Default | Change it when |
|---|---|---|
| `VECTISPIRE_HOST_SSH` | `true` | **More than one team shares the install.** With the fallback on, a repository with no key of its own is cloned using the host's `~/.ssh` identity — so adding a URL is enough to have Vectispire clone it as that identity. On a single-team install the host key already reaches every target and the fallback costs nothing; on a shared one, set it to `false` and attach a deployment key per repository. |
| `TICKET_WEBHOOK_SECRET` | unset | **You wire a tracker webhook.** Unset, the webhook route accepts unauthenticated calls rather than refusing them — chosen so that an upgrade does not silently stop existing triage synchronisation. Set it as soon as the route is reachable by anything you do not control. Note that verification is not replay-bound: a legitimate payload replayed re-applies its decision. |

Both are recorded with their reasoning in the project's threat model.

## Running from source

```bash
git clone https://github.com/asmolabs/vectispire.git
cd vectispire
npm install

cd vectispire-java && ./gradlew :vectispire-core:bootRun --args='--server.port=3180'
npm --workspace @vectispire/frontend start    # UI on :4280, proxies /api to :3180
```

`npm` covers the interface alone. The control plane is a Gradle build in `vectispire-java/`
and shares nothing with it but the HTTP contract.

## Verifying a release

Each release carries four files: the jar, its SBOM, and a Sigstore bundle for each. Verify
before running anything — a security tool you took on trust is a contradiction.

```bash
cosign verify-blob \
  --bundle vectispire-0.9.0.jar.cosign.bundle \
  --certificate-identity "https://github.com/asmolabs/vectispire/.github/workflows/release.yml@refs/tags/v0.9.0" \
  --certificate-oidc-issuer https://token.actions.githubusercontent.com \
  vectispire-0.9.0.jar
```

Each flag pins something, and dropping any one of them gives back most of what signing was
for. `--certificate-identity` names the **workflow file and the tag**, not the repository:
matching the repository alone would accept a signature minted by any workflow anybody can
add to it, including one added in a pull request. `--certificate-oidc-issuer` says the
identity came from GitHub's token service — without it, a string that merely *looks* like
the identity above is enough. Replace the tag in both places for another version; the
identity is per-tag by design.

!!! warning "Releases signed before the move to GitHub"
    The signing identity belongs to the forge that ran the workflow, so a release built on
    the old GitLab pipeline verifies against `https://gitlab.com` and that pipeline's path,
    not against the command above. Verifying a signature with the wrong issuer cannot
    succeed — and an instruction that cannot succeed is worse than none, because it teaches
    its reader that the check passed the day they mistype it into passing. Use the identity
    of the forge that built the artefact you hold.

### Verifying an image

The images are signed the same way, by digest rather than by tag — a tag can be moved to
another image, a digest cannot.

```bash
cosign verify \
  --certificate-identity "https://github.com/asmolabs/vectispire/.github/workflows/release.yml@refs/tags/v0.9.0" \
  --certificate-oidc-issuer https://token.actions.githubusercontent.com \
  ghcr.io/asmolabs/vectispire:0.9.0
```

Each image also carries its SBOM as an attestation rather than as a file beside it, because a
file beside an image is one anybody can swap:

```bash
cosign verify-attestation --type cyclonedx \
  --certificate-identity "https://github.com/asmolabs/vectispire/.github/workflows/release.yml@refs/tags/v0.9.0" \
  --certificate-oidc-issuer https://token.actions.githubusercontent.com \
  ghcr.io/asmolabs/vectispire:0.9.0
```

There is no signing key. Sigstore keyless signs with the workflow's own OIDC identity, so
there is nothing in anybody's custody to steal or rotate.

Run the same command against the SBOM's filenames. It is worth doing: an SBOM is what
somebody feeds to their own scanner, and an unsigned one is a dependency list anybody can
rewrite before you read it.

### Verifying the build provenance

A signature says *which workflow* produced a file. Each release after v0.9.0 also carries a
[SLSA build provenance](https://slsa.dev/spec/v1.0/provenance) attestation, for the jar and for
both images, that says *how*: the repository, the **commit** the tag pointed at when the release
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
`ghcr.io/asmolabs/vectispire-agent`.

`--repo` alone is the command GitHub documents, and it is not enough on its own: it accepts an
attestation made by *any* workflow of the repository, on any branch. `--signer-workflow` narrows
it to the release workflow and `--source-ref` to the tag you meant to install — the same two
things `--certificate-identity` pins in the `cosign` commands above. Add `--format json` to read
the statement itself; the commit is under `buildDefinition.resolvedDependencies`.

The provenance adds to the signature and does not replace it: v0.9.0 and the releases before it
have a signature and no provenance, and the `cosign` commands above remain the check every release
supports.

## Next

[Register a repository and run your first scan →](first-scan.md)
