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

!!! warning "Docker socket access"
    The user running Vectispire needs access to `/var/run/docker.sock`. On Linux that
    usually means adding it to the `docker` group. Without it every scan fails at the
    first container.

## The quickest route: Docker Compose

```bash
cp .env.example .env      # then edit it — see below
docker compose up -d
```

That brings up PostgreSQL and the control plane on `http://localhost:3180`. To also start a
dedicated remote agent:

```bash
docker compose --profile with-agent up -d
```

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
  --bundle vectispire-1.0.0.jar.cosign.bundle \
  --certificate-identity "https://gitlab.com/asmolabs_be/vectispire//.gitlab-ci.yml@refs/tags/v1.0.0" \
  --certificate-oidc-issuer https://gitlab.com \
  vectispire-1.0.0.jar
```

Each flag pins something, and dropping any one of them gives back most of what signing was
for. `--certificate-identity` names the **workflow file and the tag**, not the repository:
matching the repository alone would accept a signature minted by any workflow anybody can
add to it, including one added in a merge request. `--certificate-oidc-issuer` says the
identity came from the forge's token service — without it, a string that merely *looks*
like the identity above is enough. Replace the tag in both places for another version; the
identity is per-tag by design.

There is no signing key. Sigstore keyless signs with the workflow's own OIDC identity, so
there is nothing in anybody's custody to steal or rotate.

Run the same command against the SBOM's filenames. It is worth doing: an SBOM is what
somebody feeds to their own scanner, and an unsigned one is a dependency list anybody can
rewrite before you read it.

## Next

[Register a repository and run your first scan →](first-scan.md)
