# Installation

Vectispire is two processes and a database: a Spring Boot control plane that serves the API
and the compiled interface, and — optionally — one or more remote agents. A single-machine
install needs neither the agent nor any agent configuration.

## Prerequisites

| Requirement | Why |
|---|---|
| **Docker**, running and reachable | Every scanner runs as an ephemeral container that Vectispire asks a Docker daemon to start — through a socket proxy in the composition, see below. This is not optional: there is one scan backend and it is Docker. |
| **MySQL 8** (default) or **PostgreSQL** | Both are supported and exercised by the integration campaign; MySQL is the default and the engine the composition ships. The engine is read from the JDBC URL; there is no separate dialect setting. |
| **Git** | Vectispire clones what it scans. |
| **Node 24 (LTS)**, **JDK 25** | Only if you build from source rather than running the published images. Node is pinned by `.nvmrc`; Angular 22 refuses Node 25. |

!!! warning "Access to a Docker daemon"
    Vectispire runs its scanners as containers, so it needs to reach a daemon — but **it does
    not mount the socket**. The composition puts a `docker-socket-proxy` in front, on an
    internal network, and points the control plane at it through `DOCKER_HOST`. Nothing on
    your side to configure, and no `docker` group to join.

    Running outside compose, straight against a daemon? Then the user does need access to
    `/var/run/docker.sock`, and on Linux that usually means the `docker` group. Without it
    every scan fails at the first container.

    The daemon named by `DOCKER_HOST` and every host of the JDBC URL are **reserved**: no
    webhook, AI server, SIEM collector or forge connection may be pointed at them, whatever the
    policy. In a Kubernetes pod, so is the cluster's API service (`KUBERNETES_SERVICE_HOST` and
    `KUBERNETES_SERVICE_PORT`, which every pod is given). So the
    control plane **refuses to start** when it cannot read those hosts — a `DOCKER_HOST` that is
    not `unix://`, `npipe://`, `tcp://`, `http://` or `https://`, or a JDBC URL whose hosts are
    not in the string (`jdbc:mysql+srv://`). Multi-host and replication URLs, MySQL's
    `address=(host=…)` form and host names with underscores are read; for MySQL the X protocol
    port 33060 is reserved beside the classic one.

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
    - **Secrets arrive as files.** `MYSQL_PASSWORD`, `MYSQL_ROOT_PASSWORD`, `ENCRYPTION_KEY`,
      `VECTISPIRE_BOOTSTRAP_PASSWORD`, `VECTISPIRE_SIGNING_KEY` and `VECTISPIRE_OIDC_CLIENT_SECRET`
      are still read from `.env`, but Compose hands them to the containers as files under
      `/run/secrets/`, not as environment: a container's environment is what `docker inspect`
      returns to anything that can talk to the daemon. The last two are optional and stay declared
      in `.env` when unused — empty, and no file is mounted; a `.env` without them stops
      `docker compose up` with a message naming the variable. **Upgrading:** add both lines, and
      move the OIDC client secret out of `.env.oidc`, whose values still reach the container as
      environment.
    - **The database answers the control plane only.** It sits on an internal network with the
      control plane alone and publishes no port — a port bound to `127.0.0.1` is still reachable
      from every other container on the host. For a SQL session:
      `docker compose exec db mysql -u vectispire -p vectispire`.
    - **The agent reaches the API and its own daemon proxy, nothing else** — not the database, not
      the control plane's proxy.
    - **No setting may point at the daemon's proxy or at the database.** An Ollama, webhook, SIEM
      or tracker URL naming either is refused, whatever the destination policy.

!!! warning "Scans live in a directory of the host, at the same path inside the container"
    Every scanner is a container the **daemon** starts, and the daemon resolves the directories it
    mounts into it **on its own host** — not inside the control plane's container. A scan's
    workspace (the clone, the SBOM, the secrets report while it runs) and the vulnerability
    database are therefore created in `VECTISPIRE_WORK_DIR` — `/var/lib/vectispire/work` by
    default — which the composition mounts into the control plane **at that same absolute path**
    and hands to the image's user (1000:1000, mode 0700) with the one-shot `work-dir` service before
    the control plane starts. The `with-agent` profile does the same for the agent with
    `VECTISPIRE_AGENT_WORK_DIR` (`/var/lib/vectispire/agent-work`).

    - The disk under it holds the matcher's database, some 3 GB, and each running scan's clone.
    - Change the path in `.env` if you like, never in one of the two places only: the bind is
      `path:path` on purpose.
    - **Outside this composition** — your own Compose file, Kubernetes, `docker run` — mount a host
      directory at the same path and point the JVM's temporary directory at it
      (`JDK_JAVA_OPTIONS=-Djava.io.tmpdir=<path>`). Left at the container's own `/tmp`, every
      scanner is handed an empty directory and every scan fails.
    - **The same directory holds the process's home**, `home/` under it (`-Duser.home`). That is
      where the forges' host keys are recorded, `home/.ssh/known_hosts`, and kept across restarts;
      the agent has its own under `VECTISPIRE_AGENT_WORK_DIR`. To pin them in advance, see
      [Over SSH: the forge's host key](../guide/repositories.md#ssh-host-keys). The images run as
      1000 with no account of that number and carry `HOME=/home/vectispire`, so a plain
      `docker run` has a writable home too — but in the container's own layer, lost with the
      container: a host recorded there is met again as new after a re-creation, and under
      `--read-only` the home cannot be written at all. Outside this composition, add
      `-Duser.home=<path>/home` to `JDK_JAVA_OPTIONS` as well, or mount a volume at
      `/home/vectispire`; the flag wins over the image's `HOME`.
    - **Your own `~/.ssh` is not mounted**, and `VECTISPIRE_HOST_SSH` is `false` here: attach a
      deploy key to each private repository. The composition used to mount it read-only, where the
      process never read it — and had it been read, it would have handed every key you hold to the
      process that holds `ENCRYPTION_KEY`.
    - On Docker Desktop the path is in its virtual machine, not on your Mac or PC, which is what
      you want: both sides of the mount are there.

The composition pulls two published images, so nothing here needs a JDK or a Gradle cache:

```
ghcr.io/asmolabs/vectispire:0.10.0
ghcr.io/asmolabs/vectispire-agent:0.10.0
```

They are public — no login, no token. Pull one on its own with
`docker pull ghcr.io/asmolabs/vectispire:0.10.0`, and see
[Verifying a release](#verifying-a-release) before you run it.

## Before the first start

Most settings live in the database and are edited from **Settings** once the application
runs. Four things have to be right *before* the first start, because they are needed to
reach that screen at all.

### The database

```bash
VECTISPIRE_DB_URL=jdbc:mysql://localhost:3306/vectispire
VECTISPIRE_DB_USER=vectispire
VECTISPIRE_DB_PASSWORD=…
```

That URL is also the default. For PostgreSQL, point the same variable at it —
`jdbc:postgresql://localhost:5432/vectispire` — and change nothing else. One MySQL server setting matters if you use [report plugins](../administration/report-plugins.md)
on large projects: at the default `max_allowed_packet` (64 MiB) a report's export is kept up to about
32 MiB, and `--max-allowed-packet=160M` restores the whole 64 MiB bound.

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
VECTISPIRE_BOOTSTRAP_PASSWORD=<at least 12 characters>
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
  serves Vectispire to the internet the moment it starts. The database, by contrast, publishes
  no port at all — not even on loopback, which other containers on the host would still reach;
  the difference is intentional and visible in `docker-compose.yml`.
- A signed-in user who can register a repository can make the control plane clone a URL they
  chose. That is the product working as intended, and it is also why *who can sign in* is the
  boundary that matters most.

If the host is reachable from outside your network, put it behind something — a VPN, an
identity-aware proxy, or a firewall rule — before anything else. If you terminate TLS in front
of it, name the proxy in `VECTISPIRE_TRUSTED_PROXIES` (`vectispire.security.trusted-proxies`); left empty, the rate limiter
counts the proxy's address rather than the caller's and stops protecting anyone.

### Two settings that change with the size of the install

| Setting | Default | Change it when |
|---|---|---|
| `VECTISPIRE_HOST_SSH` | `true` | **More than one team shares the install.** With the fallback on, a repository with no key of its own is cloned using the host's `~/.ssh` identity — so adding a URL is enough to have Vectispire clone it as that identity. On a single-team install the host key already reaches every target and the fallback costs nothing; on a shared one, set it to `false` and attach a deployment key per repository. The shipped `docker-compose.yml` sets it to `false` and mounts no `~/.ssh`: inside its container there is no host key to fall back on. |
| Inbound webhook secret (`ticket_webhook_secret`) | empty | **You wire a tracker webhook.** This one is not an environment variable: it is a database setting, set in **Settings → Tickets → Inbound webhook secret** and stored encrypted. While it is empty the webhook route refuses every call with a `403` saying the webhook is not configured, which the tracker shows in its delivery log — the route cannot hold a session, so the secret is its whole authentication. Set the same value in the tracker. A delivery is acted on once within thirty days, and a decision it carries is queued for approval rather than applied; see [Ticketing](../integrations/ticketing.md#inbound-webhook). |

Both are recorded with their reasoning in the project's threat model.

## Kubernetes {#kubernetes}

A Helm chart ships in [`deploy/helm/vectispire/`](https://github.com/asmolabs/vectispire/tree/main/deploy/helm/vectispire).
It follows [decision 0038](https://github.com/asmolabs/vectispire/blob/main/docs/architecture/en/decisions/0038-deploying-on-kubernetes.md).
It deploys:

- the control plane, which also serves the interface;
- its Ingress;
- the audit mirror's volume.

It does **not** deploy the database or the Secrets, which are yours. It runs no container itself, so
**every scan runs on an agent**. Agents run on a Docker host outside the cluster (recommended), or
in the cluster as opt-in pods.

!!! warning "Report plugins are not available on Kubernetes yet"
    A [report plugin](../administration/report-plugins.md) runs on the control plane's own Docker
    endpoint, and a pod has none. Requests answer `409 report-executor-unavailable` until a later
    version can reach a remote daemon. Built-in reports and exports are not affected: they are
    rendered by the application itself.

### The MySQL server

Installed and backed up separately. The chart points at it:

- **One host in the URL.** `jdbc:mysql://mysql.example.org:3306/vectispire`. A URL listing several
  hosts, or `mysql+srv`, is refused at startup: Vectispire must know the database's address to keep
  webhooks from reaching it.
- **TLS.** Add `sslMode=VERIFY_IDENTITY` to the URL. If the server's certificate is from a private CA,
  put that CA in a PKCS12 truststore and store it in a Secret named by `database.trustStore`. Then
  add `trustCertificateKeyStoreUrl=file:/etc/vectispire/mysql/truststore.p12&trustCertificateKeyStoreType=PKCS12`
  to the URL.
- **`max_allowed_packet` at least `160M`.** Report exports travel hex-encoded at twice their size.
- **UTC**: `default_time_zone = '+00:00'`. Some columns default to `CURRENT_TIMESTAMP`, which the
  server evaluates in the session's time zone. Do not set `TZ` on the pod.
- **Back up before every upgrade.** Migrations run at startup and have no way back. Rolling back
  means restoring the backup and the previous image digest.

### Installing

```bash
kubectl create namespace vectispire
kubectl -n vectispire create secret generic vectispire-database \
  --from-literal=password='<the database password>'   # gitleaks:allow
kubectl -n vectispire create secret generic vectispire-keys \
  --from-literal=encryption-key="$(openssl rand -base64 32)" \
  --from-literal=bootstrap-password="$(openssl rand -base64 24)"   # gitleaks:allow
kubectl -n vectispire create secret tls vectispire-tls --cert=tls.crt --key=tls.key

cp deploy/helm/vectispire/values.example.yaml my-values.yaml   # edit it
helm install vectispire deploy/helm/vectispire -n vectispire -f my-values.yaml
```

**In a namespace you were given.** When you can write only to one namespace, skip `kubectl create
namespace` and install into it with `-n <your namespace>`: the chart creates nothing cluster-wide, and
with agents off everything it renders lands there. Agents in the cluster need two more values, see
below.

**Back up the encryption key** outside the cluster. It decrypts every deployment key and token
Vectispire holds; a cluster rebuilt without it holds secrets nobody can read.

Also set a **signing key** (`secrets.signingKey`, a P-256 PKCS#8 PEM): on 0.10.0, an installation
without one answers 500 on its first evidence bundle (fixed in the next release). Keep it: replacing
it makes every document already signed unverifiable.

The chart refuses to render without its required values, and says which is missing. The full list is
in the chart's [README](https://github.com/asmolabs/vectispire/blob/main/deploy/helm/vectispire/README.md).

**Shape of the deployment:**

- one replica;
- `strategy: Recreate`, so an old pod never serves a migrated schema;
- the image pinned by digest;
- the pod: uid 1000, read-only root filesystem, every capability dropped, no service-account token;
- probes on `/actuator/health/liveness` and `/actuator/health/readiness`; readiness includes the
  database.

### The Ingress

The default annotations are ingress-nginx's. With another controller, set the same three things in
its own words:

| Setting | Why |
|---|---|
| read timeout ≥ 60 s | an agent's long poll holds its request 30 s |
| body size ≥ 256 MB | an agent's result carries the SBOM |
| TLS | the interface signs people in |

Set `trustedProxies` to the ingress controller's address range. Left empty, every audit entry and
rate limit names the controller instead of the caller. TLS ending at the Ingress would also read as
plain HTTP to the application.

**And enable `networkPolicy`, which the chart then requires.** A peer in that range is believed about
the client's address. The controller's pods have no fixed address, so the range is usually the pod
range, and without a policy keeping port 3180 to the controller any pod could call it directly and name
any address: a fresh rate-limit bucket on every request, an audit entry naming somebody else. The
policy only holds on a CNI that enforces NetworkPolicy. `trustedProxiesWithoutNetworkPolicy` renders the
chart anyway, for a range holding the controller alone.

**Two replicas** are possible but not the default. They need:

- cookie affinity (`ingress.stickySessions`): single sign-on keeps its state in the session of the
  pod that sent the person to the provider;
- a ReadWriteMany volume for the audit mirror (`auditMirror.accessMode`): each pod writes its own
  file there.

### Agents on a Docker host (recommended)

A Linux VM with Docker, outside the cluster, reaching the Ingress over HTTPS. Create the agent on the
**Agents** screen, then run it the way the composition's `with-agent` profile does:

- its own socket proxy;
- its work directory mounted **at the same path** on both sides — the daemon resolves a scanner's
  bind on its own host.

```yaml
# docker-compose.yml on the agent's host
services:
  agent:
    image: ghcr.io/asmolabs/vectispire-agent:0.10.0@sha256:121ec47d0db949946b55ec034b72fdaff909470c92353efda434bbbbb428d72e
    environment:
      VECTISPIRE_URL: https://vectispire.example.org
      DOCKER_HOST: tcp://agent-docker-proxy:2375
      # The key as a file, read through the configuration tree, not as a variable.
      SPRING_CONFIG_IMPORT: optional:configtree:/run/secrets/
      JDK_JAVA_OPTIONS: >-
        -Djava.io.tmpdir=/var/lib/vectispire/agent-work
        -Duser.home=/var/lib/vectispire/agent-work/home
    secrets:
      - source: agent_token
        target: VECTISPIRE_AGENT_TOKEN
    volumes:
      - /var/lib/vectispire/agent-work:/var/lib/vectispire/agent-work
    depends_on: [agent-docker-proxy]
    restart: unless-stopped
    networks: [outside, docker]
  agent-docker-proxy:
    image: tecnativa/docker-socket-proxy:0.3.0@sha256:9e4b9e7517a6b660f2cc903a19b257b1852d5b3344794e3ea334ff00ae677ac2
    # What ContainerRunner calls, and nothing else; every other section stays at its default, 0.
    # docker-compose.yml lists them all, each with its reason.
    environment: {PING: 1, VERSION: 1, INFO: 1, CONTAINERS: 1, IMAGES: 1, POST: 1, EXEC: 0}
    volumes:
      - /var/run/docker.sock:/var/run/docker.sock:ro
    restart: unless-stopped
    networks: [docker]
secrets:
  agent_token:
    file: ./agent-token   # the key shown once on the Agents screen, mode 0600
networks:
  outside: {}
  docker: {internal: true}
```

Before the first start, give the work directory to the agent's user:

```bash
sudo install -d -m 0700 -o 1000 -g 1000 /var/lib/vectispire/agent-work
```

**Trust.** If the Ingress certificate is from a private CA, give the agent's JVM a truststore through
`JDK_JAVA_OPTIONS`:

```
-Djavax.net.ssl.trustStore=… -Djavax.net.ssl.trustStoreType=PKCS12
```

The truststore replaces the JVM's own: include every authority the agent must trust.

See [Agents](../administration/agents.md) for:

- credentials modes;
- pinning a signing key;
- concurrency.

### Agents in the cluster (opt-in)

`agents.enabled: true` deploys one agent pod per release. The pod has two containers:

- the agent, read-only, as uid 1000;
- a Docker daemon of its own (`docker:dind`), on a Unix socket shared through an `emptyDir`. It never
  listens on TCP: the image's entrypoint would otherwise open port 2375 to the whole cluster, with no
  authentication.

The work directory is a second `emptyDir`, mounted at the same path in both containers.

**The daemon runs in a privileged container, which is root on its node.** A scanner that escapes its
own container reaches that daemon, and through it the node. Give these pods:

- **their own namespace**: the chart creates `vectispire-agents` with Pod Security Admission's
  `privileged` level. In a single namespace you were given, set `agents.namespace: ""` and
  `agents.createNamespace: false`: the agents go beside the control plane, and the pod is admitted only
  if that namespace's owner has set its level to `privileged` — for every pod in it.
  `kubectl get namespace <your namespace> --show-labels` tells you; `restricted` or `baseline` means a
  Docker host;
- **their own nodes**: `agents.nodeSelector`, and `agents.tolerations` matching a taint only they
  tolerate. Whatever you set, the chart keeps the control plane off an agent's node with a required
  anti-affinity: the control plane holds `ENCRYPTION_KEY`. On a single node it stays Pending rather
  than share one;
- **the NetworkPolicy**: on by default. It denies all ingress. List in
  `agents.networkPolicy.excludeCidrs` what an escaped scanner must not reach: the cluster's pod,
  service **and node** ranges (the kubelets, and the API server's real address), and the database's
  subnet when it is outside them, as a managed MySQL usually is. Egress then reaches the outside world
  and the Ingress. The chart refuses an empty list (`agents.networkPolicy.acknowledgeClusterReachable`
  overrides), and excludes `169.254.0.0/16` — the cloud metadata endpoint — whatever it says;
- **a pinned signing key** (`agents.signingKey.secretName`), which the chart requires: without one the
  control plane accepts the agent's results unattested.

Where the cluster forbids privileged pods, use a Docker host.

The **rootless variant** (`agents.dind.variant: rootless`, `docker:dind-rootless`) **does not scan
with this version's agent**:

- under the rootless daemon's user namespace, the workspace the agent owns as uid 1000 appears to the
  scanner as owned by root;
- the scanner, also running as uid 1000, cannot read it, and every scanner ends up absent;
- on most clusters it also needs a privileged container anyway, or unconfined seccomp and AppArmor.

The chart renders it only with `agents.dind.rootless.acknowledgeUnreadableWorkspaces: true`.

Each restart of the pod downloads the scanner images and the vulnerability database again — about
3 GB. `agents.dind.imageCache` keeps the images on a volume.

## Running from source

```bash
git clone https://github.com/asmolabs/vectispire.git
cd vectispire
npm ci

cd vectispire-java && ./gradlew :vectispire-core:bootRun --args='--server.port=3180'
npm --workspace @vectispire/frontend start    # UI on :4280, proxies /api to :3180
```

`npm` covers the interface alone. The control plane is a Gradle build in `vectispire-java/`
and shares nothing with it but the HTTP contract.

## Verifying a release

Each release carries the jar, its SBOM, the [CI gate script](../integrations/ci-gate.md) and —
from the release after 0.10.0 on — the CLI `vectispire-cli.sh`, each with a Sigstore bundle verified
as the jar is below. Verify before running anything — a security tool you took on trust is a contradiction.

```bash
cosign verify-blob \
  --bundle vectispire-0.10.0.jar.cosign.bundle \
  --certificate-identity "https://github.com/asmolabs/vectispire/.github/workflows/release.yml@refs/tags/v0.10.0" \
  --certificate-oidc-issuer https://token.actions.githubusercontent.com \
  vectispire-0.10.0.jar
```

Each flag pins something, and dropping any one of them gives back most of what signing was
for. `--certificate-identity` names the **workflow file and the tag**, not the repository:
matching the repository alone would accept a signature minted by any workflow anybody can
add to it, including one added in a pull request. `--certificate-oidc-issuer` says the
identity came from GitHub's token service — without it, a string that merely *looks* like
the identity above is enough. Replace the tag in both places for another version; the
identity is per-tag by design.

### Verifying an image

The images are signed the same way, by digest rather than by tag — a tag can be moved to
another image, a digest cannot. So verify the digest, and deploy that same digest: checking
the tag and then pulling it again checks an image you may not be running. Resolve the tag once,
with the command the release workflow uses itself:

```bash
DIGEST="$(docker buildx imagetools inspect ghcr.io/asmolabs/vectispire:0.10.0 --format '{{.Manifest.Digest}}')"
echo "$DIGEST"   # sha256:…

cosign verify \
  --certificate-identity "https://github.com/asmolabs/vectispire/.github/workflows/release.yml@refs/tags/v0.10.0" \
  --certificate-oidc-issuer https://token.actions.githubusercontent.com \
  "ghcr.io/asmolabs/vectispire@${DIGEST}"
```

Then reference the image as `ghcr.io/asmolabs/vectispire@sha256:<digest>` in your Compose file
or chart rather than by its tag.

Each image also carries its SBOM as an attestation rather than as a file beside it, because a
file beside an image is one anybody can swap:

```bash
cosign verify-attestation --type cyclonedx \
  --certificate-identity "https://github.com/asmolabs/vectispire/.github/workflows/release.yml@refs/tags/v0.10.0" \
  --certificate-oidc-issuer https://token.actions.githubusercontent.com \
  "ghcr.io/asmolabs/vectispire@${DIGEST}"
```

There is no signing key. Sigstore keyless signs with the workflow's own OIDC identity, so
there is nothing in anybody's custody to steal or rotate.

Run the same command against the SBOM's filenames. It is worth doing: an SBOM is what
somebody feeds to their own scanner, and an unsigned one is a dependency list anybody can
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
`ghcr.io/asmolabs/vectispire-agent`. From the release after 0.10.0 on, a third image is published,
`ghcr.io/asmolabs/vectispire-report-demo` — the demonstration [report plugin](../administration/report-plugins.md),
which the composition does not pull — and it verifies the same way under its own name.

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
