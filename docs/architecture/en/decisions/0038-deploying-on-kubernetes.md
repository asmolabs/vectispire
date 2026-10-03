# 0038 — On Kubernetes the control plane runs without a container endpoint, scans run on agents with a Docker daemon of their own, the database is external, and report plugins wait for an executor that can reach a remote daemon

**Date:** 2026-10-03 · **Status:** accepted · **Builds on:** [0002](0002-the-database-carries-the-queue.md), [0003](0003-long-polling-for-agents.md), [0013](0013-flyway-multi-dialect-migrations.md), [0018](0018-the-docker-socket-is-never-mounted.md), [0035](0035-report-plugins.md) · **Decider:** Laurent Boucher

*Accepted on 2026-10-03 by the product owner: option D for go-live (report plugins answer 409 until
option A is built), and agents in either of two places — on a Docker host outside the cluster, or in
the cluster as pods with a Docker-in-Docker sidecar, opt-in. The answers are at the end, under
"Decided on 2026-10-03"; §1–§7 stand as written, §2 is widened there. The docker-java TLS defect §3
found is fixed in the same lot, so a remote daemon over TLS is no longer one of option A's three
blockers.*

## Context

The first production installation is due by the end of October 2026, **on Kubernetes**, a cluster
its owner builds. MySQL is installed separately, not by Vectispire. The repository holds no
Kubernetes material: the one shipped composition is `docker-compose.yml`, which leans on three
things a standard pod does not have.

- **A Docker daemon.** The built-in worker, the plugins and the report plugins all run containers
  through `ContainerRunner`, which talks to `DOCKER_HOST` — in the composition, a socket proxy on the
  same host ([0018](0018-the-docker-socket-is-never-mounted.md)). A pod has no socket, and must not
  be given one.
- **The same path on both sides.** A scan's workspace, the matcher's database and a report's input
  are created under `java.io.tmpdir` and handed to the daemon as **bind mounts**, which the daemon
  resolves on *its* host. The composition makes the two filesystems agree by mounting
  `VECTISPIRE_WORK_DIR` at the same absolute path (installation guide, "Scan workspaces").
- **Volumes on a host.** The audit mirror and the work directory are host directories.

What already holds without a host: the queue is in the database ([0002](0002-the-database-carries-the-queue.md)),
agents poll over HTTPS and need no inbound connection ([0003](0003-long-polling-for-agents.md)),
secrets are read as files (`spring.config.import: optional:configtree:/run/secrets/`,
`ENCRYPTION_KEY_FILE`), and the health endpoint publishes Kubernetes probes
(`management.endpoint.health.probes.enabled: true`; `/actuator/health/liveness` and `/readiness` are
open to anonymous callers, `PlatformMetricsTest`).

## Decision

### 1. What runs in the cluster

- **The control plane, as a Deployment**, from the published image **by digest** (Jib, user
  `1000:1000`, port 3180). It serves the interface from the same jar and the same origin — no second
  workload for the front end, and `connect-src 'self'` stays true.
- **An Ingress with TLS** in front of it, for people and for agents alike. Three settings follow
  from what the application does, not from taste:
  - the **read timeout at least 60 s**: an agent's long poll holds its request up to 30 s
    (`AgentJobPoller.MAX_WAIT`);
  - the **body size at least 256 MB**: an agent's result carries the SBOM
    (`VECTISPIRE_MAX_BODY_AGENT_RESULT`); a rule-set upload is 64 MB;
  - **`VECTISPIRE_TRUSTED_PROXIES` set to the ingress controller's addresses**, or the rate limiter
    and every audit entry name the controller (`TrustedProxies`), and `X-Forwarded-Proto` is
    ignored: TLS ending at the Ingress then reads as plain HTTP to the pod, and the single sign-on
    hand-off cookie goes out without `Secure`.
- **`VECTISPIRE_EMBEDDED_WORKER=false`.** The control plane runs no container: there is no daemon to
  run one on (§3).
- **Nothing else.** No database, no daemon, no sidecar.

**Replicas: one at go-live, two supported once the two conditions below are in place.** The code was
written for several instances, and each mechanism is named:

| Shared state | How two instances agree |
|---|---|
| The scan queue | conditional take on the row, leases reclaimed when they lapse (0002, `ScanQueue`) |
| Scheduling, purge, triage expiry, reclaim | a leader lease by conditional `UPDATE` (`LeaderElection`, `SchedulerService`) |
| Maintenance tasks | run on every instance by contract, written to tolerate it (`MaintenanceTask`); the relay claims each message (`OutboxService.relay`) |
| Sessions, MFA challenges, rate windows | rows, not maps (`SessionEntity`, `MfaChallengeEntity`, `RateWindows`, V44) |
| Agents' long polls | each re-reads the queue every second, whatever instance holds the request (`AgentJobPoller`) |
| The audit chain | its head is a locked row (V66, `AuditChainConcurrencyIntegrationTest`) |
| The document signing key | generated once, insert-if-absent, read back (`SigningKeyService`) |

Each is tested against the real engines by two sessions or two threads; **none is tested by two
running applications**, which is why one replica is the go-live figure. Two replicas need:

- **sticky sessions for single sign-on.** The OIDC code flow keeps its state and nonce in the servlet
  session (`OidcConfiguration`, `SessionCreationPolicy.IF_REQUIRED`); a callback landing on the other
  pod finds no authorization request and the sign-in fails. Cookie affinity on the Ingress closes it.
  Password sign-in and MFA do not need it — both are rows;
- **an audit-mirror file per pod** (§5), never one file appended to by two processes.

Report-run and discovery concurrency are per instance (`VECTISPIRE_REPORT_CONCURRENCY`,
`VECTISPIRE_DISCOVERY_CONCURRENCY`): two replicas double them.

### 2. Scans run on agents, on a dedicated Docker host

Scans, scanner plugins and SARIF-producing checks run on **agents on a Docker VM outside the
cluster**, exactly the shape the composition's `with-agent` profile ships: the agent, its own socket
proxy, its work directory mounted at the same absolute path, its home under it
([Agents](../../../../docs-site/administration/agents.md)). The agent reaches the control plane
through the Ingress over HTTPS, which is all 0003 asks of it; its JVM must trust the Ingress
certificate. Nothing about the agent changes: its scanners' bind mounts are paths on its own host,
which is its daemon's host.

This is also the boundary 0018 names as the real one — execution on another machine than the
process holding `ENCRYPTION_KEY` — reached by construction rather than by a profile somebody has to
choose.

### 3. Where containers cannot run, today: report plugins

0035 §2 runs report plugins on **the control plane's own container endpoint**, under the built-in
worker's switch. On Kubernetes that endpoint would have to be a **remote daemon**, reached over TCP
with TLS. The executor was read for what that would do (`ContainerRunner`, `ContainerRun`,
`ReportPluginRenderer`, `ImageSignatureVerifier`, `ReportExecutorConfiguration`, docker-java 3.7.1's
sources). **It does not work today, for three independent reasons:**

1. **TLS is read and not used.** `ContainerRunner.clientAt` builds its configuration with
   `DefaultDockerClientConfig.createDefaultConfigBuilder()`, which does read `DOCKER_TLS_VERIFY` and
   `DOCKER_CERT_PATH` into `getSSLConfig()` — and then builds the transport with
   `new ApacheDockerHttpClient.Builder().dockerHost(…)` alone, never `.sslConfig(…)`. docker-java's
   `ApacheDockerHttpClientImpl` chooses `https` for a `tcp://` host only when it was given an SSL
   context. So `DOCKER_HOST=tcp://host:2376` speaks plain HTTP to a TLS port, and every call fails.
2. **The inputs are bind mounts, and a bind is a path on the daemon's host.** Three of them:
   the report's input directory holding `export.json` (`ReportPluginRenderer.writeInput`, mounted
   read-only at `/input`), the cosign public key of a key-form signer (`ImageSignatureVerifier`), and
   the registry login written for a private registry (`ContainerRunner.run`, `REGISTRY_LOGIN_MOUNT`).
   All go through `HostConfig.withBinds`, and a daemon given a bind whose source it does not have
   **creates it, empty**. A remote daemon would therefore hand the plugin an empty `/input` (the run
   fails with `exit_code`, recorded as possibly having read the export), hand cosign a directory
   where the key should be (`signature_unverified`), and hand it no login (`registry_authentication_required`).
   Every failure is safe — nothing unverified runs, nothing is signed — and none is a report.
   *The output, by contrast, would work*: it is a tmpfs volume owned by a holder container and read
   back through the archive API (`copyArchiveFromContainerCmd`), which never names a host path. A
   keyless signer on a public registry would verify too: it binds nothing.
3. **The executor exists only with the built-in worker.** `ReportExecutorConfiguration` is
   `@ConditionalOnProperty("vectispire.worker.enabled")`. Off, there is no executor and a report
   request answers 409 `report-executor-unavailable`. On, the built-in worker also claims scans and
   runs them on the same remote daemon — whose workspaces are binds too, so every scan would fail —
   and the control plane would clone with deployment keys again, the concentration 0003 and 0018
   took apart.

And one assumption of the composition would be lost even once all three are fixed: **the socket
proxy is the API filter.** A daemon's own TCP listener with TLS has none: whoever holds the client
certificate has `exec`, volumes, Swarm and the rest. A remote report host should keep the shipped
proxy behind a mutual-TLS terminator on that host, so that the certificate opens the same calls the
composition's proxy opens and no more.

**What works on Kubernetes today, then:** the whole product but report plugins — scans and scanner
plugins on agents, SARIF imports, triage, the gate, the built-in reports and exports (rendered in the
JVM, not in a container), discovery, SIEM, tickets. Report plugins answer 409, as 0035 says an
all-agent installation does.

### 4. The database is external

- **MySQL, one host in the URL** — `jdbc:mysql://db.example.org:3306/vectispire`. A URL whose hosts
  come from DNS (`mysql+srv`) or that names several is refused at startup by `ReservedEndpoints`,
  which must know the database's address to keep webhooks off it.
- **TLS to MySQL** through Connector/J's own properties: `sslMode=VERIFY_IDENTITY`, and the server's
  CA in a truststore mounted from a Secret (`trustCertificateKeyStoreUrl=file:…`).
- **`max_allowed_packet` at least `160M`** on the server. An export and a signed report package are
  bounded at 64 MiB and travel hex-encoded at twice their size (`ReportExportCeiling`); at the
  default 64 MiB the bound falls to about 32 MiB. Irrelevant until report plugins run, set now so that
  it is not the next surprise.
- **UTC.** The JVM is UTC — the image sets no zone, and the chart must not set `TZ` — and the server's
  `default_time_zone` should be `'+00:00'`: the MySQL migrations give some columns a
  `CURRENT_TIMESTAMP` default (V10, V12, V13), which the server evaluates in the session's zone.
- **Migrations at startup, as today.** Flyway takes a MySQL named lock while it migrates
  (`GET_LOCK`, flyway-mysql 12.4.0's `MySQLNamedLockTemplate`), so two pods starting together do not
  both migrate: one does, the other waits. Backups and the restore drill (`scripts/restore-drill.sh`)
  are the database owner's.

### 5. Secrets, and what must survive a restart

**Secrets are files, from Kubernetes Secrets, mounted under `/run/secrets/`** — the config tree the
application already imports, which Spring Boot reads as Kubernetes lays it out:

| File | Holds | Why it is required |
|---|---|---|
| `encryption_key`, read through `ENCRYPTION_KEY_FILE` | the key that decrypts every deployment key and token | not named `ENCRYPTION_KEY`, or the config tree sets the variable too and both are refused |
| `VECTISPIRE_DB_PASSWORD` | the database password | — |
| `VECTISPIRE_BOOTSTRAP_PASSWORD` | the first administrator's password | read only while the user table is empty |
| `vectispire.signing.key` | the document signing key, PEM | optional; set it with two replicas, and keep it: a replaced key makes every signed document unverifiable |
| `vectispire.oidc.client-secret` | the OIDC client's secret | with single sign-on |
| `VECTISPIRE_PREVIOUS_ENCRYPTION_KEYS_FILE` | earlier keys, during a rotation | during a rotation only |

**Nothing on the control plane's disk has to survive a restart, but the audit mirror.** With the
worker off it clones nothing, so it records no SSH host keys and holds no matcher database; the
signing key, when generated, is stored encrypted in the database. The mirror
(`VECTISPIRE_AUDIT_MIRROR`) is what makes deleting the last audit entry a second edit in a second
medium; on Kubernetes it is a **persistent volume**, and **one file per pod** — the pod's name in
the path — because two processes appending to one file on a shared volume interleave lines.
`/audit-log/verify` then compares the table with the answering pod's file: entries the other pod
wrote are "missing from the mirror", which is reported and does not break integrity; an entry in a
file and not in the table still does.

### 6. The pod's shape

- **Security context**: `runAsNonRoot`, user and group 1000, `allowPrivilegeEscalation: false`,
  every capability dropped, `seccompProfile: RuntimeDefault`, and a **read-only root filesystem**
  with `emptyDir` volumes for `java.io.tmpdir` and the home (`/home/vectispire`). Read-only is the
  intent, to be confirmed by starting the image so before the chart claims it.
- **Probes**: a **startup probe** on `/actuator/health/liveness` long enough for the migrations (the
  composition allows 120 s), then liveness on `/actuator/health/liveness` and readiness on
  `/actuator/health/readiness`, with `management.endpoint.health.group.readiness.include` set to
  `readinessState,db` so that a pod that lost its database stops receiving traffic rather than
  answering 500.
- **Resources**: the image already sizes the heap at 75 % of the container's memory
  (`-XX:MaxRAMPercentage=75`). Start at a request of 1 GiB and a limit of 2 GiB, 0.5 CPU requested,
  and measure: the built-in reports render in memory.
- **NetworkPolicy, optional and coarse.** Ingress on 3180 from the ingress controller only. Egress
  to DNS, to the database, to the forges (discovery reads their API; the internal CA is pinned on the
  forge connection, not in the JVM), to the OIDC issuer, the SIEM collector, the trackers and the
  threat-intelligence feeds or their mirrors. A policy names addresses, not hosts, so it is a floor:
  the per-destination control stays `OutboundUrlGuard` → `PinnedHttpSender`.

### 7. Upgrades

**`strategy: Recreate`, not a rolling update.** Flyway's lock keeps two migrations from colliding,
but a rolling update also keeps the *previous* release serving against the *migrated* schema, and
nothing in the migration rules (0013, 0027) asks a migration to keep the previous release working.
An upgrade therefore stops every pod, starts the new image, which migrates, and serves. There is no
down migration: rolling back is restoring the database backup taken before the upgrade, with the
previous image digest.

## The options for report plugins on Kubernetes

| | What it takes | What it costs |
|---|---|---|
| **A. A copy-in executor over a remote daemon** | (1) `clientAt` passes the configuration's SSL settings to the transport — a few lines; (2) inputs copied in instead of bound: a second holder owning a tmpfs volume, filled through the archive API (`copyArchiveToContainerCmd`; the daemon refuses an archive written to a read-only root but not to a volume path — the tests must confirm it), mounted read-only into the plugin; used for the export, the cosign key and the registry login — some two hundred lines in `ContainerRunner`/`ContainerRun`; (3) a report-executor switch of its own, defaulting to the worker's. Tests against a daemon that cannot see the process's files. **About two to three days.** | The control plane holds a client certificate to a Docker host: root on that host. A host for reports only, its proxy behind mutual TLS, keeps that to what reports need. 0035 §2 holds unchanged. |
| **B. Report plugins on agents** — 0035's later lot | The export sealed to one designated agent with 0031's keys, a new kind of agent job, the renderer on the agent, the output returned and checked before it is signed. | The largest. The confidential export leaves the control plane for a host whose operator may not be the project's reader — the reason 0035 deferred it. The cluster then holds no Docker credential at all. |
| **C. A shared filesystem at the same path** on the pod and the report host (NFS) | No code for the binds; TLS through a sidecar; the worker switched on for the executor. | Rejected: switching the worker on brings scans and clones back to the control plane, and the export and every workspace cross the network on a share. |
| **D. Go live without report plugins** | Nothing. | Report plugins answer 409 until A or B lands; everything else works. |

**Recommendation: D for the end of October, then A.** The deadline is met with the shape that is
tested today, and A is small, keeps 0035's reasoning intact, and is what an installation without a
local daemon will ask for again. Decided so: see answer 1 below.

## Alternatives considered

- **A Docker-in-Docker sidecar beside the control plane.** It needs a privileged container, which is
  root on the node in all but name, in the pod that holds `ENCRYPTION_KEY` — 0018's concentration,
  made worse. (Beside an *agent* it is accepted, opt-in: see "Decided on 2026-10-03", answer 2.)
- **Mounting the node's Docker or containerd socket.** Root on the node, for every workload the node
  carries; and a containerd socket does not speak the Docker API `ContainerRunner` uses anyway.
- **Running scanners as Kubernetes Jobs** — a Kubernetes backend for `ContainerRunner`. The closed
  shape does not map one to one: an `emptyDir` size limit is enforced by eviction, not by the kernel
  as the bounded output's tmpfs is; the pod creating them needs RBAC to create pods, from the process
  that holds the key. A rewrite of the executor, not a deployment choice; not for October.
- **The built-in worker on a remote daemon.** Every workspace is a bind (§3), and the control plane
  would clone again.
- **MySQL in the chart** (a database sub-chart). The database is installed and backed up by its
  owner; a chart that also ships one invites two of them.
- **A rolling update.** See §7.
- **Several replicas from day one.** See §1: the mechanisms exist, two running applications have not
  been tried, and SSO needs affinity.

## Consequences

- A Kubernetes installation is an all-agent installation: at least one agent — on a Docker host, or
  in a pod with its own daemon — is required before the first scan.
- Report plugins are unavailable on Kubernetes until the question above is settled and built.
- The audit mirror needs a persistent volume and a file per pod.
- The installation guide gains a Kubernetes section, and the chart lives under
  `deploy/helm/vectispire/`, linted and rendered in CI for each of its shapes.

## Decided on 2026-10-03

1. **Report plugins: D for go-live, then A.** The control plane has no container endpoint; a report
   request answers 409 `report-executor-unavailable`, as 0035 says of an all-agent installation. The
   copy-in executor (A) is the next lot. Its first item, docker-java's TLS, is fixed now:
   `ContainerRunner.clientAt` hands the transport the configuration's SSL settings, so `tcp://…:2376`
   with `DOCKER_TLS_VERIFY=1` and `DOCKER_CERT_PATH` speaks TLS with the client certificate.
2. **Agents in either of two places, chosen per installation.**
   - **On a Docker host outside the cluster — the recommendation**, and the only choice where the
     cluster forbids privileged pods. The chart deploys nothing for it; the agent runs as the
     composition's `with-agent` profile does, and reaches the control plane through the Ingress.
   - **In the cluster, as pods with a Docker-in-Docker sidecar — opt-in**, off by default. The
     agent pod holds no database credential and no `ENCRYPTION_KEY`, which is what made a sidecar
     unacceptable beside the control plane. What it costs is said here, because the chart cannot
     say it: **a privileged container is root on its node.** A scanner that escapes its container
     reaches a daemon that can start privileged containers, hence the node. So the agents run in a
     namespace of their own, on a node pool of their own (`nodeSelector`, a taint they alone
     tolerate), behind a NetworkPolicy that lets them reach the control plane and the forges and
     nothing else in the cluster. The pod has the daemon to itself on a **Unix socket in a shared
     `emptyDir`, never TCP**: the `docker:dind` entrypoint adds `--host=tcp://0.0.0.0:2375`, with no
     TLS and no authentication, unless the command names `dockerd` itself — measured, and an open
     2375 on a pod address is a privileged daemon for the whole cluster. The work directory is a
     second `emptyDir` mounted **at the same path** in the agent and the daemon, for the reason the
     composition mounts `VECTISPIRE_AGENT_WORK_DIR` at the same path: a scanner's bind is resolved by
     the daemon.
   - **The rootless variant (`docker:dind-rootless`) is offered and refused by default, because it
     does not scan.** Measured on 29.8.2: under the rootless daemon's user namespace, the
     workspace the agent creates as uid 1000, mode 0700, appears to the scanner as owned by root,
     and the scanner — run as the workspace's owner, uid 1000 (`ContainerRun.runningAsOwnerOf`) —
     reads `Permission denied`. Every scanner would be absent, silently as far as triage goes.
     The agent never runs a scanner as root, and no mapping of the pod's uid closes the gap: the
     daemon's uid 1000 is the container's root. The rootless image also needs, on most clusters,
     either a privileged container anyway or seccomp and AppArmor unconfined with an unmasked
     `/proc` — so it rarely spares the privilege it is meant to. The chart renders it only under an
     explicit acknowledgement, so that it is there to try when the agent learns to map owners, and
     never chosen by accident.
3. **The chart is written** (`deploy/helm/vectispire/`), with §1–§7 as its defaults.

