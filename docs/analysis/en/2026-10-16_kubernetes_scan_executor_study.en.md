# Study: launching scans on Kubernetes instead of Docker

**Date:** 16 October 2026 · **Tree studied:** `develop` @ `312b7cc8`, and the Rust port's
foundations (`feat/rust-agent` @ `c93eef175`) · **Status:** proposal, no code written · **Would
amend:** [decision 0038](../../architecture/en/decisions/0038-deploying-on-kubernetes.md)

---

## 0. In one paragraph

Today every scanner, scanner plugin and report plugin runs as a Docker container, created by
`ContainerRunner` (`vectispire-common/.../scanning/ContainerRunner.java`, 820 lines) in one closed
shape (`ContainerRun`, 201 lines). It is reached through a socket proxy on the machine that scans
([0018](../../architecture/en/decisions/0018-the-docker-socket-is-never-mounted.md)). A
**Kubernetes backend** would create those runs as pods in a dedicated namespace instead, and
needs no Docker daemon at all. Decision 0038 set this aside on 2026-10-03, "not for October", for
three reasons: the output bound becomes eviction instead of a kernel limit, the process creating
pods needs RBAC, and the executor has to be rewritten. This study re-examines those reasons
against the code and finds:

- **The rewrite is real but bounded.** The estimate is **33 to 55 developer-days** for one backend
  (§9), either in the Java agent or in the Rust one.
- **Only the agent should hold it**, never the control plane.
- **It is safer than what agents in a cluster use today.** That is the opt-in Docker-in-Docker
  sidecar, a privileged container that is root on its node. A namespace-scoped Role under Pod
  Security Admission `restricted` limits a compromised agent to unprivileged pods in one namespace.
- **It is also narrower than an agent VM's own blast radius:** the socket proxy, as
  `docker-compose.yml` itself says, "reduces the surface, it does not draw a boundary".
- **Three properties of the closed shape cannot be expressed per pod** and have to be compensated
  or accepted: a per-container PID limit, `noexec` on scratch space, and an inode limit (§3).

**Recommendation:** do not build it for production; production runs on Docker Compose VMs
(decided 2026-10-14) and does not need it. Build it **once, in the Rust agent**, after that agent
has passed its side-by-side conformance period, and only when a named installation needs agents
inside a cluster that forbids privileged pods. The go/no-go criteria are in §11.

---

## 1. Who needs this, and when

| Installation | Where scans run today | Does it need this? |
|---|---|---|
| Production (end of October 2026) | Agents on Docker Compose VMs, one per instance | **No.** A VM has its own daemon. |
| Kubernetes, agents outside the cluster (0038's recommendation) | Agents on a Docker host | No |
| Kubernetes, agents inside the cluster (0038, answer 2, opt-in) | Agent pod + privileged `docker:dind` sidecar on a dedicated node pool | **Yes: this is what it replaces** |
| A cluster whose policy forbids privileged pods (common on managed and hardened clusters) | Not possible today | **Yes: the only way to scan in-cluster** |

So the need is conditional. Nothing in the October plan depends on it.

## 2. Where the executor runs: the agent only

**The control plane must never create scan pods.** It holds `ENCRYPTION_KEY`, which decrypts every
deployment key Vectispire stores (decision 0003). 0038 already rejected giving the key-holding
process RBAC to create pods, and nothing here changes that. A pod-creating credential on the
control plane would let a control-plane compromise run arbitrary images in the cluster, holding the
key. The built-in worker therefore stays a Docker-only feature; on Kubernetes,
`VECTISPIRE_EMBEDDED_WORKER=false` remains the rule.

The agent holds no database credential and no key, by construction of the build graph (0003; the
Rust port preserves it with a `cargo metadata` test). It is the right place for a credential that can
start pods, as it is today the place for a Docker endpoint.

## 3. Mapping the closed shape to a pod

Read from `ContainerRunner.closedHostConfig` (≈ lines 329–367), `create` (≈ 371–410) and `ScannerLimits`
(`DEFAULT`: 2 GiB memory, 512 PIDs, 15 min timeout, 256 MiB output).

| `ContainerRun` property (Docker) | Pod / Job equivalent | Parity |
|---|---|---|
| `CapDrop: ALL` | `securityContext.capabilities.drop: [ALL]` | exact |
| `no-new-privileges` | `allowPrivilegeEscalation: false` | exact |
| `ReadonlyRootfs` | `readOnlyRootFilesystem: true` | exact |
| user = workspace owner (`runningAsOwnerOf`); no scanner runs as root | `runAsUser`/`runAsGroup`, `runAsNonRoot: true` | exact; every scanner is already non-root, so PSA `restricted` admits them all |
| default seccomp | `seccompProfile: RuntimeDefault` | exact (required by `restricted`) |
| `Memory`, `NanoCPUs` | `resources.limits.memory` / `cpu` (requests = limits) | exact |
| `PidsLimit: 512` | **no per-pod field.** Only the kubelet's `podPidsLimit`, set per node | **gap**: needs a dedicated node pool configured with it |
| `NetworkMode: none` | a NetworkPolicy denying all egress to pods labelled for offline steps | **pod-level, not container-level**, and silently absent if the CNI does not enforce NetworkPolicy (§7) |
| `NetworkMode: bridge` (database update, cosign, plugins that declare network) | a second label selecting a policy allowing egress except cluster, private and metadata ranges | same intent; NetworkPolicy cannot name DNS hosts |
| tmpfs `/tmp` and `HOME`, `rw,noexec,nosuid,mode=1777,size=512m` | `emptyDir {medium: Memory, sizeLimit: 512Mi}` | **gap**: no `noexec`/`nosuid` mount option exists for volumes. Size: see §5 |
| label `dev.vectispire.scanner` | pod labels (+ scan id, step) | exact, and better: `ownerReferences` to the agent pod |
| timeout (`waitFor`, 15 min default) | `activeDeadlineSeconds` + the agent's own wait | exact |
| explicit removal, holder TTL after a crash | `ttlSecondsAfterFinished` (Jobs) or explicit deletion + a label sweep at agent start | exact |
| image by digest (`ScannerImages`) | `image: name@sha256:…`, `imagePullPolicy: IfNotPresent` | exact |
| registry login (`RegistryLogin`, `DOCKER_CONFIG` file) | a file copied in (§4), never an `imagePullSecret` shared with other workloads | see §6 |
| no service account | `automountServiceAccountToken: false`, a service account with no Role | exact |
| `Ulimit fsize` on bounded outputs | **no field** | gap, compensated by the capped read (§5) |
| bounded output's inode count (`OUTPUT_INODES`) | **no field** (`nr_inodes` is not exposed) | gap, accepted: memory limit bounds the cost |

Everything above that is "exact" is enforced by the kubelet and the runtime, the same mechanisms
Docker uses. The three gaps are the price of the change and belong in the ADR.

## 4. How the workspace reaches the scanner

Today the workspace is a host directory, mode 0700, owned by the agent's uid 1000, bind-mounted
into each scanner container. The daemon resolves the bind on its own host, which is why 0038's
in-cluster agents mount the work directory at the same path in the agent and the daemon. A pod on
another node cannot see the agent's files.

| Option | For | Against |
|---|---|---|
| **A. A shared ReadWriteMany volume** (NFS, CephFS) | closest to a bind | needs an RWX storage class, which many clusters lack; every workspace and the repository's source cross the network on a share (0038 rejected the same for reports, option C); file ownership over NFS reopens the uid question |
| **B. An init container that clones** | no copy | the clone credentials (deploy key, HTTPS token) would be handed to a pod in the scan namespace, and the clone code would run twice; the agent's host-key pinning and redirect refusal would have to be re-implemented in that image |
| **C. Copy in and out over `exec` + tar** (what `kubectl cp` does) | the pod needs **no network at all**; ownership is whatever the receiving container's `runAsUser` writes, which **closes the 0700/uid gap 0038 measured on rootless Docker** | needs `pods/exec` in the Role (scoped to the scan namespace); the copy is a stream the agent must cap |
| **D. A sidecar serving the workspace over HTTP** | no `exec` permission | the pod needs network to the agent, and NetworkPolicy is per pod, so the scanner gets that network too |
| **E. Ephemeral containers** | none for this use | they cannot be given volumes or resources the way needed; designed for debugging |

**Recommended: C.** It is the direct analogue of what `ContainerRunner` already does with the
archive API for bounded outputs (`copyArchiveFromContainerCmd` on the holder container). Shape of one step:

1. The agent creates the pod: an `emptyDir` for the workspace, a native sidecar **holder** (a pinned
   minimal image that sleeps; `restartPolicy: Always` in `initContainers`, Kubernetes ≥ 1.29), a
   plain init container waiting for a marker file, and the scanner as the main container.
2. The agent streams the workspace into the waiting init container with `exec tar -x`. It writes
   the marker, and the scanner starts.
3. The scanner writes its report into the `emptyDir`. The holder keeps the pod alive after the
   scanner exits.
4. The agent reads the report with `exec cat` through the same capped reader as today: over the
   ceiling is a **failure, not a truncation**, as `ContainerRunner` says. Then it deletes the pod.

**Do not read reports from pod logs.** The kubelet rotates container logs at `containerLogMaxSize`,
10 MiB by default. A 200 MB SBOM read through `pods/log` would be cut silently, and a cut JSON read
leniently is exactly the absent-versus-empty defect fixed in 0.11.1. Logs are for stderr only, which the runner already caps
at 1 MiB (`STDERR_BYTES`) and the scanners quote to 2,000 characters.

## 5. The bounded output without a size-limited tmpfs volume

`ContainerRun.BoundedOutput` exists because a tool wrote beside its report until the executor's disk
was full. Its bound is a tmpfs volume with `size=`, kept alive by a holder, plus `fsize` and an inode
count. That is three kernel limits.

- **An `emptyDir` on disk with `sizeLimit` is enforced by eviction.** The kubelet notices on its
  housekeeping pass and evicts the pod, so a tool can overshoot for seconds. That is 0038's
  objection, and it holds for disk.
- **An `emptyDir` with `medium: Memory` is a tmpfs**, and its pages are charged to the pod's
  memory cgroup. So the memory limit bounds it by the kernel. Recent Kubernetes versions also mount
  it with `size=` equal to `sizeLimit` (the `SizeMemoryBackedVolumes` behaviour), which gives
  `ENOSPC` like today. **That has to be verified on the target cluster's version**; where it holds,
  0038's eviction objection falls for memory-backed outputs.
- **What remains a gap:** `fsize` (a sparse `truncate -s 1T` file costs nothing on tmpfs) and the
  inode count. Both are compensated by the reader: the agent's `exec cat` is capped at the
  output's ceiling and fails above it, exactly as `OutputArchive.read` does today.

## 6. The scanners one by one

- **Gitleaks, Checkov, Semgrep, Syft on a tree:** offline, workspace in, report out. Option C covers
  them unchanged. Semgrep's and Checkov's rules are placed in the workspace already
  (`Workspace.rules`, `RulePlacement`), so nothing else needs mounting.
- **Grype and its database** (`VulnerabilityDatabase`, 408 lines). The database is a few GB, with a
  `FileChannel` lock so one download happens at a time per host. The Rust port takes the same POSIX
  record lock, so both agents agree.
  - **Recommended:** a **ReadWriteOnce PVC** owned by the agent. Scanner pods are scheduled **on
    the agent's node** (pod affinity) and mount it read-only; RWO admits several pods on one node.
    The download runs as a networked pod on that node.
  - The lock stays a local POSIX lock on one node's filesystem.
  - **Avoid RWX/NFS here:** POSIX locks over NFS depend on the server and client configuration.
- **Image scans** (`DependencyScanner.exportImage`, `ContainerRunner.exportImage`: `pullImageCmd` +
  `saveImageCmd`). There is no daemon to pull and save the image.
  - **Recommended:** a networked step running a **pinned `crane` or `skopeo`** image. It copies the
    image into an OCI layout in the workspace, with the registry login copied in as a file; then
    Syft and Grype read the layout offline.
  - Letting Syft or Grype pull from the registry themselves would give credentials and network to
    the parsers of hostile metadata.
  - **A reference-set check is mandatory:** Syft on an OCI layout against Syft on a Docker archive.
    The package fields are expected to be equal, but the source metadata differs, and fingerprints
    must not move (AGENTS.md, "fingerprint").
- **Cosign** (`ImageSignatureVerifier`) already runs as a container with network and a login file.
  Nothing changes but the transport of the key and login file (option C).
- **Scanner plugins** (`PluginScanner`; [0017](../../architecture/en/decisions/0017-custom-checks-as-container-images.md)):
  same shape, network only when the manifest asks, bounded output as §5.
- **Report plugins** (`ReportPluginRenderer`, [0035](../../architecture/en/decisions/0035-report-plugins.md)): see §8.

## 7. RBAC, blast radius and isolation

**The Role** sits in a dedicated namespace, for example `vectispire-scans`, bound to the agent's
service account:
- `pods`: `create`, `get`, `list`, `watch`, `delete`;
- `pods/exec`: `create`;
- `pods/log`: `get`;
- nothing else: no secrets, no deployments, nothing cluster-wide.

**The namespace** is labelled `pod-security.kubernetes.io/enforce: restricted`, so the API server
itself refuses a privileged pod, a `hostPath`, host networking or a root user, whatever the agent
asks.

| A compromised agent can… | Today: VM + socket proxy | Today: in-cluster DinD (0038 answer 2) | Kubernetes backend |
|---|---|---|---|
| become root on its host or node | **yes**: `POST /containers/create` with a bind of `/`, which the proxy cannot refuse (`docker-compose.yml`) | **yes**: a privileged daemon | **no**: PSA `restricted` |
| run arbitrary images | yes, on its VM | yes, on its node | yes, as restricted pods in one namespace |
| read other workloads | whatever its host holds | the node's | **nothing**: other namespaces, no Role |
| exec into pods | n/a | n/a | **only pods in the scan namespace**, which are its own |

**Isolation measures the chart would carry:**
- a `ResourceQuota` and a `LimitRange` on the namespace;
- a dedicated node pool (taint and `nodeSelector`) carrying the `podPidsLimit` setting;
- the two NetworkPolicies;
- optionally a `runtimeClassName` for gVisor or Kata, as defence in depth against escapes.

**Never skip silently.** A NetworkPolicy on a CNI that does not enforce it is accepted and ignored.
The agent must therefore **probe at startup**: it runs a pod with the offline label, tries to
connect out, and refuses to scan if it succeeds. A scanner that "has no network" on paper and full
network in fact is the kind of green this repository forbids.

## 8. Report plugins: does this unlock 0038's options A and B?

Partly, and not where one might hope.
- **Not on the control plane.** Running report plugins there as pods would put pod-creation RBAC
  next to `ENCRYPTION_KEY`, which §2 refuses. So option A, a remote executor driven by the control
  plane, is not made cheaper.
- **On agents (option B), yes for the execution part.** An agent with this backend can run a report
  plugin as a restricted pod. But option B's real cost is elsewhere:
  - the confidential export sealed to one designated agent (0031's keys);
  - a new kind of agent job;
  - the output returned and checked before signing.

  That is unchanged by the backend. So report plugins stay a separate decision; the backend only
  removes "and that agent needs a Docker daemon".

## 9. Effort

In developer-days, for one backend, with a team that knows the codebase and Kubernetes. Parts 8 to
10 are shared if both agents ever get it.

| # | Part | Java agent | Rust agent |
|---|---|---|---|
| 1 | Executor seam: an interface over the runner, including `exportImage`, registry login, bounded output and availability | 3–5 | 2–4 |
| 2 | Pod spec from `ContainerRun`; create, watch, wait, deadline, delete; owner references; label sweep at start | 6–9 (fabric8 client: a large new dependency, `verification-metadata.xml` review) | 5–8 (`kube` + `k8s-openapi`, through `cargo deny`) |
| 3 | Workspace in and report out over `exec` + tar; native-sidecar holder; capped reads | 5–8 | 5–8 |
| 4 | Limits and gaps (§3, §5); failure mapping (§10) with tests | 3–5 | 3–5 |
| 5 | Image export with `crane`/`skopeo` to an OCI layout; Syft and Grype on layouts; reference set; cosign transport | 4–6 | 4–6 |
| 6 | Vulnerability database on an RWO PVC with node affinity; download pod | 2–4 | 2–4 |
| 7 | NetworkPolicies and the startup enforcement probe | 2–3 | 2–3 |
| 8 | Helm chart: `agents.executor: kubernetes`, namespace with PSA labels, Role and RoleBinding, policies, quota, node pool, PVC; render and kubeconform tests | 3–5 | 3–5 |
| 9 | CI: a kind job (node image pinned by digest) running `scripts/composition-scan-check.sh MODE=agent` against this backend, in the nightly | 4–6 | 4–6 |
| 10 | ADR amending 0038, docs in English and French, security review | 3–4 | 3–4 |
| | **Total** | **35–55** | **33–53** |

Building it in **both** agents costs about **20–30 more days** (parts 1–7 again).

## 10. Failure semantics: never empty

Every outcome maps onto what `ContainerRunner` already raises, a `ScannerFailureException` naming
the step, so the step is **absent** and its issue types stay as they were
([0007](../../architecture/en/decisions/0007-none-is-not-an-empty-list.md)). None of them may become
an empty result.

| Kubernetes outcome | Mapped to |
|---|---|
| `ErrImagePull`, `ImagePullBackOff` past a short grace | failure: the image could not be pulled |
| `Unschedulable` past a pending timeout | failure: no node could run the step (quota, taints) |
| `OOMKilled` (exit 137 with that reason) | failure: exceeded its memory |
| `DeadlineExceeded` | `ScannerFailureException.timedOut`, as today |
| `Evicted` (disk `sizeLimit`, node pressure) | failure: wrote more than allowed, or the node reclaimed it |
| capped read over the ceiling | failure, not truncation, as today |
| pod deleted by someone else, agent restart mid-step | failure; the label sweep removes leftovers |
| non-zero exit | as today: the scanner's own exit-code rules |

**Observability:** each pod is labelled with the scanner, step and scan id. The agent logs the pod's
events on failure, so "why" is visible without cluster access.

## 11. Decision proposal

**What the ADR would say (amending 0038):** agents may run their scans as pods in a dedicated
namespace under PSA `restricted`, with a namespace-scoped Role, copy-in and copy-out over `exec`,
memory-backed outputs, and a startup probe that refuses an unenforced NetworkPolicy. The three gaps
are accepted with their compensations: PIDs per node pool, no `noexec` scratch, the inode count.
The control plane never gets this credential. The Docker-in-Docker sidecar becomes the fallback for
clusters older than native sidecars.

**Go only if all of these hold:**
1. A named installation needs agents inside a cluster that forbids privileged pods. Without one,
   the work has no user.
2. The target clusters are on Kubernetes ≥ 1.29 for native sidecars. On their versions, a
   memory-backed `emptyDir` with `sizeLimit` is measured to give `ENOSPC`, not eviction.
3. Their CNI enforces NetworkPolicy, as the startup probe shows on the real cluster.
4. `composition-scan-check.sh MODE=agent` gives **identical findings** on the Docker and Kubernetes
   backends, with the reference sets unchanged, including the image scan through an OCI layout.
5. A security review of the Role, the namespace and the policies finds nothing above low.

**Where to build it: in the Rust agent, once.** The Rust port is under way, its container crate
(`vectispire-rust/crates/container`, 519 lines) is young, and its `ContainerRunner` is a concrete
type, so adding the seam there now costs least. Building it in Java first only makes sense if
criterion 1 appears before the Rust agent has finished its side-by-side period. In that case, build
it in Java and port it with the rest.

## 12. Risks

- **`pods/exec` is a strong verb.** Here it is scoped to a namespace holding only the agent's own
  pods. A Role written wider by an operator would turn it into exec on other workloads, so the chart
  must render it and a test must pin its rules.
- **NetworkPolicy without enforcement** gives full network silently; the probe of §7 is not
  optional.
- **Latency:** one pod per step, plus image pulls (Semgrep's image is 419 MB compressed). Mitigation:
  `IfNotPresent` on a dedicated node pool, optionally a pre-pull DaemonSet.
- **Version spread** between clusters (native sidecars, memory-backed `sizeLimit`).
- **Supply chain:** a Kubernetes client is a large dependency in either language, reviewed through
  `verification-metadata.xml` or `cargo deny`.
- **Fingerprints:** the OCI-layout path for image scans is the one place where the scanner's input
  changes; the reference set guards it (§6).

## 13. What was read

- **Code:** `ContainerRunner`, `ContainerRun`, `ScannerLimits`, `Workspace`, `OutputArchive`, and
  the scanners under `scanning/scanners/`: `SecretsScanner`, `SastScanner`, `IacScanner`,
  `DependencyScanner`, `VulnerabilityDatabase`, `ImageSignatureVerifier`, `PluginScanner`,
  `ReportPluginRenderer`, `ScannerImages`.
- **Compose:** the socket-proxy notes in `docker-compose.yml`.
- **Decisions:** 0003, 0007, 0017, 0018, 0031, 0035 and 0038, including its answers of 2026-10-03
  and its amendment of 2026-10-10.
- **Rust:** the container crate of `feat/rust-agent`.
- **Not run:** the Kubernetes behaviours named in §5 (memory-backed `sizeLimit`), §4 (log rotation
  default) and §7 (PSA) are stated from the Kubernetes documentation's defaults. Criterion 2 asks
  for them to be measured on the target clusters.
