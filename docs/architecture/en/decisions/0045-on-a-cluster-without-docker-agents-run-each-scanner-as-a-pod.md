# 0045 — On a cluster without Docker, agents run each scanner as a pod in a namespace of their own

**Date:** 2026-10-25 · **Status:** accepted · **Amends:** [0038](0038-deploying-on-kubernetes.md) · **Builds on:** [0003](0003-long-polling-for-agents.md), [0007](0007-none-is-not-an-empty-list.md), [0017](0017-custom-checks-as-container-images.md), [0018](0018-the-docker-socket-is-never-mounted.md) · **Decider:** Laurent Boucher

## Context

Every scanner, scanner plugin and report plugin runs today as a Docker container, created by
`ContainerRunner` (`vectispire-common/.../scanning/ContainerRunner.java`) in one closed shape: no
capabilities, no new privileges, a read-only root filesystem, the workspace owner's uid, no network
unless the step needs it, memory, CPU and PID limits, a fresh container for every run, removed after
it. Decision [0038](0038-deploying-on-kubernetes.md) put the agents that serve a Kubernetes installation
either on a Docker host outside the cluster or in the cluster beside a privileged `docker:dind` sidecar.

The first production installation runs **inside a cluster with no Docker at all** (decided by the
product owner on 2026-10-25, replacing the Docker Compose VMs chosen on 2026-10-14): no daemon, no
privileged pod, no VM beside the cluster. Neither of 0038's places for an agent exists there, and a
scan has nothing to run its scanners in.

The [study of 2026-10-16](../../../analysis/en/2026-10-16_kubernetes_scan_executor_study.en.md) costed a
Kubernetes backend for the executor and set out the conditions under which to build it; the first of
them — a named installation inside a cluster that forbids privileged pods — now holds.

Three cheaper shapes were weighed on 2026-10-25 and rejected:

- **The scanners as long-lived sidecars of the agent's pod.** No Kubernetes permission needed, but the
  pod's containers are fixed when it starts, so a scanner plugin — an image a task names (0017) — cannot
  run, the installation's own scanner plugin included; the containers of a pod share its network, so
  every scanner gets the agent's; and a sidecar outlives its run, so a scanner a hostile repository
  compromised stays in place to read the next repositories. Three of the closed shape's properties lost.
- **The scanners as processes in the agent's image.** A scanner exploited by a repository would run in
  the same container as the deploy keys and tokens the agent unseals for the clone.
- **Podman on a VM**, which would likely accept today's agent unchanged: excluded by the installation.

## Decision

1. **The executor gets a seam, and a Kubernetes implementation behind it.** `ContainerRunner`'s contract
   — run a `ContainerRun`, export an image, log in to a registry for one run, bound an output, say whether
   the backend is available — becomes an interface, with today's Docker runner and a Kubernetes one. The
   agent chooses by configuration (`vectispire.agent.executor: docker | kubernetes`). **The control plane
   never gets the Kubernetes one**: it holds `ENCRYPTION_KEY`, and a credential that starts pods beside it
   would let a control-plane compromise run arbitrary images in the cluster with the key in hand (0003,
   0038). On Kubernetes the built-in worker stays off (`VECTISPIRE_EMBEDDED_WORKER=false`), as 0038 says.
   **The Kubernetes backend lives in `vectispire-agent`, not in `vectispire-common`**, which the control
   plane shares: the control plane cannot compile against it, as the agent cannot compile against a
   database driver (0003). **And it speaks to the API server over the JDK's own `HttpClient` and
   `WebSocket`**, as the agent already speaks to the control plane, with no client library: what it needs
   is five calls — create, read, list and delete a pod, and `exec` over the `v5.channel.k8s.io` WebSocket
   protocol — and a client such as fabric8 would add dozens of artifacts to review and pin for them.
2. **One pod per run, as today one container per run.** The pod carries every property of the closed
   shape that Kubernetes expresses per pod, exactly: `capabilities.drop: [ALL]`,
   `allowPrivilegeEscalation: false`, `readOnlyRootFilesystem: true`, `runAsNonRoot` with the workspace
   owner's uid and gid, `seccompProfile: RuntimeDefault`, memory and CPU limits equal to requests,
   `activeDeadlineSeconds` for the timeout, `automountServiceAccountToken: false`, the image by digest,
   and labels naming the scanner, the step and the scan. It is deleted after its run, and the agent
   sweeps its label at start for what a crash left.
3. **In a namespace of its own, under a Role that reaches nothing else.** The pods run in a dedicated
   namespace labelled `pod-security.kubernetes.io/enforce: restricted`, so the API server itself refuses a
   privileged pod, a `hostPath`, host networking or a root user, whatever the agent asks. The agent's
   service account holds, in that namespace only: `pods` `create`, `get`, `list`, `watch`, `delete`,
   `deletecollection` (the sweep by label); `pods/exec` `create` and `get`; `pods/log` `get`. Nothing
   cluster-wide, no secrets. **Both verbs on `pods/exec`**: an `exec` over WebSocket opens with a `GET`,
   authorized as `get` — refused with `create` alone on Kubernetes 1.34, measured — and from 1.35 the API
   server checks `create` as well. The chart renders the Role,
   and a test pins its rules: `pods/exec` written wider by an operator would reach other workloads.
4. **The workspace goes in, and the report comes out, over `exec`.** The agent clones as today, then
   streams the workspace into the pod's `emptyDir` with `tar` over `exec`, into an init container waiting
   for it; the scanner starts once it is there, and a holder — a second ordinary container that outlives
   the scanner — keeps the pod running so its report can be read with a capped `exec` read. Not a native
   sidecar, as the study had it: Kubernetes stops those as soon as the pod's ordinary containers have
   exited, and the report would go with them. **Never from the pod's logs**: the
   kubelet rotates them (10 MiB by default), and a cut report read leniently is the absent-versus-empty
   defect again. Over the ceiling is a failure, not a truncation, as today. No clone credential ever
   reaches a scan pod.
5. **No network unless the step needs it, and proven so.** Offline steps — every scanner on a tree, the
   matcher, plugins that do not declare network — carry a label a NetworkPolicy denies all egress to.
   Networked steps — the matcher's database update, the image copy, cosign, plugins that declare network
   — carry another, allowed out except to the cluster's, private and metadata ranges. A NetworkPolicy the
   CNI does not enforce is accepted and ignored, so **the agent probes at start**: it runs an offline pod
   that tries to connect out, and refuses to scan if it can.
6. **Three properties of the closed shape cannot be set per pod, and are accepted with their
   compensations:** the PID limit (the kubelet's `podPidsLimit`, set on the dedicated node pool the
   chart requires); `noexec` and `nosuid` on scratch space (no volume option exists); and `fsize` and the
   inode count of a bounded output, which a memory-backed `emptyDir` with `sizeLimit` replaces — charged to
   the pod's memory, `ENOSPC` past its size — with the capped read behind it.
7. **The matcher's database is kept on a ReadWriteOnce volume in the scans' namespace**, *amended on
   2026-10-26*: a volume of the agent's, as first written, cannot be mounted by scan pods, since a claim
   belongs to one namespace. The agent keeps its database as today — downloaded by a networked pod, under
   the same file lock, into its own directory — and each generation, which never changes once published,
   is copied onto the volume once, through the receiving container of the first matcher pod that needs it,
   marked complete, and mounted read-only by every matcher after; generations the agent no longer holds
   are removed from it. Every pod mounting it is sent to the agent's node, where the volume attaches. No
   shared network filesystem: locks over NFS depend on its configuration.
8. **An image target is copied, not pulled by a parser.** A pinned `crane` (or `skopeo`) step copies the
   image into an OCI layout in the workspace, with the registry login handed to it as a file; Syft and
   Grype read the layout offline. Letting them pull would give network and credentials to the parsers of
   hostile metadata. A reference set holds Syft on an OCI layout against Syft on a Docker archive:
   **fingerprints must not move**.
9. **Never empty.** Every Kubernetes outcome is a failure naming the step — an image that cannot be
   pulled, a pod nobody can schedule, `OOMKilled`, the deadline, an eviction, a read over its ceiling, a pod
   deleted underneath — so the step is absent and its backlog stays as it was (0007).
10. **Built in the Java agent first.** The Rust agent is not ready to serve an installation; the backend
    is ported with the rest when it is.

**Before it scans anything for the installation**, all of these hold, and the results are written in
this record: the cluster runs a Kubernetes version its upstream still supports; on it, a memory-backed
`emptyDir` with `sizeLimit` is measured to answer `ENOSPC` rather than an eviction; its CNI enforces
NetworkPolicy, as the probe shows; `scripts/composition-scan-check.sh MODE=agent` gives **identical
findings** on the Docker and the Kubernetes backends, the image scan included, with the reference sets
unchanged; and a security review of the Role, the namespace and the policies finds nothing above low.

## Consequences

- **No Docker anywhere** in a Kubernetes installation that chooses this executor; the Docker-in-Docker
  sidecar of 0038 stays for clusters that allow privileged pods and prefer it.
- **The agent holds a Kubernetes credential.** It is narrower than what an agent holds today — a socket
  proxy that cannot refuse a bind of `/`, or a privileged daemon that is root on its node — but
  `pods/exec` is a strong verb, which is why the Role is rendered by the chart and pinned by a test.
- **Each run costs a pod.** Scheduling and image pulls add latency; the chart pulls `IfNotPresent` on the
  dedicated pool, and a pre-pull may follow.
- **The cost is 35 to 55 developer-days** (the study, §9): the seam, the pod spec and its lifecycle, the
  copy in and out, the limits, the image copy and its reference set, the database volume, the policies
  and their probe, the chart, and a nightly job on a `kind` cluster running the composition check against
  this backend.
- **Until it ships, the installation has no built-in scans.** It goes live on 0.11.1 without an agent;
  report plugins answer 409 as 0038 decided, and stay a separate decision.
- **No new dependency**: the API server is reached with the JDK. The cost is ours — the `exec` WebSocket
  protocol written and tested here rather than taken from a library.

## Spike, 2026-10-25

`scripts/k8s-executor-spike.sh` runs the mechanism with kubectl and makes the measurements above; it is
meant to be run on the target cluster too. On a throwaway k3s cluster, Kubernetes 1.31, all four checks
passed:

1. Pod Security `restricted`, enforced on the namespace, refuses a pod running as root.
2. A pod under the offline NetworkPolicy cannot reach the outside (k3s's policy controller enforces it).
3. A write past a memory-backed `emptyDir`'s `sizeLimit` (8 MiB) stops at the limit with `ENOSPC`; the pod
   is not evicted.
4. One scan step end to end: a workspace copied into a waiting init container over `exec` and `tar`, the
   pinned gitleaks image run on it offline under `restricted` as uid 1000, its report read back from the
   holder over `exec` through a capped read, and the token planted in the workspace found in it.

It corrected the study on one point, now in decision 4: the holder is an ordinary container, since a
native sidecar is stopped with the pod and the report with it — which also removes the native sidecars'
version floor. Not yet measured: the target cluster itself, and the parity of findings across the two
backends, which needs the Java backend.

## Built so far, 2026-10-25

`KubernetesExecutor` in `vectispire-agent`, tested on k3s 1.34 as the agent's service account under the Role
above (`kubernetesTest`, in CI's `kubernetes` job, on the runner since `jvm`'s container has no Docker). What building it settled:

- **Standard output goes to a file through a wrapper**, never through the log: the scanner runs as
  `busybox sh -c 'exec "$@" >stdout 2>stderr'`, with a **static** busybox (the musl image, pinned) that the
  receiving init container copies in, since syft's and grype's images have no shell and no libc. The
  wrapper has to name the program Docker would have prepended, so **each tool's entrypoint is declared**
  beside its image (`ScannerImages.*_ENTRYPOINT`, carried by `ContainerRun.entrypoint`), and
  `ScannerEntrypointsTest` holds every declaration to the pinned image's configuration. Docker ignores the
  declarations. A run that declares none — a plugin — keeps its image's entrypoint; its log is read as a
  diagnostic, and its standard output is not captured, which a parser reads as absent.
- **A writable mount brings back the regular files the scanner wrote, and nothing else**: entries go in
  dated 1970, so `find -type f -mtime -1` names what is new; a link, a name outside the mount, or a path
  through a link already in the workspace is refused and the step fails.
- **Chosen by configuration and rendered by the chart**: `VECTISPIRE_AGENT_EXECUTOR=kubernetes`, refused
  at start when incomplete, sweeping this agent's leftovers by its name; `agents.executor: kubernetes`
  renders the scans' namespace under `restricted`, the Role — whose rules the k3s tests read from the
  template — the deny-all and online policies, and the control plane's anti-affinity to scan pods.
- **The API server is named, not guessed** (`agents.kubernetes.apiServer.cidrs`): the agent's policy allows
  it, and every scan pod's excludes it whatever `excludeCidrs` covers — the chart's own check found an
  online scan pod that could reach it through a gap in an operator's list.
- **Not built yet**: image targets (§8 — `exportImage` fails the step, so the inventory is absent) and
  registry credentials for a tool (none held).
- **The matcher's cache (§7, as amended)**: on k3s a generation is seeded once and then served without a
  copy — a change made to the agent's copy afterwards does not reach the pod — mounted read-only, and a
  retired generation is pruned from the volume; the end-to-end check finds its claim bound by the matcher.
- **The probe (§5) runs at every start**: a pod offline and one online try the API server's address with
  `nc`; either reaching it, or a probe that cannot run, stops the agent. On k3s it refuses the namespace
  with no policy and the online policy whose exclusions miss the API server, and starts under the chart's.
- **Scan pods' resources are set, not derived** (`cpu-millis`, `memory-mib`): the default's CPU quota is
  this JVM's cores minus one, the agent pod's view of its node, and scan pods asking for nine CPUs on a
  developer's machine were never scheduled — measured.
- **Run end to end** by `scripts/kubernetes-scan-check.sh`, nightly: a k3s server and an agents' node, the
  chart installed with this executor, the agent's own image declared and keyed through the API, and the
  composition check's fixture scanned — every scanner a pod on the agents' node, each finding its plant. Its
  first runs found what no test of a piece could: the agent's secrets mounted read-only at `/run/secrets`,
  where the kubelet then had no place for the service account's token (the agent never started; they are at
  `/etc/vectispire/secrets` now); and that one node is not enough, since the control plane's anti-affinity
  keeps scan pods off its node — as it should.

## Security review, 2026-10-26

A read-only review of the branch at 1072613c0 found nothing critical or high, and two mediums arising from
operator values, both fixed before merge:

- **M1 — the namespace's level was the chart's alone to set.** With `createNamespace: false` nothing checked
  that the scans' namespace enforced `restricted`, and a compromised agent could have started a privileged
  pod there. The agent now proves it at every start — a dry run of a privileged, root, host-mounting pod, which
  its `create` verb allows, must be refused by Pod Security — with no switch to turn it off; the chart asks for
  an acknowledgement before using a namespace it did not create.
- **M2 — one scans namespace for every release.** The default name was shared and the online policy selected
  scan pods by their network label alone, so two releases would have shared policies and the Role's reach. The
  namespace is now `<release>-scans` by default, and the online policy selects this agent's pods only.

And the lows: the probe gets a positive control on the pod's loopback, so a missing or broken `nc` reads as an
unknown rather than as "blocked" (L1); the control plane's anti-affinity also covers the Kubernetes executor's
agent pod (L2); the work volume has a size — what was copied, what the scanner may write and a margin (L3);
the copy back refuses a written name with a line break, which would have let the holder archive a path the
scanner chose (L4); a stdout that cannot be read back fails the step instead of reading as empty (L5); and the
archive reader refuses sparse entries and caps what it writes. **Left for later, named**: an admission policy
holding scan pods to their pool against a compromised agent setting `nodeName` (L2, first half — it needs a
compromise and then a kernel escape), and probing every API server address rather than the Service's.
