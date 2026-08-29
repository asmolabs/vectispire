# 0017 — Organisation-specific checks arrive as container images, not as uploaded JARs

**Date:** 2026-08-29 · **Status:** proposed · **Decider:** Laurent Boucher

## Context

The question asked was whether Vectispire should accept an uploaded JAR so that a company can add
checks specific to its own organisation — an internal package that is forbidden, a configuration
convention nobody outside the company would recognise, a naming rule that only means something
against that company's registry.

**The need is real and is not currently served.** The Semgrep rule set upload covers rules that
Semgrep can express, and [`RuleSetService`](../../../../vectispire-java/vectispire-core/src/main/java/com/asmolabs/vectispire/core/services/RuleSetService.java)
already solves the hard half of the problem — storing an artefact centrally and serving it to every
executor, so that two agents cannot disagree about what was looked for. Nothing covers a check that
needs to *run code*: read a lockfile in a house format, call an internal convention, cross-reference
a manifest against an internal catalogue.

The vehicle is the question, not the need.

### Why not a JAR

**There is no sandbox left in the JVM.** The `SecurityManager` was removed for good, and this
project runs on JDK 25. A JAR loaded into the process gets what the process has: the connection
pool, the key that encrypts deployment keys and tracker tokens, the Docker socket, the network,
the filesystem. Every constraint that
[`ContainerRunner`](../../../../vectispire-java/vectispire-common/src/main/java/com/asmolabs/vectispire/common/scanning/ContainerRunner.java)
builds deliberately — network cut, read-only mount, ephemeral container, `cap_drop: ALL` — would be
bypassed by any plugin. A product whose purpose is to audit a supply chain would be offering
arbitrary third-party code execution inside its own control plane.

**It breaks the two-sided architecture.**
[`ScanRunner`](../../../../vectispire-java/vectispire-common/src/main/java/com/asmolabs/vectispire/common/scanning/ScanRunner.java)
runs identically inside the control plane and on a remote agent, and is forbidden from reaching
persistence — `ArchitectureTest` enforces it. A JAR would therefore have to be provisioned on every
agent's filesystem, which is precisely the asymmetry `RuleSetService` was written to remove: two
agents, one provisioned and one not, taking turns on the same target make the backlog resolve and
reappear each turn, silently, because the step *ran* both times. A JAR reproduces that in a worse
form — not present against absent, but version A against version B.

**It freezes the internal API.** A plugin compiled against `IacFinding`, `Workspace` and
`ContainerRun` makes those types a public contract, and every refactor becomes somebody else's
broken JAR. The client's Jackson meets Spring Boot 4.1's on the same classpath.

**It gets [decision 0007](0007-none-is-not-an-empty-list.md) wrong in silence.** An empty list means
"analysed, clean" and authorises ingestion to resolve the target's issues of that type. A
third-party plugin returning `List.of()` from a swallowed exception declares the target fixed. That
distinction is subtle, load-bearing, and exactly the kind of thing a check author writing their
first plugin does not know.

### Why this does not reopen 0010

[0010](0010-one-scan-runner.md) says a registry of scanner engines, each with its own argument
template and rule file, would be a different decision that should supersede it. **This is not that.**
No `ScannerEngine` interface returns, and no per-engine argument template is introduced: what is
added is one more concrete scanner beside `IacScanner` and `SastScanner`, with a fixed command
shape and a fixed output format, parameterised by an image digest — which is what `ScannerImages`
already does for every scanner here. 0010 stands unamended.

## Decision

A custom check is **an OCI image plus a declaration**, executed through the existing
`ContainerRunner`, emitting **SARIF 2.1.0 on stdout**.

### The execution contract

Run through `ContainerRun.of(...)`, which is the closed shape: network cut, read-only root
filesystem, 512 MB tmpfs scratch, `cap_drop: ALL`, `no-new-privileges`, the scanned tree mounted
read-only at the usual source path. The Docker socket is not reachable — `ContainerRunner` carries
no option to mount it, and that missing capability is the isolation.

**SARIF, because it is already in the building.** `SarifExport` produces it and `SastScanner`
already parses a report of that family, so no new format is invented and no new parser is owned.
The SARIF parsing is factored out of `SastScanner` into something both call. A check author can
test their image with `docker run` alone, without a Vectispire instance.

**Exit code 0 means "analysed", findings or not. Any other code is a failure**, surfaces as
`ScannerFailureException`, and leaves the artefact absent — which ingestion reads as "not looked
at" and which leaves the backlog untouched, per [0007](0007-none-is-not-an-empty-list.md). This is
the only way a check author can be dangerously wrong: an image that exits 0 with an empty SARIF
after crashing declares the target clean and resolves its whole custom backlog. **The plugin
documentation opens on this paragraph.**

### Digest, never tag

The control plane resolves the tag to `sha256:…` at registration, and `ScanTask` carries the
digest. `ScanTask` already transports `rulesHash` for exactly this reason: an executor that reads
"the active set" for itself scans with whatever it found at the moment it asked, and two executors
diverge. A `latest` tag reproduces that failure identically.

### The finding type is not the plugin's to choose

A new `FindingType.CUSTOM` with `GateParticipation.ON_REQUEST` — the argument is `AI_REVIEW`'s,
unchanged: third-party code that invented a "critical" would fail somebody else's build. An
administrator may promote it to `ALWAYS` by policy. **This is the most consequential choice here
after the sandbox**, because the default decides what a mistaken or hostile check can do to a
pipeline nobody warned.

### Fingerprints are prefixed by the check id

The SARIF `ruleId` enters the issue fingerprint — that is why `SastScanner` passes
`--no-rewrite-rule-ids`. Two checks both emitting `CKV_AWS_20` would otherwise collide into one
issue. The fingerprint is therefore `check id + ruleId + file + …`, and the documentation states
plainly that renaming a rule loses the triage attached to it.

### Registration is an administrator's act

The pull is the only network operation and it happens on the host, outside the container. It
executes nothing, but letting any user cause an arbitrary image to be pulled onto the Docker daemon
remains an operator's decision, not a reader's. Registration is admin-only and constrained by an
allowlist of registries; optional cosign verification before the pull reuses the DSSE infrastructure
already present.

**Store and activate stay separate**, as in `RuleSetService`: activation changes what the next scan
looks for, and the operator sees the triage impact before deciding.

## Consequences

**An agent on a closed network fails at the pull**, which raises `ScannerFailureException`, which
leaves the artefact absent and the backlog intact. Correct by default, and documented: pre-pull the
image on each agent, or use a registry the agents can reach.

**What is given up.** In-process extension, and with it the ability for a check to consult the
database, the issue history, or another target. A check sees a tree and emits findings about that
tree. Anything needing the corpus is a rule over ingested data — a different feature, on the gate
policy screen, with no untrusted code in it at all.

**If a JAR is demanded anyway** — some buyer will ask for it by name — the answer is a separate
process, never the application's JVM: a `vectispire-plugin-sdk` module with a stable interface, the
plugin launched as `java -jar` through this same `ContainerRunner` with the network cut, speaking
JSON over stdin/stdout, cosign-verified at upload, SDK version pinned, per-check timeout. Which is
this decision with a Java-shaped wrapper — which is the demonstration that the JAR was a packaging
detail and never an architecture.

## What it touches

| Module | Work |
|---|---|
| `vectispire-common` | `CustomScanner` beside `IacScanner`; SARIF parsing factored out of `SastScanner`; `ScanTask.Step.CUSTOM` and the declared checks carried on the task; `ScanArtifacts.custom(...)` as an `Optional` |
| `vectispire-core` | entity and `CustomCheckService` modelled on `RuleSetService`; admin controller; tag-to-digest resolution; ingestion and `FindingType.CUSTOM` |
| `vectispire-angular` | Administration → Custom checks |
| tests | `ScannerContractTest` extended rather than duplicated — it is where the `Optional` contract is locked |
| docs | this record, and the plugin author's guide whose first paragraph is the exit-code contract |

## Phasing

1. **The contract.** `CustomScanner`, shared SARIF parsing, one globally-declared check, gated
   `ON_REQUEST`. Nothing in the UI yet.
2. **Deployment reality.** Per-target checks, registry allowlist, digest pinning, agent pre-pull
   documentation.
3. **Operation.** The administration screen, cosign verification, triage impact before activation.
