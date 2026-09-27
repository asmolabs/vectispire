# 0017 — Organisation-specific checks arrive as container images emitting SARIF, and SARIF only from declared internal sources

**Date:** 2026-09-27 · **Status:** accepted · **Decider:** Laurent Boucher

*Proposed on 2026-08-29 as "custom checks as container images, not uploaded JARs"; amended and accepted
on 2026-09-27, when the plugins were built. What changed from the proposal is listed at the end.*

## Context

The question asked was whether Vectispire should accept an uploaded JAR so that a company can add
checks specific to its own organisation — an internal package that is forbidden, a configuration
convention nobody outside the company would recognise, a naming rule that only means something
against that company's registry. A second question arrived with it on 2026-09-25: a team that
already runs an analyser — an on-premise SonarQube, a CI job running Semgrep or CodeQL — wants its
results in the same backlog, triaged once.

**The need is real.** The Semgrep rule set upload covers what Semgrep can express, and
[`RuleSetService`](../../../../vectispire-java/vectispire-core/src/main/java/com/asmolabs/vectispire/core/rules/RuleSetService.java)
already solves the hard half — storing an artefact centrally and serving it to every executor by
hash, so that two agents cannot disagree about what was looked for. Nothing covered a check that
needs to *run code*, nor a report somebody else's tool already produced.

The vehicle is the question, not the need.

### Why not a JAR

**There is no sandbox left in the JVM.** The `SecurityManager` was removed for good, and this
project runs on JDK 25. A JAR loaded into the process gets what the process has: the connection
pool, the key that encrypts deployment keys and tracker tokens, the Docker endpoint, the network,
the filesystem. Every constraint
[`ContainerRunner`](../../../../vectispire-java/vectispire-common/src/main/java/com/asmolabs/vectispire/common/scanning/ContainerRunner.java)
builds deliberately would be bypassed by any plugin. A product whose purpose is to audit a supply
chain would be offering arbitrary third-party code execution inside its own control plane.

**It breaks the two-sided architecture.**
[`ScanRunner`](../../../../vectispire-java/vectispire-common/src/main/java/com/asmolabs/vectispire/common/scanning/ScanRunner.java)
runs identically in the built-in worker and on a remote agent, and cannot reach persistence. A JAR
would have to be provisioned on every agent's filesystem — two agents taking turns on one target,
one with version A and one with version B, resolve and reopen the backlog each turn.

**It freezes the internal API** — `Workspace`, `ContainerRun` and the finding records become
somebody else's compile-time contract — and **it gets [0007](0007-none-is-not-an-empty-list.md)
wrong in silence**: a plugin returning `List.of()` from a swallowed exception declares the target
fixed.

### Why this does not reopen 0010

[0010](0010-one-scan-runner.md) says a registry of scanner engines, each with its own argument
template and rule file, would supersede it. **This is not that.** No `ScannerEngine` interface
returns: what is added is one more concrete scanner, `PluginScanner`, with a fixed output format
(SARIF 2.1.0) and a fixed confinement, parameterised by a manifest the governor wrote. The
arguments in a manifest are the plugin's own command line, not a Vectispire template per engine.
0010 stands unamended.

## Decision

### 1. A plugin is a container, run exactly like the scanners Vectispire ships

A plugin is **an OCI image pinned by digest plus a manifest**, executed by the existing
`ContainerRunner`, through the same Docker endpoint (`DOCKER_HOST`, the internal proxy — never a
mounted socket, never a daemon of the plugin's own), and it writes **SARIF 2.1.0 into a file**.

- **The closed shape, with no exception**: `ContainerRun.of(...)` — `cap_drop: ALL`,
  `no-new-privileges`, read-only root filesystem, `noexec` tmpfs scratch, the scanner limits'
  memory, process and CPU ceilings, a label, the container removed in a `finally`.
- **Not root**: it runs as the workspace owner's `uid:gid`, the lesson of the Grype database mount —
  what root writes into a mount is root's on the host. A host that reports no owner does not run a
  plugin at all rather than run it as root.
- **Only the analysed tree is mounted**, read-only, at `/repo/source` (the repository's sub-path if
  it has one, after `SourceFiles.within` proved it lies inside the clone). **Not the workspace**:
  its root holds the secrets report in the clear and the SBOM.
- **One writable directory**, empty, created for the run, at `/repo/output`; the report is read
  from `/repo/output/<output>`, not from stdout, so the plugin may log freely. It is read as a
  regular file, not through a link, and only up to the scanner output ceiling
  (`ScannerLimits.outputBytes`, the one added on 2026-09-26), enforced while reading.
- **Network `none`.** A plugin that needs the network says so in its manifest with a written
  justification (20 to 500 characters), which the governor registers and the audit log carries —
  the Grype precedent made explicit. There is no other way to open it.
- **Arguments are a list**, handed to the image's entrypoint with no shell on Vectispire's side;
  `{source}` and `{output}` are replaced by the two container paths.
- **Bounded time**: the manifest may ask for less than the scanner limits' fifteen minutes, never
  more.
- **Runs wherever scanners run**: the built-in worker or a remote agent, through the same
  `ScanRunner`, so a plugin never sees the database or `ENCRYPTION_KEY`.
- **Rule and vulnerability databases** are embedded in the pinned image, or reached through the
  declared network exception to an internal mirror (the Grype model). Never a free download at
  start: the network is cut unless declared.

The container suite runs a pinned busybox that reports its own confinement from the inside — not
uid 0, no ethernet and no route, a read-only image and tree, `noexec` scratch, no socket, and
`/repo` holding only `source` and `output` (`PluginScannerIntegrationTest`).

### 2. The manifest

```json
{
  "id": "acme-lint",
  "name": "ACME house rules",
  "image": "registry.acme.internal/sec/acme-lint@sha256:<64 hex>",
  "languages": ["java", "kotlin"],
  "arguments": ["--sarif", "{output}", "{source}"],
  "output": "results.sarif",
  "exit_codes": [0, 1],
  "network": false,
  "network_justification": null,
  "timeout_seconds": 600
}
```

| Field | Rule |
|---|---|
| `id` | 2–40 lowercase letters, digits, inner hyphens. **Enters every issue's fingerprint; never renamed, never reused** — there is no delete. |
| `name` | 1–100 characters, display only. |
| `image` | `repository@sha256:<64 lowercase hex>`, **no tag, not even beside the digest**. |
| `languages` | At least one, from the Semgrep catalogue's directories (`Language`). |
| `arguments` | At most 32 entries of at most 4,096 characters; newline and tab allowed (a `sh -c` script inside the image), any other control character refused. |
| `output` | A bare file name in `/repo/output`, default `results.sarif`. |
| `exit_codes` | The codes meaning "analysed", findings or not; default `[0]`. Anything else fails the step. |
| `network` / `network_justification` | Off by default; on only with a justification, and a justification without it is refused. |
| `timeout_seconds` | 10–900, or absent for the scanner limits' timeout. |

The manifest's **digest** (`PluginManifest.digest`) covers every field. Memory, processes and CPU
are the scanner limits' and are not negotiable per plugin.

**An internal registry**: `vectispire.scanning.plugin-registry` (`VECTISPIRE_PLUGIN_REGISTRY`, and
the agent's `vectispire.agent.images.plugin-registry`) relocates every plugin image — the registry
host replaced, the repository path and the digest kept — so a mirror can serve the image but cannot
substitute another one. That is stricter than the scanner images' override, which accepts any
reference, because a plugin is third-party code that reads every file it is given.

### 3. The control plane is the authority; executors fetch by id and digest

The dispatcher decides a scan's plugins when it builds the task — the enabled plugins activated for
the repository's project — and the task carries each as `{id, digest}`, exactly as it carries the
rule set's hash. The executor fetches the manifest by both halves (the built-in worker from its own
tables, an agent from `GET /api/v1/agent/plugins/{id}/{digest}`), **recomputes the digest and
refuses a manifest that does not match**. Every manifest a plugin ever had is kept, by digest, and
never rewritten, so a task queued before an update still gets the manifest it was built with. A row
edited in the database no longer hashes to its key and is served to nobody.

An agent older than plugins ignores the field and reports no plugin step; that is read as absent and
resolves nothing, so the agent contract version does not move.

### 4. Languages, and the third state

A plugin runs only if one of its declared languages is present in the analysed tree.
`LanguageCensus` decides: **file names only, never content** — a lowercase copy, one
`lastIndexOf`, two map lookups per file, manifests (`pom.xml`, `package.json`, `pyproject.toml`,
`go.mod`, `Cargo.toml`…) counted as signs — links neither followed nor counted, `.git` and
`node_modules` skipped. It is linear in the names, with no pattern that could backtrack (the
2026-09-26 audit), and bounded: 200,000 entries or sixty seconds, and early once every language any
plugin asked about has been seen. **A census that hit a bound cannot prove a language absent, so
every plugin then runs.**

Each plugin of a scan ends in exactly one of three states, carried by `ScanArtifacts.plugins` as a
sealed `PluginStep` with a discriminator on the wire:

| State | Meaning | What ingestion does |
|---|---|---|
| `produced` | It ran, exited on a declared code, and its report was read: every run succeeded and carried a `results` array. | Its findings become `plugin` issues; **its own** open issues on the target that it did not report are resolved — an empty report resolves them all, and nothing else. |
| `not_applicable` | None of its languages is in the tree; it was not started. | Its issues are left as they are. **Not a failure**: the scan says "not applicable", not "failed". |
| `absent` | It should have run and produced no usable report — definition not obtained or not matching its digest, undeclared exit code, no report, report refused (size, link, location outside the tree, malformed), a run that says `executionSuccessful: false`, a run without `results`, or no run at all. | Its issues are left as they are, **and the reason is a failure of the scan**, under `plugin <id>`. |

Absent and not-applicable leave the backlog alone for the same reason — nothing was examined — and
are told apart because only one of them is somebody's problem. Reporting a Java plugin on a Python
repository as absent would put a failure on every scan until nobody read the failures; reporting it
empty would resolve its issues the day the Java left and reopen them, triage cleared, when it came
back. A plugin missing from the list is absent; a `produced` step whose findings did not arrive is
read as absent, never as "ran, found nothing".

SARIF already says it: a run whose `results` property is absent did not compute results; an empty
array means none were found. `SarifReport` keeps that as an `Optional`.

### 5. The fingerprint contract

A plugin or imported finding is fingerprinted by the one formula, with the **tool key in the
package's slot**:

```
SHA-256(target NUL type NUL rule id NUL tool key NUL normalised path)
```

- **type**: `plugin` for a plugin Vectispire ran, `imported` for a declared source's report — two
  types, so the provenance is the first thing every screen, filter and export shows.
- **tool key**: `plugin:<id>`, or `import:<source slug>/<tool name, stripped and lowercased>`.
  **Not the image, not its digest, not the tool's version**: a plugin moved to a new image keeps its
  id and its whole triage. Renaming the plugin, the source or the tool resolves and recreates the
  backlog; the documentation says so.
- **rule id**: the SARIF `ruleId` (or the rule the result points at), whole. A result naming no rule
  refuses the report — without one it has no identity across runs.
- **path**: the location normalised by `SarifPaths` — `%XX` decoded as UTF-8, backslashes as
  separators, `file:` stripped, the container's `/repo/source` removed, empty and `.` segments
  dropped, joined with `/`. A `..`, another scheme, an absolute path outside the known root, or a
  control character refuses the report. The line is not in it.

The tool key is also the **resolution scope**: a clean report resolves that tool's issues and never
the type's, so one plugin coming back empty says nothing about another plugin, an import, or a
scanner. It is pinned by value in `ToolFingerprintTest`.

### 6. Registration is the platform governor's; activation is per project

- **Registering, updating, enabling and disabling a plugin require `@RequiresPlatformGovernor`**
  (`Role.governsPlatform`, SUPERUSER alone). Deciding that third-party code which will read the
  estate's source may exist on the platform is a rule everybody else plays by. Each change is
  audited (`PLUGIN_REGISTERED`, `PLUGIN_UPDATED`, `PLUGIN_ENABLED_CHANGED`) with the manifest's
  digest, image, languages and network exception, and signalled to the SIEM as `ZAN-SEC-021`.
- **Switching a plugin on for a project requires `@RequiresSecurityLead`** — the roles that
  `canWriteGovernance` and see the whole estate: the decision activating a rule set is, scoped to
  one project. `PLUGIN_ACTIVATED` / `PLUGIN_DEACTIVATED`, `ZAN-SEC-021` too.
- **Nothing is global.** A repository filed in no project (decision 0023) runs no plugin; a disabled
  plugin keeps its activations and runs none; deleting a project takes its activations
  (`ProjectDeleted`, published by `targets` in the deleting transaction).
- **No delete**: an id names every issue the plugin opened, and other code registered under it would
  inherit their triage.
- Reading the registry is any signed-in account's — an image, arguments and languages name no
  target; which projects a plugin reads is answered to the governance roles.

**The gate**: plugin and imported findings are `GateParticipation.ON_REQUEST`, like AI review — a
third-party tool's "critical" must not fail a build nobody warned — on their own policy flag,
`include_plugins`, which a stored policy or a caller may turn on. The AI review flag admits AI
findings alone. They stay out of the security figures, the effort estimate and the remediation
total, for the same reason.

### 7. SARIF from internal sources only

The policy decided on 2026-09-25: **external means outside the organisation.** Results from a service
outside it, to which the code would have been handed — hosted SonarCloud, hosted CodeQL, a SaaS
scanner — are not imported. SARIF produced by an internal tool that already has the code — an
on-premise SonarQube, the team's own CI — is.

**A source is declared**, by the platform governor (it is the platform saying "this producer is inside
the organisation"): a slug, one integration API key holding the `sarif_import` scope (never granted
by default), **exactly one scope — a project or a repository, never the estate** — and the tool names
it may deliver. One key is one source, so the key names the source. `SARIF_SOURCE_CHANGED`,
`ZAN-SEC-022`.

**An import** (`POST /api/v1/repositories/{id}/sarif-imports`, `@AcceptsApiKey(SARIF_IMPORT)`,
`@RequiresWriteAccount`) is accepted only when:

1. it comes with an integration key — a session is not a source (403);
2. the key is declared for an enabled source — otherwise 403, audited `SARIF_IMPORT_REFUSED` and
   signalled `ZAN-SEC-023`;
3. the repository is visible to the key (its account's visibility intersected with the key's own
   restriction, decision 0024) **and** inside the source's scope — otherwise 404, in the words of a
   repository that does not exist (the out-of-scope case is audited and signalled too);
4. the body is within `vectispire.http.max-body.sarif-import` (32 MB, `RequestBodyLimitFilter`, 413),
   and reads under `SarifReport`'s guards — nesting 64, strings 1 MB, 20 runs, 100,000 results,
   duplicate keys and trailing content refused, `externalPropertyFileReferences` and
   `inlineExternalProperties` refused, **every location relative** (the producer's checkout is
   unknown here, so an absolute path is outside the tree) (400);
5. every run succeeded, carries `results`, and was produced by a tool the source declares — a failed
   or result-less run is refused (400) rather than read as clean; an undeclared tool is 403, audited
   and signalled.

Then the same rules as a plugin: each run's tool is its own scope and fingerprint key; the report
resolves what that tool no longer reports on that repository, and nothing else. Imported issues carry
their provenance — type `imported`, `tool` (the key), `toolName` and `toolVersion` from
`tool.driver`, and `importSource`, the declared source's slug, kept after the source is deleted. The
import itself is a row (`t_sarif_import`: source, key, repository, tools, the document's SHA-256, the
counts) and a `SARIF_IMPORTED` audit entry: an imported issue's dated evidence, where a scanned one
has its scan.

**The limits, honestly.** Nothing in a SARIF file proves where it was made; a declared source's key
can upload whatever its holder has. What makes the policy enforceable *enough*:

- the declaration is a named, audited act of the one role that sets platform rules, and binds one key
  to one producer and one scope — an import is attributable to a key and a person;
- the tool allow-list per source catches a pipeline that starts depositing another tool's output —
  including a hosted service's, which names itself (`SonarCloud` is not `SonarQube`);
- every accepted document's hash is recorded, so a report can be matched to the pipeline run that
  produced it;
- a refused import is a SIEM event, so a key used for what it was not declared for is visible.

**A denylist of SaaS driver names was considered and rejected.** It would be theatre in one direction
— a renamed driver passes — and wrong in the other: CodeQL CLI run in the organisation's own CI and
GitHub-hosted CodeQL both say `CodeQL`. The allow-list per source is the same check turned the right
way: it names what this producer is expected to send. What remains is the organisation's own
discipline in who holds a declared key, which the audit trail makes reviewable rather than invisible.

### 8. Compiling analysers — design, not built

CodeQL for Java, SpotBugs and their kind need to build the code, which the closed shape forbids: the
tree is read-only and the network is cut. The design, recorded for the follow-up:

- **a dedicated writable, disposable work volume**, a copy of the tree (never the tree itself, never
  the workspace), mounted at `/repo/work` and deleted with the workspace — the source stays read-only;
- **network limited to one declared internal dependency mirror per plugin** (Nexus, Artifactory):
  the manifest names the mirror's host, the justification says why, and the container joins a
  network whose only route is that mirror (an egress proxy with an allow-list, or a Docker network
  with no default route) — never the open network;
- the same ceilings, with a longer timeout only as an explicit, audited manifest field.

Not built now: it needs a Docker network per mirror and an egress proxy that do not exist yet, and a
half-built version would open the network wider than the manifest says. **The one hook that exists**
is the declared network exception, which such a plugin can use today — with the whole network, which
is exactly why the justification is required and audited.

## Consequences

- One migration, `V41`, written once in `common`: `t_plugin`, `t_plugin_manifest`,
  `t_plugin_activation`, `t_sarif_source`, `t_sarif_import`, provenance columns on `t_issue` and
  `t_finding`, each plugin's outcome on `t_scan` (`plugin_steps` — the only place a not-applicable
  plugin is recorded, since it is nobody's failure), `include_plugins` on `t_gate_policy`. No foreign key: the `plugins` module's listeners
  purge its rows on `TargetDeleted` and `ProjectDeleted`.
- A new module, `core.plugins`, using `access`, `access::security`, `issues`, `scanning` and `targets`;
  `scanning` declares the port `ScanPlugins` it implements. The agent route lives in `agents`, through
  that port.
- **An agent on a closed network fails at the pull**, which leaves the plugin absent and its backlog
  intact. Pre-pull, or point `VECTISPIRE_PLUGIN_REGISTRY` at a registry the agents reach.
- **What is given up**: in-process extension; a plugin sees a tree and emits findings about it, and a
  check needing the corpus is a rule over ingested data, not a plugin.
- **Not bounded**: the disk the plugin writes into `/repo/output` — a bind mount cannot carry a size
  limit. The report is read up to the ceiling, the container up to its timeout; a size-limited volume
  is a follow-up. So is cosign verification of the image before the pull.

## What changed from the 2026-08-29 proposal

| Proposed | Decided |
|---|---|
| SARIF on stdout | SARIF in a file under `/repo/output`: the plugin may log, and the report is read with the file guards. |
| Registration by an administrator, a registry allow-list | Registration by the platform governor; images relocated to one internal registry, digest kept. |
| One finding type `CUSTOM` | `PLUGIN` and `IMPORTED`, so provenance is visible at the type; both on request, on `include_plugins`. |
| Fingerprint `check id + ruleId + file` | The one formula with the tool key in the package slot, the key being `plugin:<id>` or `import:<source>/<tool>`. |
| Global checks first, per-target later | Activation per project from the start; nothing global. |
| No language model | Declared languages, a bounded census, and a third state: not applicable. |
| — | SARIF import from declared internal sources. |
| Cosign verification in phase 3 | Still a follow-up. |
