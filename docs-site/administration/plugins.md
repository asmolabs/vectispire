# Plugins and SARIF imports

A plugin is **your own analyser, packaged as a container image**, that Vectispire runs during a scan
beside Syft, Grype, Gitleaks, Checkov and Semgrep — and that reports what it found as SARIF. A SARIF
import is the other half: a report an internal tool of yours already produced — an on-premise
SonarQube, your own CI — deposited into a repository's backlog.

Both land in the same backlog, triaged once. Decision
[0017](https://github.com/asmolabs/vectispire/blob/main/docs/architecture/en/decisions/0017-custom-checks-as-container-images.md)
records why they work the way they do.

!!! danger "Read this first: exit code 0 means *analysed*"
    A plugin that exits on one of its declared exit codes and writes a SARIF log with an empty
    `results` array has told Vectispire **"I looked at this repository and found nothing"**. Every
    issue that plugin opened on the repository is then **resolved** — triage, justifications and
    all. If your analyser fails, **exit with another code, or do not write the report, or write the
    run without `results`, or set `"executionSuccessful": false`**: each of those leaves the plugin's
    issues exactly as they were and records the failure on the scan. Never swallow an error and
    write an empty report.

## Writing a plugin

### The manifest

```json
{
  "id": "acme-lint",
  "name": "ACME house rules",
  "image": "registry.acme.internal/sec/acme-lint@sha256:4f2d…(64 hex)",
  "languages": ["java", "kotlin"],
  "arguments": ["--sarif", "{output}", "{source}"],
  "output": "results.sarif",
  "exit_codes": [0, 1],
  "network": false,
  "network_justification": null,
  "timeout_seconds": 600
}
```

| Field | What it means |
|---|---|
| `id` | 2 to 40 lowercase letters, digits and inner hyphens. **It is part of every issue the plugin opens**: it can never be renamed or reused. |
| `name` | What the screens show. |
| `image` | Pinned **by digest**: `repository@sha256:<64 hex>`. A tag — even beside the digest — is refused. |
| `languages` | The languages the plugin reads, from the Semgrep catalogue's list: `apex`, `bash`, `c`, `clojure`, `csharp`, `dockerfile`, `elixir`, `go`, `html`, `java`, `javascript`, `json`, `kotlin`, `ocaml`, `php`, `python`, `ruby`, `rust`, `scala`, `solidity`, `swift`, `terraform`, `typescript`, `yaml`. |
| `arguments` | The command handed to the image's entrypoint, as a list — no shell is involved. `{source}` becomes `/repo/source`, `{output}` becomes `/repo/output/<output>`. |
| `output` | The file name the plugin writes its SARIF to, in `/repo/output`. Default `results.sarif`. |
| `exit_codes` | The exit codes that mean "analysed", findings or not. Default `[0]`. Any other code fails the plugin's step. |
| `network` | `false` unless the plugin genuinely needs to reach something — an internal rule mirror. `true` requires `network_justification`, 20 to 500 characters, recorded in the audit log. |
| `timeout_seconds` | 10 to 900. It can shorten the scanners' fifteen minutes, never extend them. |

### What the plugin runs under

Exactly what every scanner Vectispire ships runs under — there is no option to loosen it:

- **the analysed tree only, read-only**, at `/repo/source` (the repository's sub-path, when it has
  one). Not the rest of the workspace;
- **one empty writable directory**, `/repo/output`, where the report goes. Write logs to stdout or
  stderr as you like — the report is read from the file;
- **no network** unless the manifest declares it; **no Docker socket**, no capability,
  `no-new-privileges`, a **read-only root filesystem**, `/tmp` and `$HOME` as small `noexec` scratch
  space;
- **not root**: the user that owns the workspace on the scanning machine. Your image must work as an
  arbitrary non-root uid;
- the scanner limits for memory (2 GB), processes and CPU, and your timeout;
- the report is read as a regular file (a link is refused), up to 256 MiB.

Rule or vulnerability databases belong **inside the image**, pinned with it. If the plugin must fetch
them, declare the network exception and point it at an internal mirror: nothing is downloaded freely
at start.

Try it with the same confinement before you register it:

```bash
docker run --rm --network none --cap-drop ALL --security-opt no-new-privileges \
  --read-only --tmpfs /tmp:rw,noexec,nosuid --user "$(id -u):$(id -g)" \
  -v "$PWD:/repo/source:ro" -v "$PWD/out:/repo/output" \
  registry.acme.internal/sec/acme-lint@sha256:… --sarif /repo/output/results.sarif /repo/source
```

### What the report must say

- **SARIF 2.1.0**, one or more runs, each naming its tool (`tool.driver.name`).
- **Every run carries a `results` array** — possibly empty. A run *without* `results`, or whose
  invocation says `"executionSuccessful": false`, is read as a failure.
- **Every result names its rule** (`ruleId`, or a rule it points at). The rule id is part of the
  issue's identity: renaming a rule loses the triage attached to it.
- **Locations are paths inside the tree**: relative to `/repo/source`, or absolute under it
  (`/repo/source/src/App.java`, `file:///repo/source/src/App.java`). A location outside it, a `..`,
  or a URL refuses the whole report.
- Severity comes from `properties.security-severity` (the CVSS-like score, on the result or its rule)
  when present, otherwise from the level: `error` is high, `warning` (the default) medium, `note` and
  `none` low.
- A result of kind `pass` or `notApplicable`, or with an accepted suppression, is not a finding.
- No `externalPropertyFileReferences`, no `inlineExternalProperties`.

## Registering a plugin

Only the **platform governor** registers, updates, enables or disables a plugin: it is third-party
code that will read the source of every project it is switched on for. Every change is in the audit
log with the manifest's digest, and forwarded to the SIEM (`ZAN-SEC-021`).

**On screen**, **Plugins** — in the sidebar under Configuration, for every account — lists each plugin
with its state, languages, network exception and the start of its manifest digest; the eye opens its
detail: the image, the digest in full, the arguments in order, the report file, the exit codes, the
network and its justification, the timeout, and who registered and last changed it. Governance readers
also see the projects it is switched on for. The governor alone gets **Register a plugin**, the pencil
that edits the manifest, and **Enable** / **Disable**. The form says where the id is typed that it can
never be renamed or reused, and locks it when editing; a refusal — an id already taken, a tag beside
the digest, a justification too short — stays in the form with the server's reason.

Through the API:

- `POST /api/v1/plugins` with the manifest registers it.
- `PUT /api/v1/plugins/{id}` with a new manifest updates it. **A new image version keeps the id, and
  keeps every issue and its triage.** The id itself never changes.
- `PUT /api/v1/plugins/{id}/enabled` with `{"enabled": false}` stops it everywhere from the next
  scan, without forgetting where it was switched on.
- There is no delete: the id names every issue the plugin ever opened.

Every signed-in account can read the registry (`GET /api/v1/plugins`).

**An internal registry.** Set `VECTISPIRE_PLUGIN_REGISTRY` (and the same on each agent) to pull every
plugin image from your mirror: the registry host is replaced, the path and the digest are kept, so the
mirror can serve the image but not substitute another.

## Switching it on for a project

A plugin runs on nothing until it is switched on for a
[project](solutions-and-projects.md): `PUT /api/v1/projects/{projectId}/plugins/{pluginId}` —
administrators, the CISO and the governor. A repository filed in no project runs no plugin.
`DELETE` switches it off; its open issues stay as they are.

**On screen**, in [Solutions & projects](solutions-and-projects.md) each project offers **Plugins** to
the governance roles: every registered plugin with its languages and a switch, on for those running on
the project, with who switched it on and when. The switches work for administrators, the CISO and the
governor; an auditor reads them. A plugin disabled on the platform says so on its row — its activation
is kept and runs nothing until it is enabled again.

## What a scan says about each plugin

Each plugin of a scan ends in one of three states:

| State | When | Its issues on the repository |
|---|---|---|
| **produced** | It ran and its report was read. | Opened for what it reports; **resolved for what it no longer reports** — its own issues only. |
| **not applicable** | None of its languages is in the repository; it was not started. | Left as they are. Not a failure. |
| **absent** | It should have run and gave no usable report (pull failed, undeclared exit code, no report, refused report, failed run). | Left as they are, and the scan lists the failure under `plugin <id>`. |

The scan's detail lists each plugin with its state (`plugins`: `produced` with its number of findings,
`not_applicable` with the languages it looked for, `absent` with the reason). On the scan's page, the
**Plugins** card shows the three apart on purpose: **produced** in green with the number of findings in
its report, **not applicable** in grey with the languages it looked for, **absent — failed** in red with
the reason. Each names its plugin, linked to the registry, and its manifest digest. A plugin's findings
say which tool and version reported them.

Languages are detected from file names and manifests (`pom.xml`, `package.json`, `pyproject.toml`,
`go.mod`…), within a bound; a repository too large to count runs every plugin rather than skipping
one wrongly.

## How an issue keeps its identity

A plugin issue is identified by **its rule, its normalised path and the tool** — `plugin:<id>` — on its
repository. The image, its digest and the tool's version are **not** part of it, which is what lets a
plugin be upgraded without losing triage. Renaming the plugin, the rule, or moving the file makes a new
issue. The line number is never part of it.

Plugin and imported findings **do not fail a CI gate unless the gate policy includes them**
(`include_plugins`, see [gate policies](gate-policies.md)): a third-party tool's "critical" must not
break a build nobody warned. They are not counted in the security figures either.

## Importing SARIF from an internal tool

**Only from inside the organisation.** An on-premise SonarQube, your own CI job — a tool that already
had the code. **Never a hosted service outside the organisation** to which the code would have been
handed. Vectispire cannot tell from a file where it was produced, so the rule is enforced by
*declaring* each internal source, and by what the declaration binds.

### 1. Issue the key

On [API keys](api-keys.md), issue a key with the **`sarif_import`** scope (it is never granted by
default) from an account that may cause effects — not an auditor. Restrict it to a repository when the
source feeds one.

### 2. Declare the source

The **platform governor** declares it — that is the platform stating "this producer is inside the
organisation":

```bash
curl -X POST https://vectispire.example/api/v1/sarif-sources \
  -H "Authorization: Bearer $GOVERNOR_SESSION" -H "Content-Type: application/json" \
  -d '{"slug": "payments-ci", "name": "Payments CI", "api_key_id": "<key id>",
       "project_id": 12, "tools": ["Semgrep OSS", "SonarQube"]}'
```

- **one key, one source**: the key names the source when it uploads;
- **exactly one scope** — a project (`project_id`) or a repository (`repository_id`), never the whole
  estate;
- **the tools it may deliver**, compared with each run's `tool.driver.name` without regard to case. A
  report from any other tool is refused — including a hosted service's, which names itself.

The slug is part of every imported issue's identity: name the producer, not the key. Declaring the same
slug again with a new key — to rotate it — continues the same backlog.

**On screen**, **SARIF sources**, in the Administration section for the governance roles, lists the
declarations — slug and name, the scope by project or repository name, the tools, the key, who declared
it. The governor has **Declare a source**: the key is chosen among the unexpired keys holding
`sarif_import`, the scope is a project *or* a repository, the tools are separated by commas. Disabling
stops a source's imports; removing it keeps the issues it imported, under its slug.

### 3. Upload

```bash
curl -X POST https://vectispire.example/api/v1/repositories/42/sarif-imports \
  -H "Authorization: Bearer $VECTISPIRE_SARIF_KEY" \
  -H "Content-Type: application/sarif+json" \
  --data-binary @results.sarif
```

The answer (`201`) says what the report did: `resultsCount`, `createdCount`, `resolvedCount`,
`reopenedCount`, the tools, and the SHA-256 of the document you sent. It is refused with:

| Status | Why |
|---|---|
| `403` | not an integration key, a key no enabled source is declared for, or a tool the source is not declared for |
| `404` | a repository the key cannot see, or outside the source's scope — answered as if it did not exist |
| `400` | not SARIF 2.1.0, a location outside the repository or absolute, a link to external content, a run that failed or has no `results` |
| `413` | larger than `VECTISPIRE_MAX_BODY_SARIF_IMPORT` (32 MB) |

**Locations must be relative to the repository's root** (`src/App.java`): the checkout path of your
CI is unknown to Vectispire, so an absolute path is refused. Each run's tool is its own scope: a later
report from the same tool resolves what it no longer reports on that repository, and touches nothing
else — no other tool's issues, no plugin's, no scanner's.

Every repository row on [Repositories](../guide/repositories.md) has **SARIF**, which opens that
repository's import history, read-only: when and by which source and account, the tools, the counts
opened, resolved and reopened, and the document's SHA-256. Nothing is uploaded from the interface.

Imported issues say where they came from: type **imported**, the source, and the tool's name and
version. An auditor tells "analysed by Vectispire" (types `plugin`, `sast`…) from "declared by the CI"
(`imported`) at a glance: the backlog says it under the type ("analysed by Vectispire · acme-lint",
"declared by payments-ci · SonarQube"), its type filter offers both, and an issue's page has a
**Provenance** card with the plugin or the source, the tool and version, and the tool key that scopes
its resolution. Every import is kept with its document hash and in the audit log; a refused
one is a SIEM event (`ZAN-SEC-023`).

### Example: GitLab CI running Semgrep

```yaml
sast-to-vectispire:
  image: semgrep/semgrep@sha256:…
  script:
    - semgrep scan --config p/default --sarif --output semgrep.sarif .
    - >
      curl --fail-with-body -X POST
      "$VECTISPIRE_URL/api/v1/repositories/$VECTISPIRE_REPOSITORY_ID/sarif-imports"
      -H "Authorization: Bearer $VECTISPIRE_SARIF_KEY"
      -H "Content-Type: application/sarif+json"
      --data-binary @semgrep.sarif
```

`VECTISPIRE_SARIF_KEY` is a masked, protected CI variable. Declare the tool name your report carries —
look at `runs[0].tool.driver.name` in `semgrep.sarif`. Semgrep writes paths relative to the directory
it scanned, which is what Vectispire expects when it scans the repository root.

### Example: SonarQube on your premises

SonarQube does not write SARIF by itself. The step that turns your SonarQube project's issues into a
SARIF log — a small job reading its Web API (`/api/issues/search`), or a converter your team has vetted
— is yours; keep it inside the organisation, like SonarQube itself. Then:

```bash
curl --fail-with-body -X POST \
  "https://vectispire.example/api/v1/repositories/42/sarif-imports" \
  -H "Authorization: Bearer $VECTISPIRE_SARIF_KEY" \
  -H "Content-Type: application/sarif+json" \
  --data-binary @sonarqube.sarif
```

Declare the source with the driver name your converter writes (for example `SonarQube`), and make sure
the paths are relative to the repository root, not to SonarQube's project base directory if they
differ.

### What the declaration can and cannot prove

It cannot prove a file did not come from a SaaS: whoever holds a declared key can upload what they
have. What it gives you is **a named, audited decision** by the platform governor binding one key to
one producer and one scope; **a tool allow-list** that refuses a report from anything else; **the hash
of every accepted document**, to match a report to the pipeline run that produced it; and **a SIEM
event on every refusal**. Who holds a declared key is then your organisation's discipline, and the
audit trail makes it reviewable.

## Analysers that compile

CodeQL for Java, SpotBugs and similar tools need to build the code, which the read-only tree and the
cut network forbid. A dedicated writable copy of the tree and a network limited to your internal
dependency mirror are designed (decision 0017) but not yet available. Until then, run them in your own
CI and import their SARIF as above.
