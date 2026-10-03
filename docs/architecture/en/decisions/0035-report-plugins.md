# 0035 — A report plugin is a signed container image that turns a project export into one document, which the platform validates, signs and keeps with its provenance

**Date:** 2026-10-03 · **Status:** accepted · **Builds on:** [0017](0017-custom-checks-as-container-images.md), [0032](0032-security-checklists.md) §10 · **Decider:** Laurent Boucher

*Accepted on 2026-10-03: the owner settled the open questions the proposal ended with, and the
answers are written into the body and listed in "Decided on 2026-10-03" at the end. Nothing of it was
built when it was accepted; the lots at the end say in which order it is.*

## Context

Organisations do not want Vectispire's screens in their files: they want **their own documents** —
a security checklist in the spreadsheet layout their security function designed years ago, a
quarterly risk summary in the word-processor template their management reads, a PDF their
regulator's form asks for. Each organisation's format is its own, often internal, and changes on
its own calendar. None of them belongs in this repository.

[0032](0032-security-checklists.md) §10 met the first such document and settled it in core: the
organisation's workbook, patched cell by cell, signed inside the sign-off. It also wrote down why
that was not the general answer, and deferred the general answer to this record:

- the signature is the control plane's — the key never leaves it — so a plugin hands back bytes and
  core signs them, and *what a signature over a plugin's output claims* has to be decided;
- a report plugin receives project data the way a scanner plugin receives a tree, in the closed
  shape — but triage decisions, checklist answers and figures across a whole project are confidential
  in a way a source tree already handed to a scanner is not;
- `checklist.json` was declared the input contract a report plugin would receive.

[0017](0017-custom-checks-as-container-images.md) already answered the vehicle for code somebody
else wrote: **not a JAR in the JVM, a container image pinned by digest**, signed by a declared signer,
run in `ContainerRun`'s closed shape, registered by the platform governor and activated per project.
This record reuses that answer wherever it holds and says where a report differs from a check. It
differs in three ways that matter:

1. **The data flows the other way.** A scanner plugin reads a tree Vectispire cloned and emits
   findings Vectispire believes only after parsing them. A report plugin reads what Vectispire
   *knows* — the aggregated, triaged state of a project — and emits a document Vectispire cannot
   parse into facts.
2. **The output carries the platform's signature.** A scanner's report becomes rows; a report
   plugin's output leaves the platform as a file, signed by the key every Vectispire document is
   signed with ([`SigningKeyService`](../../../../vectispire-java/vectispire-core/src/main/java/com/asmolabs/vectispire/core/crypto/SigningKeyService.java)).
3. **The trigger is a person, not a schedule.** A report is requested for one project by somebody
   who can see it, and the requester is part of what the document states.

Every example in this record is invented for it. The demonstration plugin of §6 is the only plugin
this repository will ever contain.

## Decision

### 1. What a report plugin receives: the project export, a versioned JSON document

A report plugin receives **one file, `export.json`**, a document Vectispire builds for **one project,
as the requester sees it**, conforming to a published schema. It receives nothing else: no
database, no route, no token, no network (§2). **The plugin never queries Vectispire** — whatever the
document needs must be in the export, and whatever is not in the export the plugin cannot learn.

**The schema** is named **`vectispire-project-export`**, versioned `MAJOR.MINOR`, starting at `1.0`.

- It is a JSON Schema (draft 2020-12) kept in the repository at
  `vectispire-java/vectispire-common/src/main/resources/schemas/project-export/v1.schema.json` — one
  file per major — published with the user guide, and served by the control plane at
  `GET /api/v1/schemas/project-export/{major}` so a plugin author can read the version the
  installation actually produces.
- Every export states `"schema": "vectispire-project-export"` and `"schema_version": "1.0"` in its
  first two fields.
- **A minor adds, never removes or changes**: a new optional field, a new enumeration value announced
  in the schema as open. A plugin written for `1.0` reads `1.3` unchanged; a plugin must ignore what
  it does not know, and the schema says so.
- **A major is anything else**: a field removed, renamed, retyped, or a meaning changed. A new major
  is a new schema file; the control plane produces **the current major and the previous one** for at
  least one minor release line of the product after the new one appears, and the release notes name
  the release that drops the old one.
- **The manifest declares the major it reads** (`export_schema: 1`, §2). A plugin asking for a major
  the installation no longer produces is not run, and says so; it is never handed a document of
  another major.
- **The schema is held to the code by a test**, the way `openapi.json` is: every export built by the
  test suite is validated against the schema file, and a change to the schema file fails a test that
  pins its digest until the change is reviewed and the minor or major moved. A generator and a schema
  that disagree would be a contract nobody keeps.

**What is in version 1.0**, each part bounded and each present even when empty — an absent part means
"not produced", an empty array "produced, nothing in it" ([0007](0007-none-is-not-an-empty-list.md)):

| Part | Content |
|---|---|
| `export` | schema and version, export id, generated at (UTC), `ProductVersion`, the requester (account id and display name), the requester's locale, the installation's name |
| `project` | id, name, description, its solution, its repositories and the container images filed in it (name, display URL **without credentials**, default branch, sub-path) |
| `scans` | per target, the newest completed scan: id, finished at, the types it examined, its failures and plugin steps (the states of 0017 §4) |
| `gate` | per target, the last recorded verdict, its policy's name and the reasons |
| `issues` | every issue **not resolved** on the project's targets: id, type, severity, rule, title, tool key, package and version, advisory ids, path and line, first and last seen, status, the triage decision with its justification, who decided and when, the review date, the remediation deadline |
| `issue_counts` | per type and severity, open, accepted, false positive and resolved — so a document can state totals without carrying the resolved backlog |
| `inventory` | the project's consolidated components: name, version, purl, licences, the targets they come from |
| `compliance` | the project's compliance state, computed over its targets as the project's compliance screen computes it: per framework, its status and score, and per control its id, name, status, score and details; the targets monitored, observed and fresh, which cap those verdicts — a checklist line and a document citing it need the state the checklist was measured against |
| `checklists` | per template, the newest **signed-off** revision's statement, embedded verbatim — the `checklist.json` of [0032](0032-security-checklists.md) §10, with its own version — and the open revision's, if any, marked `"draft": true` |

**What is out, deliberately:**

- **Source code, and anything quoted from it**: no snippet, no matched value of a secret (a secret
  issue states its rule and its file, as the SIEM event does), no AI review exchange.
- **Credentials of any kind**: deployment keys, clone tokens, registry credentials, API keys, the
  installation's settings.
- **Evidence files' bytes**: named by name, media type, size and SHA-256, as `checklist.json` already
  does. A report can cite a file; it cannot carry it.
- **Accounts beyond their display name**: no e-mail address, no role, no team, no grant. The names
  that are in it are those of the requester, of triage deciders and of checklist authors — already on
  every signed checklist; an e-mail address never is, not even where an account has no display name
  (the export then carries the account id alone).
- **The audit log, other projects, the organisation-wide statement of applicability and the SIEM
  configuration.** A project report speaks for one project.
- **Posture**: the security score, the scorecard and its candidate, the ranking and the plans. They are
  figures of the portfolio, tuned on their own calendar; a document that needs one cites the screen.
- **Resolved issues one by one** — counted in `issue_counts`, not listed: a resolved backlog over
  years would dominate every export and serve almost no document.

**Bounds, refused rather than truncated.** An export larger than **64 MiB** of JSON, or with more
than **100,000** issues or components, is not built: the request is refused with the figure that
exceeded. A truncated export would be signed into a document that looks complete; that is the lie
0007 exists to refuse.

**Visibility: the whole project, or nothing** — the rule of [0032](0032-security-checklists.md) §8,
for the same reason. A report speaks for a project and is signed by the platform; built from part of
a project it would state, under the platform's key, a state that leaves out repositories nobody
told the reader about. The export is built only when
[`RowVisibility.requireWhollyVisibleProject`](../../../../vectispire-java/vectispire-core/src/main/java/com/asmolabs/vectispire/core/access/RowVisibility.java)
admits the caller (account grant intersected with the integration key's restriction,
[0024](0024-integration-api-keys-act-for-an-account.md)); otherwise **404**, the words of an absent
project. The export service takes the `VisibleProject` the guard mints, never a bare id.

**The export is downloadable on its own**, signed: `GET /api/v1/projects/{id}/export` returns
`export.json` and its detached signature, to the callers who may request a report (§4: write accounts
and auditors seeing the whole project), under `@AcceptsApiKey(EXPORT)`, audited `PROJECT_EXPORTED` and
signalled `VECTI-SEC-032`. This is how an organisation writes and tests its private plugin against its own
data **without Vectispire running it** — and it gives nobody anything they could not already read
through the routes; it only gathers it.

### 2. How it runs: the closed shape of 0017, tightened

A report plugin is **an OCI image pinned by digest plus a manifest**, run by the existing
`ContainerRunner` in `ContainerRun.of(...)`'s shape — `cap_drop: ALL`, `no-new-privileges`, read-only
root, `noexec` scratch, not root, the scanner limits' memory, process and CPU ceilings, removed in a
`finally` — exactly as 0017 §1 states it. What differs:

```json
{
  "id": "acme-checklist",
  "name": "Security checklist, organisation layout",
  "image": "registry.example.internal/reports/acme-checklist@sha256:<64 hex>",
  "export_schema": 1,
  "arguments": ["--in", "{input}", "--out", "{output}"],
  "output": "checklist.xlsx",
  "media_type": "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet",
  "max_output_bytes": 20971520,
  "timeout_seconds": 120,
  "signature": {
    "identity": "https://ci.example.internal/reports/acme-checklist/release@refs/tags/v2.1.0",
    "issuer": "https://ci.example.internal/oidc"
  }
}
```

| Field | Rule |
|---|---|
| `id`, `name`, `image`, `arguments` | As 0017 §2: lowercase id never renamed nor reused, display name, `repository@sha256:<64 hex>` with no tag, an argument list with no shell on Vectispire's side. `{input}` and `{output}` are replaced by the two container paths. |
| `export_schema` | The major of `vectispire-project-export` the plugin reads (§1). |
| `output` | A bare file name in `/report/output`. |
| `media_type` | One of the closed list of §3. |
| `max_output_bytes` | At most **50 MiB**; default 20 MiB. |
| `timeout_seconds` | 10–300; default 120. |
| `signature` | **Required** — keyless (`identity` and `issuer`, both, exact) or `public_key`, as 0017 §9. |

The manifest's digest covers every field, and every manifest a plugin ever had is kept by digest, as
0017 §3: a run names the digest it was started with, and the provenance (§3) names it too.

**No network, and no exception.** 0017 §1 lets a scanner plugin open the network with a written
justification, because a scanner may need a vulnerability database. A renderer needs nothing from the
network: its fonts, templates and logos are in its image. The input is the most aggregated
confidential data the platform holds; a network exception would be a declared exfiltration channel.
The manifest has no `network` field, and the container is created with network `none`.

**One input, read-only.** `export.json` is written into a per-run directory on the executor holding
that file alone, mounted read-only at `/report/input`, and deleted in the `finally` — not the
workspace, not a clone, nothing else. Whether the file is bind-mounted or copied in through the
archive API is settled at implementation against the socket proxy's filter, the way 0017 §10 settled
the output.

**One output, bounded.** `/report/output` is 0017 §10's bounded output — the tmpfs volume kept by a
holder, `fsize` at the ceiling — with the manifest's `max_output_bytes` as the ceiling and **16
inodes**: a renderer writes one file, and room for a few temporary ones is all it is given. The
output is read as a regular file, never through a link, checked against the ceiling before its bytes
are read. A full volume means the run failed, as in 0017: what could not be written is not in the
document.

**The exit code is `0` or the run failed.** A renderer has no "found something" code to declare.

**The signer is required, and there is no waiver.** 0017 §9.1 lets the governor waive the signature
for one scanner plugin, and lets an executor's operator switch the requirement off. Neither applies
here. A scanner plugin's output is parsed into rows the backlog can contradict at the next scan; a
report plugin's output leaves the platform **under the platform's signature**. Signing the output of an
image nobody vouched for would lend the installation's key to whoever could push to a registry. An
unsigned or unverified report plugin is **refused** — `unsigned`, `signature_unverified`, the reasons
of 0017 §9.1 — and nothing is started. `VECTISPIRE_PLUGIN_SIGNATURE_REQUIRED=false` does not reach it.

**Where it runs: the control plane's container endpoint, not an agent — in this version.** 0017's
answer for checks is "wherever scanners run", because a scanner plugin reads a tree the executor
already holds. A report plugin reads a document the control plane builds from its database; sending
it to a remote agent would ship the project's whole triaged state to a host that today receives
clones and returns findings, and whose operator may not be the one who can read the project. So a
report runs on **the Docker endpoint the built-in worker uses** (`DOCKER_HOST`, the socket proxy of
[0018](0018-the-docker-socket-is-never-mounted.md) — never a mounted socket), through the same
`ContainerRunner`. The principle 0017 keeps is kept: the plugin's code is in a container, never in the
JVM, and never sees the database, `ENCRYPTION_KEY` or the signing key; only the export reaches it.

An installation with no container endpoint on the control plane — the built-in worker switched off,
every scan on agents — **cannot run report plugins in this version**, and the screens and the route
say so (409, `report-executor-unavailable`) rather than queue a run nobody will claim. Running on an
agent is a later lot (decided on 2026-10-03, answer 1); until it is built, an installation whose scans
all run on agents gets the 409.

**Runs are queued in the database, not held in a request.** `POST /api/v1/projects/{id}/reports`
records a run (`pending`) and answers 202 with its id; a bounded pool on the control plane (two runs
at a time by default) claims it, builds the export **at the claim** — the instant the document
describes — and runs the plugin. A run is in exactly one state:

| State | Meaning |
|---|---|
| `pending`, `running` | Requested; claimed. A `running` run older than its timeout and ten minutes at start-up is failed with `executor_lost`. |
| `produced` | The plugin exited `0`, its output passed §3's checks, the package is signed and stored. |
| `failed` | Exit code, timeout, full output, no output, output refused by §3, export over its bounds — with the reason. Nothing is stored but the run and its reason. |
| `refused` | Not started for want of a verified signer (`unsigned`, `signature_unverified`), or the manifest's `export_schema` is not produced (`export_schema_unavailable`). Told apart from `failed` because the fix is provenance or version, not the plugin's code. |

### 3. What it produces: one file, checked, signed by the platform, with its provenance

**One file, of a declared type.** The manifest's `media_type` is one of a closed list, each with a check
Vectispire runs on the bytes before believing the declaration:

| Media type | Check |
|---|---|
| Office Open XML workbook, document, presentation (`.xlsx`, `.docx`, `.pptx`) | a zip, read with the zip guards the checklist template importer already applies (`WorkbookReader`) (entry count, total uncompressed size, no absolute or `..` entry name); `[Content_Types].xml` present and naming the main part the type requires; **no `vbaProject.bin`** — a macro-enabled package is refused whatever its extension |
| OpenDocument spreadsheet, text (`.ods`, `.odt`) | a zip whose first entry is `mimetype`, stored, holding exactly the declared type; the same zip guards; no `Basic/` or `Scripts/` directory |
| PDF | starts with `%PDF-1.` or `%PDF-2.`, ends with `%%EOF` within its last kilobyte |
| CSV, plain text | valid UTF-8, no NUL byte |

**HTML is not offered.** A document served from the product's origin and opened in a browser runs in
that origin; sandboxing it correctly is a design of its own for a format no organisation asked for.

**The check is a type check, not a malware scan**, and the record says so: a PDF can carry JavaScript in
a compressed object stream no byte search finds. What bounds that risk is the signer requirement (§2),
the governor's review of who may sign (§4), and how the file is served — **always as an attachment**,
with `Content-Type` the declared type, `X-Content-Type-Options: nosniff` and
`Content-Security-Policy: sandbox`, never rendered inline by the interface.

**Stored, bounded, in the database.** The package's bytes go to a table of their own that no listing
reads, in a `${bytes}` column (the placeholder 0032 introduced), never on the control plane's disk —
the restore drill proves the database, and a second instance would not see a file. The export the
plugin was given is kept with the run, by the same rule: what the signature attests to (below)
includes the input, and an input that cannot be produced later is a claim nobody can check. Both are
purged with the run by the **evidence window** (`evidence_retention_days`,
[maintenance](../../../../docs-site/administration/maintenance.md)), like other evidence; a run's row and
its digests stay as long as the audit log does.

**Signed by the platform's key, detached, whatever the format.** The package is a zip, like 0032's:

- `<output>` — the plugin's file, byte for byte;
- `<output>.sig` — a detached signature by the signing key, verifiable with `cosign verify-blob --key`
  against the published public key, like every other export;
- `provenance.json` — an in-toto statement whose subject is the output's SHA-256, wrapped in a DSSE
  envelope signed by the same key (`SigningKeyService.wrapAndSignDsse`, as the evidence bundle's
  attestation).

**The provenance states**: the run id; the project (id and name); the plugin's id, its manifest digest,
its image digest and the signer cosign verified (identity and issuer, or the key's fingerprint); the
export schema and version and the export's SHA-256; the output's media type, size and SHA-256;
[`ProductVersion`](../../../../vectispire-java/vectispire-core/src/main/java/com/asmolabs/vectispire/core/settings/ProductVersion.java);
the requester; the instants requested, exported, started and finished; the signing key's id. The same
fields are columns of the run, and the audit entry `REPORT_PRODUCED` names the digests.

**What the platform's signature claims — and what it does not.** It claims: *this installation gave this
export, of this project, at this instant, to this image, verified as built by this signer, at the request
of this account, and these are the bytes the image wrote.* It does **not** claim the document is a true
rendering of the export: a renderer can omit a line or invent one, and nothing short of parsing every
format back into facts could tell. The provenance makes that checkable instead: the export is kept, its
digest is signed, and anybody who doubts the document can render the export again with the same image
— the image is pinned, the export is fixed, a deterministic renderer gives the same bytes. The
documentation for plugin authors asks for determinism (no "now", no random identifiers) and the
demonstration plugin (§6) is.

**Signed PDF and Office signatures were rejected** (alternatives): one detached signature works for
every type, needs no format library in the control plane, and is verified by the tool every other
Vectispire document is verified with.

### 4. Governance: the registry of 0017, a separate list, four-eyes on the image

**A registry of its own, beside the scanner plugins'.** Report plugins live in their own tables —
plugin, manifests by digest, activations, runs, documents — in a new module `core.reportplugins` (§7), not in
`t_plugin` with a `kind` column. A scanner plugin's id enters fingerprints, its manifest has languages
and exit codes, its activation decides a scan; a report plugin's has none of those and has a media
type, an export major and a requester. Sharing one table would make every rule of each conditional on
the other's kind. What they share is code, not rows: the manifest's image and signer rules, the
relocation by `VECTISPIRE_PLUGIN_REGISTRY`, the cosign verifier and the bounded output, all in
`vectispire-common`.

| Act | Who | Marker, and what the service checks |
|---|---|---|
| Register a plugin, update its manifest, enable or disable it | platform governor | `@RequiresPlatformGovernor`, as 0017 §6 |
| **Approve** a registered or updated manifest | with `FOUR_EYES_APPROVAL_REQUIRED` on, **another person** holding `canWriteGovernance` (governor, administrator, CISO); with it off, the registration takes effect at once | `@RequiresSecurityLead` + the comparison in the service |
| Activate or deactivate it for a project | security lead, whole project visible | `@RequiresSecurityLead` + the guard |
| Request a report, download the export | write accounts (`canCauseEffects`) **and auditors** (`AUDITOR`), whole project visible — the platform governor is neither | `@RequiresAccount` + the role check and the guard, both in the service (export: `@AcceptsApiKey(EXPORT)` too); each request audited |
| Read a project's runs and download a produced document | whole project visible | `@RequiresAccount` + the guard |
| Withdraw a manifest's documents | platform governor | `@RequiresPlatformGovernor` |

**Four-eyes on the image, which 0017 does not have.** A manifest registered or updated while
four-eyes is on is `pending_approval` until a second person approves that digest; a run never uses an
unapproved digest, and the previous approved one keeps serving meanwhile. The reason is the signature:
a scanner plugin's output is checked again by every scan, a report plugin's leaves under the
installation's key, and one person deciding alone which code may produce signed documents is the
concentration four-eyes exists to split. It follows the platform setting rather than always applying,
for 0032's reason: an installation with one approver could otherwise never register one. Whether
scanner plugins should gain the same rule is left to a change of its own (decided on 2026-10-03): it
would amend an accepted decision, 0017 §6.

**Nothing global, no delete** — as 0017 §6: a report plugin runs only for a project it is activated
for; disabling keeps the activations and runs nothing; deleting a project takes its activations, its
runs and its documents; an id is never reused, since documents in the world name it.

**Withdrawal.** A detached signature cannot be un-made. When an image turns out to be wrong — a renderer
that dropped lines, a signer compromised — the governor **withdraws** a manifest digest, with a
justification of 20 to 500 characters: every document it produced is marked `withdrawn`, stays stored
(evidence of what was handed out), is served with the withdrawal stated in the response and on screen,
and `GET /api/v1/report-documents/{sha256}` answers a signed-in holder of a document whether the
installation still stands by it. Withdrawing disables the digest; a fixed image is a new manifest.

**Audit**, each after commit through `AuditLogService`: `REPORT_PLUGIN_REGISTERED`,
`REPORT_PLUGIN_UPDATED`, `REPORT_PLUGIN_APPROVED`, `REPORT_PLUGIN_ENABLED_CHANGED`,
`REPORT_PLUGIN_ACTIVATED`, `REPORT_PLUGIN_DEACTIVATED`, `REPORT_PLUGIN_WITHDRAWN`, `PROJECT_EXPORTED`,
`REPORT_REQUESTED`, `REPORT_PRODUCED`, `REPORT_FAILED`, `REPORT_REFUSED`, `REPORT_DOWNLOADED`.

**SIEM**, through the outbox ([0025](0025-siem-events-leave-through-the-outbox.md)). The highest
identifier emitted when this was accepted is `VECTI-SEC-030`; these three are **reserved** from that
day — no other event takes them — and frozen by `SecurityEventTypeTest` as each lot emits its own:

| Id | Event | Severity | Why a SOC wants it |
|---|---|---|---|
| `VECTI-SEC-031` | Report plugin registered, changed, approved, activated or withdrawn | 6 | third-party code gains or loses access to a project's whole triaged state, or the right to produce documents under the installation's key |
| `VECTI-SEC-032` | Project export left the platform | 4 | an export was downloaded or handed to a report plugin: who took a project's whole state, and where it went |
| `VECTI-SEC-033` | Report plugin refused, or its output refused | 6 | an image without a verified signer was asked to run, or produced a file that is not what it declared — either is how a tampered plugin shows itself |

A failed run for an ordinary reason (exit code, timeout) is audited, not signalled: it is work going
wrong, not a security event.

### 5. Private plugins: private registries, private repositories, nothing here

The plugin an organisation actually needs is, by construction, private: its layout is the
organisation's, and so is its code. **Nothing of a private plugin enters this repository** — not its
manifest, not its image reference, not its layout, not a sample of its output, not a test naming it.
The repository carries the schema, the mechanism and the demonstration plugin of §6; an organisation
carries its plugin in its own repository, built by its own pipeline, signed by its own signer, pushed
to its own registry, and declared in its own installation's database.

**Pulling from a private registry.** *(Corrected on 2026-10-03: the accepted text said Vectispire
stores registry credentials for container scanning, encrypted under `ENCRYPTION_KEY`, and that the
verifier could not use them yet. Neither was true — nothing in the code stores a registry credential —
and the verifier has read a private registry since [0017](0017-custom-checks-as-container-images.md)
§9.2.)* **Vectispire stores no registry credential.** An image pull — and, since 0017 §9.2, the
signature check before it — uses the Docker configuration of the machine that runs it (`DOCKER_CONFIG`,
`~/.docker/config.json`, or docker-java's `registry.*` properties): the daemon receives what docker-java
resolves for that reference, and the verifier is handed exactly that, for one run, in a read-only
one-entry configuration erased with the container. A registry that will not be read is refused as
`registry_authentication_required`, never as an unverified signer.

A report plugin runs on the control plane (§2), so **a private plugin image is pulled and verified with
the control plane's Docker configuration** — the operator gives the control plane's container
credentials for that registry, as they give an executor's for a scanner plugin. Nothing crosses the
database, the agent protocol or `ENCRYPTION_KEY`; nothing is sealed to an agent. **The manifest holds no
secret and names no credential**: the credential is the one the pull of the image's reference resolves,
so a manifest's digest carries nothing that rotates. A registry that cannot hold a credential the
control plane may use can be mirrored through `VECTISPIRE_PLUGIN_REGISTRY`, which keeps the digest and
requires the signatures to be copied with it.

**A private signer.** The manifest's `signature` accepts an organisation's own key (`public_key`,
verified without the transparency log, 0017 §9) or its own OIDC issuer and CI identity: neither has to
be public, and neither enters this repository.

### 6. The demonstration plugin: the contract's executable test

**`vectispire-report-demo`** is the one report plugin this repository contains. It is a reference, a
test and a starting point — not a product feature anybody is expected to activate.

- **What it does**: reads `export.json`, refuses a `schema` it does not know or a major other than its
  own (exit 2, and a message on stderr), and writes **`summary.xlsx`**: a `Summary` sheet (project,
  requester, `ProductVersion`, export instant, gate verdicts per target, counts per type and severity),
  an `Issues` sheet (one row per issue in the export, triage included) and a `Checklists` sheet (each
  embedded checklist's items, answers and authors). Deterministic: the export instant, never "now";
  fixed zip timestamps and entry order; the same export gives the same bytes.
- **Where it lives**: a Gradle subproject, `vectispire-java/vectispire-report-demo`, JDK only for the
  workbook — `java.util.zip` and an XML writer, the approach 0032 §10 took for the checklist rather
  than a spreadsheet library — and Jackson for the input. It does not depend on `vectispire-core` nor
  on `vectispire-common`: a plugin knows the schema, not the platform, and a demo that imported the
  platform's records would prove nothing about the contract.
- **How it is built and signed**: Jib, like the two images, in the `release` workflow's `build` job,
  handed over as an archive with its checksum; `publish` pushes it to the same namespace, **signs it by
  digest** with the same keyless identity as the control plane's images
  (`…/.github/workflows/release.yml@refs/tags/<tag>`), verifies that signature before going on, and
  states its digest in the release notes — exactly the path of the two images in
  [`release.yml`](../../../../.github/workflows/release.yml). The manifest an operator pastes to try
  it is in the user guide, with that digest and that identity.
- **How it serves as the contract test**:
  1. the `jvm` job runs it in-process against exports built by the core's test suite from generated
     projects, and checks the workbook it writes — every issue in the export is a row, every count
     matches;
  2. the container suite builds its image to a local archive, registers it in a test installation,
     and runs a report end to end through the real `ContainerRunner` — export, closed shape, bounded
     output, type check, signature, provenance — then verifies the package with `cosign verify-blob`
     against the installation's public key, the command the documentation tells a recipient to run;
  3. a schema change that the demo does not read any more fails (1) before it reaches a release;
     a major bump that forgets the demo fails (2).

### 7. Where it sits

A new vertical module **`core.reportplugins`** (decisions 0028–0030), above `checklists` — the export embeds
their statements — and above `compliance`, whose project state the export carries (answer 8). Its `package-info` lists, each with its reason:
`access`, `access::security` (the markers, the whole-project guard), `targets` (the project, its
targets, `ProjectDeleted`), `scanning` (newest scans, plugin steps), `issues`, `issues::queries` (the
backlog, through `IssueFilters`), `inventory` (consolidated components), `gate` (verdicts),
`checklists` (signed-off statements), `compliance` (the project's compliance state). The foundation (`audit`, `settings`, `crypto`) is shared. The
module's name avoids `reporting`, which is the PDF pagination four domains share, and
`common/domain/reports`, which holds the coverage and test-report imports.

The export builder is a service of `reportplugins` reading through those modules' published interfaces;
the pure parts — the export's records, its writer, the output type checks — live in
`vectispire-common/domain/reportplugins`, JDK and Jackson only.

## Alternatives considered

- **A Java plugin interface loaded into the control plane.** 0017 rejected it for checks, and every
  reason is stronger here: a report plugin in the JVM would hold the database, `ENCRYPTION_KEY` and the
  signing key itself, and could sign whatever it liked.
- **A templating language in core** (a template the organisation uploads, filled by Vectispire). It
  answers the simplest layouts and none of the rest — a document that computes, groups or chooses —
  and turns into a programming language with the platform's key behind it. The checklist renderer of
  0032 is the one built-in template, and it stays the only one.
- **Plugins calling Vectispire's API with a short-lived token.** Simpler to write against, and the
  plugin could ask for exactly what it needs. It would give third-party code a network path into the
  control plane, make what the plugin read unknowable after the fact, and the document's input
  unreproducible. A fixed export, kept and hashed, is what makes the signature mean something.
- **Several narrower exports** (issues only, checklist only) chosen by the manifest. Each is a
  contract to version; one export with parts, each present or absent, is one schema to keep.
- **Partial visibility, with the omissions marked** — how a project's CycloneDX export behaves (built
  for "the project as far as the caller sees it"). Acceptable for an inventory, not for a signed
  statement about a project: a recipient reads the title, not a footnote. A marked partial report stays
  possible as a later option if somebody asks for one (answer 2); nobody has.
- **Running on agents, as 0017 does for checks.** See §2: the data would leave the control plane for a
  host that never held it. Designed as a later lot, with the export sealed to one agent the governor
  designates, using the sealing keys of [0031](0031-a-sealing-key-is-believed-only-on-the-pinned-key.md).
- **A network exception, as 0017 allows.** A renderer needs no network; an exception would be a
  declared exfiltration path for the most confidential document the platform builds.
- **A waiver for unsigned report plugins, as 0017 §9.1 allows.** The platform signs the output;
  waiving the image's provenance would lend the installation's key to an anonymous image.
- **Signing the output in its own format** — PAdES for PDF, XML-DSig for Office files. Three
  mechanisms, three libraries with their own advisories, and nothing for CSV; a recipient would need a
  different tool per format. The detached signature is uniform and already verified the same way as
  every other Vectispire export. An organisation that needs a qualified electronic signature applies it
  afterwards, by a person, which is what such a signature means anyway.
- **The plugin signing its own output.** A key inside an image is a key anybody who pulls it holds; and
  the claim worth signing is the platform's — what it gave and what came back — not the renderer's.
- **One registry with scanner plugins (`t_plugin.kind`).** See §4: two sets of rules in one table, each
  conditional on the other's kind; the code is shared instead.
- **Rendering synchronously in the request.** A container start, a pull and a signature check exceed
  what a request should hold, and a restart would lose the work without a trace. A run row is the trace.
- **The demonstration plugin as a shell script on busybox.** Smaller, and unable to write a workbook
  without reimplementing zip: a demo that produces CSV would not exercise the zip guards, which are the
  checks most likely to be wrong.

## Consequences

- A new module, `reportplugins`, and its `package-info`, reviewed line by line; `ArchitectureTest.MODULES` and
  `ModularityTest.MODULES` gain it.
- Migrations from the next free version when the lot lands, written once in `common` with the
  placeholders: `t_report_plugin`, `t_report_plugin_manifest`, `t_report_plugin_activation`,
  `t_report_run`, `t_report_document` (bytes apart, `${bytes}`), `t_report_export` (bytes apart). No
  foreign key; the module's listeners purge on `ProjectDeleted`, and the maintenance tick purges by the
  evidence window — a `MaintenanceTask`, so `MaintenanceJobsTest` asserts it is called.
- A published schema, `vectispire-project-export` 1.0, with a test that holds it to the generator; every
  later change to the export is a reviewed schema change.
- New routes and their OpenAPI contract; three SIEM identifiers and a catalogue entry for each; new audit
  operations.
- A third image built and signed by the release, and its digest in the release notes.
- **An installation without a container endpoint on the control plane has no report plugins** until
  agent execution is built.
- **A private registry requiring authentication is read with the control plane's Docker
  configuration** (§5): the operator provides it there; Vectispire stores none.
- The platform's signature on a report means *provenance*, not *truth*; the user guide says so in those
  words, and a recipient who needs more re-renders the kept export.
- Documentation in both languages: an administration page for report plugins (registry, approval,
  activation, withdrawal), a guide page for requesting and verifying a report, a reference page for the
  export schema and for plugin authors, and the SIEM catalogue.

## Decided on 2026-10-03

The proposal ended with eleven open questions. The owner answered them on 2026-10-03; the body above
already reads as answered.

1. **Installations whose scans all run on agents.** Control-plane execution first; agent execution —
   an export sealed to one designated agent, with 0031's keys — is a later lot. Until it lands, an
   installation with no container endpoint on the control plane gets the 409
   `report-executor-unavailable` (§2).
2. **Whole project or nothing.** Yes: the export and every report are built only for a caller who sees
   the whole project, and anybody else gets the 404 of an absent project (§1). A marked partial report
   is not offered.
3. **Names in the export.** The display names of the requester, of triage deciders and of checklist
   authors are in the export; e-mail addresses never are (§1).
4. **Who may request a report.** **Write accounts and auditors** (`Role.AUDITOR`) who see the whole
   project — the proposal had left the auditor out. An auditor reads a project's whole state already;
   handing the same state to a document is reading, not acting, and an audit is precisely where an
   organisation's own document is wanted. The platform governor, who causes no effects and holds no
   triage, does not request reports. Every request is audited (`PROJECT_EXPORTED`, `REPORT_REQUESTED`),
   and an export leaving the platform raises `VECTI-SEC-032` (§4).
5. **The media types.** Office Open XML (`.xlsx`, `.docx`, `.pptx`), OpenDocument (`.ods`, `.odt`),
   PDF and CSV (plain text with it); HTML, the legacy binary Office formats and macro-enabled packages
   are refused (§3).
6. **No network and a required signer with no waiver.** Confirmed as written (§2).
7. **Retention.** The evidence window — `evidence_retention_days`, 400 days by default — for exports
   and documents; run rows are kept with the audit log (§3).
8. **Compliance and posture in the export.** Export 1.0 carries the project's **compliance state** —
   a checklist's measured lines and the documents built on them cite it — and **not posture** (§1).
9. **Scheduled reports.** Out of scope: a requester is part of what a document states, and a schedule
   has none.
10. **Four-eyes on scanner plugins.** Left to a separate change: it would amend 0017 §6, an accepted
    decision, and is decided there, not here.
11. **The SIEM numbers.** `VECTI-SEC-031` to `VECTI-SEC-033` are reserved from this day (§4).

## Built in R1 (2026-10-03): where the code says more than §1

Lot R1 — the export, its schema and its signed download — settled these points §1 left open or stated
loosely. The code is in `core.reportplugins` (`ProjectExportService`) and
`common/domain/reportplugins` (`ProjectExport`, `ProjectExportSchema`, `ProjectExportBounds`).

- **The whole project includes its images.** The checklists' guard reads the repositories alone; an
  export carries the images' scans, backlog and components too, so it is built only for a caller who
  sees every target filed in the project (`RowVisibility.requireEveryTargetOfProject`), the checklists'
  rule holding as well.
- **The download is a zip** of `export.json` and `export.json.sig` — the checklist package's shape, the
  signature as `cosign` writes it. The schema route asks for a signed-in account or an `export` key.
- **The embedded statements name people by display name.** `checklist.json` records user names; the
  export rewrites each to the account's display name, or null, and names the signed package by its
  SHA-256 (`document_sha256`) — the statement under the signature is the package's. A display name that
  is an e-mail address is left out as one.
- **An issue's text travels for vulnerabilities, licences and end of life only** (`title`); for every
  other type it is null, since a tool's message may quote the code it matched, and a secret's the secret.
- **The gate's register keeps counts, not reasons**: the export carries the counts it recorded, the
  policy's source and version, and no reason one by one.
- **Components carry no licence in 1.0**: the inventory indexes none per component. A minor adds them
  when it does.
- **The installation is named by its brand name and its public URL**, where one is configured.
- **A triage decision is one somebody recorded**: an issue under review by default, nobody named, has
  `triage: null`; its status is in `issue_counts`, counted by type, severity, state and triage status.
- **Over a bound, 409 `project-export-too-large`** with the part, the figure and the bound as members; the
  issues are counted before one is read, the JSON written into a buffer that stops at 64 MiB.

## Built in R2 (2026-10-03): where the code says more than §4

Lot R2 — the registry — settled these points §4 left open. The code is in `core.reportplugins`
(`ReportPluginService`, migration V72) and `common/domain/reportplugins` (`ReportPluginManifest`,
`ReportMediaType`, `ReportPluginManifestStatus`); what both registries enforce alike (id, name, arguments,
output name) moved to `common/domain/plugins/ManifestRules`, shared as code with 0017's manifest, whose
messages and digest are unchanged.

- **A manifest digest is in one of four states**: `pending_approval`, `approved`, `superseded` — pending,
  and replaced by a later registration before anybody approved it: it never ran and can no longer be
  approved — and `withdrawn`, final. A plugin holds at most one approved digest, the one a run uses, and
  one pending.
- **A digest approved before, and never withdrawn, serves again at once** when the governor sets the
  plugin back to it: two people have vouched for exactly those bytes. A withdrawn digest is refused (409
  `report-plugin-withdrawn`).
- **Four-eyes is read when the approval is given**, as for a checklist template's publication: a manifest
  left pending from before the rule was switched off may then be approved by its registrant. The
  comparison is by account id; the route carries `@RequiresSecurityLead` and the service checks
  `canWriteGovernance` again. Switching four-eyes on already needs two accounts that write governance
  (the checklist templates' rule), which is what an approval needs too: no guard of its own.
- **The output's name ends with its media type's extension**: the name is what a recipient opens, and a
  workbook declared `.xlsx` and named `.xlsm` would open as a macro-enabled one.
- **`export_schema` must be a major this installation produces** at registration, rather than a plugin
  registered to be refused at every run.
- **Any digest not yet withdrawn may be withdrawn**, a pending one included, which can then no longer be
  approved. Withdrawing the approved digest leaves the plugin with none until a new manifest is approved.
- **Switching a plugin on needs an approved digest** (409 `report-plugin-not-approved`), and the export's
  guard: every target filed in the project, images included. The activations of a project are listed to
  any account that sees it whole — those who will request its reports; the registry itself is governance
  reading.
- **The plugin row carries an optimistic revision**: an approval racing an update fails as 409
  `report-plugin-changed` rather than installing a digest the update had just set aside.
- **Every 409 names its cause** (`report-plugin-id-taken`, `-four-eyes`, `-not-pending`, `-not-approved`,
  `-withdrawn`, `-changed`). The seven audit operations each signal `VECTI-SEC-031`, as `REPORT_PLUGIN_CHANGED`.

## Implementation, in lots

| Lot | Content | Size |
|---|---|---|
| R1 | Export schema 1.0, its records and writer in `common`, the builder in `reportplugins`, the whole-project guard, the schema test, `GET …/export` signed, `PROJECT_EXPORTED`, `VECTI-SEC-032` | M |
| R2 | The registry: manifest rules, tables, governor routes, four-eyes approval, activation, audit, `VECTI-SEC-031`; `integrationTestAll` for the migration | M |
| R3 | The executor: run queue and claim, export at claim, input mount, bounded output with 16 inodes, signer required with no waiver, the four states, restart recovery | L |
| R4 | Output checks per media type, storage, the signed package and the DSSE provenance, download headers, `VECTI-SEC-033`, the purge task | M |
| R5 | `vectispire-report-demo`: the module, Jib, the in-process and container contract tests, `release.yml` build, sign, verify and release notes | M |
| R6 | The interface: registry and approval screens, a project's **Reports** tab, run states, downloads, withdrawal | M |
| R7 | Withdrawal and the document status route | S |
| R8 | Documentation in English and French: administration, guide, schema reference, SIEM catalogue, upgrade notes | M |
| Later | Agent execution with a sealed export | L |

R1 is useful alone — an organisation can start writing its plugin against its own export — and R2 to
R4 ship together, since a registry nothing runs, or a runner nothing governs, is not a feature.
