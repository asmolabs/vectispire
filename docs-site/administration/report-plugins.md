# Report plugins

A report plugin is **your organisation's own document, rendered by your own container image** from a
project's [export](../guide/exports.md#project-export): a checklist in your security function's
spreadsheet layout, a quarterly summary in your management's template. Vectispire gives the image the
export, checks the file it writes, and signs it with the platform's key. Decision
[0035](https://github.com/asmolabs/vectispire/blob/main/docs/architecture/en/decisions/0035-report-plugins.md)
records why it works the way it does.

!!! warning "This version runs a report, it does not yet hand you the document"
    You can register a report plugin, have its manifest approved, switch it on for a project, withdraw it,
    and **request a report**: the control plane builds the project's export, verifies the image's signer and
    runs the plugin in its closed shape, and the run records what came of it — the output's size and SHA-256
    included. **The document itself is not served yet**: checking it against its declared type, signing it
    and its download come in a later release, and until then its bytes are not kept.

## The manifest

```json
{
  "id": "quarterly-summary",
  "name": "Quarterly risk summary",
  "image": "registry.example.internal/reports/quarterly-summary@sha256:4f2d…(64 hex)",
  "export_schema": 1,
  "arguments": ["--in", "{input}", "--out", "{output}"],
  "output": "summary.xlsx",
  "media_type": "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet",
  "max_output_bytes": 20971520,
  "timeout_seconds": 120,
  "signature": {
    "identity": "https://ci.example.internal/reports/quarterly-summary/release@refs/tags/v2.1.0",
    "issuer": "https://ci.example.internal/oidc"
  }
}
```

| Field | What it means |
|---|---|
| `id` | 2 to 40 lowercase letters, digits and inner hyphens. **Never renamed nor reused**: the documents it produced name it. |
| `name` | What the screens show, at most 100 characters. |
| `image` | Pinned **by digest**: `repository@sha256:<64 hex>`, no tag. |
| `export_schema` | The major of `vectispire-project-export` the plugin reads. A major this installation does not produce is refused; `GET /api/v1/schemas/project-export/{major}` serves the ones it does. |
| `arguments` | The command handed to the image's entrypoint, as a list — no shell. `{input}` and `{output}` become the container's input and output paths. |
| `output` | The one file the plugin writes in `/report/output`: a bare name ending with its media type's extension (`.xlsx`, `.docx`, `.pptx`, `.ods`, `.odt`, `.pdf`, `.csv`, `.txt`). |
| `media_type` | One of the Office Open XML workbook, document and presentation types, `application/vnd.oasis.opendocument.spreadsheet`, `application/vnd.oasis.opendocument.text`, `application/pdf`, `text/csv`, `text/plain`. **HTML, the legacy binary Office formats and macro-enabled packages are refused.** |
| `max_output_bytes` | The output's ceiling, at most 50 MiB; default 20 MiB. |
| `timeout_seconds` | 10 to 300; default 120. |
| `signature` | **Required, with no waiver** — keyless (`identity` and `issuer`, both, matched exactly) or `public_key`, as for [analysis plugins](plugins.md#signing-the-image). The platform signs what the plugin writes, and does not lend its key to an image nobody vouched for. |

There is **no `network` field**: a report plugin always runs without a network. Its input is a
project's whole triaged state.

**The manifest holds no secret.** An image in a private registry is pulled — and its signature
verified — with the **control plane's Docker configuration** (`DOCKER_CONFIG`, `~/.docker/config.json`):
give the control plane read credentials for that registry, the way an executor gets them for analysis
plugins ([registry credentials](../guide/containers.md#registry-credentials)). Vectispire stores no
registry credential.

## Registering, approving, switching on

| Gesture | Who | Route |
|---|---|---|
| Register a plugin | the platform governor | `POST /api/v1/report-plugins` |
| Give it another manifest | the platform governor | `PUT /api/v1/report-plugins/{id}` |
| Approve a manifest digest | the platform governor, an administrator or a CISO — **not the account that registered it** while [four-eyes](four-eyes.md) is on | `POST /api/v1/report-plugins/{id}/manifests/{digest}/approval` |
| Enable or disable it | the platform governor | `PUT /api/v1/report-plugins/{id}/enabled` |
| Switch it on or off for a project | the platform governor, an administrator or a CISO | `PUT` / `DELETE /api/v1/projects/{id}/report-plugins/{pluginId}` |
| Withdraw a manifest digest | the platform governor, with a justification | `POST /api/v1/report-plugins/{id}/manifests/{digest}/withdrawal` |

**With four-eyes on**, a registered or updated manifest is `pending_approval` until somebody else who
writes governance approves **that digest**. Meanwhile the plugin's previously approved manifest keeps
serving; a plugin with none cannot be switched on for a project. Registering another manifest before the
pending one is approved sets the pending one aside (`superseded`): it can no longer be approved. Setting a
plugin back to a manifest approved earlier, and never withdrawn, takes effect at once — two people have
vouched for exactly those bytes.

**With four-eyes off**, a registration or an update takes effect at once, recorded as approved with
`approvalFourEyes: false`. A manifest left pending from before the switch may then be approved by any
governance writer, its registrant included.

Every manifest a plugin ever had is kept, by digest, with its status — `pending_approval`, `approved`,
`superseded` or `withdrawn` —, who registered it, who approved it and whether four-eyes applied: the
`manifests` of `GET /api/v1/report-plugins/{id}`, newest first. Reading the registry is for the roles that
read governance; the plugins switched on for a project (`GET /api/v1/projects/{id}/report-plugins`) are
listed to anybody who sees the whole project, images included — the people who will ask for its reports.

## Withdrawing a manifest

A signature cannot be unmade. When an image turns out to be wrong — a renderer that drops lines, a signer
compromised — the governor **withdraws** its digest, with a justification of 20 to 500 characters. The
digest never runs again and cannot be registered again; if it was the plugin's approved one, the plugin has
none until a fixed image — a new manifest — is approved. The documents it produced stay stored and will be
served marked withdrawn, with the justification. There is no delete: an id names every document the plugin
produced.

## Requesting a report

`POST /api/v1/projects/{id}/reports` with `{"pluginId": "quarterly-summary"}` asks for a report of the
project by a plugin switched on for it. It answers **202** with the run, `pending`; the control plane's
executor claims it within seconds. **Write accounts and auditors** may ask, if they see the whole project,
images included — anybody else gets the 404 of a project that does not exist; the platform governor, who
acts on nothing a project holds, gets a 403. Integration keys cannot ask for a report: the export is built
for a person.

**Where it runs: on the control plane, never on an agent.** The plugin runs on the Docker endpoint the
built-in worker uses (`VECTISPIRE_DOCKER_HOST` or `DOCKER_HOST` — the socket proxy in the shipped
composition). An installation whose built-in worker is switched off (`VECTISPIRE_EMBEDDED_WORKER=false`,
every scan on agents) **cannot run report plugins in this version**: a request is refused, 409
`report-executor-unavailable`, rather than queued for nobody. Running on an agent is a later lot.

**What the claim does**, in order:

1. checks again what the request checked — the plugin still switched on for the project, enabled, with an
   approved manifest — and runs **the manifest approved at that moment**, never one awaiting approval;
2. reads the requester again: an account deactivated, or one that no longer sees the whole project or no
   longer holds a role that may ask, gets no export built;
3. builds the project's [export](../guide/exports.md#project-export) for the requester, at that instant —
   the one the document describes;
4. verifies the image's signer with the pinned cosign **before the image is pulled**, with the control
   plane's Docker configuration for a private registry; anything but a verified signer is a refusal, and
   nothing is started;
5. runs the image **without any network**, not as root, every capability dropped, a read-only root file
   system, the scanners' memory, process and CPU ceilings; the export alone, read-only, at
   `/report/input/export.json`; one writable directory, `/report/output`, which cannot hold more than the
   manifest's `max_output_bytes` nor more than 16 files; stopped at the manifest's `timeout_seconds`;
6. reads the file the manifest names, as a regular file, within the ceiling. **Exit code 0, or the run
   failed.**

A run is in exactly one state:

| State | Meaning |
|---|---|
| `pending` | Requested, waiting for the executor. |
| `running` | Claimed. Its executor renews its lease while it runs, however long the pull and the signature check take. A run whose lease lapses — the longest timeout a manifest may declare, the verifier's two minutes and ten minutes, seventeen minutes without a renewal — was left by an executor that stopped: it is failed, `executor_lost`, and not retried. Ask again. |
| `produced` | The plugin exited 0 and wrote its file within its bounds. The export it was given is kept with the run. |
| `failed` | `exit_code`, `timeout`, `output_full` (the directory filled or a file outgrew the ceiling), `output_missing`, `output_not_regular`, `export_too_large`, `requester_not_allowed`, `plugin_unavailable`, `executor_lost`, `executor_error` — with the detail, the plugin's own words for an exit code. |
| `refused` | Not started: `signature_unverified`, `unsigned`, `registry_authentication_required`, or `export_schema_unavailable` (the manifest reads an export major this installation no longer produces). The fix is the image's provenance or its version, not its code. |

**One run of a plugin per project at a time**: a second request while one is pending or running is
refused, 409 `report-run-in-progress` — it is the one to wait for. The project's runs, newest first, are at
`GET /api/v1/projects/{id}/reports`, one at `GET /api/v1/projects/{id}/reports/{runId}`, for anybody who sees
the whole project: the state, its reason and detail, the manifest, image and signer it ran with, the export's
SHA-256 and size, the output's SHA-256 and size, the instants requested, started, exported and finished.

**How many at once**: `VECTISPIRE_REPORT_CONCURRENCY`, two by default, on each instance of the control
plane; it looks for waiting runs every `VECTISPIRE_REPORT_INTERVAL` (10 s). **What is kept**: the export a
produced run was given, until the [evidence window](maintenance.md) (`evidence_retention_days`) has passed —
then its bytes go and the run keeps its digest; a failed or refused run keeps nothing but itself and its
reason. Deleting a project takes its runs and their exports.

## What is recorded

Every gesture is written to the [audit log](audit-log.md) — `REPORT_PLUGIN_REGISTERED`,
`REPORT_PLUGIN_UPDATED`, `REPORT_PLUGIN_APPROVED`, `REPORT_PLUGIN_ENABLED_CHANGED`,
`REPORT_PLUGIN_ACTIVATED`, `REPORT_PLUGIN_DEACTIVATED`, `REPORT_PLUGIN_WITHDRAWN`, each naming the manifest
digest — and sent to the [SIEM](../integrations/siem.md#event-catalogue) as `VECTI-SEC-031`. A gesture that
changes nothing — the same manifest again, a plugin already switched on — records nothing.

A report run records `REPORT_REQUESTED` when it is asked, `PROJECT_EXPORTED` when the export reaches the
plugin's container (sent to the SIEM as `VECTI-SEC-032`, the export's SHA-256 first), then
`REPORT_PRODUCED` (the output's, the manifest's and the export's digests), `REPORT_FAILED` or
`REPORT_REFUSED` — each in the requester's name. **A refusal is sent to the SIEM as `VECTI-SEC-033`**: an
image without a verified signer asked to run is how a tampered plugin shows itself. A failure for an
ordinary reason is audited, not signalled.

## Refusals

| Answer | When |
|---|---|
| 400 | A manifest refused — the `detail` names the first thing wrong; a withdrawal without its justification. |
| 403 | A role that may not make the gesture. |
| 404 | A plugin, or a digest of it, that does not exist; a project that does not exist or that you do not see whole (`Project not found.`); a report asked of a plugin not switched on for the project, in the same words whether it exists or not. |
| 409 `report-plugin-id-taken` | The id is registered already. |
| 409 `report-plugin-four-eyes` | Four-eyes is on and you registered this digest. |
| 409 `report-plugin-not-pending` | The digest is not awaiting approval: approved, superseded or withdrawn. |
| 409 `report-plugin-not-approved` | Switching on, or asking a report of, a plugin with no approved manifest. |
| 409 `report-plugin-disabled` | Asking a report of a plugin the governor disabled. |
| 409 `report-executor-unavailable` | Asking a report where the built-in worker is switched off: this version runs report plugins on the control plane only. |
| 409 `report-run-in-progress` | A report of this plugin for this project is already pending or running. |
| 409 `report-plugin-withdrawn` | Registering again, or withdrawing again, a digest already withdrawn. |
| 409 `report-plugin-changed` | Another gesture changed the plugin while yours was being decided: read it again. |
