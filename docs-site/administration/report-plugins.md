# Report plugins

A report plugin is **your organisation's own document, rendered by your own container image** from a
project's [export](../guide/exports.md#project-export): a checklist in your security function's
spreadsheet layout, a quarterly summary in your management's template. Vectispire gives the image the
export, checks the file it writes, and signs it with the platform's key. Decision
[0035](https://github.com/asmolabs/vectispire/blob/main/docs/architecture/en/decisions/0035-report-plugins.md)
records why it works the way it does.

!!! warning "This version has the registry, not the runner"
    You can register a report plugin, have its manifest approved, switch it on for a project and
    withdraw it. **Nothing renders a report yet**: running a plugin, checking its output and signing the
    document come in a later release. Registering now settles who vouches for which image ahead of time.

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

## What is recorded

Every gesture is written to the [audit log](audit-log.md) — `REPORT_PLUGIN_REGISTERED`,
`REPORT_PLUGIN_UPDATED`, `REPORT_PLUGIN_APPROVED`, `REPORT_PLUGIN_ENABLED_CHANGED`,
`REPORT_PLUGIN_ACTIVATED`, `REPORT_PLUGIN_DEACTIVATED`, `REPORT_PLUGIN_WITHDRAWN`, each naming the manifest
digest — and sent to the [SIEM](../integrations/siem.md#event-catalogue) as `VECTI-SEC-031`. A gesture that
changes nothing — the same manifest again, a plugin already switched on — records nothing.

## Refusals

| Answer | When |
|---|---|
| 400 | A manifest refused — the `detail` names the first thing wrong; a withdrawal without its justification. |
| 403 | A role that may not make the gesture. |
| 404 | A plugin, or a digest of it, that does not exist; a project that does not exist or that you do not see whole (`Project not found.`). |
| 409 `report-plugin-id-taken` | The id is registered already. |
| 409 `report-plugin-four-eyes` | Four-eyes is on and you registered this digest. |
| 409 `report-plugin-not-pending` | The digest is not awaiting approval: approved, superseded or withdrawn. |
| 409 `report-plugin-not-approved` | Switching on a plugin with no approved manifest. |
| 409 `report-plugin-withdrawn` | Registering again, or withdrawing again, a digest already withdrawn. |
| 409 `report-plugin-changed` | Another gesture changed the plugin while yours was being decided: read it again. |
