# Report plugins

A report plugin is **your organisation's own document, rendered by your own container image** from a
project's [export](../guide/exports.md#project-export): a checklist in your security function's
spreadsheet layout, a quarterly summary in your management's template. Vectispire gives the image the
export, checks the file it writes, and signs it with the platform's key. Decision
[0035](https://github.com/asmolabs/vectispire/blob/main/docs/architecture/en/decisions/0035-report-plugins.md)
records why it works the way it does.

**On screen**: the registry is under **Administration → Report plugins** — every plugin with its approved
and pending digests and its manifest history; the governor pastes a manifest, which is checked in words
before it is sent, enables, disables and withdraws; a security lead approves, and under four-eyes the account
that registered a digest sees why it cannot approve it. A project's page carries the plugins switched on for
it, the runs, the downloads and the project export: see [Reports](../guide/exports.md#reports) in the user
guide. Every route below is also there for automation.

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
| Approve a manifest digest | the platform governor, an administrator or a CISO — **never the account that registered it**: only a digest registered under [four-eyes](four-eyes.md) waits for approval | `POST /api/v1/report-plugins/{id}/manifests/{digest}/approval` |
| Enable or disable it | the platform governor | `PUT /api/v1/report-plugins/{id}/enabled` |
| Switch it on or off for a project | the platform governor, an administrator or a CISO | `PUT` / `DELETE /api/v1/projects/{id}/report-plugins/{pluginId}` |
| Withdraw a manifest digest | the platform governor, with a justification | `POST /api/v1/report-plugins/{id}/manifests/{digest}/withdrawal` |

**With four-eyes on**, a registered or updated manifest is `pending_approval` until somebody else who
writes governance approves **that digest**. Meanwhile the plugin's previously approved manifest keeps
serving; a plugin with none cannot be switched on for a project. Registering another manifest before the
pending one is approved sets the pending one aside (`superseded`): it can no longer be approved. Setting a
plugin back to a manifest approved earlier, and never withdrawn, is a new decision too: it waits for
somebody else's approval like any other, since it was replaced, perhaps for a reason.

**With four-eyes off**, a registration or an update takes effect at once, recorded as approved with
`approvalFourEyes: false`, and so does setting a plugin back to a manifest approved earlier. **A manifest
left pending from before the switch still needs somebody other than its registrant**: it was registered
under four-eyes, and is approved under it.

Every manifest a plugin ever had is kept, by digest, with its status — `pending_approval`, `approved`,
`superseded` or `withdrawn` —, who registered it, who approved it and whether four-eyes applied: the
`manifests` of `GET /api/v1/report-plugins/{id}`, newest first. Reading the registry is for the roles that
read governance; the plugins switched on for a project (`GET /api/v1/projects/{id}/report-plugins`) are
listed to anybody who sees the whole project, images included — the people who will ask for its reports.

## Withdrawing a manifest

A signature cannot be unmade. When an image turns out to be wrong — a renderer that drops lines, a signer
compromised — the governor **withdraws** its digest, with a justification of 20 to 500 characters. The
digest never runs again and cannot be registered again; if it was the plugin's approved one, the plugin has
none until a fixed image — a new manifest — is approved. There is no delete: an id names every document the
plugin produced.

**Every document the digest produced is withdrawn with it, and kept.** Nothing is deleted nor rewritten: the
package stays exactly as it was handed out — evidence of what left — and its signature still verifies, since a
detached signature cannot be unmade. What changes is what the installation says of it:

- each run that used the digest carries `withdrawnAt`, `withdrawnBy` and `withdrawalJustification` on
  `GET /api/v1/projects/{id}/reports` and `…/reports/{runId}`;
- its download is still served, with the header `Vectispire-Document-Status: withdrawn` (`upheld` for every
  other document);
- the [status route](#does-the-installation-still-stand-by-a-document) answers `withdrawn` to anybody who asks
  about it.

The withdrawal is read from the manifest at every answer, not copied onto the documents, so it reaches every
document of the digest, whenever it was produced. **A run in hand when the digest is withdrawn signs nothing**:
the file it writes is discarded and the run fails `plugin_unavailable`, as a run claimed after the withdrawal
does. The audit entry `REPORT_PLUGIN_WITHDRAWN` counts the documents withdrawn.

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
`report-executor-unavailable`, rather than queued for nobody. Running on an agent is a later lot. The runs
queued before the worker was switched off are not left waiting: one nothing claims for seventeen minutes,
while no executor runs or starts anything, is failed `executor_unavailable`, and a run that was in hand is
failed `executor_lost` once its lease lapses — every instance looks for both every minute.

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
7. **checks the file on its bytes** against the manifest's `media_type` — see
   [below](#the-check-on-the-output) — and, if it passes, signs it and stores its package. A file that is not
   what was declared is **refused**, `output_refused`, and discarded unsigned.

A run is in exactly one state:

| State | Meaning |
|---|---|
| `pending` | Requested, waiting for the executor. |
| `running` | Claimed. Its executor renews its lease while it runs, however long the pull and the signature check take. A run whose lease lapses — the longest timeout a manifest may declare, the verifier's two minutes and ten minutes, seventeen minutes without a renewal — was left by an executor that stopped: it is failed, `executor_lost`, and not retried. Ask again. |
| `produced` | The plugin exited 0, wrote its file within its bounds, the file passed the check of its declared type, and its signed package is stored. The export it was given is kept with the run. |
| `failed` | `exit_code`, `timeout`, `output_full` (the directory filled or a file outgrew the ceiling), `output_missing`, `output_not_regular`, `export_too_large`, `requester_not_allowed`, `plugin_unavailable`, `executor_lost`, `executor_unavailable` (nothing claimed it for seventeen minutes while no executor worked), `executor_error` — with the detail, the plugin's own words for an exit code. |
| `refused` | Not started: `signature_unverified`, `unsigned`, `registry_authentication_required`, or `export_schema_unavailable` (the manifest reads an export major this installation no longer produces). Or started, and **`output_refused`**: the file it wrote is not what its manifest declares — the detail says what the check found. Its bytes are discarded; the run keeps their SHA-256 and size, and the signer that vouched for the image. Each is how a tampered plugin, or one nobody vouched for, shows itself. |

**One run of a plugin per project at a time**: a second request while one is pending or running is
refused, 409 `report-run-in-progress` — it is the one to wait for. The project's runs, newest first, are at
`GET /api/v1/projects/{id}/reports`, one at `GET /api/v1/projects/{id}/reports/{runId}`, for anybody who sees
the whole project: the state, its reason and detail, the manifest, image and signer it ran with, the export's
SHA-256 and size, the output's SHA-256, size and media type, the package's SHA-256 and the key it was signed
with, the instants requested, started, exported and finished.

**How many at once**: `VECTISPIRE_REPORT_CONCURRENCY`, two by default, on each instance of the control
plane; it looks for waiting runs every `VECTISPIRE_REPORT_INTERVAL` (10 s). **What is kept**: the export a
produced run was given, and its document's package, until the [evidence window](maintenance.md)
(`evidence_retention_days`) has passed — then their bytes go and the run keeps their digests; a failed or
refused run keeps nothing but itself and its reason. Deleting a project takes its runs, their exports and
their documents.

**On MySQL, a report's export is bounded by `max_allowed_packet` too.** The export is kept in one row,
written in one statement, and the driver sends it hex-encoded, at twice its size: on a server left at its
default packet of 64 MiB, a run whose export would pass about 32 MiB fails `export_too_large` before the
plugin runs, the detail saying so. Start MySQL with `--max-allowed-packet=160M` (the shipped composition
does) and every export up to the 64 MiB bound is kept. The bound is read from the server at each run;
PostgreSQL has none below 64 MiB. A download of the export (`GET …/export`) keeps nothing and is not
affected. **The document's package is a row of its own, under the same packet**: on a default server the file
a plugin may write is lowered from its manifest's `max_output_bytes` to about 31 MiB for the run, and a
plugin that fills it fails `output_full`, the detail saying why. The same `--max-allowed-packet=160M`
restores the manifest's ceiling, up to 50 MiB.

## The check on the output

Before anything is signed, the file is held to the type its manifest declares — **on its bytes**, not its
name:

| Type | What is checked |
|---|---|
| Office Open XML (`.xlsx`, `.docx`, `.pptx`) | A zip read through the guards the checklist template import applies — at most 2,000 entries, each inflating to at most 256 MiB and all to 512 MiB, none more than 100 times its compressed size, no name held twice, no archive inside — and two more: no absolute or `..` entry name, and a central directory that lists exactly the entries the file holds, in order (a recipient's program reads that directory). `[Content_Types].xml` present, the package's main part present and of the type the declared type requires. **No VBA project (`vbaProject.bin`), no macro sheet, no macro-enabled part, no ActiveX control** — a macro-enabled workbook renamed `.xlsx` is refused. No external relationship but a hyperlink: an attached template fetched from a server is how a document with no macro of its own runs one. |
| OpenDocument (`.ods`, `.odt`) | The same zip guards; the first entry `mimetype`, stored uncompressed, holding exactly the declared type; no `Basic/` or `Scripts/` directory. |
| PDF | Starts with `%PDF-1.` or `%PDF-2.`, and `%%EOF` within its last kilobyte. |
| CSV, plain text | Valid UTF-8, no NUL byte, and **nothing a browser would read as HTML or XML** — a page opening with `<!DOCTYPE html`, `<html`, `<script`, `<?xml`… is HTML under another name. |

Every type: not empty, and within the manifest's `max_output_bytes`.

**It is a type check, not a malware scan.** A PDF can carry JavaScript in a compressed object stream no byte
search finds. What bounds that is the signer every report plugin needs, the review of who may sign, and how
the file is served: always as an attachment, `X-Content-Type-Options: nosniff`, under
`Content-Security-Policy: sandbox`.

## The document, and how to verify it

`GET /api/v1/projects/{id}/reports/{runId}/document` downloads a produced run's **package**, a zip named
`report-<run>-<plugin>.zip`, to anybody who sees the whole project — the people who may read the run.
Audited `REPORT_DOWNLOADED`. It holds two files:

| File | What it is |
|---|---|
| `<output>` | The plugin's file, byte for byte — `summary.xlsx` for the manifest above. |
| `provenance.json` | An [in-toto](https://in-toto.io/) statement whose subject is the file's SHA-256, in a DSSE envelope signed by the platform's key, the key every Vectispire export is signed with. |

**The file itself is never signed.** The platform's key also signs VEX and CSAF documents and the project
export, raw. A detached signature over a plugin's bytes would have the platform sign whatever an image chose
to write, a document passing for one of Vectispire's VEX included. The file is therefore bound only by the
provenance's subject, a typed statement the platform writes itself. A package produced by `v0.11.0-rc.1` still
holds an `<output>.sig`: do not rely on it, verify the provenance.

**The provenance states** the run (id and the instants requested, started, exported and finished), the
project (id and name), the requester (account id and display name — never an e-mail address), the plugin
(id, manifest digest, image and image digest, and the signer cosign verified: identity and issuer, or the
SHA-256 of its key), the export (schema, version, id, SHA-256 and size), the file (name, media type,
SHA-256 and size), the product version and the id of the signing key. Every field is one the run recorded:
the same values are on `GET /api/v1/projects/{id}/reports/{runId}`.

**Verify it against a key you obtained separately**, never one handed to you with the document:

```bash
curl -fsS -H "Authorization: Bearer $VECTISPIRE_TOKEN" -o report.zip \
  "$VECTISPIRE_URL/api/v1/projects/12/reports/34/document"
curl -fsS -o vectispire-signing-key.pub "$VECTISPIRE_URL/api/v1/crypto/public-key.pub"
unzip report.zip
cosign verify-blob-attestation --key vectispire-signing-key.pub --insecure-ignore-tlog=true \
  --type https://vectispire.dev/report-provenance/v1 --signature provenance.json summary.xlsx
```

The last command checks the envelope's signature **and** that the statement's subject is this file's
digest. `--insecure-ignore-tlog=true` says only that the signature was never published to Sigstore's public
transparency log — Vectispire signs with its own key and publishes nothing; the key is what is checked. To
read the statement: `jq -r .payload provenance.json | base64 -d | jq .`

**What the signature means: provenance, not truth.** It says that *this installation gave this export, of
this project, at this instant, to this image, verified as built by this signer, at the request of this
account, and that these are the bytes the image wrote*. It does **not** say the document renders the export
faithfully: a renderer can leave a line out or invent one, and nothing short of reading every format back
into facts could tell. The statement says so itself (`claim`). What makes it checkable instead: the export is
kept with the run for the evidence window and its SHA-256 is in the statement, the image is pinned by digest,
and a deterministic renderer given the same export writes the same bytes — anybody who doubts the document
renders the export again with the same image and compares.

### Does the installation still stand by a document?

A signature that verifies says the installation produced the document; it cannot say the installation has not
since withdrawn the code that produced it. Ask, with the SHA-256 of the package you were given **or of the file
inside it**:

```bash
sha256sum summary.xlsx
curl -fsS -H "Authorization: Bearer $VECTISPIRE_TOKEN" \
  "$VECTISPIRE_URL/api/v1/report-documents/<sha256>"
```

```json
{
  "sha256": "9c1e…(64 hex)",
  "standing": "withdrawn",
  "productions": [{
    "matched": "output",
    "runId": 34, "projectId": 12, "projectName": "Checkout",
    "pluginId": "quarterly-summary",
    "manifestDigest": "5be0…", "imageDigest": "sha256:4f2d…",
    "outputMediaType": "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet",
    "outputSha256": "9c1e…", "packageSha256": "0d7a…",
    "producedAt": "2026-10-01T09:12:44.120Z",
    "signingKeyId": "e3b4…",
    "documentKept": true,
    "withdrawnAt": "2026-10-03T14:02:10.551Z", "withdrawnBy": "governor",
    "withdrawalJustification": "The renderer dropped accepted issues from the sheet."
  }]
}
```

| `standing` | Meaning |
|---|---|
| `upheld` | Produced and signed here, by a manifest that was not withdrawn. |
| `withdrawn` | Produced and signed here, and the manifest that produced it has since been withdrawn — when, by whom and why are on the production. |
| `unknown` | Nothing you may see has that digest. |

**Who is answered.** Any signed-in account — no integration key —, about the documents of the projects it sees
whole, images included: the people who may read the runs. **A document of a project you do not see whole, of a
deleted project, and a digest never produced here all answer `unknown`, in the same words**: a different answer
for "exists, but not yours" would tell anybody holding a copy which project it came from. A holder without that
grant asks somebody who has it.

`productions` lists the runs that produced it, newest first: one for a package, which names its run; possibly
more for a file, since a deterministic renderer may write the same bytes twice — `upheld` as long as one of them
stands. A document whose bytes the [evidence window](maintenance.md) purged is still answered, with
`documentKept: false`: copies of it are still in the world. A run whose output was refused signed nothing, and
is not a document here. The digest is 64 hexadecimal characters, either case, a `sha256:` prefix accepted;
anything else is a 400. The question is not audited: it shows nothing the runs do not.

## The demonstration plugin

Vectispire publishes one report plugin of its own, **`vectispire-report-demo`**: a reference to read, a
starting point to copy, and the contract's executable test (decision 0035 §6). Nobody is expected to keep
it switched on.

**What it renders**: `summary.xlsx`, three sheets drawn from the export and from nothing else —

| Sheet | Content |
|---|---|
| `Summary` | The project, its solution, who asked, the installation, the Vectispire version, the export's instant and id; the gate's last verdict per target (`never judged` where there is none); the export's counts per type, severity, state and triage status, and their total. |
| `Issues` | One row per issue the export lists, in its order: target, type, severity, identifier, title, tool, component, path and line, first and last seen, KEV, EPSS, CVSS, fix versions, the triage decision with who made it and when, the remediation deadline. |
| `Checklists` | One row per line of each checklist the export embeds: the template, the revision and its status, the answer, its comment, who gave it and whether it was a person or Vectispire, the measurement, the proofs still standing named by file name and SHA-256. |

A value the export leaves null stays an empty cell — never a zero nobody measured. It reads every 1.x export
and ignores what it does not know; an export of another schema or another major makes it exit 2, one with a
part missing exit 1, each with its reason on stderr — which the run records as its detail. Its workbook passes
the [check on the output](#the-check-on-the-output): every build of Vectispire checks it.

**The same export gives the same bytes.** The workbook carries no "now": the instant it states is the
export's, every zip entry is dated 1980-02-01, the parts go in one order. A run's output SHA-256 can
therefore be checked by anybody holding the export it was given, by rendering it again with the same image.
This version keeps that export with the run and does not serve it yet; an
[export](../guide/exports.md#project-export) downloaded later is another document — its own id and instant —
and renders another workbook. To see the property for yourself, download one export, put it in `in/` as
`export.json`, and render it twice —

```bash
docker run --rm --network none --read-only --user "$(id -u):$(id -g)" \
  -v "$PWD/in:/report/input:ro" -v "$PWD/out:/report/output" \
  ghcr.io/asmolabs/vectispire-report-demo@sha256:<digest> \
  --in /report/input/export.json --out /report/output/summary.xlsx
sha256sum out/summary.xlsx
```

**Registering it.** Each release attaches the plugin's manifest, `vectispire-report-demo.manifest.json`, with
its Sigstore bundle. The manifest names the image by the digest the release pushed and signed, and that
release's signing identity — `https://github.com/asmolabs/vectispire/.github/workflows/release.yml@refs/tags/<tag>`,
issuer `https://token.actions.githubusercontent.com`. Verify it before you paste it anywhere:

```bash
cosign verify-blob \
  --bundle vectispire-report-demo.manifest.json.cosign.bundle \
  --certificate-identity "https://github.com/asmolabs/vectispire/.github/workflows/release.yml@refs/tags/<tag>" \
  --certificate-oidc-issuer "https://token.actions.githubusercontent.com" \
  vectispire-report-demo.manifest.json
```

then, as the platform governor, `POST /api/v1/report-plugins` with the file as the body. It looks like this,
the image and the identity being the release's:

```json
{
  "id": "vectispire-report-demo",
  "name": "Vectispire demonstration summary",
  "image": "ghcr.io/asmolabs/vectispire-report-demo@sha256:<digest>",
  "export_schema": 1,
  "arguments": ["--in", "{input}", "--out", "{output}"],
  "output": "summary.xlsx",
  "media_type": "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet",
  "max_output_bytes": 20971520,
  "timeout_seconds": 120,
  "signature": {
    "identity": "https://github.com/asmolabs/vectispire/.github/workflows/release.yml@refs/tags/<tag>",
    "issuer": "https://token.actions.githubusercontent.com"
  }
}
```

Have it approved (by somebody else with four-eyes on), switch it on for a project and request a report, as
above. The image is public on GHCR: the control plane needs to reach `ghcr.io` and Sigstore's public
transparency log, and no registry credential. An installation that mirrors its plugins
(`VECTISPIRE_PLUGIN_REGISTRY`) copies the image **with its signature**.

**Writing your own from it.** The source is
[`vectispire-java/vectispire-report-demo`](https://github.com/asmolabs/vectispire/tree/main/vectispire-java/vectispire-report-demo):
a Java program depending on nothing of Vectispire — a plugin knows the export's
[schema](../guide/exports.md#project-export), not the platform — built into a distroless image by Jib. What
to keep from it whatever you write yours in: read the export as a tree and ignore what you do not know;
refuse another major rather than guess; never render an absent part as an empty one; write the file once,
whole; take no instant from the clock.

## What is recorded

Every gesture is written to the [audit log](audit-log.md) — `REPORT_PLUGIN_REGISTERED`,
`REPORT_PLUGIN_UPDATED`, `REPORT_PLUGIN_APPROVED`, `REPORT_PLUGIN_ENABLED_CHANGED`,
`REPORT_PLUGIN_ACTIVATED`, `REPORT_PLUGIN_DEACTIVATED`, `REPORT_PLUGIN_WITHDRAWN`, each naming the manifest
digest — and sent to the [SIEM](../integrations/siem.md#event-catalogue) as `VECTI-SEC-031`. A gesture that
changes nothing — the same manifest again, a plugin already switched on — records nothing.

A report run records `REPORT_REQUESTED` when it is asked, `PROJECT_EXPORTED` when the export reaches the
plugin's container (sent to the SIEM as `VECTI-SEC-032`, the export's SHA-256 first), then
`REPORT_PRODUCED` (the output's, the package's, the manifest's and the export's digests, and the signing
key), `REPORT_FAILED` or `REPORT_REFUSED` — each in the requester's name. **A refusal is sent to the SIEM as
`VECTI-SEC-033`**, an output refused included (its SHA-256 in the entry): an image without a verified signer
asked to run, or a file that is not what it declared, is how a tampered plugin shows itself. A failure for an
ordinary reason is audited, not signalled. A download records `REPORT_DOWNLOADED`, with the output's and the
package's SHA-256, in the downloader's name — and, for a withdrawn document, that it was served as withdrawn. A
withdrawal's `REPORT_PLUGIN_WITHDRAWN` names the number of documents withdrawn with the digest, then the
justification.

## Refusals

| Answer | When |
|---|---|
| 400 | A manifest refused — the `detail` names the first thing wrong; a withdrawal without its justification; a document status asked with anything but a SHA-256. |
| 403 | A role that may not make the gesture. |
| 404 | A plugin, or a digest of it, that does not exist; a project that does not exist or that you do not see whole (`Project not found.`); a report asked of a plugin not switched on for the project, in the same words whether it exists or not; the document of a run that did not produce, or whose bytes the evidence window purged — the run keeps its digests. |
| 409 `report-plugin-id-taken` | The id is registered already. |
| 409 `report-plugin-four-eyes` | Four-eyes is on and you registered this digest. |
| 409 `report-plugin-not-pending` | The digest is not awaiting approval: approved, superseded or withdrawn. |
| 409 `report-plugin-not-approved` | Switching on, or asking a report of, a plugin with no approved manifest. |
| 409 `report-plugin-disabled` | Asking a report of a plugin the governor disabled. |
| 409 `report-executor-unavailable` | Asking a report where the built-in worker is switched off: this version runs report plugins on the control plane only. |
| 409 `report-run-in-progress` | A report of this plugin for this project is already pending or running. |
| 409 `report-plugin-withdrawn` | Registering again, or withdrawing again, a digest already withdrawn. |
| 409 `report-plugin-changed` | Another gesture changed the plugin while yours was being decided: read it again. |
