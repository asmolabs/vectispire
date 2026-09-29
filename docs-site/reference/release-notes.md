# Release notes

## Next release (after 0.9.0)

Not tagged yet. Read **Before you upgrade** first: four of its points stop something working
until an operator acts, on purpose.

### Before you upgrade

**SIEM signature identifiers are renamed from `ZAN-SEC-nnn` to `VECTI-SEC-nnn`, all at once.** The
number and the meaning of every event stay the same; only the prefix changes, and no event carries
the old one any more — not even those still queued when you upgrade, since the identifier is
written when an event leaves. **A correlation rule, alert or dashboard filtering on `ZAN-SEC-` stops
matching, without any error.** Before upgrading, change each one to the new prefix, or to match both
while you roll out. The CEF `signatureId`, the syslog `MSGID` and the webhook's JSON all carry it.
See [SIEM](../integrations/siem.md#event-catalogue).

| Before | From this version | Event |
|---|---|---|
| `ZAN-SEC-002` | `VECTI-SEC-002` | Actively exploited vulnerability (KEV) detected |
| `ZAN-SEC-003` | `VECTI-SEC-003` | Security gate refused a build |
| `ZAN-SEC-005` | `VECTI-SEC-005` | Finding settled by triage |
| `ZAN-SEC-006` | `VECTI-SEC-006` | MFA backup code consumed |
| `ZAN-SEC-007` | `VECTI-SEC-007` | Sign-in failure ceiling reached |
| `ZAN-SEC-008` | `VECTI-SEC-008` | MFA failure ceiling reached |
| `ZAN-SEC-009` | `VECTI-SEC-009` | Bearer token failure ceiling reached |
| `ZAN-SEC-010` | `VECTI-SEC-010` | Account privileges or credentials changed |
| `ZAN-SEC-011` | `VECTI-SEC-011` | Team access grant changed |
| `ZAN-SEC-012` | `VECTI-SEC-012` | API key issued |
| `ZAN-SEC-013` | `VECTI-SEC-013` | API key revoked |
| `ZAN-SEC-014` | `VECTI-SEC-014` | Agent declared or its credentials changed |
| `ZAN-SEC-015` | `VECTI-SEC-015` | Agent result refused: attestation did not verify |
| `ZAN-SEC-016` | `VECTI-SEC-016` | Four-eyes triage request approved |
| `ZAN-SEC-017` | `VECTI-SEC-017` | Four-eyes triage request refused |
| `ZAN-SEC-018` | `VECTI-SEC-018` | Audit log integrity verification failed |
| `ZAN-SEC-019` | `VECTI-SEC-019` | Security-relevant setting changed |
| `ZAN-SEC-020` | `VECTI-SEC-020` | Agent sealing key refused: signature or generation did not verify |
| `ZAN-SEC-021` | `VECTI-SEC-021` | Analysis plugin registered, changed or activated |
| `ZAN-SEC-022` | `VECTI-SEC-022` | SARIF import source declared or changed |
| `ZAN-SEC-023` | `VECTI-SEC-023` | SARIF import refused: undeclared source, scope or tool |
| `ZAN-SEC-024` | `VECTI-SEC-024` | Checklist template version published or retired |
| `ZAN-SEC-027` | `VECTI-SEC-027` | Report import refused: undeclared source, kind or scope |
| `ZAN-SEC-999` | `VECTI-SEC-999` | SIEM connector health check |

**Delegated scans stop until each delegating agent is updated and has a pinned signing key.**
An agent in `delegated` credentials mode receives a repository's SSH key or HTTPS token sealed for
its sealing key. That key is now accepted only when the agent signs it with the Ed25519 key an
administrator pinned ([decision 0031](https://github.com/asmolabs/vectispire/blob/main/docs/architecture/en/decisions/0031-a-sealing-key-is-believed-only-on-the-pinned-key.md)),
and no credential is ever sent in the clear, over TLS or not. Until an agent is updated **and** its
signing key is pinned, it claims no scan that needs a credential — those scans wait, pending and
costing no attempt, for an executor that can take them. Agents in `local` mode, image scans and
repositories without a credential are not affected. Before upgrading: pin each delegating agent's
signing key on the **Agents** screen, then update the agents. See
[Agents](../administration/agents.md).

**Attempts counted by withheld claims are given back once, at the first start.** Before this
version each poll of such an agent took a scan needing a credential — one attempt — and put it
back, so a scan nothing had tried could fail as "lease exhausted" at its first real takeover. On a
database with a `delegated` agent, the waiting scans of repositories carrying a credential that no
agent was ever handed (no `AGENT_CREDENTIAL_SENT`) have their attempts reset to 0, recorded once — by one instance, when several start together — as
`SCAN_ATTEMPTS_REPAIRED`. Not touched: a scan delivered at least once, running, completed or already
failed — run a failed one again by hand — image scans, and repositories without a credential.

**Secrets reach the containers as files, not as environment variables.** The shipped
`docker-compose.yml` now hands `ENCRYPTION_KEY`, the database passwords, the bootstrap password,
`VECTISPIRE_SIGNING_KEY` and the OIDC client secret over as Compose secrets under `/run/secrets/`:
a container's environment is readable by anything that can inspect it through the Docker daemon.
If you run your own composition or manifests, move these to files the same way
(`ENCRYPTION_KEY_FILE`, `spring.config.import: optional:configtree:/run/secrets/`). Your `.env`
must declare `VECTISPIRE_SIGNING_KEY` and `VECTISPIRE_OIDC_CLIENT_SECRET`, empty if unused:
Compose stops with the variable's name rather than dropping a signing key an installation was
using, because a replaced key makes every document already signed unverifiable.

**The database is no longer published on the host.** The `127.0.0.1:3306` port mapping is gone
and the database sits on an internal network. A tool that connected to it from the host needs
`docker compose exec` or a network of its own.

**Every request body has a ceiling.** 1 MB by default (`VECTISPIRE_MAX_BODY_DEFAULT`); routes
with their own keep it: VEX 16 MB, SARIF imports 32 MB, rule-set uploads 64 MB, agent results
256 MB. A client sending a larger body to an ordinary route now gets a 413.

**The KEV feed is CISA's catalogue, read from the network.** It was a list of ten records typed
into the code; the control plane now reads `known_exploited_vulnerabilities.json` every six hours
and from the **Threat Intelligence** settings tab, and a scan asks the stored copy instead of
downloading it. The control plane needs to reach `www.cisa.gov` — or set `VECTISPIRE_KEV_URL` to a
mirror (and `VECTISPIRE_KEV_ALLOW_PRIVATE=true` if it is on a private network), see
[Configuration](configuration.md#threat-intelligence). The upgrade empties the old feed: until the
first synchronisation, the status says *never synchronized* and a scan marks nothing as actively
exploited. That first synchronisation also **un-flags** open issues whose CVE the catalogue does not
list, including those the typed-in list had flagged.

**Scans need a host directory mounted at the same path — the shipped composition now makes one.**
The scanners are containers the Docker daemon starts, and it resolves what it mounts into them on
its own host; the composition kept the scans' workspaces in the control plane's own `/tmp`, so every
scanner received an empty directory and **no scan of the shipped `docker-compose.yml` ever
succeeded**. It now mounts `VECTISPIRE_WORK_DIR` (default `/var/lib/vectispire/work`, some 3 GB for
the vulnerability database) at the same path and prepares it with a one-shot `work-dir` service;
`docker compose up` does it, nothing to do but have the disk. If you run **your own composition or
manifests**, mount a host directory at the same absolute path and set
`JDK_JAVA_OPTIONS=-Djava.io.tmpdir=<path>` — see [Installation](../getting-started/installation.md)
and [Configuration](configuration.md#scan-workspaces). Scanners now run as the workspace's owner
rather than as root, which could not read it.

**Images built from the `Dockerfile` run as 1000:1000**, like the published ones. If you built your
own and its audit mirror volume already exists, hand it over once:
`docker run --rm -v vectispire_audit:/a alpine chown -R 1000:1000 /a`.

**SSH clones with a deploy key work through the composition — and it no longer mounts your
`~/.ssh`.** Through the shipped `docker-compose.yml` no such clone had ever succeeded: the images
have no account for their user, the home was `/`, and the known-hosts file could not be created
(*"The known-hosts file could not be prepared: /.ssh"*, shown as *"The clone of … failed."*).
Behind that, the host-key check refused every host it had not met before (*"Server key did not
validate"*) — outside the composition too, unless the host was already in the running user's
`~/.ssh/known_hosts`. Now a first contact is recorded and a changed key refused, the process's home
is `$VECTISPIRE_WORK_DIR/home` (the agent's under `$VECTISPIRE_AGENT_WORK_DIR`), and the
`${HOME}/.ssh` mount is gone, with `VECTISPIRE_HOST_SSH` now `false` in the composition. What to do:

- Nothing, if your private repositories carry a deploy key: `docker compose up` creates the home.
- If you relied on the mount — only images you built from the `Dockerfile` ever read it — attach a
  deploy key to each of those repositories on the **SSH keys** screen. A `local` agent of the
  `with-agent` profile clones with `$VECTISPIRE_AGENT_WORK_DIR/home/.ssh`, empty unless you put a
  dedicated key there.
- **Your own composition or manifests:** add `-Duser.home=<work dir>/home` to `JDK_JAVA_OPTIONS`.
  Without it, the images now fall back to `HOME=/home/vectispire`, which a plain `docker run` can
  write but which is lost with the container — hosts recorded there are met again as new.
- **Outside a container,** a clone with a key no longer reads the running user's `~/.ssh/config`:
  a `Host` alias, `Port` or `ProxyJump` there stops applying to it. Put the real host and port in
  the repository URL. Hosts already in `~/.ssh/known_hosts` stay checked against it.

See [Over SSH: the forge's host key](../guide/repositories.md#ssh-host-keys) for pinning the keys
in advance.

**EPSS scores come from FIRST's daily file, and scans no longer call `api.first.org`.** Each scan
used to send the CVE it had found to FIRST's API — which told a third party what each repository was
vulnerable to — and on an estate without outbound access every score stayed unknown. The control
plane now downloads `epss_scores-current.csv.gz` once a day and from the **Threat Intelligence**
tab, stores it (some 380,000 rows, a few seconds on MySQL and PostgreSQL), refreshes the open
issues' scores from it, and scans read the stored copy. It needs to reach
`epss.empiricalsecurity.com` — or set `VECTISPIRE_EPSS_URL` to a mirror (and
`VECTISPIRE_EPSS_ALLOW_PRIVATE=true` on a private network), see
[Configuration](configuration.md#threat-intelligence); an allow-list that opened `api.first.org` for
scans can close it. Until the first synchronisation, which the first maintenance turn runs half a
minute after the start, a new finding gets no EPSS score — unknown, not zero — and scores already
on issues stay until the file replaces them.

**A permanent failure no longer retries; transient ones wait 1, then 5, then 15 minutes.** A scan
that could not run — on an agent or on the built-in worker — fails at once, on its first attempt and
with the reason, when another attempt would meet the same refusal: a host key that changed, an
authentication refused, a repository, a branch or a sub-path that is not there, a credential that
will not open, a URL the clone refuses. Anything else — the network, a timeout, a daemon that did not
answer, a lapsed lease — goes back to the queue with the attempt counted and cannot be claimed again
for one minute after the first attempt, five after the second, fifteen after any later one
(`VECTISPIRE_SCAN_RETRY_DELAYS`, see [Configuration](configuration.md#scan-queue)), and fails at the
third. Before, a lone agent retook the scan it had just reported at its next poll and spent the three
attempts in seconds; the built-in worker failed a scan for good at its first error, with the raw
message. A sub-path the clone does not hold now fails the scan before any scanner runs, where each
analyser used to report it.

**Signing a checklist off needs the signing key.** The sign-off now renders and signs the checklist's
document in the same transaction. An installation with neither `ENCRYPTION_KEY` nor a configured
`vectispire.signing.key` answers 412 there, as every other signed export already did — and a sign-off
that cannot be signed is not recorded. See [Security checklists](../guide/security-checklists.md).

**Schema migrations V32 to V55 run at start**, on MySQL and PostgreSQL. Back up the database
first, as for any upgrade — [backup and restore](https://github.com/asmolabs/vectispire/blob/main/docs/en/BACKUP_AND_RESTORE.md).

### Changes an integration can see

- **A compliance verdict can be `NO_DATA`.** Until a target has been scanned successfully, every control
  that reads the estate — and every framework — reads `NO_DATA` with a score of zero, which is no
  measurement, on `GET /api/v1/compliance/summary`, the framework detail, the evidence bundle's
  `01_compliance_frameworks.json` and the statement of applicability's `measured`; a target never
  scanned reads `NO_DATA` in the matrix, with no `frameworkScores`. It read *compliant* on zero findings
  nobody looked for, and ISO 27001 A.8.8 *non-compliant* on "1 target(s) have never been scanned" with
  no target registered. The SoA's `divergence` gains `UNEVIDENCED`, between `OVERSTATED` and
  `UNDERSTATED`, for a line evidenced here with nothing measured — it read `CONSISTENT`. No monthly
  capture is written for a framework with nothing measured.
- **A checklist answer names its author's kind.** Every answer in a checklist view, a line's history
  and `checklist.json` carries `answeredByKind` — `person`, or `system` for an answer Vectispire gave
  from the line's measurement — and `withdrawn`, true only on the history row by which Vectispire
  withdrew its own answer. Tell an automatic answer by `answeredByKind`, never by `answeredBy`: it
  reads `Vectispire`, a name an account may also hold. `checklist.json` is statement `form` 2 for it.
- **Every error is an RFC 9457 problem** (`application/problem+json`) with a `detail` meant to be
  shown — see [API errors](errors.md). Refusals that carried no sentence now do: an unknown route,
  405, 406, 415, an unreadable body, the sign-in refusals, the 401 of a missing or invalid
  credential (which had no body) and the 403 of a role (which had the container's
  `{timestamp, status, error, path}`). The three rate limiters answered `{"message": …}`: the
  sentence is now `detail`, and a new `retryAfterSeconds` repeats the `Retry-After` header. A
  client reading `message` must read `detail`. A URL refused before the application — by the
  security firewall (`//`, an encoded `..`) or by the servlet container (a lone `%`), which
  answered its own HTML page — is a 400 problem too.
- **A 500 no longer quotes the failure.** An error nobody wrote a message for — including one that
  used to answer 400 or 404 with a library's own words ("For input string", "No value present",
  "No enum constant …") — is a 500 whose `detail` gives a `correlationId`, logged with the error.
  The refusals Vectispire writes keep their status and their sentence.
- Granting a repository or an image that does not exist, or that the granting administrator
  cannot see, is refused with a **404**; a grant naming a missing project was a 400 and is a 404.
- An **API key restricted to a target** acts on that target only; a restriction no route would
  enforce is refused when the key is issued. A key restricted to a deleted target is revoked with
  it, and each revocation is audited under the key's id.
- Integration keys act for the account they belong to; an agent's key is confined to the agent
  routes (403 elsewhere).
- The threat-intelligence sync is audited as `THREAT_INTEL_SYNCED`, no longer `SETTING_UPDATED`;
  a change of certified scope is audited as `CERTIFIED_SCOPE_CHANGED`. A filter on the old
  operation stops finding syncs.
- Recording a gate verdict is a write: the auditor and the platform governor are refused.
- `GET /api/v1/threat-intel/status` and both sync routes answer the catalogue's version, its
  release date, the last attempt and its error; `status` is `NEVER_SYNCED`, `SYNCED` or `FAILED`.
  A sync that cannot read the catalogue answers **200** with `FAILED` and the reason, keeps the
  catalogue in use, and is audited as a failed `THREAT_INTEL_SYNCED`. `GET /api/v1/epss/cve/{id}`
  answers from the stored catalogue and EPSS file only — a **404** for a CVE neither holds.
- The same routes answer the EPSS file's state under `epss`: its status, model version, score
  date, the CVE it scores, the last attempt and its error, and `inProgress` while a synchronisation
  runs. Both sync routes read the catalogue and the EPSS file, and write one `THREAT_INTEL_SYNCED`
  entry for each. `epss_score` and `epss_percentile` leave `t_threat_intel_feed` (V45).
- An OWASP review is recorded before the model is asked: `GET …/owasp-review` may answer
  `status: running` while another request waits, and reads `failed` once the model's timeout has
  passed with nobody left to settle it.
- New finding types `plugin` and `imported`, and new fields on issues and scans (`tool`,
  `toolName`, `toolVersion`, `importSource`, a scan's `plugins[]`). The OpenAPI document in the
  repository is the contract.
- **Reachability is not computed, and says so.** An issue's `reachability` and `reachableSymbols`
  stay in `GET /api/v1/issues` and `GET /api/v1/issues/{id}`, marked deprecated in the OpenAPI
  document: always `UNKNOWN` and null, since nothing analyses the call graph. Removed where only
  the interface read them: `reachableEpssCount` and each ranked issue's `reachability` from
  `GET /api/v1/epss/priorities`, `reachability` from each target of the blast radius, the
  `reachability` key of an attack-path node's `metadata`, and `deterministic.exposure` from the AI
  advisor's answer. `POST /api/v1/ai-advisor/explain/cve/{id}` ignores a `reachability` parameter.
  In OpenVEX, a finding awaiting triage reads "Awaiting contextual triage." rather than
  "Awaiting reachability confirmation and contextual triage."
- **The AI advisor's `deterministic.activelyExploited` is `deterministic.kev`**: `LISTED`,
  `NOT_LISTED` or `UNKNOWN`, read from the stored CISA catalogue — the boolean said false before
  any catalogue had been read. `deterministic.packageName`, `currentVersion`, `targetVersion` and
  `remediation.suggestedVersion` are null when nothing is recorded, rather than "the component",
  "current" or "the fixed version", and a model's advice no longer carries a VEX justification.
- **`POST /api/v1/ai-advisor/explain/cve/{id}` no longer reads `packageName`, `currentVersion` or
  `fixVersion`**: they were printed as the advice's facts on the caller's word alone. A client still
  sending them is answered as if it had not; the route accepts no integration key. A CVE no issue
  you can see carries is explained from the stored feeds alone, and its VEX suggestion is
  `under_investigation` even when CISA lists it — it said `affected`, about an estate nothing showed
  to carry it. An issue's suggested upgrade is one command for the ecosystem its purl names (Maven,
  npm, PyPI, Cargo, NuGet, Composer, Go), with a Maven `<dependency>` only for Maven, and none when
  the purl is missing or names another ecosystem — it offered `mvn` and `npm` together whatever the
  component. Both explain routes take `language` (`en`, `fr`; English when absent, anything else a
  400): the model answers in the screen's language, where it answered in French for everyone.
- **The EPSS generation a file replaces is kept until the next one is applied** (V47,
  `epss_previous_generation`), so a scan enriched during a switch no longer finds its scores gone;
  `t_epss_score` holds two files' rows between synchronisations, some 760,000.
- **The agent protocol has a seventh call**, `POST /api/v1/agent/jobs/{id}/failure`: a scan the agent
  claimed and could not run is reported at once with its reason — requeued with the attempt counted,
  or failed at the last — instead of waiting twenty minutes for its lease to lapse. The claim's answer
  carries the `attempt` the report names; an older agent reads past it. Signed like a result when the
  agent's key is pinned, audited as `AGENT_SCAN_FAILED`. An agent of this version falls back to the
  lapse against an older control plane (404). See [Agents](../administration/agents.md#when-a-scan-cannot-run-on-an-agent).
- **The failure report takes a `kind`**, `permanent` or `transient` (V48 adds `t_scan.not_before`): a
  permanent failure fails the scan at once, a transient one waits before its next claim. Absent — an
  older agent — or unknown reads as transient. The answer adds `permanent` and `retryAt`, the instant
  the scan can be claimed again. A scan's summary (`GET /api/v1/scans`, `GET /api/v1/scans/{id}`) adds
  `notBefore`, set on a waiting scan whose last attempt could not run.
- **A scan's detail adds `examinedTypes`** (V49 adds `t_scan.examined_types`): the built-in finding
  types whose step produced in that scan, as wire names — `vulnerability`, `secret`, `iac`, `sast`,
  `quality`, `eol`, `license`. A type left out was not examined, and its issues were left as they
  were. `null` means *not recorded* — a scan from before this version, or one that never ran — and
  never *examined nothing*, which is `[]`. Plugins stay in `plugins`, in their three states.
- **A declared source states its `kinds`** (V50 adds `t_sarif_source.kinds`): `sarif`, `coverage`,
  `test_report`. A declaration without them is `sarif` alone, and every source declared before this
  version stays a SARIF source. `tools` is required with `sarif` and refused without it.
- **Switching four-eyes on needs two accounts that can publish a checklist template** — the platform
  governor, an administrator or a CISO — besides an account that can approve a triage: under
  four-eyes a template's author may not publish it. The setting is refused with a sentence saying
  so; a deployment where it is already on is not changed. See [Four-eyes](../administration/four-eyes.md).
- **Switching four-eyes on also needs two accounts that can approve** — an administrator, a CISO or
  a security champion: under four-eyes a project's checklist is signed off by an approver who wrote
  none of it, and the approver who filled one in cannot sign it. Refused with a sentence saying so; a
  deployment where the setting is already on is not changed. See [Four-eyes](../administration/four-eyes.md#signing-a-checklist-off).
- **A 409 may name its cause** in the problem's `type`, `urn:vectispire:problem:<cause>`, where a route
  refuses for several reasons that call for different gestures — the project checklists' routes do
  (`checklist-changed`, `checklist-line-changed`, `checklist-four-eyes`, `checklist-incomplete`, …),
  and so do the checklist templates' (`checklist-template-changed`, `checklist-template-not-draft`,
  `checklist-template-has-draft`, … and `checklist-four-eyes`, which means the same there — see
  [Checklist templates](../administration/checklist-templates.md#refusals-for-scripts-and-integrations)).
  A problem without a cause keeps `about:blank`; the `detail` is unchanged. A `checklist-incomplete`
  problem also names its lines as data, in a `lines` member — each line's `itemId`, `position` and
  `problems` (`unanswered`, `evidence_required`, …) — so that a client points at them in its own
  language rather than parsing the English sentence.
- **A checklist's measured lines add two 409 causes and change three routes.** A submission answers
  `checklist-measurement-contradicted` when a line is answered *yes* where its measurement fails, and a
  sign-off `checklist-measurement-changed` when a line's measurement is no longer what the submission
  stored — each naming its lines in the problem's `lines` member (`itemId`, `position`, `answer`,
  `outcome`, `reason`, and for the sign-off `submittedOutcome`, `submittedReason`). A *yes* where a
  measurement has no data needs a comment and a proof at submission: `checklist-incomplete` names them
  `comment_required` and `evidence_required`, the tokens it already had. The answer route takes an
  optional `measurementDigest`; a checklist line's view gains `rule`, and a template version's items
  and each measurement carry their `boundRule`, structured as the rules route takes it. On a draft, a
  line's `problems` and the checklist's `readyToSubmit` count what its measurement keeps from a
  submission — `measurement_contradicted` for a *yes* against a failure, the comment and proof a *yes*
  without data needs — judged as the submission judges it, so a client needs no second request to know
  whether it will pass. A measurement's evidence names each repository, `repositoryName` beside
  `repositoryId` (null for one no longer in the project). The closed vocabularies of the checklist views
  are enumerated in the OpenAPI document, and the two problems' `lines` members have their schemas
  (`ChecklistIncompleteProblem`, `ChecklistMeasurementProblem`). A SARIF import's view gains `toolKeys`
  (V53): the tool keys its runs were accepted for, a sorted list, `null` for an import accepted before.
- **A SARIF import's `tools` is a list of strings**, one `name version` per run in the report's order —
  it was one comma-joined string, on the upload's answer and on `GET /api/v1/repositories/{id}/sarif-imports`.
  A comma inside a tool's version is written as a semicolon, so a comma always separates two tools. SARIF
  imports are new in this release, so no 0.9.0 integration read the string; a script written against a
  development build that split it must read the list. **`toolKeys` is a list too**, sorted — it was the
  keys joined by commas — and stays `null`, never an empty list, for an import accepted before V53. On the same lists, a plugin activation names its
  project — `projectName`, `solutionId`, `solutionName` beside `projectId` — and a declared source its key,
  `apiKeyName` beside `apiKeyId` (`null` once the key is revoked); a scan's `plugins[].state` is enumerated
  in the OpenAPI document: `produced`, `not_applicable`, `absent`.
- **A new key scope, `report_import`**, never granted by default: the scope of the coverage and
  test-report uploads, apart from `sarif_import` so that a key sending a coverage figure never deposits
  findings.

### New

- **Vectispire answers the lines it measures** (V56 adds `answered_by_kind` and `withdrawn` to
  `t_checklist_answer`). On a draft checklist, a line bound to a rule is answered *yes* when its
  measurement passes and *no*, with the measurement as its comment, when it fails — when a scan
  completes or a SARIF, coverage or test report is accepted for one of the project's repositories, and
  when the checklist is opened, moved or reopened; no data answers nothing, and withdraws an answer of
  Vectispire's that rested on data it no longer has. The author is Vectispire, no account: marked
  *automatic* on the screen, in the history, the `Evidence` sheet and `checklist.json`, audited as
  `CHECKLIST_ANSWERED` with no user. A person's answer is never replaced; Vectispire replaces its own
  only when what it states changes — its value, or its comment carrying the figures — so a new scan
  measuring the same thing writes nothing. Submitting
  and signing off are unchanged — people, under four-eyes, and a *yes* on a line asking for a proof
  still needs it. **On by default**: the platform governor's setting `checklist_auto_answer` returns to
  answers by people only. Checklists already in draft are answered at their project's next scan, import
  or opening. See [Security checklists](../guide/security-checklists.md#automatic-answers).
- **The measured lines of a checklist answered as measured, in one act.**
  `POST /api/v1/projects/{id}/checklists/{revision}/answers/as-measured`, body
  `{ edition, lines: [{ itemId, measurementDigest }] }`, on a draft: each line named — as shown, with
  the digest read — that is unanswered, still on that evidence and passing is answered *yes* by the
  caller, resting on that measurement — the one click of a measured line, for every line shown at once,
  each answer a row of its history and a `CHECKLIST_ANSWERED` entry of its own. Lines already answered,
  named lines whose evidence moved, passing lines not named, lines without data and failing lines —
  whose *no* needs a comment a person writes — are left alone and returned in `skipped` with their
  reason (`already_answered`, `measurement_changed`, `not_shown`, `no_data`, `needs_comment`). The whole-project
  guard of every checklist route; anything written since the edition read refuses the act
  (`checklist-changed`). See [Security checklists](../guide/security-checklists.md#measured-lines).
- **A signed-off checklist is a signed document** (V55 adds `t_checklist_document`).
  `GET /api/v1/projects/{id}/checklists/{revision}/document` returns a zip: `checklist.xlsx`, the
  organisation's own workbook with only the answer, comment and header cells written and an `Evidence`
  sheet added, and `checklist.json`, the same statement machine-readable — each with a detached
  signature when the revision is signed off. That package is rendered and signed inside the sign-off
  and served as stored, so next year's download is the document that was signed; a draft or submitted
  revision renders on request, unsigned, and says so. `@AcceptsApiKey(EXPORT)`, audited
  `CHECKLIST_EXPORTED`. Verify with
  `cosign verify-blob --key vectispire-signing-key.pub --insecure-ignore-tlog=true --signature checklist.xlsx.sig checklist.xlsx`
  — [Security checklists](../guide/security-checklists.md).
- **Checklist lines measured by the evidence that ran** (V54 adds `t_checklist_measurement`). A security
  lead binds a rule to a draft's line (`PUT /api/v1/checklist-templates/{slug}/versions/{ordinal}/rules`,
  on the `revision` read, audited `CHECKLIST_TEMPLATE_RULES_BOUND`): dependency analysis, a findings
  threshold over built-in steps, plugins or imported tools, coverage, a test suite passed, or component
  versions from an explicit list — each with its maximum age (required, 1 to 366 days) and its own
  parameters, part of the line's content digest and carried like its proof requirement.
  `GET /api/v1/projects/{id}/checklists/{revision}/measurements` shows each bound line's measurement —
  pass, fail or no data with its reason (`never_examined`, `step_absent`, `examination_unrecorded`,
  `stale`, `not_applicable_anywhere`, …), never a pass by default — beside the answer. The submission
  measures again and refuses a *yes* against a failure; the sign-off measures again and is refused when
  a measurement changed since the submission, and freezes the rest with the revision. Vectispire
  never answers: an answer may rest on a measurement the person read, and stays theirs. **A
  repository's scans from before V49, and a source's SARIF imports from before V53, read as
  `examination_unrecorded`** — nothing recorded whether they looked — until its next scan or upload.
  On the template screen a security lead binds a draft's line to its rule, the line's KPI text
  beside the parameters and the rule in words beside both, a *secrets at zero* preset included, and
  saves the lines changed together; the auditor and a published version read each line's rule. On a
  project's checklist each bound line shows its measurement — met, not met, or no data with its
  reason in words — as of when, its figures and each repository's evidence on demand; a met or not-met
  line offers to answer as measured in one click, resting on the measurement read. The page says
  whether the measurements are live or frozen by the sign-off, and **Submit** stays greyed out, with
  the lines named, while a measurement keeps the revision back — a *yes* contradicted, or a *yes*
  without data missing its comment or proof —
  [Security checklists](../guide/security-checklists.md#measured-lines).
- **What proof a checklist line asks for is set on the template's draft**
  (`PUT /api/v1/checklist-templates/{slug}/versions/{ordinal}/evidence`, on the `revision` read): for
  each line, `none`, `link_or_file` or `file`, and for a proof that expires, its validity in months
  (1–120). Until now every imported line asked for none, so no proof was ever required at submission.
  The requirement is part of what the line asks: a line whose requirement moved is *changed* against
  the previous version, and a project's answer carried onto it waits for confirmation. Confirming a
  layout again keeps each line's requirement, and a new workbook's line takes the previous version's
  under the same key; deriving a version carries them. Audited `CHECKLIST_TEMPLATE_EVIDENCE_SET`. The
  draft's screen sets it line by line, in the **Proof asked** column of the items read, and sends only
  the lines changed — [Checklist templates](../administration/checklist-templates.md#4-say-what-proof-each-line-asks-for).
- **Project checklists, answered by people** (V52 adds `t_checklist`, `t_checklist_answer`,
  `t_checklist_evidence`, `t_checklist_file`). A project's checklist is opened on a published template
  version (`POST /api/v1/projects/{id}/checklists`), answered line by line — every answer kept, with
  its author and instant — proven by links and files (25 MB, served back only as downloads),
  submitted, returned, signed off by an approver, reopened, or moved to a newer version with its
  answers carried: current where the line did not change, awaiting confirmation where it did. Only a
  caller who sees the **whole** project reads or writes it; anybody else is answered 404. Every write
  names the `edition` read. Audited `CHECKLIST_*`; a sign-off is sent to the SIEM as `VECTI-SEC-025`, a
  refused sign-off or a return as `VECTI-SEC-026`. Deleting a project deletes its checklists; the audit
  entries stay. The screens come with the interface's half of this lot.
  `GET /api/v1/projects/{id}/checklists/context` names the project and its newest revision for a page
  that has no checklist to show yet; the list and the offered versions stay bare arrays.
- **Coverage and test reports from declared sources.** A pipeline sends a JaCoCo, Cobertura or lcov
  coverage report (`POST /api/v1/repositories/{id}/coverage-imports?format=…`) or a JUnit report — one
  XML file or a zip of them (`…/test-report-imports`) — with a `report_import` key its source is
  declared for. The figures are kept, never the document; an empty report is refused rather than
  recorded as zero, and nothing opens or resolves an issue. Audited `COVERAGE_IMPORTED`,
  `TEST_REPORT_IMPORTED` and `REPORT_IMPORT_REFUSED`, the refusal sent to the SIEM as `VECTI-SEC-027`.
  `scripts/vectispire-cli.sh` gains `coverage` and `test-report` — [Importing coverage and test reports](../administration/plugins.md#importing-coverage-and-test-reports).
- **The scan page shows which steps examined the tree.** A *What this scan examined* card lists the
  built-in steps that produced and those that did not look — failed, or not run for that target —
  so a clean list of findings reads as clean only for the steps that ran. Scans from before this
  version say *Not recorded* until the target is scanned again — [Scans](../guide/scans.md#reading-a-scan).
- **Solutions and projects**: a solution holds projects, a project references repositories, and a
  grant may name a whole project — [Solutions and projects](../administration/solutions-and-projects.md).
- **A project moves to another solution** (`solutionId` on `PATCH /api/v1/projects/{id}`), with its
  repositories, grants, checklists, plugin activations and SARIF sources; nobody's access changes. A
  name the target solution already holds is refused with 409 `project-name-taken` —
  [Solutions and projects](../administration/solutions-and-projects.md#moving-a-project-to-another-solution).
- **Analysis plugins**: third-party analysers packaged as container images, registered by the
  platform governor, switched on per project, run confined like the built-in scanners, only when
  a language they declare is present. An image may declare its signer; the signature is verified
  before the pull, and `VECTISPIRE_PLUGIN_SIGNATURE_REQUIRED` requires one for every plugin.
- **SARIF imports** from declared internal sources (a CI job, an on-premise SonarQube), each bound
  to one restricted key and one scope, with the provenance kept on every issue —
  [Plugins and SARIF imports](../administration/plugins.md). Gate policies count plugin and
  imported findings only when they say so (`include_plugins`).
- **Git over HTTPS** with a managed token bound to one host, beside SSH keys;
  `VECTISPIRE_GIT_ALLOWED_HOSTS` restricts where anything is cloned from.
- **SIEM export** over syslog UDP, TCP or TLS (RFC 5424, CEF), sent after commit —
  [SIEM export](../integrations/siem.md).
- **Parallel scans on an agent**, 1 to 16 at once (`max_concurrent`), counted by the database.
- **One vulnerability database per host**, downloaded once under a lock and shared read-only by
  every scan instead of once per scan (some 3 GB), in `VECTISPIRE_VULNERABILITY_DB_DIR`; the matcher
  now runs with no network.
- **Resetting an agent's sealing key** from the Agents screen, for a host whose clock was put back
  or a key suspected of having leaked.
- Single sign-on records the provider's second factor and may require it
  (`VECTISPIRE_OIDC_REQUIRE_MFA`); Vault Transit may hold the encryption key.
- **The screens no longer show reachability**, which nothing computes: the issues list loses its
  reachable / unreachable tags, the issue detail its reachability panel, the EPSS page its
  "reachable and weaponised" card and its column, the blast radius its column. The scorecard
  charges every critical 8 points, the EPSS ranking is CVSS × EPSS with KEV on top, and the
  attack paths no longer admit or flag a node on it — no figure an installation has shown moves,
  since every issue read `UNKNOWN`. The AI advisor says the exposure was not assessed.
- **The AI advisor no longer invents exploitation figures.** Explaining a CVE the estate does not
  carry showed an EPSS probability of 75 % for every CVE, and "actively exploited" for two
  identifiers typed into the code; a listed CVE without a score read 85 %. It now shows the KEV
  listing and the EPSS score the stored feeds hold, and says "unknown" when they hold nothing —
  before the first synchronisation, for instance. The impact sentences nobody had looked up
  ("a remote attacker may execute arbitrary code") are gone, no upgrade is proposed without a
  recorded fixed version, and the EPSS page no longer shows a percentile of 0 for a CVE the file
  does not score.
- **The bundled rules no longer pile up in the work directory.** Each start of the control plane
  or of an agent unpacked them to a new `vectispire-bundled-rules-*` directory and none was ever
  removed. The directory now goes when the process stops, and the first start of this version
  sweeps what earlier ones left: only directories of that name, owned by the process's user, older
  than the process and held by no running one.

### Security

This release closes the findings of the security review of 2026-09-26 and its follow-ups —
authentication limits under concurrent attempts, single sign-on linking, SSRF and parser
differentials on clone URLs, bounded outbound reads, audit and SIEM completeness, and the
agent's sealing key. Jackson is raised above the Spring Boot BOM for GHSA-q4xh-88c3-wmh7 (High) and
two related advisories, on the control plane **and the agent**, whose own SBOM is now scanned in the
pipeline — it was not, and sat on an advised version unseen. The `cosign verify-blob --key` commands
the product and the compliance guide hand out now carry `--insecure-ignore-tlog=true`: without it,
cosign looked for the signature in a transparency log Vectispire never publishes to and refused every
export. Build dependencies and plugins are now verified against signatures and
checksums. The detail is in the commit history and in the
[decision register](https://github.com/asmolabs/vectispire/tree/main/docs/architecture/en/decisions).
