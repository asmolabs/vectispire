# Release notes

## Next release (after 0.10.0)

### Changes an integration can see

#### Score formula (0.11.0)

**Grades drop because mediums, lows and every further issue now count — not because a project got
worse. Nothing in your repositories changed.** The scorecard's formula is replaced, everywhere at once
— the cards, the project and solution scorecards, the dashboard's ranking and the public badge —
([decision 0036](https://github.com/asmolabs/vectispire/blob/main/docs/architecture/en/decisions/0036-the-posture-score-formula.md),
[how it is computed](../guide/repositories.md#how-the-scorecard-grade-is-computed)).

- **The score is `100 × e^(−risk points / 55)`, rounded and never below 1**, over **risk points** that
  weigh what is open: 25 an actively exploited issue (CISA KEV, whatever its severity, counted in that
  class only), 10 a critical, 4 a high, 0.5 a medium, 0.125 a low, 4 a disallowed licence. **Any exploited
  issue caps the score at 54 (D).** There is no longer a bonus for a completed scan. The bands do not
  change. The old formula — a hundred less 25 per KEV on top of its severity, 8 per critical, 4 per high,
  5 per licence, plus 5 for a scan — reached 0 at twenty-seven highs and read fifty or five hundred
  mediums at 100, A+. Some figures, old → new: one critical 97 A+ → 83 B; one exploited critical 72 B →
  54 D; fifty mediums 100 A+ → 63 C; one disallowed licence 100 A+ → 93 A; twenty-seven highs 0 F → 14 F.
  On the eleven seeded targets of the comparison, eight change grade and none rises.
- **A new field, `riskPoints`**, on `GET /api/v1/scorecards/repositories/{id}` and `…/containers/{id}`,
  on the `scorecard` of `GET /api/v1/projects/{id}/compliance` and `…/solutions/{id}/compliance`, and on
  each row of the maturity ranking (`GET /api/v1/dashboard/posture-analytics`, `targetScoreboard[].riskPoints`)
  — `null` exactly when the score is. Signed-in routes only.
- **The public badge (`GET /api/v1/scorecards/badges/{token}.svg`) keeps its look and shows the letter
  alone** — it may change letter and colour on its next render with nobody having touched the
  repository, and never shows the risk points: they would tell anyone reading the README how much is
  open, and when that moves.
- **A project or a solution is graded by its weakest link**: its score is the lowest score among the
  scanned targets of it you see, each as its own card computes it, held at the scanned share as before,
  and the scorecard names that target in a new field, `weakestTarget` (kind, id, name, its own score,
  grade and risk points). It used to be the formula over the scope's summed backlog, which graded a
  scope lower the more targets it held. Its `riskPoints` are the whole scope's open backlog, each issue
  and licence once.
- **A scope's `licenseViolationCount` can fall.** A project or a solution filing both an image and a
  repository that one scan named counted that scan's disallowed licences twice; each is counted once
  now, as each target's own card already did.
- **`GET /api/v1/scorecards/global` changes shape: the portfolio has no single grade.** A grade over a
  whole estate is crushed by its size or is the worst target's grade under another name. The response
  is now `grades` — every grade, `NO_DATA` included, with how many of the targets you see read it —,
  `weakestTarget` (`null` when none is scanned), `riskPoints`, `totalTargets`, `observedTargets` and the
  open counts (`openCriticalCount`, `openHighCount`, `openKevCount`, `overdueCount`,
  `licenseViolationCount`). **`score`, `grade`, `targetId`, `targetKind`, `targetName`, `hasAttestation`
  and `recommendations` are gone**, rather than kept with a meaning they no longer have: an integration
  thresholding the global `score` must move to the distribution or the weakest target. The dashboard
  shows the same three figures.
- **The ranking breaks ties on the risk points**, the fewer first, where it kept the listing order:
  inside F every score is held at 1, and at 54 the exploited cap holds many.
- **`GET /api/v1/dashboard/trends` gains `score_formula_changed_on`**, the day (ISO, UTC) this
  installation's grades changed formula — the day it was upgraded, written by migration V69 when the
  installation already held a completed scan; `null` on a fresh one. The dashboard's trend chart draws a
  dated line there, and says it in words under the chart.
- **Nothing else reads the grade.** The gate, SIEM events, notifications, tickets and the exports
  (SARIF, VEX, CSAF, CycloneDX) are unchanged. A check of yours that reads the badge's letter or the
  API's `score` — "no worse than B" — will see it drop.

#### Every target without a schedule is now scanned weekly (0.11.0)

**A repository or an image with neither a scan interval nor a cron expression used to be scanned only
when somebody asked — and that is what every target added through the forms got. It is now rescanned
on the installation's default interval, seven days unless an administrator changes it.** To keep a
target as it was, set it to **manual only**. Targets somebody deliberately left unscheduled cannot be
told apart from the ones nobody scheduled, so all of them move to the default at the upgrade.

- **A new setting, `scan_default_interval_days`** (*Settings › Scanners › Scheduling*, default `7`,
  `0` for no default — the old behaviour, for every target at once)
  ([how](../administration/settings.md#default-rescan-interval)).
- **The rounds are spread over the week.** Each target under the default has its own moment in the
  interval, derived from its kind and identifier, and keeps it from week to week: a thousand targets
  come a handful an hour, never all at once. Migration V70 records the upgrade as their last scheduled
  round, so the first round falls in the week after the upgrade rather than in its first minute —
  `lastScheduledScanAt` of those targets reads as the upgrade until then. A target's own interval or cron
  expression behaves exactly as before.
- **New fields on `GET /api/v1/repositories` and `GET /api/v1/containers`**, and on what their create and
  update return: `scanManualOnly` (boolean) and `schedule`, the schedule in force as the server decides it
  — `mode` (`manual`, `cron`, `interval` or `default`) and `intervalMinutes` (the interval it runs at under
  `interval` and `default`; `null` for a cron expression, for manual only and for `default` when the
  installation has none). Read `schedule` rather than working the precedence out from the other fields.
- **`scanManualOnly` on `POST`/`PATCH /api/v1/repositories` and `/api/v1/containers`.** `true` clears the
  interval and the expression; sent beside a positive interval or an expression it is refused (400); an
  update naming an interval or an expression without it leaves manual only. **An interval of `0` now
  means "not set" — the default — and no longer "manual only"**, and is stored as `null`
  (`scanIntervalMinutes` reads back `null`, not `0`). A negative interval is refused (400). A script that
  switched rescans off by sending `0` must send `scanManualOnly: true`.
- **A scheduled round is skipped while a scan of the target is running**, as it was while one was
  waiting. The *Scan* button is unchanged.
- **A dependency-analysis checklist rule asking for a matching schedule counts the default**: a
  repository with no schedule of its own, under a weekly default, now matches a seven-day maximum age;
  one set to manual only never does.

#### A repository target is filed once (0.11.0)

**Adding a repository that is already a target — the same repository, on the same branch and sub-path —
is refused, and so is an edit that would make one target another's twin.** Two URLs name the same
repository once the scheme, the user part, the port, the case, a trailing `.git` and trailing slashes are
set aside: `git@gitlab.example.org:Team/API.git` and `https://gitlab.example.org/team/api` are one
([the rule and its limits](../guide/repositories.md#filed-once)). Another directory of a monorepo, or
another branch, is another target and is accepted as before.

- **`POST /api/v1/repositories` and `PATCH /api/v1/repositories/{id}` answer 409** with the type
  `urn:vectispire:problem:target-already-registered`. When the caller sees the existing target, the
  problem carries its id as `existingRepositoryId` and the `detail` names it; otherwise neither — the
  refusal says the target exists and nothing of which one. A script that registers repositories
  unconditionally must treat this 409 as "already there".
- **The database enforces it** (migration V73, a unique index on a hash of the three parts): two
  creations racing past the check end in one target and one 409, on PostgreSQL and MySQL.
- **Nothing is deleted at the upgrade.** Targets already filed twice keep working, are scanned and are
  editable; the oldest of each pair is the one a new filing is compared with. **A new route, `GET
  /api/v1/repositories/duplicates`** (administrators), lists them, grouped, oldest first, each target in
  the shape of the repository list, to [merge by hand](../guide/repositories.md#filed-twice-before-this-release).
- **Until the first maintenance turn after the upgrade** (thirty seconds after the start, then hourly),
  targets registered before it are not yet compared, and a duplicate of one of them is accepted — and
  then listed by the route above.

#### Other changes

- **A coverage import answers `packagesState`**, and a checklist measurement has three more reasons.
  `POST` and `GET /api/v1/repositories/{id}/coverage-imports` carry `packagesState` — `kept`, `too_many`,
  `path_refused`, `inconsistent`, or `null` for an import accepted before this version — and a rule's
  `reason` may read `packages_unrecorded`, `packages_not_kept` or `scope_matches_nothing`, only on a
  coverage line [scoped to packages](../administration/checklist-templates.md#coverage-over-a-scope-of-packages).
  A client that switches over `reason` should handle them; one that does not still reads no data. A
  rule's form (`boundRule`, the rules route) gains an optional `scope`; a rule without one keeps its
  canonical form and its content digest. Schema V71 adds a column and a table, nothing to do.
- **A plugin refusal has a third reason, `registry_authentication_required`**, and a checklist
  measurement a matching reason, `plugin_registry_authentication_required`: the plugin's image declares
  a signer, and its registry would not let the signature be read. A client that switches over
  `refusal` or over a measurement's `reason` should handle the new token; one that does not know it
  still reads a refusal.
- **A checklist's automatic answers arrive within a minute of a scan or a report, not at once.** A
  completed scan, or an accepted SARIF, coverage or test report, queues them with its own results, and
  the scheduler's next relay gives them, retrying if answering fails. They used to be given just after
  the commit, and a server stopping in between left the lines unanswered until the next scan. A script
  that reads a checklist right after uploading a report should wait for the relay — opening, moving or
  reopening a revision still answers at once.
- **A SIEM event an audit entry signals, and `SECURITY_GATE_FAILED`, are queued with what caused them.**
  They were queued just after, in a transaction of their own, and a stop between the two lost them.
  If the two cannot be written together, the entry or the verdict is still written and the event queued
  right after it, as before; the server logs a warning when that happens.
- **An agent's `AGENT_RESULT_SUBMITTED` audit entry is written up to a minute after the result**, from
  the outbox, instead of just after it — and is no longer lost when the server stops in between. The
  entry's timestamp is when it is written; the moment the result was accepted is in its description
  ("… at 2026-…"), with the delivery's id.
- **An issue's triage history gains entries of origin `reopen`**, on `GET /api/v1/issues/{id}`
  (`decisions`) and in a target's history (`GET /api/v1/history/repositories/{id}`), with a new field,
  `previousResolvedAt` — null on every other entry. Their `actor` is null, as on an `expiry`. The history
  CSV gains a last column, `decision_previous_resolved_at`; a target's `decisions` count leaves reopenings
  out.
- **The CLI is a release asset, signed like the gate script.** `vectispire-cli.sh` is attached to the
  release with its Sigstore bundle, `vectispire-cli.sh.cosign.bundle`, signed by `release.yml` at the
  tag and verified with the same `cosign verify-blob` command as the jar; the release notes print its
  SHA-256. The snippets of the **CI/CD** dialog on *Repositories* and of
  [`CI_CD_INTEGRATION`](https://github.com/asmolabs/vectispire/blob/main/docs/en/CI_CD_INTEGRATION.md#-getting-the-cli)
  used to download `scripts/vectispire-cli.sh` from the repository's raw URL at the tag and run it
  unchecked; they now download the asset, compare its SHA-256 with the one they pin, and stop the job
  on any other file. A pipeline copied from an earlier snippet keeps working, unchecked, until it is
  replaced — 0.10.0 and earlier carry no CLI asset.
- **`VECTI-SEC-030` (remediation deadline passed) is as severe as the late issue**: CEF severity 8 for
  a critical issue, 7 for a high, 5 for a medium, 3 for a low — in the CEF header and in the syslog
  priority, and the minimum severity is compared with that. It was a fixed 6, under the default minimum
  (High), so with the factory configuration no breach reached the SOC, not even a critical one's. With
  the default, critical and high breaches now arrive; Medium lets medium ones through too. **A SOC rule
  matching these alerts on severity 6 must adapt** — match `VECTI-SEC-030` on the signature, and read
  the severity as the issue's. An event already queued at the upgrade leaves at 6, as it was raised —
  [SIEM export](../integrations/siem.md#event-catalogue).

- **Publishing a checklist template version can answer 409 `checklist-template-unrenderable`.**
  `POST /api/v1/checklist-templates/{slug}/versions/{ordinal}/publish` fills the workbook in once, as a
  sign-off would, and refuses a workbook no sign-off could be written into; the problem's `cells` member
  names each cell at fault (`cell`, `kind` — `shared` or `array` — and `range`). See *Fixed* below.
  **Opening a project checklist, or moving one to another version, can answer 409
  `checklist-version-unrenderable`** — `POST /api/v1/projects/{id}/checklists` runs the same trial on the
  version opened on or moved to, and refuses one published earlier that fails it, with the same `cells`
  member; nothing is stored or recorded. The version moved from is never tried.
  `GET /api/v1/projects/{id}/checklists/offered` still lists such a version, with a new member,
  `unrenderable` — the trial's `detail` and the same `cells` — which is null on every other version.

### New

- **Forge connections: a read-only token to a GitHub or a GitLab, probed before it is kept**
  ([Forge connections](../administration/forge-connections.md), decision 0037, lot D1 — the discovery
  and the import of repositories come next). `/api/v1/forge-connections`, administrators only, no screen
  yet. The token is presented to the forge once through the outbound guard and refused when it is
  rejected, broader than read-only (GitLab: `read_api`; GitHub: a fine-grained token, or a classic one on
  Enterprise Server, flagged `canWrite`), or the server is older than GitLab 16 or GHES 3.12. A
  self-managed server on the internal network is reached when the administrator says so, behind its own
  CA when it is pinned for that connection — there is no switch that skips verification. The token is
  encrypted with its row as context, replaced in place, re-sealed when the connection is saved during an
  `ENCRYPTION_KEY` rotation, and never returned. Audited `FORGE_CONNECTION_CHANGED` and
  `FORGE_CONNECTION_REFUSED`; signalled `VECTI-SEC-034`, and `VECTI-SEC-036` for a blocked address or a
  refused scope.
- **A coverage line may measure a scope of packages**
  ([how to write one](../administration/checklist-templates.md#coverage-over-a-scope-of-packages)). A
  `coverage_threshold` rule takes an optional `scope` — `include` and `exclude` patterns over package
  paths, `**/service/**`, `org/example/**`, `**` for whole segments and `*` within one — decided in the
  template rather than in each build's coverage filter, where a reviewer never saw it. The figure is
  covered over total across the matching packages; the evidence names how many matched, and the
  measurement's summary — the signed document's `Evidence` sheet — states the scope beside the figure. To
  measure it, a coverage import now keeps its counts per package beside its totals (a JaCoCo or Cobertura
  `<package>`, an lcov file's directory), up to 10,000 packages and only when they add up to the totals.
  A scope matching nothing, an import from before this version (upload the report again) or one whose
  packages were not kept is no data in those words — never 0 %, 100 % or the report's totals. Patterns
  that would not read as written — `org.example.service`, `**/serv**`, `?` — are refused when the rule is
  bound. Until a line is rebound with a scope, nothing changes.

- **A project's export, signed, and its published schema** — the first lot of report plugins
  ([decision 0035](https://github.com/asmolabs/vectispire/blob/main/docs/architecture/en/decisions/0035-report-plugins.md),
  accepted on 2026-10-03). `GET /api/v1/projects/{id}/export` returns a zip of `export.json` — the
  project's targets, newest scans, gate verdicts, unresolved issues with their triage, counts, components,
  compliance state and checklist statements, as `vectispire-project-export` 1.0 — and `export.json.sig`,
  verifiable with `cosign verify-blob --key` against the instance's public key. For write accounts and
  auditors who see the whole project, images included, and integration keys with the `export` scope; no
  source, secret value, credential or e-mail address. Over 100,000 issues or components or 64 MiB, it is
  refused (409 `project-export-too-large`), never cut short. The schema is served at
  `GET /api/v1/schemas/project-export/1`. Audited `PROJECT_EXPORTED`, sent to the SIEM as the new
  `VECTI-SEC-032`; `VECTI-SEC-033` is reserved for the plugins themselves
  ([how](../guide/exports.md#project-export)).

- **The report plugins' registry** — the second lot of decision 0035. The platform governor registers a
  report plugin from its manifest — an image pinned by digest, the export major it reads, the one file it
  writes and its media type from a closed list (Office Open XML, OpenDocument, PDF, CSV, plain text; no
  HTML, no macro-enabled package), its output ceiling and timeout, and a signer, **required with no
  waiver** — at `POST /api/v1/report-plugins`. **With four-eyes on, each manifest digest waits for a second
  person**: an administrator, a CISO or another governor approves it
  (`POST /api/v1/report-plugins/{id}/manifests/{digest}/approval`), never the account that registered it
  (409 `report-plugin-four-eyes`), while the previously approved manifest keeps serving. A security lead
  switches an approved plugin on for a project they see whole
  (`PUT /api/v1/projects/{id}/report-plugins/{pluginId}`); the governor withdraws a digest with a
  justification, and it never runs nor registers again. No delete. Every gesture is audited
  (`REPORT_PLUGIN_*`) and sent to the SIEM as the new `VECTI-SEC-031`. A private plugin image is pulled
  and verified with the control plane's Docker configuration: the manifest holds no credential, and Vectispire stores none
  ([how](../administration/report-plugins.md)).

- **Report runs** — the third lot of decision 0035. A write account or an auditor who sees a whole project
  asks a report of a plugin switched on for it (`POST /api/v1/projects/{id}/reports`, 202): the run is
  queued in the database and claimed by the **control plane's** executor — the Docker endpoint the built-in
  worker uses, never an agent — two at a time by default (`VECTISPIRE_REPORT_CONCURRENCY`). At the claim it
  runs the manifest approved at that moment, builds the project's export for the requester as they see it
  then, verifies the image's signer with cosign **before the pull** (no waiver, the control plane's Docker
  configuration for a private registry), and runs the image **without any network**, the export alone and
  read-only, one output directory bounded by the manifest's `max_output_bytes` and 16 files, the manifest's
  timeout, exit 0 or failed. A run is `pending`, `running`, `produced`, `failed` or `refused`, with its
  reason (`GET /api/v1/projects/{id}/reports`); one of a plugin per project at a time (409
  `report-run-in-progress`); a run whose executor died is failed `executor_lost` after its lease. A
  produced run keeps the export it was given, purged by the evidence window; nothing else is kept of a run
  that did not produce. **An installation whose built-in worker is switched off cannot run report plugins**
  in this version: 409 `report-executor-unavailable`. Audited `REPORT_REQUESTED`, `PROJECT_EXPORTED`
  (`VECTI-SEC-032`, the export reaching a plugin), `REPORT_PRODUCED`, `REPORT_FAILED`, `REPORT_REFUSED` —
  the last sent to the SIEM as the new `VECTI-SEC-033`. **The document is not served yet**: checking it
  against its declared type, signing it and its download are the next lot, and until then its bytes are
  not kept — the run records their size and SHA-256 ([how](../administration/report-plugins.md#requesting-a-report)).

- **Experimental: other scorecard weights, side by side with the production ones.**
  `GET /api/v1/scorecards/simulation`, administrators only, scores every visible target, project and
  solution under the card's formula and under the weights asked for, with each row's risk points; with
  no parameter the two agree. It served to decide the formula above, sets both ways of grading a scope
  — the weakest link the card uses and the rejected sum — beside each other, and is retired in the
  release after this one ([how](../guide/repositories.md#score-simulation)).
- **A weekly record of the OWASP Top 10 coverage starts now.** Every six hours at most, the maintenance
  turn records, for every repository and image — scanned or not — and for each of the ten categories,
  the state the OWASP grid shows (findings, not measured, not covered, nothing found), the open findings
  it counts, and apart from them the open findings whose triage is settled, so that accepted risks can be
  shown as such — for a target never scanned, its findings as the grid counts them once a target beside it
  is scanned, so that a project's or an estate's week reads what the live grid reads. The current week
  (Monday 00:00 UTC) is rewritten until it closes; a closed week keeps its
  last capture. **Weeks before the upgrade have no recorded state** — whether a category was covered or
  measured then depended on settings and rules that have moved since, and the weekly view below says
  "not recorded" for them rather than guess.
  A deleted target's rows go with it (migration V67), and the record is purged by the evidence
  window, *Evidence kept for (days)* (`evidence_retention_days`, 400 days by default, zero keeps it for
  ever), as the gate's verdicts and the compliance captures are: a week is kept while any of it is
  inside the window, and a purged week reads as reconstructed in the weekly view below.
- **The OWASP Top 10, week by week: `GET /api/v1/owasp/coverage/weekly`.** Up to 52 ISO weeks (the
  last 12 by default), over the caller's estate or one project or solution, for the targets they may see
  (a scope they see nothing of answers 404, as an absent one does). Each week gives, per category, the
  state, the open and the settled findings as the weekly record captured them, and the issues opened and
  resolved in the week. **A week before the record is reconstructed from the issues' dates** and says
  so: its state and settled figure are `null` rather than guessed, and its open figure counts every issue
  open at the week's end, whatever its triage — the triage of a past date is not known. An earlier
  resolution of a reopened issue counts — not open from that resolution to the reopening, and a
  resolution of its week — from the reopening entries of the triage history; a reopening before this
  release left none, and such an issue still counts as open between that earlier resolution and its
  reopening. Each week and category also gives **`reopened`**, the issues a recorded reopening brought
  back in the week — what makes open rise with no opened figure to match. **It is `null`, not zero, on a
  week that began before reopenings were recorded** (dated by V68's application, a day's margin aside);
  `reopenedRecordedFrom` names the first week that has it.
- **New backlog filters for that view's figures**: `owasp_category` (`A01`…`A10`, placed as the grid
  places issues — a vulnerability is `A06`), `open_at` (open at the end of that day, UTC) and
  `first_seen_from` / `first_seen_to` / `resolved_from` / `resolved_to` — `open_at` and the resolved range
  read a reopened issue's earlier resolutions the same way — and `reopened_from` / `reopened_to` (a
  reopening the triage history recorded in that range). **`owasp_category=any`** lists the issues placed
  in any of the ten categories — a week's totals — and never a licence, quality, plugin or import
  finding, which no category holds. **With a date and no `state`,
  `GET /api/v1/issues` lists every state**, since the issues open on a past day are mostly resolved
  since; the default stays `open` otherwise.
- **The OWASP report screen gains a "By week" view** (*OWASP report* → *By week*, or
  `/owasp?view=weekly`): a heatmap of the ten categories over 12, 26 or 52 weeks or a chosen range, for
  the whole estate or one project or solution; the curves of what is open per category; the issues
  opened, reopened (stacked on the opened, in purple) and resolved each week; the selected week's figures and their change since the week before;
  and that week's grid. **Reconstructed weeks are hatched** and their curves dashed — their open count
  includes accepted risks, so no change is shown across the week the record started. **Accepted
  risks are shown apart**, in grey, never added into the open count. Every count opens the backlog it
  counts — open at the week's Sunday (not settled, on a recorded week), or first seen / resolved /
  reopened from its Monday to its Sunday, in the same scope — **the totals included**, which open the
  issues placed in any category (except a recorded week's total open count where a category was not
  measured: the grid counted nothing there, and the list would). A week before reopenings were recorded
  shows a dash for them, not a zero. The backlog says what it was asked in a banner, with the way back
  and a way to clear it. The figures export as CSV, one row per week and category with the
  reconstructed flag; *Print / PDF* prints the view without the application's menus (the browser's
  own "save as PDF" — no PDF is generated on the server). Window, scope and selected week are in the
  address, so a link reproduces the view.

### Fixed

- **A signed plugin whose image lives in a private registry is verified instead of refused.** The
  signature verifier asked the registry anonymously, so a registry that serves nothing to an anonymous
  pull answered "unauthorized" and the plugin was refused as `signature_unverified` — a signer problem
  on screen for a signature nobody had read. cosign is now handed, for its run alone, the credentials
  the executor's own pulls use for that registry (its Docker configuration; Vectispire stores none),
  read-only and erased with the container. A registry that still refuses — no credentials held, or the
  ones held refused — gives the new refusal `registry_authentication_required`, which says which.
- **The container guide said registry credentials were stored encrypted with `ENCRYPTION_KEY`.** They
  never were: a pull uses the Docker configuration of the executor that scans. The guide now says so,
  and how to give an executor credentials for a private registry.
- **The licences of the interface now ship with it.** `ng build` writes the notices of the npm
  packages it bundles (Angular, Optimus UI, chart.js…, mostly MIT) beside the `browser/` folder, and
  only that folder reached the jar and the image; the MIT notice of the shell (Sparked, PrimeTek's
  Sakai ported to Optimus UI — copied code, not a package) shipped nowhere either. Both are now in the
  jar under `static/licenses/` (`3rdpartylicenses.txt`, `sparked/LICENSE.md`), `NOTICE` names the
  shell, and the build refuses a bundle that lost either.
- **A `git://` repository its server does not serve was retried for a quarter of an hour before failing
  as "the clone failed".** `git daemon` answers a path it does not have, or does not export, with a
  refusal of its own, which was read as an unknown failure — transient — so the scan waited one minute,
  then five, and spent its three attempts on the same answer. It now fails at its first attempt, as a
  repository absent over HTTPS or SSH always has, with `git://… could not be found.` A host that does not
  resolve, over `git://` or SSH, is still retried — the network may come back — and now says
  `… could not reach its host.` where it said `The clone of … failed.`
- **A checklist template whose workbook no sign-off could fill in was published, and found at the first
  sign-off.** A cell Vectispire writes — an answer or a comment of an item row, a header value — that
  holds the master of a shared formula (a helper filled down the comment column, typically) or an array
  formula over several cells cannot be written without breaking the cells depending on it. The sign-off
  refused it, rightly, but only once a project had answered every line: the revision stayed submitted,
  its draft could not even be exported, and the version could never be signed. Publication now runs the
  sign-off's own rendering once, with placeholder answers and nothing kept, and refuses such a version,
  naming every cell — the sign-off of a version published earlier names them all too, where it named
  the first. A version published before this release with such a cell still refuses its sign-offs:
  publish a corrected one and move the projects' checklists to it — see
  [a formula in a cell Vectispire writes](../administration/checklist-templates.md#a-formula-in-a-cell-vectispire-writes).
  Nor is a checklist **opened on, or moved to**, such a version any more: the same trial runs there, the
  cells are named on screen, and nothing is opened — no project starts a checklist that could never be
  signed. Moving a checklist away from such a version is never refused: that is the way out —
  [when the server refuses](../guide/security-checklists.md#when-the-server-refuses). The templates
  screen and the project checklist screen both name the cells in the reader's language and say what to do.
  The versions a project is offered list such a version disabled, *cannot be signed off*, its cells
  named beneath — rather than offering it to be refused once chosen.
- **A reopened issue left no trace in its triage history.** When a scan or an import found a resolved
  issue again, it reopened it and cleared a `fixed` decision with no entry: the history showed `fixed` as
  the last word on an issue standing open under review again, and the resolution it had — from when to
  when — was lost. The reopening is now an entry of its own: the triage it left (or kept, for a
  judgement that survives the return), the date the resolution it ended began, and the scan that found
  the issue again; nobody is named, since nobody decided (migration V68). A reopening before the upgrade
  stays without an entry.
- **Concurrent audit writes could break the audit chain, and raise a false tampering alarm.** Two
  entries written at the same moment — two requests on one server, or two servers — could both chain
  onto the same predecessor; the verification then reported the chain broken, and the SIEM received
  `AUDIT_CHAIN_BROKEN`, although nothing had been altered. Entries are now written one at a time,
  across servers too (migration V66). An installation that saw an unexplained break should verify again
  after the upgrade: entries written from then on chain correctly; a break already recorded stays where
  it is, since rewriting an integrity log is what it exists to reveal.
- **The first evidence bundle of an installation without `vectispire.signing.key` answered 500.** The
  signing key created on first use joined the bundle's read-only transaction, which MySQL and PostgreSQL
  refuse to write in. It is now created outside it.
- **Following a link from one scan to another could show the previous scan.** The scan page kept the
  first scan on screen until the second answered, and if the first answer came last it replaced the
  second: the address named scan 35 while the header, the plugins and the findings were scan 34's. The
  page now clears the previous scan and cancels its request when the address changes.
- **Changing a password no longer ends on the dashboard.** An account whose password had been set by
  an administrator, following a link it had been handed, signed in, was sent to change its password and
  then to the dashboard, the link forgotten; the same happened to a change opened from the top bar or
  the account page. The change now returns to the page asked for — or the one it was opened from — and
  only to a page of Vectispire: an address pointing elsewhere is ignored.
- **"1 scans", "1 target(s)": counts now agree with their noun**, in English and French. Forty-six
  messages — scans queued, issues to be resolved, entries missing from the audit chain, targets never
  scanned, components listed, checklist lines answered… — were written in the plural or with "(s)" and
  said so whatever the number. Each now has a singular and a plural chosen by the language's own rule: in
  French 0 takes the singular ("0 dépôt"), in English the plural ("0 repositories"). The last ones follow:
  the audit chain's verdict, a team's deletion warning, the checklist's "lines 3 still need attention"
  and the other messages naming lines, and six counted labels (blast radius, EPSS, licences, rule files).
- **The last labels frozen in one language follow the language preference**: the change tags of the
  inventory diff ("AJOUTÉ", "SUPPRIMÉ"…), a notification channel's state ("Configuré", "Inactif"), the
  "UNPROTECTED" and "HIGH RISK" tags of the attack surface, and the badge image's alternative text.

### Performance

- **The dashboard's maturity ranking no longer reads the estate's SBOMs at every load.** Its licence
  term — five points a refused licence, the same as on each target's scorecard — was counted from the
  whole licence inventory each time the page opened: every scan's SBOM parsed and every component row
  read, for a reader granted five targets as for an administrator. Measured on two hundred targets of two
  scans and 250 components each, a load cost about 420 ms; it now costs 30 to 50 ms. Each target's
  licences are counted once and counted again only when its scans change — a new scan, an SBOM removed by
  the retention purge, a target deleted — and a licence policy change applies at the next load. The
  ranking's scores are unchanged, with one precision: when two scans of a target declare the same
  component under different licences, the newer scan's licence is now the one kept, on the ranking and
  on the licence inventory alike, where it used to depend on the order the scans were read in.
- **The portfolio scorecard and the licence screen no longer read the estate's history for what those
  tallies already count.** The portfolio scorecard's licence term, the licence summary of the whole
  estate and the evidence bundle's licence summary are counts by licence, now taken from the same
  per-target tallies as the ranking; the scans attached to no target are tallied together and count, as
  before, for a reader who sees the whole estate only. A reader granted some targets has their licence
  inventory read from their targets' scans alone, where every scan, component and licence finding of
  the installation used to be read and then narrowed. On the same estate, each of these calls cost 340
  to 840 ms, for either reader; warm, the portfolio scorecard now costs 40 to 55 ms, a summary about 20
  and a restricted reader's inventory about 25. An administrator's licence inventory and licence
  conflicts over the whole estate still read every scan's SBOM and every component row, since they list
  one row per component of every scan, but only the columns they need: 220 to 350 ms instead of 380 to
  620. The answers are unchanged — the same entries, counts and score for an administrator and for a
  restricted reader — with one precision: when a component the SBOM does not declare has rows in two
  scans of a target with different package URLs, the older row's is now the one shown, where it
  depended on the order the database returned the rows in.

## 0.10.0 — 2026-10-01

Read **Before you upgrade** first: five of its points stop something working
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

**A checklist line on static analysis reads "no data" until each repository is scanned again.** A
line on `builtin:sast`, `builtin:quality` or a plugin now counts a repository as examined only where
the analysis read the tree's languages, judged on what the scan recorded: its census and, from V58,
the languages of the SAST rules its task carried. No earlier scan recorded the latter, so every such
line measures `languages_unrecorded` until the next scan of each repository, and an automatic *yes*
Vectispire gave there is withdrawn at the next measurement. Then, on an installation with only the
bundled rules — one Python pattern — a Java or JavaScript repository measures `language_not_analysed`:
install a rule set covering its languages (Rule sets, *import from the catalogue*) and scan again. A
line that passed before because its rules found nothing in code they could not read was not measuring
anything. See [Security checklists](../guide/security-checklists.md#measured-lines).

**Secure coding, IaC and secrets now read coverage, as vulnerabilities did — scores drop on an estate
scanned in part.** ISO 27001 A.8.28, A.8.9 and A.5.15, and the controls of the same categories in NIS 2,
DORA, PCI DSS and SOC 2, were scored on zero findings alone: ten targets with one scanned clean read
them *compliant*, beside an A.8.8 that read *non-compliant* on the same estate. They now carry A.8.8's
coverage cap — a target never scanned makes the control non-compliant, one scanned outside the
freshness window makes it partial at best, the score is at most the share of targets observed, and the
detail says so. **An estate fully scanned inside the window reads as before.** On one scanned in part,
these controls and their frameworks' scores fall at the first page load after the upgrade, and a
declaration that such a control is implemented reads *contradicted* in the statement of applicability.
The compliance progression rewrites the running month's point on its next capture and shows the fall
as *same estate, same rules, N points down*: nothing in the estate changed — the old score counted
targets nobody looked at as clean, and the months already captured keep that score. Scan the rest of
the estate, or tell whoever reads the chart before they do. See
[Compliance](../guide/compliance.md#no-data-is-not-compliant).

**A target never scanned has no security grade any more, and a portfolio, project or solution scanned
in part has its score capped — grades fall, and published badges can read *no data*.** The scorecard
subtracts what it finds from a hundred, so a repository registered and never scanned read 100, A+, on
its card and on its README badge, and a project whose only target was never scanned read the same.
Such a card now grades `NO_DATA`, with no score, and the badge reads *no data* in grey. Where only some
of the targets are scanned — the global scorecard, a project's, a solution's — the score is capped at
the scanned share: ten targets with one scanned clean score 10, F, where they read A+. A repository or
image with a completed scan keeps its grade. Nothing is stored, so the change shows at the first read;
scan the targets the new recommendation names. See
[How the scorecard grade is computed](../guide/repositories.md#how-the-scorecard-grade-is-computed).

**A plugin whose image is not signed no longer runs, unless the platform governor waives the
requirement for it.** `VECTISPIRE_PLUGIN_SIGNATURE_REQUIRED` now defaults to `true`, on the control
plane's built-in worker and on every agent. Plugins did not exist in 0.9.0, so no released installation
loses anything; a **development build** that registered a plugin without a `signature` in its manifest
sees it **refused** from the first scan after the upgrade — the scan's **Plugins** card says *refused —
unsigned*, the scan lists the failure under `plugin <id>`, its issues stay as they were, and a checklist
line on it reads *no data* (`plugin_unsigned`). Before upgrading, declare the image's signer on each such
plugin, or — while it cannot be signed — have the governor record a waiver with its justification on the
plugin's page (`PUT /api/v1/plugins/{id}/unsigned-waiver`). Setting the variable to `false` still runs
every unsigned plugin on that executor, with no trace of why; the waiver is the documented way. Why the
default moved: a registry, mirror or tag compromised upstream runs code over the source of every project
the plugin is on for, and having no network does not stop it from fabricating or hiding findings. See
[Plugins](../administration/plugins.md#running-an-unsigned-plugin) and
[decision 0017](https://github.com/asmolabs/vectispire/blob/main/docs/architecture/en/decisions/0017-custom-checks-as-container-images.md).

**Schema migrations V32 to V64 run at start**, on MySQL and PostgreSQL. Back up the database
first, as for any upgrade — [backup and restore](https://github.com/asmolabs/vectispire/blob/main/docs/en/BACKUP_AND_RESTORE.md).

### Changes an integration can see

- **Three new SIEM events, and the export says when it stops.** `VECTI-SEC-028` is sent to the
  collector being left when the export is switched off or pointed elsewhere — the silence used to be
  the only signal. `VECTI-SEC-029` announces a new secret of high or critical severity, once per
  issue; `VECTI-SEC-030` an issue passing its remediation deadline, once per issue, from the hourly
  turn (forwarded from a minimum severity of Medium). A correlation rule written for the retired
  `001` and `004` does not match them: they took new numbers. `GET`/`PUT /api/v1/siem/config` carry
  `tlsCaPem`, `tlsCaSubject` and `tlsCaNotAfter`, and `POST /api/v1/siem/test` accepts `tlsCaPem` —
  [SIEM export](../integrations/siem.md#event-catalogue).
- **The GitLab gate template now fails the pipeline on a red verdict.** `ci/gitlab/vectispire-gate.gitlab-ci.yml`
  shipped `allow_failure: true`, so a failed gate showed as a warning and the pipeline passed; it now
  accepts only exit `3`, which `VECTISPIRE_GATE_MODE: advisory` produces for a red verdict. A
  pipeline that relied on the old behaviour sets that variable. The template also needs
  `VECTISPIRE_GATE_VERSION`, the tag it was included at: it downloads that release's
  `vectispire-gate.sh` and runs it only at the SHA-256 it pins — it ran `ci/vectispire-gate.sh` from
  the consumer's checkout, where there is no such file. It no longer declares
  `VECTISPIRE_REPOSITORY_ID` or `VECTISPIRE_CONTAINER_ID` on its job, so a value set globally reaches
  the gate. See [CI examples](../integrations/ci-examples.md#gitlab-ci).
- **The release carries `vectispire-gate.sh` and its Sigstore bundle**, signed by the same workflow
  identity as the jar.
- **`vectispire-cli` exits `2` with the server's `detail` on a refusal**, where it exited with curl's
  `22` and printed nothing. Exit `1` is now only a red verdict; a failed or timed-out scan is `2`.
  `scan` follows the scan already waiting on a `409`; `sbom --repo-id` takes the latest *completed*
  scan, where it took the latest, which could be pending; `status`, advertised and missing, exists.
- **A scorecard can grade `NO_DATA`, with a `null` score, and carries `totalTargets` and
  `observedTargets`.** `GET /api/v1/scorecards/repositories/{id}`, `/containers/{id}`, `/global` and
  the `scorecard` of `GET /api/v1/projects/{id}/compliance` and `/solutions/{id}/compliance` answer
  grade `NO_DATA` and `score: null` when none of the card's targets holds a completed scan — they
  answered 100 and `A_PLUS`. `score` is no longer always present as a number: a client reading it as
  one must test `grade` first. `observedTargets` below `totalTargets` means the score is capped at
  that share. `SecurityGrade` gains `NO_DATA`; a client mapping the grades it knows should treat an
  unknown one as no grade.
- **The dashboard's maturity ranking can grade `NO_DATA`, with a `null` `securityScore`.** In
  `targetScoreboard` of `GET /api/v1/dashboard/posture-analytics`, a target holding no completed scan —
  its findings came from a SARIF import alone — ranks last as `NO_DATA`; it could read 100, A, at the
  head of the ranking. Its counts stay. A target never scanned carries no issue and is not listed, as
  before.
- **The dashboard's maturity ranking grades each target as its scorecard does: its scores and grades
  change.** In `targetScoreboard` of `GET /api/v1/dashboard/posture-analytics`, `securityScore` and
  `maturityGrade` are now the target's scorecard `score` and `grade` — the ones
  `GET /api/v1/scorecards/repositories/{id}` and `/containers/{id}` and the badge answer. The ranking
  had a rule of its own (100 minus 25, 10, 3 and 1 per open critical, high, medium and other; A from 90,
  B from 75, C from 50, D from 30), which read 0, F for ten open highs as for five hundred. The same
  rows read other numbers now: ten highs on a scanned target read 65, C, where they read 0, F.
  `maturityGrade` takes the scorecard's values, `A_PLUS`, `A`, `B`, `C`, `D`, `F`, `NO_DATA`, with the
  scorecard's thresholds (A+ from 95, A from 85, B from 70, C from 55, D from 40); `A_PLUS` is new to
  this field, and the document types it as that enum. A target scanned clean is now listed, at 100,
  `A_PLUS`; it was left out, having no issue. The rows keep their shape; `openCritical` and `openHigh`
  are the card's counts, `openMedium` and `openLow` are shown and not scored, and `totalResolved` and
  `targetMttrDays` are unchanged.
- **A `component_versions` line reads `no_data` (`version_unrecorded`) where the SBOM states no
  version for a declared package.** Syft writes `UNKNOWN` for a Maven dependency whose version a
  parent or a BOM manages and it does not resolve; that was judged "not an allowed version", the line
  read `fail`, and Vectispire's automatic answer wrote *no* for a module that is present. Now a package
  none of whose occurrences states a version makes its repository *no data*, the package named in the
  evidence, and an automatic *no* resting on it is withdrawn. Where some occurrences state a version,
  those judge and the others are named beside them; a stated disallowed version and a package absent
  from the SBOM still fail. `NoDataReason` gains `version_unrecorded`: a client mapping the reasons
  it knows should treat an unknown one as no data.
- **`GET /api/v1/solutions` accepts a `read` API key**, as the repository and image lists it regroups
  already did — it answered 403. A key restricted to one repository or image reads the projects
  holding it, partial, and no project through its account's grants.
- **A project's figures and filters include the container images filed in it.** Once an image is
  filed in a project, `GET /api/v1/issues?project_id=…` and `?solution_id=…` answer its issues beside
  the repositories', and the `openIssues` of `GET /api/v1/solutions` count them; each project node,
  solution node and the `unfiled` group gain `containerCount` (and projects and `unfiled` a
  `containers` list), `repositoryCount` staying a count of repositories. Nothing changes until an
  administrator files an image: every existing image starts in no project.

- **A rule-set change that would resolve open issues answers 409 unless their number is accepted.**
  `POST /api/v1/rule-sets/{id}/activate` and `POST /api/v1/rule-sets/deactivate` refuse, with the type
  `urn:vectispire:problem:rule-set-activation-loses-issues` and the members `affectedIssues` and
  `losingIssues`, a change whose rules leave behind open issues the next scan would resolve with their
  triage — unless the body carries `acceptLosing` equal to `affectedIssues`, read again at the request;
  a stale, lower or higher number is refused with the current one. A change that resolves nothing
  needs no field. `GET /api/v1/rule-sets/deactivate/impact` previews a deactivation as
  `/{id}/impact` previews an activation, and neither counts the bundled rules' issues any more, which
  never resolve. Rule sets did not exist in 0.9.0, so no integration built against that release calls
  these routes; one written against a development build since does, and must now send the number —
  [Rule sets](../administration/rule-sets.md).
- **Two new reasons for a measurement without data**, `language_not_analysed` and
  `languages_unrecorded`, in a measurement's `reason` and a repository's `status` in its evidence — a
  script matching the reasons it knows should treat an unknown one as no data, which it is.

- **A name already taken is a 409 with a type, whatever the gesture.** Creating a solution, or
  renaming one, to a name another solution holds (case aside) answered `400`; it answers `409` with the
  type `urn:vectispire:problem:solution-name-taken`. Creating a project, or renaming one within its
  solution, to a name the solution holds answered `400`; it answers `409` with the type
  `urn:vectispire:problem:project-name-taken`, as a move to such a solution already did. The `detail`
  is unchanged. Branch on the `type`, not on the status — a `400` from these routes is now a malformed
  name only (empty, too long) — [Solutions and projects](../administration/solutions-and-projects.md).
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
  in the OpenAPI document: `produced`, `not_applicable`, `absent`, `refused` — the last with `refusal`
  (`unsigned`, `signature_unverified`); a produced one carries `signature` (`verified`, `waived`,
  `not_required`). A plugin carries `unsignedWaiver` (`null` for none), set and withdrawn through
  `PUT` / `DELETE /api/v1/plugins/{id}/unsigned-waiver`; a scan's task carries `runsUnsigned` with each
  plugin. Two reasons join a checklist measurement's `no_data`: `plugin_unsigned`,
  `plugin_signature_unverified`. Two audit operations, `PLUGIN_SIGNATURE_WAIVED` and
  `PLUGIN_SIGNATURE_WAIVER_REVOKED`, both signalled as `VECTI-SEC-021`.
- **A new key scope, `report_import`**, never granted by default: the scope of the coverage and
  test-report uploads, apart from `sarif_import` so that a key sending a coverage figure never deposits
  findings.

### New

- **A syslog-over-TLS collector can pin its own CA.** Pasted in PEM on the SIEM card, it replaces the
  Java runtime's trust store for that connection alone — no more `cacerts` mounted over the JVM's,
  which made every outbound TLS connection trust the private CA too. Only a current CA certificate is
  accepted; hostname verification stays on — [SIEM export](../integrations/siem.md#tls).
- **One project on its own: its read, its compliance and score, its consolidated SBOM.**
  `GET /api/v1/projects/{id}` reads one project as its node in the tree describes it, its solution
  named. `GET /api/v1/projects/{id}/compliance` and `GET /api/v1/solutions/{id}/compliance` run the
  estate's evaluation over the scope's targets only — same controls, same caps, `NO_DATA` when none of
  them was scanned — with the portfolio scorecard computed the same way. `GET
  /api/v1/projects/{id}/components` merges the components of the newest completed scan of each
  repository and image by package URL and version, naming the targets carrying each and what was read
  of every target (`listed`, `empty`, `absent`, `never_scanned`, and `complete`), and `GET
  /api/v1/cyclonedx/projects/{id}/cyclonedx-vex.json` renders it as CycloneDX 1.5 with the project's
  VEX, `compositions` saying whether it is complete. The first three accept a `read` key, the document
  an `export` key. Each follows the tree's rule: a project seen in part is computed over that part and
  says `partial`; one seen not at all answers `404` like one that does not exist —
  [Solutions and projects](../administration/solutions-and-projects.md#one-project-on-its-own-its-figures-compliance-and-components).

- **Container images can be filed in projects** (V59 adds `t_container.project_id`), like
  repositories: at most one project each, filed, moved and taken out by an administrator through
  `PUT` / `DELETE /api/v1/projects/{id}/containers/{containerId}`, audited as
  `PROJECT_CONTAINERS_CHANGED`. **A grant on a project now covers its images too**, resolved at each
  request: an image filed in the project is visible to the project's holders at once, and stops being
  visible through that grant the moment it leaves. The tree lists each project's images and the
  unfiled ones; a project's move carries them; deleting a project returns them to no project; a team
  granted a project is notified of its images' scans. `GET /api/v1/containers` names each image's
  project (`projectId`, `projectName`), and **Containers** shows it with a link into the tree, where
  images are filed with the same dialogs as repositories. Checklists still measure a project's repositories only —
  [Solutions and projects](../administration/solutions-and-projects.md#what-stays-repository-only).

- **The languages detected in a repository are kept.** Every repository scan counts its tree's
  languages and keeps them; `GET /api/v1/repositories` gives each repository `detectedLanguages` from
  its newest completed scan (`null` when unknown, `[]` when none), and each project of
  `GET /api/v1/solutions` the union over the repositories the caller sees, with `languagesUnknownFor`.
  They are spelled as a plugin manifest declares its `languages` —
  [Plugins](../administration/plugins.md#the-languages-detected-in-a-repository).
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
  a language they declare is present. An image declares its signer; the signature is verified
  before the pull, and a plugin that declares none is refused unless the governor waived the
  requirement for it, in writing (V60) — `VECTISPIRE_PLUGIN_SIGNATURE_REQUIRED`, on by default.
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
- **Signing in through single sign-on returns to the page asked for**, filter included, instead of
  the dashboard — and only to a page of this application: the sign-in screen forwards a return
  address it would follow itself, and the control plane checks it again before keeping it.
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
