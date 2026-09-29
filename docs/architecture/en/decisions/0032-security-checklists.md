# 0032 — A security checklist is the organisation's template, versioned, answered per project by people, and prefilled only from evidence that ran

**Date:** 2026-09-28 · **Status:** accepted · **Amends:** [0017](0017-custom-checks-as-container-images.md) §7 · **Decider:** Laurent Boucher

> **Note (2026-09-28).** The SIEM signature identifiers this record names as `ZAN-SEC-nnn` are
> emitted as `VECTI-SEC-nnn` since the release after 0.9.0 — same numbers, same meanings. The text
> below is left as accepted; see the [SIEM catalogue](../../../../docs-site/integrations/siem.md#event-catalogue).

## Context

Before a product goes live, many organisations ask the team that builds it to fill in a **security
checklist** and hand it to whoever approves the release. The checklist is the organisation's own: a
spreadsheet written by its security function, revised from time to time, and delivered filled in —
in the same format — for each product. Some of its lines ask for things Vectispire already measures
(dependencies analysed, static analysis clean enough, no secret in the tree), some for things a CI
pipeline measures and Vectispire never sees (test coverage, a suite of architecture tests), and the
rest for things only a person can state (a penetration test was done, documentation exists).

Today that spreadsheet is filled by hand, from screenshots of the tools. The answers carry no date
and no evidence, the author of each line is whoever saved the file last, and a new revision of the
template is filled from scratch or, worse, by copying the old answers onto lines that no longer ask
the same thing.

Decision [0023](0023-solutions-projects-and-repositories.md) introduced projects precisely because
"reports and checklists are written per project". This record designs the checklist.

### What the product already has, and why none of it is the checklist

- **The statement of applicability** ([`StatementOfApplicability`](../../../../vectispire-java/vectispire-common/src/main/java/com/asmolabs/vectispire/common/domain/compliance/StatementOfApplicability.java))
  is one declaration for the whole organisation, per framework, whose controls are an enumeration in
  the jar. A checklist is per project, its controls arrive as a file the organisation wrote, and they
  change between versions. What the SoA does teach — and this record keeps — is that **the
  interesting artefact is the disagreement between what is declared and what is measured**, and that
  a control evidenced elsewhere is "not measured here", never a finding.
- **SARIF imports from declared internal sources** ([0017](0017-custom-checks-as-container-images.md)
  §7): one integration key, one declared source, one scope, an allow-list of tools, every accepted
  document hashed and audited. Coverage and test reports are the same problem — an internal CI's
  output, deposited by a key — and reuse the model rather than invent a second one.
- **Four-eyes** on triage ([`IssueTriageService`](../../../../vectispire-java/vectispire-core/src/main/java/com/asmolabs/vectispire/core/issues/IssueTriageService.java)):
  counted as two people, not two roles, behind `FOUR_EYES_APPROVAL_REQUIRED`, which cannot be enabled
  while no second approver exists.
- **Signing** ([`SigningKeyService`](../../../../vectispire-java/vectispire-core/src/main/java/com/asmolabs/vectispire/core/crypto/SigningKeyService.java))
  and [`ProductVersion`](../../../../vectispire-java/vectispire-core/src/main/java/com/asmolabs/vectispire/core/settings/ProductVersion.java):
  every document Vectispire produces is signed by one key and states the version that produced it.

### What a template looks like — its structure, not its content

The first template the owner brought is internal to the organisation that wrote it. **Its content
does not enter this repository**: not a control, not a domain name, not a file. What it taught is
its shape, which is the shape any such workbook is likely to have:

- a workbook of three sheets: instructions in prose, the checklist itself, and a sheet holding the
  answer value list;
- on the checklist sheet, a merged title row, then **header cells** — a date, the product, the author
  — each a label cell with its value cell beside it, then a **column header row**, then **one row per
  control**;
- seven columns per control: domain, objective, control, contact person, KPI, answer, comment. The
  domain and the objective are written on the first row of their group and **left blank below**, to
  be read as "same as above". The contact is a role, not a person. The KPI is free text and mostly
  empty. The comment's header says it is mandatory when the answer is negative;
- the answer cells carry a **data validation list** that points at the value sheet — two values, a
  yes and a no, in the organisation's language. That validation is stored as an Office extension
  element, and a mainstream library announced on loading the file that it would drop it: a
  round-trip through a spreadsheet model would have lost the one rule the template enforces;
- the date's value cell holds a **formula that recalculates at every opening**, which dates any saved
  copy to the day somebody last looked at it;
- **nothing identifies a control but its text**: no id column, a numbering inside the objective's
  label, one cell comment on one row.

Every example in this record is invented for it.

## Decision

### 1. A module, `checklists`, and what it owns

A new vertical module `core.checklists` (decisions 0028–0030), above `plugins` and below
`compliance` and `platform`. It owns the templates, their versions and items, the project
checklists, their answers, evidence and measurements, and the rendered documents. Its `package-info`
declares, each with its reason:

| Dependency | Why |
|---|---|
| `access`, `access::security` | the routes' markers, `VisibilityService`, and the whole-project guard (§8) |
| `targets` | projects, their repositories, the repositories' schedules; `ProjectDeleted` |
| `scanning`, `scanning::queries` | the newest scan that examined a type, its SBOM digest (§6) |
| `issues`, `issues::queries` | open and resolved counts by tool scope and severity, through `IssueFilters` |
| `plugins` | plugin outcomes, SARIF imports, coverage and test-report imports (§7) |
| `inventory` | components of the newest SBOM, for the component-version rule |

The foundation it uses (`audit`, `settings`, `crypto`) is shared and not listed. The lines
`ArchitectureTest.MODULES` and `ModularityTest.MODULES` gain the module. `checklists` is not in
`accessForRoutesOnly`: its services refuse a project themselves (§8).

The pure parts — the model, the rules' evaluation over views, the workbook reader and writer — live
in `vectispire-common/domain/checklists`, JDK only: `java.util.zip` and StAX, no spreadsheet library
(§10).

Tables, all created in common migrations from V49 on (the next free number when the lot lands) with
the `MigrationDialect` placeholders, **no foreign key** — the owner's listeners purge them, the
`t_plugin_activation` pattern:

| Table | Owner | Holds |
|---|---|---|
| `t_checklist_template` | `checklists` | slug (unique), name, created by and at |
| `t_checklist_template_version` | `checklists` | template, ordinal, label, status (`draft`, `published`, `retired`), the source file's SHA-256 and bytes, the **layout** (JSON: sheet, header cells, column letters, first and last item rows, answer words), whether "not applicable" is offered, imported, published and retired by and at |
| `t_checklist_item` | `checklists` | version, **item key**, position, domain, objective, control, contact, KPI text, the item's **content digest**, its row in the sheet, the evidence requirement, the bound rule (kind and parameters, JSON) |
| `t_checklist` | `checklists` | project, template version, **revision**, status (`draft`, `submitted`, `signed_off`, `superseded`), the header's author, opened, submitted, returned, signed off by and at, the revision it supersedes, an `open_slot` column (below) |
| `t_checklist_answer` | `checklists` | checklist, item, value, comment, answered by and at, the measurement it rests on, carried from which answer and by whom, `needs_confirmation`. **Append-only** |
| `t_checklist_evidence` | `checklists` | checklist, item, a link or a file (name, media type, size, SHA-256), performed on, valid until, added by and at, withdrawn by and at |
| `t_checklist_file` | `checklists` | the bytes of an uploaded file, apart, so that no listing ever loads them |
| `t_checklist_measurement` | `checklists` | checklist, item, rule kind, the parameters' digest, outcome, reason, as-of instant, computed at, the evidence (JSON) |
| `t_checklist_document` | `checklists` | a signed-off revision's rendered package: its bytes, SHA-256, signature, `ProductVersion`, produced at |
| `t_sarif_source` (+ `kinds`) | `plugins` | the report kinds a declared source may deliver (§7) |
| `t_coverage_import` | `plugins` | source, key, repository, format, line and branch counts, SHA-256, the commit and branch the pipeline states |
| `t_test_report_import`, `t_test_suite_result` | `plugins` | the import's totals and SHA-256; per suite, its name and its counts |
| `t_scan` (+ `examined_types`) | `scanning` | the built-in types a scan actually examined (§6) |

Two portability notes, decided now because each has a trap:

- **Binary columns need a placeholder that does not exist yet**: `${bytes}` — `bytea`, `longblob`,
  `blob`. A new placeholder is allowed; its value is frozen once a migration uses it. The entities
  map it with an explicit JDBC type, **never `@Lob`**, which Hibernate maps to a PostgreSQL large
  object (`oid`) rather than `bytea`; `SchemaParityIntegrationTest` decides on the three engines.
- **"At most one open checklist per project"** is a unique constraint on `(project_id, open_slot)`
  where `open_slot` is `1` for a draft or submitted revision and `null` otherwise. All three engines
  allow several nulls under a unique constraint, which a partial index would have needed three
  dialects to say.

### 2. The model

A **template** is the organisation's checklist, under a slug. It has **versions**; an item belongs to
one version. An item carries:

- **domain, objective, control, contact, KPI** — the template's words, stored as imported and shown
  as written. The contact is text: a role, not an account;
- an **item key**, stable across versions (§4), and a **content digest**, SHA-256 over the normalised
  domain, objective, control, KPI text, evidence requirement and bound rule;
- an **evidence requirement**: none, a link or a file, or a file; and, when a proof expires, a
  validity in months;
- at most one **bound rule** (§6) — a line Vectispire can measure.

An **answer** is one of a closed set, `ChecklistAnswer`: `YES`, `NO`, `NOT_APPLICABLE`. The comment
is **required for `NO` and `NOT_APPLICABLE`** — a negative answer without its reason is the line the
reader of the document needs most, and "not applicable" without a justification is an exclusion
nobody argued, which the SoA already refuses (`EXCLUDED_WITHOUT_JUSTIFICATION`). A version offers
`NOT_APPLICABLE` only if its importer said so (open question 1). Bounded before the write: a comment
at 4,000 characters, a link at 2,000, an `https:` or `http:` link only.

A **checklist** is one revision of one project's answers against one version. Its **header** is the
project's name (the product), the author — the account responsible for it, chosen when it is opened —
and the date, which in a document is the **sign-off instant**, never "now" (§10).

### 3. Importing a template from a workbook

`POST /api/v1/checklist-templates/{slug}/versions` takes the `.xlsx` as a raw body (no multipart:
there is no multipart route, and `RequestBodyLimitFilter` bounds a raw body where it could not bound
a part), 10 MB, a line of its own in the filter. The reader, in `common/domain`, refuses before it
parses: more than 200 zip entries, more than 50 MB uncompressed, an entry compressed more than 100 to
one, a DTD in any part (a workbook never needs one), an external relationship target. Macros
(`.xlsm`) and the binary format are refused by content type and by the absence of the workbook part.

The import is **a draft version, previewed, then published** — never published in one step:

1. **The layout is proposed, then confirmed.** The reader finds the column header row, the header
   cells and the answer list (the data validation over the answer column, and the range it names),
   and proposes them. Finding them uses the file's structure — validation ranges, merged cells,
   which row is followed by a run of filled rows — and never a list of expected words, which would be
   one organisation's vocabulary built into the product. The importer confirms or corrects each
   column letter and each header cell. The confirmed layout is stored with the version; the renderer
   reads nothing else.
2. **Blank domain and objective cells are filled down** within the item rows, as the sheet means
   them. A row whose control cell is empty is not an item.
3. **The answer words are mapped** to `YES` and `NO` by the importer — the template's own words,
   whatever its language — and to `NOT_APPLICABLE` if the version offers it.
4. **The KPI stays text.** A rule's thresholds are structured parameters bound by a person (§6). A
   KPI is never parsed into a threshold: a number read out of a sentence is a rule nobody wrote, the
   same reason a failure's kind comes from a type and never from a message's words. The preview
   shows the KPI text beside the bound parameters so that the person binding them sees any
   disagreement.
5. **Items are paired with the previous version** (§4), and the pairing is shown.
6. **Published**, by somebody holding the right (§8). A published version is immutable. Changing a
   threshold, a binding or a word means a new version — which may be **derived** from the previous
   one without a new file: same workbook, same layout, new bindings.

The source file is kept, bytes and SHA-256: the renderer writes into it, and an auditor can compare
the delivered document with the template it claims to follow.

### 4. Versions, and how answers cross them

**A new version never rewrites an answer given under an old one.** Answers are rows of a checklist,
a checklist belongs to one version, and publishing a version changes no checklist.

**Item identity.** The key comes from an id column when the layout names one; otherwise it is derived
from the normalised control text. Pairing a new version with the previous one:

- same key, same content digest — **unchanged**;
- same key, different digest — **changed**: the KPI, the binding or the wording moved;
- no key on the other side — **added** or **removed**;
- the importer may pair an added item with a removed one by hand ("same control, reworded"), which
  gives the new item the old key and marks it changed. The pairing is recorded in the version.

**Moving a project to a new version** is an explicit act on that project
(`POST /api/v1/projects/{id}/checklists`, naming the version). It opens a new revision on the new
version and **carries** answers into it: each carried answer is a new row that points at the answer
it came from, keeps that answer's author and instant as its own, and names who carried it and when.
An unchanged item's answer is carried as current. A changed item's answer is carried with
`needs_confirmation`, and a revision holding one cannot be submitted until somebody answers the line
again or confirms it. An added item starts unanswered; a removed item's answer stays where it was
given. Measurements are **never carried** — they are recomputed (§6). The previous revision stays
readable; a draft or submitted one becomes `superseded`, a signed-off one stays signed off.

Retiring a version stops new checklists being opened on it; every checklist on it stays readable and
exportable.

### 5. A checklist per project: its life and its history

```
            submit                 sign off
  draft ────────────► submitted ────────────► signed_off
    ▲                     │                       │
    └──── return ─────────┘                       │ reopen
    ▲  (with a reason)                            ▼
    └────────────────────────────── new revision, draft
```

- **Answering** writes a new answer row; the previous one is not updated. The current answer is the
  newest row per item, the **history** is every row with its author and instant. The author is the
  principal, never a name taken from the body. A submitted revision is not answered: it is returned
  first.
- **Evidence** is a link or an uploaded file (25 MB, a line of its own in the body limits), with the
  date the work was performed and, for an item that asks for it, its validity. A file is served back
  only as a download — `Content-Disposition: attachment`, `X-Content-Type-Options: nosniff`, its
  stored media type never trusted to render — because an uploaded HTML or SVG file served inline is a
  script on the control plane's origin. Evidence is withdrawn, never deleted, while the revision is a
  draft; the withdrawal is dated and attributed.
- **Submitting** requires every item answered, every negative or not-applicable answer commented,
  every evidence requirement met and in date, no answer awaiting confirmation, and the measurements
  recomputed (§6).
- **Reopening** a signed-off revision opens the next revision with every answer carried as current
  (same version, nothing to confirm); the signed revision is never modified.

### 6. What Vectispire prefills, from what, and when it refuses

**Vectispire never answers.** It writes **measurements**; people write answers. A line bound to a rule
shows its measurement beside the answer, and the answer form is prefilled from it — one click to
accept, which records an answer by that person resting on that measurement. An answer written by
the system would put, in a document a person signs, a claim that person never made; the actor is the
principal.

A measurement has an outcome — `PASS`, `FAIL` or `NO_DATA` — a typed reason, the instant it is **as
of** (the oldest evidence it rests on), the instant it was computed, and its evidence: for each
repository of the project, the scan or the import it read, its date, its digest, and the figures.

**The rules are a closed set** (`ChecklistRule`, a sealed interface in `common/domain`, one record of
parameters per kind). No parameter has a product default that decides an outcome: thresholds are the
organisation's KPI, stated when the rule is bound, and a rule without a maximum age is refused at
binding. The form proposes seven days.

| Kind | Reads | `PASS` when, on every repository of the project |
|---|---|---|
| `DEPENDENCY_ANALYSIS` | the newest scan whose dependency step **produced**, its SBOM; the repository's schedule | such a scan is within the maximum age, it stored an SBOM, and — if the rule asks — the repository is scheduled at least as often as the maximum age; optional thresholds on open vulnerabilities |
| `FINDINGS_THRESHOLD` | for each tool scope named — `builtin:sast`, `builtin:secret`, `builtin:iac`, `builtin:vulnerability`, `plugin:<id>`, `import:<source>/<tool>` — the newest scan or import in which that scope **produced**; the backlog in that scope | every scope produced within the maximum age, and the open counts and resolved ratios meet the thresholds per severity |
| `COVERAGE_THRESHOLD` | the newest coverage import (§7) | it is within the maximum age and its line (or branch) ratio meets the minimum — per repository, or weighted over the project if the rule says so |
| `TEST_SUITE_PASSED` | the newest test-report import (§7) and the suites matching a glob | at least one suite matches, it ran at least the stated minimum of tests (skipped ones not counted), none failed and none errored, within the maximum age |
| `COMPONENT_VERSIONS` | the components of the newest SBOM | every declared package (a purl prefix) is present at one of the versions the organisation allows |

"No plaintext secret in configuration" is `FINDINGS_THRESHOLD` over `builtin:secret` with every
count at zero, offered as a preset. An invented example of a binding: *"Static analysis runs on every
change"*, KPI *"no critical, at most two high, 60 % of the medium resolved"*, bound to
`FINDINGS_THRESHOLD` over `builtin:sast` and `import:quality-server/sonarqube`, maximum age 7 days,
`critical.max_open = 0`, `high.max_open = 2`, `medium.min_resolved_ratio = 0.6`.

**The resolved ratio** of a severity is resolved ÷ (resolved + open) over the project's issues in
those scopes, **settled triage left out of both sides** — the rule every figure of risk follows, with
`not in (TriageStatus.settledWireNames())`, so that a status this version does not know still counts
as open. Every count it used is in the evidence (open question 6 is the window).

**`COMPONENT_VERSIONS` is off by default in the strongest sense**: the product ships no package list,
and the kind appears in no template until an organisation binds it with its own prefixes and allowed
versions. It exists for the organisation that requires its internal libraries at maintained
versions; nothing about any particular one is written in code or documentation.

**`NO_DATA` is never `PASS`, and it says why** — ADR [0007](0007-none-is-not-an-empty-list.md) applied
to a checklist line. The reasons are a closed set:

| Reason | Meaning |
|---|---|
| `NO_REPOSITORY` | the project has no repository. "Every one of zero repositories passes" is exactly the vacuous truth this rule forbids |
| `NEVER_EXAMINED` | a repository has no scan or import in which the scope produced |
| `STALE` | the newest one is older than the maximum age |
| `STEP_ABSENT` | the step or plugin was absent in every scan within the age — did not look, not found nothing |
| `EXAMINATION_UNRECORDED` | the scans within the age predate `examined_types`, so whether the step ran is unknown |
| `NOT_APPLICABLE_ANYWHERE` | a plugin was `not_applicable` on every repository: it applies to none of them, and a line passed by a tool that looked at nothing would be passed on absent data |
| `SUITE_NOT_FOUND`, `NO_TEST_RAN` | no suite matched, or those that matched ran nothing |

**Three states of a plugin are kept** ([0017](0017-custom-checks-as-container-images.md)): a repository
where the plugin was `not_applicable` is left out of that scope's figures and does not fail it; one
where it was `absent` is `STEP_ABSENT`. A SARIF import's tool produced when the import was accepted —
0017 already refuses a result-less or failed run.

**`t_scan.examined_types` is a prerequisite.** A scan records which plugins produced
(`plugin_steps`) but not which built-in steps did: `ScanIngestor` computes the set and discards it,
and the step failures survive only as a sentence in `error`. The set is written on the scan from V49
on. Scans from before stay `EXAMINATION_UNRECORDED` until each repository is scanned again, which is
the honest answer: nothing recorded whether they looked.

**Freshness is re-judged at every step that relies on it.** A measurement is computed on demand, at
submission, and again inside the sign-off. An answer `YES` rests on a measurement; if the sign-off's
recomputation no longer gives `PASS`, the sign-off is refused and names the lines — a signature
must not attest to evidence that stopped being true between submission and signature. A signed-off
revision freezes its measurements with it.

**Answer and measurement are reconciled** in the SoA's vocabulary, shown on the screen and in the
document:

| Answer | Measurement | Line |
|---|---|---|
| `YES` | `PASS` | consistent |
| `YES` | `FAIL` | **contradicted** — refused at submission (open question 3) |
| `YES` | `NO_DATA` | declared, not measured — allowed with a comment and evidence (open question 4) |
| `NO` | `PASS` | understated — allowed; the comment says why |
| any | no rule bound | not measured here |

**Traceability controls** — an audit trail, a role that reads it — describe the product being
built, which Vectispire does not see. They stay manual. An organisation that proves them with its
own tests binds `TEST_SUITE_PASSED` to those suites.

**Performance and limits.** The rules read the owners' APIs (`ScanCatalog`, `IssueCatalog`, the
plugins' and inventory's catalogues), each gaining the grouped query it needs — never another
module's repository. A project's repository ids reach those queries in batches of 1,000, the
`TargetCatalog.carryingCredentials` rule: an `in (:list)` sized by the data fails one day.

### 7. Two new inputs: coverage and test reports, from declared internal sources

Coverage and test reports are the internal CI's output, like its SARIF, and arrive the same way. This
amends 0017 §7:

- **A declared source states the kinds it may deliver**: `sarif`, `coverage`, `test_report`
  (`t_sarif_source.kinds`, `sarif` for every existing row). One pipeline, one key, one declaration,
  one scope — a project or a repository, never the estate. The table keeps its name: renaming it is a
  migration of its own for nothing a reader sees.
- **A new key scope, `report_import`**, never granted by default, required for the two new kinds;
  `sarif_import` stays SARIF's. A key presented for a kind its source does not declare, or without the
  scope, is refused 403, audited and signalled.
- **Routes**, `@AcceptsApiKey(REPORT_IMPORT)`, `@RequiresWriteAccount`, with 0017's refusals in 0017's
  order — a session is not a source (403), undeclared source (403), repository hidden or outside the
  scope (404, in the words of an absent repository):
  - `POST /api/v1/repositories/{id}/coverage-imports?format=jacoco|cobertura|lcov`, 16 MB. The format
    is declared, never sniffed; a body that does not read as it is 400. Stored: line and branch
    covered and total, the tool and version if the format states them, SHA-256, and the `commit` and
    `branch` the pipeline states — kept as the pipeline's word, verified against nothing.
  - `POST /api/v1/repositories/{id}/test-report-imports`, 32 MB: a JUnit XML document (`testsuites` or
    `testsuite` root) or a zip of them, since most build tools write one file per class — at most
    5,000 entries, and the reader's zip guards. Stored: totals, and per suite its name and counts.
- **XML is read without resolving anything.** Some coverage formats open with a `DOCTYPE` naming a
  DTD, so refusing any DOCTYPE would refuse them: the declaration is tolerated, never loaded, and an
  entity declaration is refused. Nesting, attribute and element counts are bounded like
  `SarifReport`'s.
- **An empty report is refused, not recorded.** Coverage over zero lines is neither 0 % nor 100 %;
  a test report with no test is not a passing suite. Both are 400, in words.
- Accepted: `COVERAGE_IMPORTED`, `TEST_REPORT_IMPORTED`. The repository's page lists the latest of
  each, with its source and date.

Coverage per file, and the test cases themselves, are not stored in this version.

### 8. Who may do what

| Act | Who | Marker, and what the service checks |
|---|---|---|
| Import, derive, bind rules on a draft version | `canWriteGovernance` — platform governor, administrator, CISO | `@RequiresSecurityLead`, which admits exactly those three |
| Publish, retire a version | the same, and, with four-eyes on, **not the person who imported or derived it** | same |
| Declare a report source | platform governor | `@RequiresPlatformGovernor`, as SARIF sources |
| Read a project's checklists | anybody to whom the **whole project** is visible | `@RequiresAccount` + the guard below |
| Open, answer, attach, submit, return, reopen | `canCauseEffects`, whole project visible | `@RequiresWriteAccount` + the guard |
| Sign off | `canApproveTriage` — administrator, CISO, security champion — whole project visible, and, with four-eyes on, **not the submitter** | `@RequiresWriteAccount` (no marker holds exactly the approvers) + the guard + the flag and the comparison in the service |

**The whole project, or nothing.** A checklist speaks for every repository of its project, and its
measurements carry figures from each. A reader who sees only part of a project would read, in a
single line, the state of repositories hidden from them. So the project's checklists are visible
when the caller's visibility is everything, when the project is granted as such, or when every one
of its repositories is visible and there is at least one; otherwise 404, the words of an absent
project (open question 5). The guard is `RowVisibility.requireWhollyVisibleProject`, which mints a
`VisibleProject` — the checklist services take it, never a bare id, and refuse through it; the
routes leave the refusal to the service (`routesLeaveTheRefusalToTheirServices`). An integration key
restricted to one repository never sees a whole project, so the export route that accepts
`@AcceptsApiKey(EXPORT)` answers such a key 404.

**The platform governor defines the checklist and does not fill it.** It may write templates — it
decides the rules — and holds neither `canCauseEffects` nor `canApproveTriage`: it cannot answer nor
sign off. The auditor reads everything and writes nothing.

**Four-eyes on the sign-off follows the platform's setting**, `FOUR_EYES_APPROVAL_REQUIRED`, compared
as two people like the triage (open question 2). The document states which applied: submitted by
whom, signed off by whom, and whether the rule required them to differ.

### 9. Audit and SIEM

Every write is an `AuditOperation`, recorded after commit (a `TransactionTemplate` for the writes,
then `AuditLogService.record`). The body is private, the audited method the only way in.

`CHECKLIST_TEMPLATE_IMPORTED`, `CHECKLIST_TEMPLATE_DERIVED`, `CHECKLIST_TEMPLATE_PUBLISHED`,
`CHECKLIST_TEMPLATE_RETIRED`, `CHECKLIST_OPENED`, `CHECKLIST_MOVED_TO_VERSION`, `CHECKLIST_ANSWERED`,
`CHECKLIST_EVIDENCE_ADDED`, `CHECKLIST_EVIDENCE_WITHDRAWN`, `CHECKLIST_SUBMITTED`, `CHECKLIST_RETURNED`,
`CHECKLIST_SIGNED_OFF`, `CHECKLIST_SIGN_OFF_REFUSED`, `CHECKLIST_REOPENED`, `CHECKLIST_EXPORTED`,
`COVERAGE_IMPORTED`, `TEST_REPORT_IMPORTED`, `REPORT_IMPORT_REFUSED`.

SIEM events, through the outbox (decision 0025). The numbers are proposed, frozen by
`SecurityEventTypeTest` when they are emitted:

| Id | Event | Why a SOC wants it |
|---|---|---|
| `ZAN-SEC-024` | checklist template published or retired | what every project attests to has changed |
| `ZAN-SEC-025` | checklist signed off | a release attestation was given, and by whom |
| `ZAN-SEC-026` | checklist sign-off refused or returned | a four-eyes refusal, or evidence that stopped holding |
| `ZAN-SEC-027` | report import refused | a key used for what its source was not declared for — `ZAN-SEC-023`'s twin |

A declared source whose kinds change is `ZAN-SEC-022`: it is the same act — who may deposit what —
and its identifier is the contract. Answers do not signal: they are work, not security events.

### 10. The filled workbook, signed — rendered in core; report plugins later

**The document.** `GET /api/v1/projects/{id}/checklists/{revision}/document` returns a zip:

- `checklist.xlsx` — **the template's own file, patched**. The renderer copies every part of the
  package byte for byte and rewrites only the answer and comment cells of each item row and the
  header's value cells: the answer as the template's own word, the comment as written, the author,
  the product, and the date **as a value — the sign-off instant**, replacing a formula if the template
  had one (and dropping the calculation chain, which would otherwise name a formula that is gone).
  Every other sheet, the validation lists, the extensions, the comments, the styles survive because
  nothing reads them. One sheet is **added**, `Evidence`, one row per item: answer, author, instant,
  the measurement's outcome, as-of date and evidence summary, the evidence's links and digests, then
  the submitter, the signer and the four-eyes rule (open question 12). Cells are written as inline
  strings so the shared-strings table is untouched. Entries are written in their original order with
  fixed timestamps, so a revision renders to the same bytes.
- `checklist.json` — the same statement, machine-readable: project, revision, template slug, version
  and source SHA-256, every item with its answers and history, measurements and evidence digests,
  submitter, signer, `ProductVersion`. Attachments are named by digest, not included.
- `checklist.xlsx.sig`, `checklist.json.sig` — detached signatures by the signing key, verifiable with
  `cosign verify-blob --key` against the published public key, like every other export.

A **signed-off** revision's package is rendered and signed inside the sign-off and stored in
`t_checklist_document`; the route serves those bytes, so the document an auditor receives next year
is the one that was signed. A draft or submitted revision renders on request, unsigned, its
`Evidence` sheet opening with *"Draft — not signed off"*.

**Why core renders the first version, and the report plugin comes later.**

- The signature is the control plane's in any case: the key never leaves it, so a plugin would hand
  back bytes and core would sign them. Designing that hand-off — which project data a container may
  receive, in which shape, and what a signature over a plugin's output then claims — is a decision of
  its own, and the P3 "report plugins" block is where it belongs.
- A report plugin receives project data the way a scanner plugin receives a tree — in the closed
  shape, no network, one bounded output. Answers, evidence and figures are confidential in a way a
  source tree already handed to a scanner is not. That boundary deserves its own record rather than
  being settled as a by-product of the first checklist.
- The first renderer is a pure function in `common/domain` — template bytes and a `checklist.json`
  statement in, package bytes out — testable in-process against generated workbooks. **`checklist.json`
  is the input contract a report plugin will receive**; the core renderer becomes the built-in
  implementation of it, the way the built-in scanners are beside plugins.
- No spreadsheet library: the renderer does not need to understand a workbook, only to replace a
  handful of cells in one part. A library that loads and re-saves a package keeps what it models, and
  the one rule this template enforces lived in an extension a mainstream reader drops.

### 11. Out of scope

- Container images in a checklist: they are not filed into projects (0023).
- Checklists per repository, per solution, or organisation-wide (that is the SoA).
- Legacy `.xls`, `.ods`, macro-enabled workbooks, and formulas evaluated by the product.
- Assigning items to accounts from the contact column, reminders, due dates, notifications.
- Running DAST or a penetration test: the product records that one was done.
- Coverage per file, individual test cases, trends.
- Signed checklists in the compliance evidence bundle — a later step, which will make `compliance`
  depend on `checklists`.
- The report plugin mechanism (§10), and any renderer but the workbook.
- A qualified electronic signature of the sign-off: the sign-off is an authenticated, audited act,
  and the document is signed by the platform's key.

## Alternatives considered

- **The checklist as one more framework of the statement of applicability.** The SoA is one
  declaration for the organisation, over controls built into the jar; it has no project, no version
  and no template file. Stretching it would turn its "undeclared" line into noise on every project.
- **Shipping a checklist.** The organisation's template is the authority, and the first one is not
  ours to publish. The product ships a model and an importer; a sample template for the test suite is
  generated by the test, from invented controls.
- **Vectispire answering the measurable lines itself.** Faster, and it would put in a signed document
  claims no person made. Measurements beside answers keep the actor the principal and keep the
  disagreement visible, which is what an assessor opens with.
- **Parsing the KPI column into thresholds.** Reads rules out of prose; a template's wording is not a
  contract. Structured parameters, bound and published by a person, with the KPI text beside them.
- **Keying answers by row number, or rewriting answers onto the new version in place.** A row number
  moves when a line is inserted; rewriting answers is precisely what the requirement forbids.
  Carried copies that point at their origin, confirmed where the item changed, keep both versions
  true.
- **A spreadsheet library (Apache POI, or a model round-trip).** A large dependency with a history of
  XML and zip advisories, and a round-trip keeps only what it models. Patching the cells of one part
  keeps everything else by construction.
- **Files on the control plane's disk.** They would escape the database backup the restore drill
  proves, and a second instance would not see them. Bytes in the database, bounded, in a table no
  listing reads.
- **Coverage through SARIF, or a plugin that runs the tests.** SARIF has no coverage; running tests
  needs a build, which the closed shape forbids (0017 §8).
- **A second kind of declared source for CI reports.** One pipeline would need two keys and two
  declarations for one producer; a kind on the one declaration says the same thing once.
- **Passing a line when the project has no repository, or when a scope applied nowhere.** The vacuous
  truth that ADR 0007 exists to refuse.

## Consequences

- A 27th module, `checklists`; the `package-info` list above, reviewed line by line.
- Migrations from V49 on, written once in `common` if they differ only by types; `${bytes}` joins
  `MigrationDialect`. `integrationTestAll` for every lot that touches them.
- `t_scan.examined_types`: prefilling from scans starts working for a repository at its first scan
  after the upgrade. The upgrade notes say so, and the lines say `EXAMINATION_UNRECORDED` until then.
- A new key scope, `report_import`; new body limits (template 10 MB, evidence 25 MB, coverage 16 MB,
  test reports 32 MB), each a line of `RequestBodyLimitFilter` with its reason.
- New audit operations and four SIEM identifiers; the catalogue test freezes them.
- New routes: the OpenAPI contract is regenerated with each backend lot, the client types with it.
- No `MaintenanceTask`: everything is computed on read and frozen at sign-off. An evidence validity
  lapsing is visible on the next read, not announced.
- Documentation in both languages: a guide page for project checklists, an administration page for
  templates, the CI integration page for the two imports, and the compliance page's link to it.
- A signed checklist is as trustworthy as its inputs: a coverage figure is the pipeline's word, bound
  to a declared key and hashed, and the document says which. That is the same limit 0017 states for
  SARIF, stated again here because a checklist is where somebody will forget it.

## Questions settled on 2026-09-28

The owner accepted every recommendation below as written; each is now part of the decision.

Each with the recommendation this proposal makes.

1. **"Not applicable".** Offer it? *Recommended: per version, off unless the importer maps a word to
   it; its comment is mandatory. When the template's value list has no such word, the importer
   supplies one; the renderer writes it and does not modify the template's list.*
2. **Four-eyes on the sign-off: the platform setting, or always?** *Recommended: the setting. An
   installation with one approver could otherwise never sign, and enabling the setting already
   requires a second approver; the document states which rule applied.*
3. **`YES` against a failing measurement.** Refuse, or allow with a comment? *Recommended: refuse at
   submission. A false positive is settled by triage, which the figures then leave out; an
   organisation that disagrees with the rule changes the binding in a new version, visibly.*
4. **`YES` with no data.** *Recommended: allowed, with a comment and an evidence item, marked
   "declared, not measured" on the screen and in the document.*
5. **A reader who sees part of a project.** *Recommended: 404 on the project's checklists. The
   alternative — answers without measurements — leaks through the answers themselves ("no: repository
   X still has a critical").*
6. **The window of a resolved ratio.** *Recommended: every issue ever recorded in those scopes on the
   project, settled triage left out of both sides, counts in the evidence. Alternative: a window
   parameter on the rule (issues first seen within N days).*
7. **Where coverage and test imports live.** *Recommended: `plugins`, beside the declared sources they
   depend on. Alternative: a new `imports` module taking the SARIF imports with it — cleaner, and a
   refactor of shipped code to do first.*
8. **One scope for both new kinds.** *Recommended: `report_import` for coverage and test reports,
   `sarif_import` unchanged. Alternative: one scope per kind.*
9. **Four-eyes on publishing a template version.** *Recommended: yes, when the setting is on —
   publishing changes what every project attests to.*
10. **Deleting a project.** *Recommended: its checklists, answers, evidence and documents are purged in
    the `ProjectDeleted` transaction, the pattern every other project-scoped row follows; the audit
    entries remain, and so do the signed documents already delivered. Alternative: keep signed
    revisions as orphans — evidence nobody can see through any grant.*
11. **Component versions.** *Recommended: an explicit list of allowed versions per purl prefix in v1.
    Version ordering per ecosystem ("at least 3.2") is a later step; an ordering done wrong passes a
    line.*
12. **Where evidence goes in the workbook.** *Recommended: the added `Evidence` sheet, the template's
    own sheets holding only the organisation's columns. Alternative: appended to the comment cell.*
13. **Uploaded files in v1, or links only.** *Recommended: both, bounded, served as downloads only.*
14. **The report plugin mechanism in the first version.** *Recommended: no — §10.*
15. **Signed checklists in the evidence bundle.** *Recommended: a later lot, once a signed-off
    revision exists to include.*
16. **The contact column.** *Recommended: text only in v1; mapping roles to teams for assignment is a
    later step.*

## Implementation

Split into independently shippable lots in
[the implementation plan](../../../analysis/security-checklists-plan.md).

## Amendment (2026-09-29) — who sets an item's evidence requirement

**The gap.** §2 gives every item an evidence requirement — none, a link or a file, or a file, and a
validity in months — and §5 refuses a submission until each is met and in date; neither says who sets
it. No column of an organisation's workbook states it, so the import of §3 read every item as `none`,
and no proof was ever required of anybody.

**The resolution.** The requirement is set by a person on a **draft** version, like its layout and its
pairs (§3, before step 6): `PUT /api/v1/checklist-templates/{slug}/versions/{ordinal}/evidence`, for
each item named by its key, the kind and the optional validity (1 to 120 months). It is the security
lead's (§8), names the `revision` the editor read (absent 400, stale 409 `checklist-template-changed`),
makes its editor one of the draft's authors for four-eyes, and is audited as
`CHECKLIST_TEMPLATE_EVIDENCE_SET` — an operation of its own, since nothing of the workbook is read
again. A published version's requirements never change: derive a new version, which carries them.

The requirement stays in the content digest, as §2 has it, so a moved requirement makes the item
*changed* (§4) and a carried answer waits for confirmation. Two consequences follow, and both are
decided the same way — a requirement follows its item's key: confirming a draft's layout again keeps
each item's requirement, and a new workbook's item takes the requirement of the previous version's
item with the same key. Read as the workbook says, both would drop every requirement, and the second
would mark every such item changed.

## Amendment (2026-09-29) — what §10 left open, as the renderer settled it

Building lot L8 met four cases §10 does not decide. Each is settled in the code; this records them so
the record and the module agree.

- **The date of an unsigned rendering is empty.** §2 and §10 say a document is dated by the sign-off
  instant, never "now". A draft or submitted revision has no sign-off, and leaving the template's own
  formula (`NOW()` in the first real template) would mean exactly "now". The cell keeps its style and
  holds nothing; `checklist.json` carries `header.date` as `null`.
- **A revision signed off before signed documents existed** has no stored package. Its download is an
  unsigned rendering whose `Evidence` sheet opens with *"Signed off by … at … — but no signed document
  was produced then: this rendering is not signed"*, and the zip carries no `.sig`. Signing it now would
  attest, under today's key and reading, to a sign-off made without one.
- **The `Evidence` sheet is written in English** whatever the template's language, and its instants as
  UTC ISO-8601 text. The organisation's own sheets keep their words; the added sheet is Vectispire's
  statement, read by auditors and by the report plugins that will receive `checklist.json`.
- **A sign-off can now fail on rendering or signing, and rolls back whole.** An installation with
  neither `ENCRYPTION_KEY` nor `vectispire.signing.key` answers 412 at sign-off, as every other signed
  export already does. A template whose written cells include the master of a shared formula cannot be
  rendered, so none of its revisions can be signed off; checking this with a trial rendering when the
  version is published is a later step.

## Amendment (2026-09-29) — the scans answer the lines they measure

**What changes.** §6 said *"Vectispire never answers"*. The product owner reversed that on
2026-09-29: a line bound to a rule is answered by Vectispire from its measurement, so that a project's
checklist arrives filled with everything the scans can state. The concern §6 named — a signed document
carrying a claim its signer never made — is met by naming the author, not by forbidding the answer.

- **When.** When a scan or an import completes on a repository of a project with a checklist in
  draft, and when a checklist is opened or moved to another version. Never on a submitted or signed-off
  revision, never on a read.
- **What.** `PASS` answers *yes*; `FAIL` answers *no*, with a comment generated from the measurement
  (the rule and the figures that failed it) — the comment a *no* requires (§5) says what was measured,
  it does not pretend a person wrote it. `NO_DATA` answers nothing.
- **Who.** The author is **Vectispire**, a system actor that is no account and can hold no role. Every
  such answer rests on the measurement that produced it (the same reference the one-click answer
  keeps), enters the line's history, is audited `CHECKLIST_ANSWERED` with the system as actor, and is
  shown as *automatic* on the screen, in the `Evidence` sheet and in `checklist.json`.
- **People first.** An answer a person gave is never replaced by the system. An automatic answer is
  replaced by the system when its measurement changes (the history keeps both), and by a person who
  answers the line — from then on the answer is theirs and the scans leave it.
- **What a person still does.** Submitting and signing off stay acts of people, under four-eyes; the
  submitter attests to the whole revision, automatic answers included, and the document says which
  answers were automatic.
- **Who decides.** A platform setting, on by default, lets an organisation return to answers by people
  only; the one-click and the as-measured act remain either way.

**As built (2026-09-29).** Six points the amendment left to the implementation, settled in the code:

- **The author is a kind, not a name.** `t_checklist_answer.answered_by_kind` (`person`, `system`, V56),
  and `answered_by_id` null for the system and only for it — a check constraint holds the two together
  on every engine. `answered_by` reads *Vectispire*, which an account may also be called: every reader
  (the scans, four-eyes, the document) decides by the kind. The system is none of a revision's authors.
- **No data withdraws Vectispire's own answer.** The table stays append-only: a system row marked
  `withdrawn` makes the line unanswered and keeps what was withdrawn in the history. Left standing, a
  *yes* on data that stopped existing would be a claim nobody makes; the submission would catch it only
  as a *yes* without data.
- **"Its measurement changes" is its evidence digest.** The same evidence writes nothing, so neither a
  second scan finding the same nor an opening moves the edition under the people filling the checklist.
- **The audit entry has no actor**, as every entry nobody asked for (the posture digest, a lapsed
  acceptance): a description naming Vectispire, never an invented user.
- **The generated comment is in English**, like the `Evidence` sheet — the platform states no document
  language — and says *Measured by Vectispire*.
- **The triggers are ports** `scanning` and `plugins` declare (`RepositoryScanned`, `RepositoryReported`),
  called after their own commit and never able to fail the scan or the import; an opening answers right
  after its own commit, so the response shows the answers. The setting `checklist_auto_answer` is the
  platform governor's, like the other rules, and audited as a security setting.
