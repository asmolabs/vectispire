# In-depth audit — code, security, documentation

**29 August 2026, 21:10** · *Version française : [`2026-08-29_21_10_23_audit_approfondi_code_securite_doc.fr.md`](../fr/2026-08-29_21_10_23_audit_approfondi_code_securite_doc.fr.md)*

## Overall score: **8.4 / 10** — up from 8.1

**This is the first audit in the series with a Docker daemon on the machine.** Every item the
20:04 audit listed as *"what this audit could not measure"* — the multi-engine campaign, the
container runtime, the browser suite, the restore drill — was executed here. Three of the five
domains move as a result, and they do not move the same way.

**Verification rises because it was performed, not because it improved.** 87 engine-campaign tests
across PostgreSQL, MySQL and SQLite; 14 container cases against a real daemon; 13 Playwright cases
in a real browser against a real control plane; the restore drill end to end, including its own
built-in mutation. None of that had ever been run in this series.

**Two domains fall, and neither is a degradation.** Both findings below are things earlier audits
scored without measuring:

- **Four-eyes approval covers one of the two statuses that settle an issue.** With
  `triage_four_eyes_required` on, a plain reader marking `not_affected` correctly lands in
  `pending_approval` — and the same reader marking `fixed` settles it outright, HTTP 200, no second
  person. `FIXED` stops failing builds exactly as `NOT_AFFECTED` does. The setting's own help text
  promises both.
- **Three HTTP endpoints load the entire issues table.** Measured at three estate sizes: 23 → 223 →
  **623** entity loads for 20 → 220 → 620 issues. One of them is `/api/v1/dashboard`, the page
  every account lands on at sign-in.

| Domain | Score | Movement |
|---|---|---|
| Documentation & Architecture | **9.0** | ↑ |
| Security & Cryptography | **8.0** | = |
| Code quality | **8.0** | ↓ |
| Compliance & Standards | **8.0** | ↓ |
| **Verification that actually runs** | **9.0** | ↑↑ |

---

## 0. Remediation status — both findings closed

*Added after the audit. Full verification after the changes: **1326 JVM tests** (1320 before, +6),
**0 failures**, and the three-engine campaign green again — **PostgreSQL 29, MySQL 29, SQLite 29** —
which matters here because a DTO projection generates different SQL on each dialect.*

| # | Finding | Closed by | Proof it can fail |
|---|---|---|---|
| §3.1 | Four-eyes did not cover `FIXED` | The queue is entered on `status().isSettled()` — the property that already means "takes this out of the gate verdict" — instead of on `NOT_AFFECTED` by name, in `IssueTriageService`, and the approval branch in `apply` is widened to match. Two cases added to `BulkTriageRoutesTest`: a reader declaring `fixed` is queued, and the requester cannot then grant their own. | Both new cases fail against the old condition — they were written before the fix and failed. |
| §3.2 | Whole-table reads | Five reads converted to column projections through `IssueRows` (`Lifespan`, `Resolution`, `Observation`, `Attribution`, `GateRow`). `ReadCostRoutesTest` pins four routes with Hibernate's entity-load counter. | Put one `findAll` back in `SlaService` → **1 test fails**. |

### The ordering problem the fix uncovered

Widening the queue broke a neighbouring rule, and the interaction is worth recording. `Triage.decide`
requires a VEX justification for `PENDING_APPROVAL` — sound while the queue could only hold
exemptions, since a dismissal with no justification exports as an invalid VEX statement. A queued
**fix** is not an exemption and has no such justification to give, so every `fixed` from a reader
came back 400.

The fix is an ordering, not an exception: validate the decision the operator actually asked for,
then queue the result. `resolveRequest` (on the request, before validation) became
`queueIfNotApprover` (on the decision, after it). A dismissal still cannot reach the queue without
its justification; a fix is no longer asked for one.

### And a correction to §3.2's attribution

The audit named four `findAll` sites. Measuring the fix found **five**, and one of the four was
wrong: `/api/v1/dashboard` does not read through `DashboardController:237` but through
`GateService.openIssuesByTarget()`, and the compliance summary stayed linear after four
conversions because of a fifth read nobody had named — `SlaService.countOverdueByTarget`, which
loads every overdue issue in the estate to group them by target and reads two columns off each.
The measurement found it; reading the four named sites would not have.

---


## 1. What I executed

| Control | Command | Result |
|---|---|---|
| JVM suites, from scratch | `./gradlew build --rerun-tasks` | **1320 tests, 0 failures, 0 errors, 0 skipped** (259 suites, 35 tasks executed) |
| **Multi-engine campaign** | `./gradlew integrationTestAll` | **PostgreSQL 29, MySQL 29, SQLite 29 — 87 tests, 0 failures** |
| **Container runtime** | `./gradlew :vectispire-common:integrationTest` | **14 cases, 0 failures**, against a live daemon |
| **Browser suite** | `npx playwright test` | **13 passed** in 2.2 min, real control plane, real Chromium |
| **Restore drill** | `bash scripts/restore-drill.sh` | **passed**, its own mutation included |
| **Shipping image** | `docker build -f Dockerfile -t vectispire:latest .` | **built, 347 MB** |
| Angular suites | `npm test` | **146 tests, 23 files, 0 failures** |
| Relative links | `python3 scripts/check-doc-links.py` | **730 links, 0 broken** |
| C4 drift | `shasum -a 256` vs `.workspace.sha256` | **identical — in step** |
| Bilingual parity | `find docs/{fr,en} -name '*.md'` | **12 / 12** |
| ADR registry | `ls docs/architecture/{en,fr}/decisions/` | **0001 → 0017**, both languages |
| Four-eyes coverage | MockMvc, both settling statuses | **half-covered — §3.1** |
| Read cost | Hibernate counters, 3 estate sizes | **three endpoints linear — §3.2** |
| Branch gap | `git rev-list --count origin/main..develop` | **9** — was 3 this morning |
| GitHub run history | — | **not executed** — still no `gh` CLI |
| `gitleaks` | — | **not executed** — not installed |

### The campaign, named

Seven suites, each run three times — once per engine: `SingleSignOnIntegrationTest` (a real
Keycloak container), `SchemaParityIntegrationTest`, `HistoryQueriesIntegrationTest`,
`ScanQueueIntegrationTest`, `ComplianceSummaryIntegrationTest`, `LeaderElectionIntegrationTest`,
`SecurityDebtIntegrationTest`. The Flyway migrations apply and the schema validates on both
deployable engines and on the SQLite fixture — the claim ADR 0013/0014 rest on, verified rather
than repeated.

### The sandbox, as a daemon enforces it and not as the code requests it

The 20:04 audit could assert the flags were *set* and marked the runtime gap 🟡. The 14 cases now
run: *every capability is dropped*, *no process can gain privileges*, *the image's own filesystem
cannot be written to*, *a read-only mount cannot be written to*, *the scratch space is writable and
cannot be executed from*, *the network is off unless the run asks for it* — and its converse — *a
scanner that runs too long is stopped, not abandoned*. That closes §3.5 of the previous audit by
measurement.

---

## 2. Testing my own tests

Two assertions this series had never mutated, plus a correction of my own method.

| Mutation applied | Expected | Observed |
|---|---|---|
| `AuditLogService`: `row.setPreviousHash(previousHash)` → `setPreviousHash(null)` | failure | **fails** — *"the audit log's integrity chain › eachEntryChainsOntoTheOneBefore"* |
| `ContainerRunner.parseJson`: empty stdout returns `Optional.of(emptyArray)` instead of `Optional.empty()` | failure | **2 tests fail** — *"an absent result is not an empty one"* and *"records the failure rather than reporting a completed scan with nothing in it"* (ADR 0007) |

The second is the ADR 0007 rule under its own mutation for the first time: an empty list resolves
every existing issue of that type, an absent result changes nothing. The distinction is asserted
and it bites.

### And a correction of my own, recorded because the method demands it

My first Playwright run reported **10 of 13 failing**, including a security case —
*"an MFA challenge cannot be brute-forced with unlimited guesses"*. It would have been the headline
of this report. It was my error: I started the control plane without
`VECTISPIRE_BOOTSTRAP_PASSWORD`, which the nightly job sets, so no bootstrap account existed and
`signIn` could not authenticate. Re-run with the job's full environment — the five variables in
`nightly.yml`, `SPRING_JPA_HIBERNATE_DDL_AUTO=none` and the raised login-attempt ceiling
included — **13 of 13 pass**. A failing test is a claim like any other, and it has to be executed
correctly before it is reported.

---

## 3. Findings

### 3.1 🔴 Four-eyes approval does not cover `FIXED`, and the compliance report counts it as if it did

**Executed.** With `triage_four_eyes_required = true`, as a plain `USER` (`Role.USER`,
`canApproveTriage = false`), through the real filter chain:

```
PROBE four_eyes_required = true
PROBE reader not_affected -> HTTP 200 status=pending_approval settled=false
PROBE reader fixed        -> HTTP 200 status=fixed           settled=true
```

**What is wrong.** `IssueTriageService.resolveRequest` downgrades a request to
`PENDING_APPROVAL` on one condition:

```java
if (!canApprove && request != null && request.status() == TriageStatus.NOT_AFFECTED) {
```

`TriageStatus` marks **two** statuses as settling — `NOT_AFFECTED(true)` and `FIXED(true)` — and
`isSettled()` is what takes an issue out of the gate verdict. A reader cannot dismiss an issue as
not applicable without a second person; the same reader can declare it fixed, alone, and it stops
failing builds just the same.

The setting's own help text, which is what an operator reads before turning it on, says: *"marking
an issue as NOT_AFFECTED **or FIXED** by a user without CISO/Admin approval privileges creates a
PENDING_APPROVAL request."* Half of that sentence is not implemented.

**Why it matters beyond triage.** `ComplianceService:158` feeds this setting into
`ComplianceEngine.cappedByPlatform`, which caps GOVERNANCE at 75 when four-eyes is **off**, with
this reason: *"the account that raises an exemption can also grant it — the gate verdict below is
advisory rather than enforced"*. Switched **on**, the assessment passes uncapped — while the
account that wants an issue out of the way can still put it there alone, by choosing the other
word. `cappedByPlatform` exists precisely so a control is never reported compliant on the strength
of a mechanism that is switched off; here it is reported compliant on the strength of one that is
half on, and the projection reaches DORA and NIS 2 GOVERNANCE controls.

**What is right about the surrounding code**, so the fix does not undo it:
`requireASecondPairOfEyes` is careful work. It reads the requester from the **event history**
rather than from the row — `triagedBy` is overwritten by each decision, so by approval time the row
already names the approver — compares case-insensitively, and documents the one case it admits
deliberately (a pre-existing request with no recorded actor, which refusing would strand). That is
maker-checker counted as two people rather than two roles, and it is correct. It simply is never
reached for `FIXED`.

**Recommendation.** Widen the condition to `request.status().isSettled()` — the property that
already exists and already means "takes this out of the gate" — rather than naming the two statuses
again. Then assert both paths: the existing `BulkTriageRoutesTest` covers `not_affected` and has no
case for `fixed`, which is why this survived. **Verification: executed** — probe above.

### 3.2 🟠 Three HTTP endpoints load the whole issues table, and the dashboard is one of them

**Executed.** Hibernate `getEntityLoadCount` / `getQueryExecutionCount`, same request, three estate
sizes:

| Route | loads @20 | loads @220 | loads @620 | queries @620 |
|---|---|---|---|---|
| `/api/v1/dashboard` | 23 | 223 | **623** | 15 |
| `/api/v1/dashboard/trends` | 22 | 222 | **622** | 1 |
| `/api/v1/compliance/summary` | 23 | 223 | **623** | 19 |
| `/api/v1/issues?page=0&size=20` | 23 | 53 | 53 | 3 |
| `/api/v1/repositories` | 3 | 3 | 3 | 3 |
| `/api/v1/licenses/summary` | 4 | 4 | 4 | 3 |

Exactly `n + 2` and `n + 3`. The query count stays flat, so this is **not** N+1: it is one query
returning every row. The paged issues route plateaus at 53 and the other two are constant — those
are bounded, and the contrast is what makes the first three unambiguous.

**Where it comes from.** Four `findAll` calls that materialise complete `IssueEntity` rows to read
two or three columns:

- [`DashboardController:211`](../../../vectispire-java/vectispire-core/src/main/java/com/asmolabs/vectispire/core/api/DashboardController.java) — every issue, mapped to `BacklogTrend.Lifespan(firstSeenAt, resolvedAt)`
- `DashboardController:237` — the same shape on the dashboard root
- [`ComplianceService:250`](../../../vectispire-java/vectispire-core/src/main/java/com/asmolabs/vectispire/core/services/ComplianceService.java) and `:379` — mapped to `MttrCalculator.ResolvedIssue(severity, firstSeenAt, resolvedAt)`

**The need is legitimate; the read is not.** The trends comment is right that the curve needs every
issue's lifespan — *"an issue resolved inside the window has to be counted as open on the days
before it was resolved, or the curve would start at today's backlog and pretend the history was
always this good"*. Two timestamps per issue is a small answer. A full entity per issue is not: at
the 500,000 rows an earlier audit estimated for a real estate, opening the dashboard materialises
500,000 objects, with their strings, on the request thread.

**Why no earlier audit saw it.** The 25 August pass found seven endpoints reading all of
`t_finding` and they were fixed; `AttackPathDatabaseTest` and `BlastRadiusDatabaseTest` now assert
read cost and are the only two that do. Nobody counted `t_issue`. This is *"an earlier audit scored
what it had not measured"*, not ground that got worse.

**Recommendation.** A projection query returning the two or three columns — `select new
BacklogTrend.Lifespan(i.firstSeenAt, i.resolvedAt) …` — keeps the answer identical and stops
materialising entities. Then pin it the way the other two are pinned: an entity-load assertion that
does not move when the fixture grows around the query.

### 3.3 🟡 `main` has fallen from 3 commits behind to 9, and the nightly runs from `main`

The 20:04 audit recorded the recovery: `main` carried `nightly.yml` with its `cron:` and sat 3
commits behind. It is now **9 behind** — the three fixes from that audit, the AI-provider feature
and two others are all on `develop` only. GitHub runs a scheduled workflow from the default branch,
so tonight's nightly will execute the tree *without* the credential-encryption fix, without
`SettingsRoutesTest`, and without `AiReviewConsentTest`. The mechanism works; it is pointed at a
week-old tree.

**Recommendation.** Merge `develop` into `main`. This is now the single highest-value action on the
verification axis, and it costs one merge.

### 3.4 🟡 A hardcoded English string on a screen that is otherwise translated — still open

Reported at 20:04 as §3.6 and unchanged:
[`settings.ts:143-144`](../../../vectispire-angular/src/app/pages/settings/settings.ts) builds the
provider dropdown from literals — `'Ollama — a model on a host you run'`, `'OpenAI-compatible
API'` — while every other label two lines above goes through `this.i18n.t(…)`. The French bundle
has no key for them.

*Still not a finding, re-verified:* the 52 keys in `fr.json` absent from `en.json` are by design —
`settings.ts:379` reads `translated !== key ? translated : setting.label`, so English falls back to
the server's own English label and only French needs an override.

---

## 4. What verified clean

Executed this pass, and correct.

- **Portability.** 87 tests across PostgreSQL 16, MySQL 8 and SQLite. `SchemaParityIntegrationTest`
  green on all three: the Flyway multi-dialect migrations and `ddl-auto: validate` hold.
- **Federation.** `SingleSignOnIntegrationTest` runs against a real Keycloak container, three times.
- **The sandbox, at runtime.** See §1.
- **The audit chain.** Mutated and caught (§2). The restore drill goes further: it verifies the
  chain **survives a restore**, that the mirror reports the 5 entries the restored table lost, and —
  in its own built-in mutation — that restoring the mirror alongside the database makes the loss
  invisible to `intact` while `missingFromMirror` still carries the signal. A drill that tests its
  own blind spot is rare and worth saying so.
- **Brute force and MFA.** Executed in a browser: *burst login requests trigger HTTP 429 Bucket4j
  rate limiting*, *an MFA challenge cannot be brute-forced with unlimited guesses*, both green
  against a live control plane.
- **The ADR registry has substance.** 0001 → 0017 in both languages. The four shortest files —
  0004, 0008, 0009, 0011 — are short because they are **superseded**, each carrying its status,
  its date, its successor and what it supersedes: `0004 → 0008 → 0009 → 0014` and `0011 → 0013`.
  That is a decision register with its reversals recorded, which is the thing the prompt asks about.
- **Documentation.** 730 links, 0 broken. C4 fingerprint identical. 12/12 per language tree. The
  STRIDE model now carries **E7** (the model-review endpoint) with six rows, **TB5** and **F17**,
  in both languages — the §3.4 finding of the 20:04 audit, verified closed.
- **Previous findings.** All five from 20:04 hold under a from-scratch build: the credential routes
  refuse the generic path, the acknowledgement can be withdrawn, `SettingsRoutesTest` and
  `AiReviewConsentTest` are in the 1320.
- **Forge.** `git remote -v` → `git@github.com:asmolabs/vectispire.git`.

---

## 5. Verification that actually runs — 9.0, and what the 1.0 is

Almost everything the pipeline claims is now executed *here*. What remains is the difference
between "it passes on this machine" and "it passed on the runner":

- **No run history was read.** Still no `gh` CLI. Nothing in this report says a GitHub job has ever
  been green. Everything in §1 was executed locally, which is a stronger claim than reading a file
  and a weaker one than a green pipeline.
- **The nightly points at a stale tree** — §3.3.
- **`gitleaks` was not run** — not installed. Config and baseline read, not executed.
- **Jib could not build.** `./gradlew :vectispire-core:jibDockerBuild` fails locally pulling
  `eclipse-temurin` from Docker Hub (unauthenticated pull). The `Dockerfile` route — the one that
  ships — built fine. Environmental here; worth knowing the `images` job depends on a registry pull
  that can be rate-limited.

---

## 6. Recommendations, prioritised

| # | Finding | Action | How it was verified |
|---|---|---|---|
| 1 | §3.1 | `resolveRequest`: condition on `status().isSettled()`, not on `NOT_AFFECTED`; add the `fixed` case to `BulkTriageRoutesTest` | **Executed** — both statuses driven through the real chain |
| 2 | §3.2 | Projection queries at the four `findAll` sites; pin the cost with an entity-load assertion | **Executed** — Hibernate counters at 20 / 220 / 620 |
| 3 | §3.3 | Merge `develop` into `main` so the nightly runs the current tree | **Executed** — `git rev-list --count` = 9 |
| 4 | §3.1 | Re-check the GOVERNANCE mapping once the fix lands: the assessment is uncapped on this control's strength | **Executed** — read `ComplianceEngine:170` against the probe result |
| 5 | §3.4 | Route the two provider labels through `i18n.t` | **Executed** — key-set diff and the fallback at `settings.ts:379` |
| 6 | §5 | Record the first green GitHub run's URL and date in `docs/analysis/` | **Asserted, not executed** |

---

## 7. What this audit could not measure

- **CI run history** — no `gh` CLI.
- **`gitleaks`** — not installed.
- **Jib image build** — blocked on a Docker Hub pull, §5.
- **Scale.** The read-cost measurement tops out at 620 issues, on SQLite. The linearity is
  unambiguous at that size; the wall-clock cost at 500,000 on PostgreSQL is inferred from it, not
  measured.
- **The agent, end to end.** `vectispire-agent` isolation was verified by classpath in the previous
  audit and not re-run here; no agent process was started.

---

*Working tree: this audit added one probe test, removed it, and applied two temporary mutations,
both reverted. The final `./gradlew build --rerun-tasks` executed all 35 tasks from scratch and
passed. The only uncommitted work is the documentation from the 20:04 audit and
`AiReviewConsentTest`, which pre-date this pass.*
