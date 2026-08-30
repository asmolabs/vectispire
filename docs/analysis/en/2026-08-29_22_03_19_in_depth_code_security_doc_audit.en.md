# In-depth audit — code, security, documentation

**29 August 2026, 22:03** · *Version française : [`2026-08-29_22_03_19_audit_approfondi_code_securite_doc.fr.md`](../fr/2026-08-29_22_03_19_audit_approfondi_code_securite_doc.fr.md)*

## Overall score: **8.7 / 10** — up from 8.4

**The first audit in this series where nothing was left "asserted, not executed" for want of a
tool.** Docker was present, and the two controls every earlier audit had to leave open —
`gitleaks` and the Dockerfile/Actions policy — ran for the first time. Both are green: **377
commits scanned, no leaks**; **632 checkov checks, 0 failures**.

**Both findings from 21:10 are closed, and verified by mutation rather than by re-reading.**
Putting the old four-eyes condition back fails the two cases that were added; putting a `findAll`
back fails the read-cost pin. These are not assertions that could never fail.

**And the same measurement, widened, found three more.** §3.2 of the 21:10 audit fixed four routes
and pinned four. The pin covers only those. A sweep of all **40 parameterless GET endpoints** shows
**three others** loading the whole estate — one of them adding an outright N+1, **468 queries for
620 issues**.

| Domain | Score | Movement |
|---|---|---|
| Documentation & Architecture | **8.5** | ↓ — see §8 |
| Security & Cryptography | **8.5** | ↑ |
| Code quality | **8.0** | = |
| Compliance & Standards | **8.5** | ↑ |
| **Verification that actually runs** | **10.0** | ↑ — see §8 |

*Two scores moved **after** this was written, when `gh` was installed and the run history finally
read. The overall score does not move; its composition does. The detail is in §8.*

---

## 0. Remediation status — both findings closed, and the rule found four more

*Added after the audit. Full verification after the changes: **1326 JVM tests, 0 failures**, the
three-engine campaign green, **146 Angular tests**, **13 Playwright cases** against a live control
plane.*

### What was done, in the order the method demands

**The sweep was written first, and it was red before any fix.** That is the only order that proves
anything: fixing first and writing the test afterwards produces an assertion that can no longer
fail, which this project has shipped three times.

| # | Finding | Closed by | Proof it can fail |
|---|---|---|---|
| §3.1 | `/epss/priorities` — N+1 **and** whole-table read | `ThreatIntelFeedService.lookupCves` reads the intel in one query and keeps the fallback to the curated catalogue; the read goes through an `IssueRows.EpssRow` projection; `topPriorities` is finally a *top* (50), with the aggregate counts still weighing the whole estate. | Batch put back in a loop → the sweep fails on **+150 queries**; cap removed → `EpssRoutesTest` fails. |
| §3.1 | `/scorecards/global` — whole-table read | `IssueRows.Posture` projection (four columns) at all three sites in `SecurityScorecardService`. | `findAll` restored → the sweep fails on **+200 entities**. |
| §3.1 | `/attack-paths/overview` — unbounded read **and response** | `IssueRows.GraphNode` projection, plus a ceiling of **10 nodes per target**, ranked KEV → severity → reachability. The risk score is computed from what was found, not from what is drawn. | Ceiling removed → `AttackPathRoutesTest` fails. |
| §3.2 | Hardcoded provider labels | `aiProviders` becomes a `computed` going through `i18n.t`, with keys added to **both** bundles. | Key removed from `fr.json` → `check-i18n-keys.mjs` fails. |

### The rule found what my list had missed

`ReadCostSweepTest` enumerates Spring's route table rather than a list of paths. On its first run it
flagged **seven** routes, not three: the four my audit had missed are `/vex/aggregate.json`,
`/cyclonedx/aggregate.json`, `/csaf/aggregate.json` and `/compliance/evidence-bundle.zip`.

Checked rather than assumed, **those four are legitimate**: they are document exports whose payload
carries one entry per issue, so an O(n) read serves an O(n) answer. They sit in `MAY_GROW` with the
argument, and that distinction is what the rule encodes: a read that follows the estate is a defect
when the *answer* does not.

### An assertion that could not fail, caught on my own fix

After fixing the EPSS N+1 I put it back — **and the sweep stayed green.** It measured only entities
loaded, not queries issued, so it would have blessed half the fix forever. The sweep now counts
both, and the second counter consults **no** exemption list: an export may legitimately read n rows,
never issue n queries. Re-mutated, it now fails on `+150 queries`.

### A correction to what I claimed about the graph ceiling

I wrote that scoring the cut graph would make a repository look safer. Measurement says otherwise:
`calculateRiskScore` saturates both of its issue terms — `Math.min(3, vulnCount)`, and a secret
count that reaches the ceiling of 100 at four — so with a cut of ten **the score provably cannot
move**. The service computes it from what was found regardless, because that equivalence ends the
moment somebody lowers the ceiling or reweights the formula; and the test now states what is
checkable rather than what I had assumed.

### `ReadCostRoutesTest` was folded into the sweep

It pinned four named routes with the same fixture and the same counter. Everything it asserted is
now asserted across the whole surface, so keeping it would be two copies of one rule — and the
stale copy is the one that stops being updated. Verified rather than assumed: restoring the
`findAll` in `SlaService` makes the sweep fail on `/compliance/summary` **and** on
`/compliance/export.pdf`, which the old test never covered.

---

## 1. What I executed

| Control | Command | Result |
|---|---|---|
| JVM suites, cold | `./gradlew build --rerun-tasks` | **1326 tests, 0 failures, 0 errors, 0 skipped** (260 suites, 35 tasks) |
| Multi-engine campaign | `./gradlew integrationTestAll --rerun-tasks` | **PostgreSQL 29, MySQL 29, SQLite 29 — 87 tests, 0 failures** |
| Containers at runtime | `./gradlew :vectispire-common:integrationTest --rerun-tasks` | **14 cases, 0 failures**, against a live daemon |
| Browser suite | `npx playwright test` (from `vectispire-angular/`) | **13 passed** in 2.2 min, real control plane, real Chromium |
| Restore drill | `bash scripts/restore-drill.sh` | **passed**, its own built-in mutation included |
| **`gitleaks`** | pinned CI image, `detect --config .gitleaks.toml --baseline-path …` | **377 commits, 16.1 MB, no leaks found** — *never executed before this audit* |
| **Dockerfile / Actions policy** | pinned checkov image, `--framework dockerfile,github_actions` | **260 + 372 = 632 checks, 0 failures** — *never executed before this audit* |
| Shipped image | `docker build -f Dockerfile -t vectispire:audit .` | **built, 347 MB** |
| Angular suites | `npm test` | **146 tests, 23 files, 0 failures** |
| Relative links | `python3 scripts/check-doc-links.py` | **740 links, 0 broken** |
| C4 drift | `shasum -a 256` vs `diagrams/.workspace.sha256` | **identical — in step** |
| Bilingual parity | `find docs/{fr,en} -name '*.md'` | **12 / 12** |
| ADR registry | `ls docs/architecture/{en,fr}/decisions/` | **0001 → 0017**, both languages, 18 files each |
| bflorat views | `ls docs/architecture/bflorat/{en,fr}/` | **5 / 5** in each language |
| Agent isolation | `./gradlew :vectispire-agent:dependencies --configuration runtimeClasspath` | **0** occurrences of `jdbc`, `postgres`, `mysql`, `sqlite`, `hibernate`, `flyway`, `jpa` |
| Fingerprint — literal vector | mutation, below | **pinned, and it bites** |
| **Read cost, 40 routes** | Hibernate counters, 3 estate sizes | **three linear endpoints — §3.1** |
| Branch gap | `git rev-list --count origin/main..develop` | **0** — §3.3 of 21:10 is closed |
| GitHub run history | *initially* **not executed** — no `gh` CLI | **executed since** — `gh` installed, 19 runs read, see §8 |

### A correction to my own method, recorded

My first `./gradlew integrationTestAll` returned `BUILD SUCCESSFUL in 673ms`, **18 tasks
up-to-date**. That is exactly the error the prompt forbids on CI jobs — *a declared job is not a job
that ran* — applied to Gradle: **an `UP-TO-DATE` task is not a task that executed.** Rerun with
`--rerun-tasks`, the campaign takes 2 min 23 and really executes all 87 tests. No figure in this
report comes from a cache.

Likewise, my first `npx playwright test` was launched from the repository root and picked up the
Vitest `.spec.ts` files. The Playwright config lives in `vectispire-angular/`, which is where the
nightly job runs it from.

---

## 2. Testing my own tests

Four mutations, all reverted, three of them on assertions this series had never mutated.

| Mutation applied | Expected | Observed |
|---|---|---|
| `IssueFingerprint.of`: `target` and `type` **swapped** — the exact defect established on 26 August | failure | **1 test of 8 fails** — *"a known finding has a known fingerprint"*. The seven property tests all stay green, which is precisely why the literal vector exists. |
| `SecretCipher`: the **context AAD** replaced by a constant on both sides | failure | **3 tests fail** — *"a value written with a context does not read without one"*, *"a ciphertext moved to another row does not decrypt"*, and *"a secret sealed by an earlier build still opens"* |
| `IssueTriageService.queueIfNotApprover`: back to `NOT_AFFECTED` instead of `isSettled()` | failure | **2 tests fail** — the two cases added by the 21:10 remediation |
| `ScorecardController`: a route naming a target added with no guard | failure | **`RouteScopingTest` fails**; **`AuthorizationCoverageTest` passes** |

**The fourth deserves a word.** The two rules are not redundant, and the coarser one does not see
what the finer one catches: the controller still mentions `VisibilityService` elsewhere in the file,
so the class-level lint is satisfied. This is word for word the blind spot `RouteScopingTest`
documents in its own header — *"the twenty-fourth leak walked through the gap"* — and it is now
verified by measurement rather than only narrated.

**So does the second.** *"a secret sealed by an earlier build still opens"* is a literal vector of
the same family as the fingerprint's: a ciphertext written by an earlier version, stored as a
constant, which must keep opening. Two of the project's data contracts are pinned this way, and both
bite.

---

## 3. Findings

### 3.1 🟠 Three endpoints load the whole estate — and one of them does it N+1

**Executed.** A temporary probe swept the **40 parameterless GET routes** of the HTTP surface,
Hibernate `getEntityLoadCount` / `getQueryExecutionCount`, as an administrator, at 20 then 220 then
620 issues.

| Route | loads 20 / 220 / 620 | queries 20 / 220 / 620 |
|---|---|---|
| `/api/v1/epss/priorities` | 23 / 223 / **623** | 18 / 168 / **468** |
| `/api/v1/scorecards/global` | 24 / 224 / **624** | 5 / 5 / 5 |
| `/api/v1/attack-paths/overview` | 18 / 168 / **468** | 4 / 4 / 4 |
| `/api/v1/dashboard` *(control, fixed at 21:10)* | 3 / 3 / 3 | 15 / 15 / 15 |
| `/api/v1/repositories` *(bounded control)* | 3 / 3 / 3 | 3 / 3 / 3 |

Both controls are flat: **the 21:10 fix holds**, and the contrast is what makes the first three rows
unambiguous.

**`/api/v1/epss/priorities` is the worst of the three, for two compounding reasons.** The *query*
count grows as well — this is a genuine N+1, not merely a whole-table read. In
[`EpssPrioritizationService.getFleetSummary`](../../../vectispire-java/vectispire-core/src/main/java/com/asmolabs/vectispire/core/services/EpssPrioritizationService.java),
the `for (IssueEntity issue : openIssues)` loop calls `threatIntelService.lookupCve(cveId)`, which
executes `intelRepo.findByCveIdIgnoreCase(...)` — **one query per open issue**. Two `findAll()`
calls at the top of the method (repositories and containers, materialised into `Map`s) sit on top of
that.

**`/api/v1/attack-paths/overview`** loads the open issues of the visible scope through
`findByStateAndRepoIdIn("open", repoIds)` and then walks everything in Java
([`AttackPathService`](../../../vectispire-java/vectispire-core/src/main/java/com/asmolabs/vectispire/core/services/AttackPathService.java),
lines 336–344). The coefficient is ~0.75 n because the fixture leaves three issues in four open —
the slope follows open issues rather than the whole table, which is the same illness up to a factor.

**`/api/v1/scorecards/global`** is the simplest case: constant in queries, linear in materialised
entities.

**What is right here, and must not be undone by the fix.** All three routes properly resolve a
`Visibility` — `visibility.of(...)` at `EpssController:44` and `ScorecardController:75`,
`allowanceOf(principal)` at `AttackPathController:66`. **This is not a tenant-isolation finding.**
The comment on `getFleetSummary` in fact records that it once was — *"no visibility at all, so a
restricted reader received a ranked list of every other target's most exploitable vulnerabilities"*
— and that this was repaired. The cost is what remains.

**Why 21:10 did not see them.** It measured the routes it suspected from the `findAll` sites it had
read, then pinned those. `ReadCostRoutesTest` covers four named routes. This is not ground getting
worse: **it is an earlier audit scoring what it had not measured**, for the second time running on
exactly this subject.

**Recommendation.** Two things, and the second matters more than the first.
1. Project the columns instead of materialising the rows at the three sites, the way `IssueRows`
   already does for the five reads converted at 21:10; and for EPSS, replace the per-issue
   `lookupCve` with a single `findByCveIdInIgnoreCase(...)` loaded into a `Map` before the loop.
2. **Make the sweep the rule rather than the list.** `ReadCostRoutesTest` enumerates four routes; a
   version that walks the GET surface and fails on *any* route whose count follows the size of the
   estate would have caught these three at 21:10, and will catch the next one. The exemption list —
   the legitimately paginated routes — is an argument somebody writes, exactly like
   `NAMES_NO_TARGET` in `RouteScopingTest`.

**Verification: executed** — table above, three sizes, probe removed since.

### 3.2 🟡 A hardcoded English string on an otherwise translated screen — open across three audits

Reported on 29 August at 20:04 (§3.6), then at 21:10 (§3.4), unchanged.
[`settings.ts:143-146`](../../../vectispire-angular/src/app/pages/settings/settings.ts) builds
`aiProviders` from literals — `'Ollama — a model on a host you run'`, `'OpenAI-compatible API'` —
while the neighbouring labels go through `this.i18n.t(…)`.

**Measured this time rather than asserted:** the two flattened bundles hold **661 keys in French and
609 in English**, with **52 French keys having no English counterpart and none the other way**. None
of those 52 concerns the providers — `grep -i 'ollama\|provider'` over both files returns nothing.
The 52 remain deliberate: `settings.ts:379` reads `translated !== key ? translated : setting.label`,
so English falls back to the server's own label and only French needs an override.

---

## 4. What is verified sound

Executed this time, and correct.

- **Secrets.** `gitleaks` over **377 commits** and 16.1 MB of history: no leaks. The baseline and
  the config are no longer "read, not executed".
- **Image and pipeline policy.** checkov, at the digest `ScannerImages` pins, over `dockerfile` and
  `github_actions`: **632 checks, 0 failures, 2 skipped**. The job is blocking in CI and it passes
  here.
- **Encryption at rest.** AES-256-GCM, 12-byte nonce, 128-bit tag, `v2:` prefix, context AAD — the
  §2 mutation proves the AAD genuinely binds rather than decorates.
- **Passwords.** `PasswordHasher`: `MEMORY_KIB = 19 * 1024`, `ITERATIONS = 2`, `PARALLELISM = 1`,
  PHC output `$argon2id$v=19$m=…,t=…,p=…$…`. The parameters travel with the hash, and
  `PasswordHasher:128` compares stored parameters against current ones to decide a rehash is due —
  so raising the cost does not invalidate what is stored, as claimed.
- **Agent isolation.** The runtime classpath of `vectispire-agent` contains **no** JDBC driver, no
  Hibernate, no Flyway, no JPA. `ENCRYPTION_KEY` appears anywhere in the module only inside
  `AgentIsolationTest` — that is, inside the test that asserts its absence.
- **Sandbox.** 14 cases against a live daemon: every capability dropped, no privilege gain, the
  image's own filesystem unwritable, the network off unless the run asks, an over-long scanner
  stopped rather than abandoned. No Docker socket is mounted inside a scanner; the two mounts in
  `docker-compose.yml` (lines 81 and 125) are the control plane's and the agent's, which is the whole
  reason the sandbox matters rather than an exception to its rule.
- **Tenant isolation.** `RouteScopingTest` walks the surface route by route, requires a helper to
  *prove* in its own body that it resolves an allowance, and refuses on >60 uncovered routes; both
  exemption lists carry an argument per entry and are shared, not copied. The §2 mutation confirms
  it bites.
- **Four eyes.** `queueIfNotApprover` conditions on `TriageStatus.isSettled()`, so `FIXED` queues
  just as `NOT_AFFECTED` does, and the validate-then-queue order avoids demanding a VEX
  justification from a fix. Mutation above: both cases bite.
- **Compliance — one evaluator, six mappings, counted.** `ComplianceEngine` switches on the **seven**
  categories claimed; `ComplianceFramework` declares **six** frameworks (NIS_2, ISO_27001, EU_CRA,
  DORA, PCI_DSS, SOC_2) carrying **24** `new ComplianceControl` in total, split
  VULNERABILITY_MANAGEMENT 7, SECRETS_MANAGEMENT 5, SUPPLY_CHAIN 4, SECURE_CODING 3,
  AUDIT_AND_LOGGING 3, INFRASTRUCTURE_AS_CODE 1, GOVERNANCE 1. The description "one posture
  evaluator, six mappings" is exact to the figure.
- **`cappedByPlatform`.** Three caps, each naming the switch to flip: SECRETS at 60 with no
  encryption key, AUDIT at 70 with no mirror, GOVERNANCE at 75 with no four-eyes. The GOVERNANCE cap
  now rests on a mechanism that genuinely covers both settling statuses — which was not true at
  21:10, and which was the real substance of that compliance finding.
- **Portability.** 87 tests across three engines, Flyway migrations applied and schema validated.
- **Forge.** `git remote -v` → `git@github.com:asmolabs/vectispire.git`. `main` and `develop` carry
  **exactly the same four workflows** (`git diff origin/main develop -- .github/` is empty): the
  `cron: '30 2 * * *'` in `nightly.yml` is on the default branch and points at the current tree.
  §3.3 of 21:10 is closed.
- **Documentation.** 740 links, 0 broken. C4 fingerprint identical to the recorded one. 12/12 per
  language tree, 5/5 bflorat views per language, STRIDE in both languages, ADR 0001 → 0017 in both
  languages with the reversals recorded (`0004 → 0008 → 0009 → 0014`, `0011 → 0013`).

---

## 5. Verification that actually runs — 9.5 at the time of the audit, 10.0 since

> **This section is kept as it was written, and §8 corrects it.** The one gap it names — having
> read no run history — was closed afterwards by installing `gh`. Rewriting the section would erase
> the difference between what I knew while auditing and what I learned after, which is exactly what
> this report claims to keep.

The score rises from 9.0 because the two controls every earlier audit had to declare "asserted, not
executed" have run, and because the nightly finally points at the current tree.

What remains fits in one sentence: **no GitHub run history was read.** There is still no `gh` CLI on
this machine, and nothing in this report says a GitHub job has ever been green. All of §1 was
executed here. That is a stronger claim than re-reading a workflow file, and a weaker one than a
green pipeline on the runner.

One environmental detail, carried over from 21:10 because it remains true: `./gradlew
:vectispire-core:jibDockerBuild` fails locally pulling `eclipse-temurin` without Docker Hub
authentication. The `Dockerfile` path — the one that ships — builds without trouble, 347 MB. The
`images` job depends on a registry pull that can be rate-limited.

---

## 6. Recommendations, by priority

| # | Finding | Action | How it was verified |
|---|---|---|---|
| 1 | §3.1 | `EpssPrioritizationService`: one `findByCveIdInIgnoreCase` read into a `Map` before the loop, instead of a `lookupCve` per issue | **Executed** — 468 queries for 620 issues, Hibernate counters |
| 2 | §3.1 | Project the columns at the three sites, as `IssueRows` already does for the five reads from 21:10 | **Executed** — 623 / 624 / 468 entity loads at 620 issues |
| 3 | §3.1 | **Turn `ReadCostRoutesTest` into a sweep**: fail on any GET route whose count follows the size of the estate, with an argued exemption list | **Executed** — sweeping 40 routes found three the four-route list did not cover |
| 4 | §5 | Record the URL and date of the first green GitHub run in `docs/analysis/` | **Asserted, not executed** — no `gh` CLI |
| 5 | §3.2 | Route the two provider labels through `i18n.t` | **Executed** — 661 vs 609 flattened keys, no provider key in either bundle |

---

## 7. What this audit could not measure

- **CI run history** — no `gh` CLI. This is the only structural gap left.
- **Nine routes in my own sweep.** `/api/v1/compliance`, `/api/v1/history`, `/api/v1/scorecards`,
  `/api/v1/tickets`, `/api/v1/threat-intel`, `/api/v1/vex`, `/api/v1/attestations` answered **404**,
  and `/api/v1/inventory/versions` and `/api/v1/inventory/search` answered **400** for want of a
  required parameter. Those are paths I guessed, not clean routes: **they are unmeasured, not
  sound.** The probe says so itself by refusing to count a 404 as zero cost — the guard
  `ReadCostRoutesTest` already carries, and I kept the same one.
- **Scale.** The measurement stops at 620 issues on SQLite. Linearity there is unambiguous; the
  wall-clock cost at 500,000 rows on PostgreSQL is inferred from it, not measured.
- **Jib image build** — blocked on a Docker Hub pull, §5.
- **The agent, end to end.** Its isolation is verified by classpath, which is a solid proof of
  absence; no agent process was started against a live control plane.

---

## 8. Addendum — the run history, finally read

*Added after the audit and after the remediation. `gh` was installed; the repository is public, so
the runs API answers unauthenticated.*

### What the history says — 19 runs

**The series can finally say a GitHub job has been green, with a date.** The first green run is
`verify` **#5 and #6, on 28 August 2026 at 08:59 UTC**, on `develop` and on `main`. The first two
runs, on 27 August at 13:52, **failed** — the porting bug the 28 August audit described, confirmed
here from the source rather than inferred.

**The nightly has fired, twice, from `main`, and succeeded both times:**

| Run | Fired | SHA | Result |
|---|---|---|---|
| `nightly` #1 | 29 Aug 09:17 UTC | `788afdcb` | **success** |
| `nightly` #2 | 30 Aug 08:29 UTC | `dfbd7f8f` | **success** — the current tree |

That is the question left open since the 28 August audit, settled by measurement. The nightly's four
jobs — `e2e`, `dockerfiles`, `restore`, `databases` — are green on the SHA that is today the head of
both `main` and `develop`.

**And all ten `verify` jobs are green on `main`** (#16, 29 Aug 19:48 UTC): `c4-drift`, `secrets`,
`jvm`, `dockerfile-policy`, `npm-audit`, `frontend`, `links`, `images`, `sbom`, `vulnerabilities`.
Every control the project claims is present **and** fires **and** passes, on the runner rather than
only on my machine. It is the strongest statement this series has ever been able to make, and it is
worth the missing 0.5.

**One factual caveat about the `cron:`.** It says `30 2 * * *`, and the two runs started at 09:17
and 08:29 UTC. GitHub delays scheduled workflows on shared runners, sometimes by hours. The
mechanism works; the hour is not the one written down, and a document promising "every night at
02:30" would need correcting.

### 3.3 🟠 A fourth workflow exists, has run exactly once, and failed

**Executed.** `docs` **#1**, 29 August at 19:31 UTC, on `main`: **failure**, at the
`actions/configure-pages` step, with the `deploy` job skipped. It is the only failure in the recent
history, and the only one of the four workflows that has never succeeded.

**The cause, verified rather than assumed.** `GET /repos/asmolabs/vectispire/pages` answers
**404**: GitHub Pages is not enabled on the repository, and `configure-pages` fails for exactly that
reason. `https://asmolabs.github.io/vectispire/` answers **404** as well.

**Why this is more than a red job.** Two files state it in the present tense, as fact:

- [`mkdocs.yml:1`](../../../mkdocs.yml) — *"the public documentation site, published at
  https://asmolabs.github.io/vectispire/"*, with `site_url:` on line 16 pointing at the same
  address;
- [`.github/workflows/docs.yml:1`](../../../.github/workflows/docs.yml) — *"the documentation site,
  published at https://asmolabs.github.io/vectispire/"*.

This is the family of finding this project treats as the worst: a guarantee written in the present
tense that nothing executes. The 25 August audit found its twin — a signature-verification command
that could not succeed, asserted as fact in two documents.

**And it will not retry by itself.** `docs.yml` fires only on a push to `main` touching
`docs-site/**`, `mkdocs.yml`, `ci/docs/requirements.txt` or itself — plus `workflow_dispatch`. Until
Pages is enabled, every trigger fails at the same step.

**Recommendation.** Enable GitHub Pages on the repository with `source: GitHub Actions`, then
re-run `docs` through `workflow_dispatch`. That is a repository setting rather than a code change —
it needs admin rights on `asmolabs/vectispire`, so it was not done here. If the site is not wanted
yet, then it is the sentence in those two files that has to change, not the setting: it describes an
intention in the present indicative.

### What this changes about the scores

- **Verification that actually runs: 9.5 → 10.0.** The report's one structural gap is closed, and
  closed in the right direction: the history confirms what the report asserted.
- **Documentation & Architecture: 9.0 → 8.5.** Not because the documentation got worse, but because
  I had scored an axis on what I could measure without the network. Two files announce a site that
  does not exist; that is ground no audit in the series had measured, not a regression.

The overall score stays **8.7**. It is simply better distributed.

---

*Working tree: this audit added a read-cost probe and then removed it, and applied four temporary
mutations, all reverted. `git status` is clean. The final `./gradlew build --rerun-tasks` executed
all 35 tasks cold — 1326 tests, 0 failures — after the last mutation was restored.*
