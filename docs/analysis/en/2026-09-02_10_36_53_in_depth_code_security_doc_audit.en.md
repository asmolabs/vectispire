# In-Depth Audit Report: Documentation, Source Code & Security

**Date:** 2 September 2026, 10:36 · **Tree audited:** `develop` @ `a2ff1971` · **Overall score: 8.2 / 10** (previous: 7.8)

---

## 0. In one paragraph

**The score rises from 7.8 to 8.2, and the two movements behind it run in opposite directions.**
The five open recommendations from 30 August are closed, and I checked each one: all **17 jobs
across the four workflows are bounded** (0 without `timeout-minutes`), `cosign` is pinned to
`v3.1.3` with digest verification, and `check-doc-facts.py` runs and checks 23 numeric claims.
Against that, **the series' structural finding recurs**: `main` is **10 commits behind**
`develop`, today's nine among them — and `main` is the only branch GitHub fires a scheduled
workflow from. Tonight's nightly will certify a tree containing neither the three `V17`–`V19`
migrations, nor the `AUDITOR` role, nor the VEX fix.

**And the heaviest finding of this audit is not ground getting worse: it is five audits scoring
"reachability" as a supply-chain capability without ever measuring what it computed.**
`ReachabilityAnalyzer` performs no call-graph analysis; it searches for the package name as a
substring in Semgrep findings. Its "not reachable" verdict — asserted whenever no finding mentions
the package — was published as-is into `not_affected` in OpenVEX documents and
`known_not_affected` in the CSAF documents shipped to customers, **with no human in the loop**.
Fixed during this audit (`a2ff1971`).

---

## 1. Score table

| Domain | Score | Movement | What fixes it |
|---|---|---|---|
| 📚 Documentation & Architecture | **9.0 / 10** | = | 5 Florat views × 2 languages, 17 ADRs × 2, exact 11/11 parity, 862 links unbroken. SPDX still announced in an OpenAPI tag. |
| 🛡️ Security & Cryptography | **8.2 / 10** | ▲ | Crypto conformant and verified by execution; major VEX defect closed today; three separation-of-duties gaps open. |
| ⚙️ Code Quality | **8.5 / 10** | ▲ | 1343 tests green, ArchUnit 6/6, fingerprint vector pinned **and proven by mutation**. One unbounded read measured at 52 entities. |
| 📋 Compliance & Standards | **8.5 / 10** | ▲ | 6 frameworks × 4 controls = 24, 7 categories, `cappedByPlatform` in place. The VEX fix was a compliance matter too. |
| 🔁 Verification that actually runs | **7.0 / 10** | ▼ | 17/17 jobs bounded, `cosign` pinned — but `main` does not carry the audited tree, and run history could not be read. |

---

## 2. Method, and its declared limits

Everything below was **executed**, except what is explicitly marked *asserted, not executed*.

**One tooling limit, stated up front:** `gh` is not authenticated on this machine (`gh auth login`
required, no `GH_TOKEN`). **I could not read the run history.** Everything this report says about
the pipeline concerns what is *declared* in the workflow files, never what *ran*. The series has
already shown how decisive that difference is: it cost 0.5 points on 28 August.

Two mutations were performed; their results are in §5.1 and §5.2.

---

## 3. 📚 Documentation & Architecture — 9.0 / 10

### What was executed

| Check | Command | Result |
|---|---|---|
| Florat views | `ls docs/architecture/bflorat/{fr,en}` | **5 views + README in each language** |
| C4 | `ls docs/architecture/c4/` | `workspace.dsl` + `diagrams/` present |
| STRIDE | `ls docs/architecture/security/*/` | `STRIDE_THREAT_MODEL` in FR and EN |
| ADRs | `ls docs/architecture/{en,fr}/decisions/` | **17 ADRs (0001–0017)**, symmetric |
| Bilingual parity | `comm` over basenames of `docs/en` and `docs/fr` | **11 / 11, no orphan in either direction** |
| Links | `python3 scripts/check-doc-links.py` | **862 relative links, 0 broken**, exit=0 |
| Numeric claims | `python3 scripts/check-doc-facts.py` | **26 documents, 23 claims, none contradicted**, exit=0 |

`check-doc-facts.py` independently corroborates three of my counts: 17 ADRs, 6 frameworks /
24 controls / 7 categories, and 2 deployable engines against 3 migration sets. This is the first
time in the series that a repository check confirms the auditor's figures instead of depending on
them.

### 🟡 D1 — SPDX is still announced in the API surface

ADR 0016 (25 August) records that **SPDX is not produced**, noting it was then "listed in four
documents and in the API description". The four documents are clean — no occurrence remains in
`README.md` or `docs-site/`. **One** remains, in the code:

```
vectispire-core/.../api/config/OpenApiConfiguration.java:50
  new Tag().name("SBOM & VEX").description("Software Bill of Materials (CycloneDX, SPDX), CSAF and OpenVEX documents")
```

Verified by exhaustive sweep: `grep -rn -i 'spdx' --include='*.java' */src/main` filtered to
description annotations returns only this line. The `GET /{id}/sbom` route description the ADR
named was indeed corrected — the grouping tag was missed. An integrator reading the Swagger still
finds the promise.

### 🟡 D2 — The audit prompt itself is out of date

`PROMPT_AUDIT.md` announces "ADR 0001 through 0016" in both languages; there have been 17 since
`0017-custom-checks-as-container-images.md` was added. No product consequence, but the document
used to check the documentation is the last place drift should live.

---

## 4. 🛡️ Security & Cryptography — 8.2 / 10

### 4.1 What holds, verified

| Control | Verification | Result |
|---|---|---|
| Argon2id | `PasswordHasher.java`, BouncyCastle `Argon2BytesGenerator` | Present, PHC format documented |
| AES-256-GCM | `SecretCipher.java` | `FORMAT_PREFIX = "v2:"`, `NONCE_LENGTH_BYTES = 12`, context AAD |
| SealedEnvelope | `SealedEnvelope.java`, `AgentProtocol.java` | X25519, 12-byte nonce, ephemeral key published by the agent |
| Rate limiting | `LoginRateLimitFilter.java` | Bucket4j (`Bandwidth`, `Bucket`, `ConsumptionProbe`) |
| Audit log | `AuditLogService.verify()` + `verifyAgainstMirror()` | **12 cases green** |
| Tenant isolation | `RouteAuthorizationTest` **11**, `TeamVisibility` **11**, `AuthorizationCoverage` + `RouteScoping` | **0 failures** |

**Agent isolation — measured, not read.** Rather than inspecting `build.gradle.kts`, I resolved the
real classpath:

```
./gradlew :vectispire-agent:dependencies --configuration runtimeClasspath
  | grep -icE 'mysql|postgresql|sqlite|jdbc|hibernate|spring-boot-data-jpa'
→ 0
```

Zero occurrences, and no reference to `ENCRYPTION_KEY` anywhere in `vectispire-agent/src/main`.
The advertised watertightness is real.

### 4.2 🔴 S1 — The absence of evidence was published as evidence of absence *(closed during this audit)*

This is the heaviest finding, and it is **not** ground getting worse: it is ground five audits
scored without measuring. "Reachability" has sat in axis 4 of the prompt from the start, beside
CycloneDX and CSAF, and nobody had opened `ReachabilityAnalyzer`.

**What it computed.** No call-graph analysis. A component was marked *reachable* when a Semgrep
finding from the same scan contained the package name **as a substring**, in its description or
file path. The `HIGH_RISK_SYMBOLS` constant declared at the top of the class was **read nowhere**.
What the `reachable_symbols` column held was not a symbol: a `file:line` — the analyzer's own test
pinned `TemplateHelper.java:42`.

**The reverse direction did the damage.** A component became *not reachable* as soon as Semgrep had
produced any finding anywhere and none mentioned the package. But `SAST_ENABLED` defaults to
`false` — the setting itself says switching it on takes a repository "from a few dozen
vulnerabilities to a few thousand findings" — and the product ships a single Semgrep rule for
licensing reasons. A repository that enables analysis without installing rule sets gets a handful
of findings against two hundred dependencies: **nearly everything ends up stamped "not reachable",
on an absence of evidence.**

**And that value was published with no human in the loop.** Four paths:

- `VexGeneratorService:84` and `:125` → OpenVEX `not_affected`, justification
  `vulnerable_code_not_in_execute_path`, with the sentence "Vectispire static analysis **verified**
  no direct call path invokes the vulnerable code";
- `CsafGeneratorService:63` and `:130` → product placed in `known_not_affected`, a formal
  declaration of non-exposure;
- `CycloneDxGeneratorService:214` → the same conclusion in its analysis block;
- `AiVulnerabilityAdvice:69-71` → a `not_affected` / `code_not_reachable` suggestion stating that
  "scope analysis **demonstrates** the vulnerable methods are not executed", and the model prompt
  (`AiReviewService:323`) offered `code_not_reachable` among its choices while feeding it the value.

Two verbs of proof — *verified*, *demonstrates* — on top of a text search, in machine-readable
documents. The tooling name written into every OpenVEX was "Vectispire Reachability &
Exploitability Engine".

**Closed by `a2ff1971`.** The analyzer becomes one-directional: it can raise a hand, it cannot clear
anybody; no match means `UNKNOWN`. The three generators no longer derive exoneration from the
field — only a human triage, justified and signed, clears a component. The tooling name becomes
"Vectispire ASPM".

**The quality gate never read this field** (`grep -rn -i 'reachab'
vectispire-common/.../domain/gate/` → empty): the most operational path was spared.

### 4.3 🟠 S2 — The four-eyes control can be switched off from inside *(open)*

`FOUR_EYES_APPROVAL_REQUIRED` is written through the PUT at `SettingsController:137`, open to
SUPERUSER, ADMIN and CISO. All three carry `canApproveTriage() == true` (`Role.java:18-20`). A CISO
whose decision has just gone to the approval queue can disable the setting, settle alone, and
re-enable it. The change is audited, so it is detectable after the fact — but after-the-fact
detection is not the control four-eyes is meant to be.

**The knot:** no role able to write settings is unable to approve. There is therefore nobody to
entrust the setting to without reopening the same hole.

**To the model's credit:** the approver is checked against the **requester** recorded on the event,
not merely against the role. An account cannot approve its own request even holding the role. The
hole is narrower than it looks — but switching the setting off short-circuits the whole mechanism,
that check included.

### 4.4 🟡 S3 — SUPERUSER and ADMIN are the same role *(open)*

Both carry `(true, true, true, true)`. No production line distinguishes them; only
`BootstrapService:105` creates one. The accounts screen offers an elevation that does not exist.

### 4.5 🟡 S4 — Approving the exemption and lowering the gate are the same role *(open)*

`GatePoliciesController` is open for writing to the CISO, who also approves triages. Not a defect
in itself — often that is precisely whose job it is — but in a product whose reason for existing is
holding a gate, the question deserves an explicit answer.

### 4.6 What was strengthened since 30 August

Three pieces of work done before this audit and checked by it:

- **An `AUDITOR` role**, and the separation of a governance *read* marker
  (`@RequiresGovernanceRead`) from a *write* marker (`@RequiresSecurityLead`). Previously, the only
  way to open the audit log to somebody was to also grant them the right to rewrite the policy they
  had come to check.
- **Real foreign keys on MySQL** (`V19`). Twenty-four columns declared `references … on delete
  cascade` inline, a form MySQL parses and discards — verified empirically on a fresh MySQL 8: the
  inline form produces neither constraint nor index, the table-level form produces both.
- **The scanner container CPU quota**, which asked the JVM's `availableProcessors()` while the
  container runs on the daemon's host. On a macOS workstation: 10 cores JVM-side, 4 daemon-side,
  and Docker refused the create — no scan started at all.

---

## 5. ⚙️ Code Quality — 8.5 / 10

### 5.1 Mutation #1 — The fingerprint vector, permuted

The prompt names this the trickiest point, and documents the 26 August 2026 gap: "by swapping two
fields: no test failed". **The gap is closed, and I proved it.**

`IssueFingerprintTest:52` now pins a literal:
`44c39a41c912df031c920698f4698aa76cdcf27617f2e99f4f6759de1f97851d`.

I swapped `input.type().wireName()` and `input.identifier()` in `IssueFingerprint.of`:

```
under mutation: 0 failures of 4    (relational properties)
under mutation: 0 failures of 3    (what makes two findings different)
under mutation: 1 failure  of 1    → "a known finding has a known fingerprint"
```

**All seven relational tests pass.** Determinism, version excluded, targets separate, purl
precedence, field boundary: none sees a permutation that would nonetheless change every fingerprint
in the estate and lose all triage in silence. Only the literal vector catches it. This is the
clearest demonstration this repository owns of what a golden test is worth.

### 5.2 Mutation #2 — The authorization marker lists

Adding a sixth marker, I broke two invariants at once: the security-lead expression stripped of
CISO, and a route given back its inline `@PreAuthorize`. **Three failures of eleven**, each new case
catching its own. Mutations reverted.

That work also revealed the marker list lived in **three places** test-side —
`RouteAuthorizationTest` as classes, `RouteScopingTest` as a regex alternation,
`AuthorizationCoverageTest` as a `contains` chain — and that the last two reported every route that
had just adopted the new marker as unguarded. Collapsed to one source.

### 5.3 What holds

| Check | Command | Result |
|---|---|---|
| Full suite | `./gradlew test` | **1343 tests, 0 failures** |
| Layering | `--tests '*Architecture*'` | **6 cases, 0 failures** |
| Migrations | `--tests '*Migrations*'` | **3 cases, 0 failures** |
| ADR 0007 | `grep 'Optional.empty()' scanning/scanners/` | 8 occurrences |
| Playwright | `ls e2e/*.spec.ts` + `grep -c 'test('` | 5 suites, **13 cases** *(declared; not executed here, no browser launched)* |

### 5.4 🟠 Q1 — An unbounded read, measured

The prompt asks for measurement rather than reasoning. I instrumented `SbomDiffService.diffLatest`
with the Hibernate counters, on an estate of 51 repositories of which one is of interest:

```
>>> MEASURE diffLatest: entities=52 queries=5
    (2 scans to compare, 50 scans belonging to other targets in the estate)
```

**52 entities loaded to compare 2.** `SbomDiffService:164` does
`scans.findAll().stream().filter(...)` — the per-target filter in Java over the whole `t_scan`
table, dimensioned at 100,000 rows per year. The cost follows the estate, not the target.

**What makes the finding sharp:** `Scans` exposes `findByRepoId` and `findByContainerId`, and
`LicenseGovernanceService:122-124` uses them correctly, forty lines away in the same layer. Since
`V18`, `idx_scan_repo` serves that query. The right way exists, it is indexed, and it is already in
use next door.

Two reads of the same kind, **found by inspection and not measured**:

- `EvidenceVaultService:144` — `scansRepo.findAll().stream().filter(...).limit(20)`: loads the whole
  estate to keep twenty.
- `LicenseGovernanceService:126` — `findAll()` with no filter when no target is requested (estate
  view). Defensible for an estate-wide report, unbounded nonetheless.

A fourth, `SecurityScorecardService:123`, is **deliberate and documented**: its comment explains
that the reader's allowance is a set of targets rather than a column, so no derived query can
express it, and that it is "named rather than left to look like an oversight". I count it as an
owned trade-off, not a defect.

---

## 6. 📋 Compliance & Standards — 8.5 / 10

### 6.1 One evaluator, six mappings — verified by counting

```
frameworks : 6  ['NIS_2', 'ISO_27001', 'EU_CRA', 'DORA', 'PCI_DSS', 'SOC_2']
controls   : 4 per framework → 24
categories switched on in evaluateControl : 7
  AUDIT_AND_LOGGING, GOVERNANCE, INFRASTRUCTURE_AS_CODE, SECRETS_MANAGEMENT,
  SECURE_CODING, SUPPLY_CHAIN, VULNERABILITY_MANAGEMENT
```

The prompt's description is exact, and `check-doc-facts.py` confirms the same three numbers
independently. `cappedByPlatform` is applied to every evaluation (`ComplianceEngine:94`), so a
control cannot be reported compliant on the strength of a mechanism that is switched off.

### 6.2 Supply-chain formats

CycloneDX 1.6, CSAF 2.0 and OpenVEX have real generators and exposed routes
(`/csaf/scans/{id}/csaf.json`, `/vex/scans/{id}/openvex.json`, plus the aggregates). **SPDX is not
produced** — the sweep finds only licence vocabulary (`spdxExpression`), consistent with ADR 0016.
See D1 for the residual promise in the OpenAPI tag.

**The VEX fix in §4.2 is a compliance matter too**: a CSAF document placing a product in
`known_not_affected` on the strength of a text search is a declaration the publisher could not
defend if a customer challenged it.

---

## 7. 🔁 Verification that actually runs — 7.0 / 10

### 7.1 What is declared, and correctly

| Control | Verification | Result |
|---|---|---|
| Job bounding | YAML parse of the 4 workflows | **17 jobs, 0 without `timeout-minutes`** |
| `cosign` | `release.yml:111-113` | Pinned `v3.1.3`, digest verified |
| Nightly can fire | `git cat-file -e github/main:.github/workflows/nightly.yml` | **Present on `main`** — the `cron:` can therefore trigger |
| Doc checks | `check-doc-links.py`, `check-doc-facts.py` | exit=0 for both |

The 30 August recommendation on timeouts is **closed**: my first count, done with a regex, reported
25 jobs against 17 timeouts and would have produced a false finding; the YAML parse gives 17 for 17.

### 7.2 🔴 V1 — `main` does not carry the audited tree *(the finding that recurs)*

```
git rev-list --left-right --count github/main...github/develop
→ main ahead: 0   develop ahead of main: 10
```

Today's nine commits — the three migrations, the `AUDITOR` role, the VEX fix, the CPU quota — are
**all absent from `main`**. And GitHub runs a scheduled workflow from the default branch only.

Concrete consequences, in order of severity:

1. **The nightly's multi-engine campaign (`integrationTestAll`) will not exercise `V17`, `V18` or
   `V19`.** These are schema migrations, one of which installs 24 foreign keys and deletes orphan
   rows. They were validated here against a real PostgreSQL and a real MySQL through Testcontainers,
   but no *scheduled* verification will cover them until `main` moves.
2. **The VEX fix will be covered by no nightly run.** It is the most consequential change of the day.
3. `ci.yml` contains **no** invocation of `integrationTest` (`grep -c` → 0): the engine campaign is
   a nightly-only control, and therefore a `main`-only one.

On 28 August the same gap cost 0.5 points; on 30 August it led the report. It has not been closed
structurally — only caught up by hand, once.

### 7.3 ⚪ V2 — Run history could not be read *(asserted, not executed)*

`gh run list` returns:

```
To get started with GitHub CLI, please run: gh auth login
```

No `GH_TOKEN` in the environment. **This report can therefore assert nothing about what actually
ran**: not the date of the last green nightly, not the state of `docs.yml` (which the 29 August
audit noted had run once and failed, Pages not being enabled), not whether `release.yml` has been
triggered since. Three questions opened by earlier audits stay open for want of a tool, not for
want of looking.

---

## 8. Recommendations, by value

| # | Recommendation | Supporting verification |
|---|---|---|
| **R1** | **Merge `develop` into `main`.** Without it, the VEX fix and the three migrations will be covered by no scheduled verification. | `git rev-list --left-right --count` → 0 / 10. **Executed.** |
| **R2** | **Decide who may switch off four-eyes** (S2). Two ways out: remove triage approval from administrators — beware, an installation whose only accounts are administrative would then have nobody to drain the queue — or require two people to change a governance setting. | `Role.java:18-20` + `SettingsController:137`. **Executed** (cross-reading, no mutation: the change alters permissions on live installs). |
| **R3** | **Bound `SbomDiffService.diffLatest`** by calling `findByRepoId` / `findByContainerId`, indexed since `V18` and already used by `LicenseGovernanceService`. | **Measured: 52 entities for 2 scans.** |
| **R4** | **Authenticate `gh` on the audit machine**, or provide a read-only `GH_TOKEN`. Three findings in the series stay unverifiable without it. | **Not executed**, and that is the point. |
| **R5** | **Remove SPDX from the OpenAPI tag** (D1). One line. | Exhaustive `grep`: a single residual occurrence. **Executed.** |
| **R6** | **Settle SUPERUSER** (S3): give it a power of its own — role administration is the classic answer — or fold it into ADMIN. | `Role.java:18-19`, `BootstrapService:105`. **Executed.** |
| **R7** | **Rename `reachable_symbols`.** The column holds `file:line`. A name that lies about its contents is how the §4.2 defect survived five audits. | The analyzer's test pinning `TemplateHelper.java:42`. **Executed.** |
| **R8** | **Add `integrationTestAll` to `ci.yml`**, at least on pull requests touching `db/migration/`. The engine campaign must not depend on a single branch. | `grep -c integrationTest .github/workflows/ci.yml` → **0**. **Executed.** |

---

## 9. On the score movement

The prompt asks whether the ground got worse or an earlier audit scored what it had not measured.
Both, and they must be separated.

**The ground improved** on declarative verification (17/17 jobs bounded, `cosign` pinned) and on
security (a read-only role, real foreign keys, a repaired CPU quota). These are pieces of work
done, which I checked.

**An earlier audit scored what it had not measured** on reachability. The word has sat in axis 4 of
the prompt from the start, between CycloneDX and EPSS, and five reports counted it as a capability
earned. Nobody had opened the class. The compliance score of those five reports was, on that point,
overstated — not out of indulgence, but because the capability was listed and never probed. That is
exactly the pattern this prompt exists to break.

**And a structural finding recurs**: `main` behind. That is neither of the two — it is a process
defect caught by hand twice and never tooled.
