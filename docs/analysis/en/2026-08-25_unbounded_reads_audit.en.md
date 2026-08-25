# In-depth audit — the pattern behind two defects

**Date:** 2026-08-25 · **Scope:** documentation & architecture, security & cryptography, code
quality, regulatory compliance · **Method:** claims verified by running, not by reading

> **On the prompt this audit answers.** The copy it was launched from is a stale one: it asks for
> ADR 0001–0013 (there are fifteen), names MariaDB and a second secrets engine (removed by
> [0014](../../architecture/en/decisions/0014-two-engines-and-a-test-fixture.md) and
> [0015](../../architecture/en/decisions/0015-one-secrets-engine.md)), and says no Docker socket is
> mounted — the *scanners* get none, the control plane and the agent do, which is the whole reason
> the sandbox matters. `PROMPT_AUDIT.md` in the repository is current. This audit measures the
> code, not the prompt's assumptions.

## Scores

| Domain | Score | Movement | What decided it |
|---|:--:|:--:|---|
| Documentation & Architecture | **9.0** / 10 | ↘ from 9.4 | The corpus is complete, bilingual and now verified against the code — but it took this pass to find eleven claims in the Florat dossier the code did not support, including a resource control that does not exist |
| Security & Cryptography | **8.8** / 10 | ↘ from 9.3 | Every control named is real and most are tested by tampering rather than by assertion. Two residual gaps: no CPU quota on scanner containers, and until today two rate limiters answered the same endpoint with two different contracts |
| Code Quality & Architecture | **7.8** / 10 | ↘ from 9.1 | Layering, the scanner return-type contract and the three-engine campaign are exemplary. **Seven HTTP endpoints load whole tables into memory** — the defect repaired twice today is systemic, not incidental |
| Regulatory Compliance | **8.2** / 10 | ↘ from 9.0 | Six frameworks, CycloneDX, CSAF, OpenVEX, EPSS and reachability are real and reachable. **No SPDX document is ever produced**, though the SBOM endpoint's own API description promises one |
| **Overall** | **8.5** / 10 | ↘ from 9.2 | |

**Every score moved down, and that is the finding rather than a regression.** Nothing got worse
this week; five audits scored ground they had read and not measured. This one ran the browser
suites, drove a real control plane, swept the service layer for a pattern instead of judging
services one at a time — and the pattern was there. A score that falls when the measurement
improves is the measurement working.

---

## 1. Documentation & Architecture — 9.0

### What holds

**Structural completeness is genuine.** Five Florat views, a C4 model in Structurizr DSL with a CI
job that regenerates the diagrams and fails on drift, a STRIDE model, fifteen ADRs — all of it in
both languages, with heading-for-heading parity (6/6, 5/5, 3/3, 7/7 on the chapters; 8/8, 11/11,
7/7, 6/6, 9/9 on the views). `docs/fr` and `docs/en` have no orphan on either side.

**The C4 model is in step with the code.** It names exactly the five scanner images
[`ScannerImages`](../../../vectispire-java/vectispire-common/src/main/java/com/asmolabs/vectispire/common/scanning/scanners/ScannerImages.java)
pins — syft, grype, gitleaks, checkov, semgrep — and describes the database as "PostgreSQL / MySQL
(Flyway Migrations)", which is what [0014](../../architecture/en/decisions/0014-two-engines-and-a-test-fixture.md)
decided. No MariaDB, no four-engine claim, no second secrets engine anywhere outside the records
that were superseded.

**All fifteen ADRs now carry their argument**, including the four short ones, which say what
proved them wrong — the part a successor cannot supply, because a successor argues its own case.
The engine history reads end to end and ends one engine from where it started: 0014's supported
set is exactly 0008's.

### What this pass found

**Eleven claims in the Florat dossier that the code did not support**, since corrected. Three
matter more than the rest:

* **A control that does not exist.** The dimensioning view listed `CPU Quota: 2.0 vCPUs` per
  scanner container and promised "enforced CPU and memory caps".
  [`ContainerRunner`](../../../vectispire-java/vectispire-common/src/main/java/com/asmolabs/vectispire/common/scanning/ContainerRunner.java)
  sets memory, a PID limit and a timeout — and no CPU limit of any kind. An operator sizing a host
  against that figure was sizing against nothing. The neighbouring numbers were wrong too: 2 GB not
  1.5, 15 minutes not 10, and the PID cap of 512 — the control that *does* exist — was unmentioned.
* **A mechanism described as its opposite.** Leader election was taught as `SELECT … FOR UPDATE` on
  `lease_name = 'SCHEDULER'`. The column is `name`, the value lowercase, and no `FOR UPDATE` is
  issued anywhere: acquisition is a conditional `UPDATE` guarded on the previous holder and
  expiry — a compare-and-swap that holds no lock across the pass.
* **A lookup strategy that was never built.** The volumetric table claimed indexing on `target_id`,
  `status`, `fingerprint`. None of those columns is named that, and `t_issue` carried **no index at
  all**. See §3.

**Five code comments named Liquibase** where the build has used Flyway since
[0013](../../architecture/en/decisions/0013-flyway-multi-dialect-migrations.md). One of the five
justified a design choice with a Liquibase-specific mechanism absent from this build; its rationale
was removed rather than translated into a Flyway equivalent nobody had tested.

**The runtime chapter asserted that SQLite is deployable** — the one thing
[0014](../../architecture/en/decisions/0014-two-engines-and-a-test-fixture.md) establishes it is
not — and that retention purges and the outbox relay are leader-elected. Only the scheduler is.

### What still costs a point

The documentation is now verified, but **nothing verifies it continuously.** Link checking and C4
drift run in CI; no job compares a published figure against the constant it names. That is how
`2.0 vCPUs` survived: it was never wrong in a way a build could see.

---

## 2. Security & Cryptography — 8.8

### Controls that are real, and tested by breaking them

| Control | Where | How it is checked |
|---|---|---|
| Scanner sandbox | `ContainerRunner` | `cap_drop ALL`, `no-new-privileges`, read-only rootfs, `network: none` unless a tool must fetch its database, tmpfs for `/tmp` and `/home/scanner`, PID cap 512, memory 2 GB — all set in code, none of them optional |
| No socket in a scanner | `DependencyScanner` | The daemon is spoken to by the control plane alone; the cataloguer receives an exported archive. The comment states the reason plainly: whoever reaches the socket can start a privileged container |
| Agent isolation | `AgentIsolationTest` | ArchUnit forbids `java.sql`, `jakarta.persistence`, `org.springframework.data`, `org.flywaydb` and `liquibase` in the agent module, with a non-empty-import guard so the rule cannot pass vacuously |
| Audit chain | `AuditLogDatabaseTest`, `AuditLogServiceTest` | Both **mutate a stored row** and assert the chain reports it. Tamper detection asserted by tampering, at two levels |
| Audit mirror | compose default | Closes the case the chain cannot see — deleting the last entry, which nothing descends from, leaves a chain that verifies perfectly |
| Four-eyes | approval path | The approver is checked against the **requester recorded on the event**, not merely against a role, so one account holding both roles cannot hold both halves |
| Rate limiting | `LoginRateLimitFilter` | Token bucket per address over all three credential-presenting endpoints, `X-Forwarded-For` honoured only from configured trusted proxies |

### What this pass found

**Two limiters guarded `/api/v1/auth/login` with two different contracts.** The address filter has
always returned `Retry-After`; the account throttle
([`LoginThrottle`](../../../vectispire-java/vectispire-common/src/main/java/com/asmolabs/vectispire/common/domain/auth/LoginThrottle.java),
five failed attempts per user) returned a bare 429 whose wait was legible only inside an English
sentence. Which of the two fires first depends on whether the attempts share an address or a
username — so a client honouring the header, including this application's own sign-in screen, was
told nothing or something depending on how it was being attacked. Repaired, with a test that
asserts the value is a positive integer rather than merely present.

**A diagnosis of mine was wrong and is corrected here.** Eight of eleven browser tests were
reported as an application defect — "a login returns 200 with a token and leaves the browser on
`/login`". Driving a real browser shows the login navigating exactly as written. The failing page
said `The server answered 429`: eleven sign-ins inside a minute from one address is a burst by the
only definition the server has. The suites were not independent and were pretending to be.

### The residual gap

**No CPU quota is applied to scanner containers.** A scanner analysing hostile input can saturate
every core for the length of its timeout — fifteen minutes. The timeout bounds how long; nothing
bounds how much. This is now stated in the dimensioning view rather than contradicted by it, but
stating a gap is not closing it.

---

## 3. Code Quality & Software Architecture — 7.8

### What is exemplary

**The layer rule is enforced and cannot pass vacuously.** `ArchitectureTest` checks six layers with
an explicit non-empty-import guard, and forbids the domain from importing Spring, Hibernate,
`java.sql` or a Docker client.

**ADR 0007 is enforced by a type, checked by reflection.** `ScannerContractTest` identifies
container-running scanners by the fact that they *hold* a `ContainerRunner` rather than by name, so
a scanner added in six months is in scope the moment it exists. It exists because the gap was real
and cost the most sensitive finding type: two secret scanners returned `List`, merged inside a
`catch (Exception ignored)`, and a failure of the second silently resolved every leaked credential
only it could detect.

**The engine campaign runs and is honest about what it proves.** Three engines, 15 migrations per
dialect, 33 entities validated under `ddl-auto: validate`, and a schema-parity suite that asserts a
*lower bound* on the entity count — because an exact number checks that somebody updated a literal,
which is exactly how the campaign was silently red for an unknown period.

1229 unit tests, 9 integration suites, coverage floors scoped per package and mutation-verified.

### The finding: whole-table reads are systemic

Two were repaired today — `SecurityDebtService` and `GateService`. Sweeping the service layer for
the pattern rather than judging services one at a time shows **seven more, all reachable over
HTTP**:

| Service | Endpoint | What it loads |
|---|---|---|
| `BlastRadiusService` | `/api/v1/blast-radius` | **every finding and every issue**, twice over |
| `SecurityScorecardService` | `/api/v1/scorecard` | every issue, twice; every scan, twice |
| `EpssPrioritizationService` | `/api/v1/epss` | every issue, then filters open **in Java** |
| `EvidenceVaultService` | `/api/v1/compliance/...` | every issue and every scan, filtered in Java |
| `LicenseGovernanceService` | `/api/v1/licenses` | every component and every finding |
| `CsafGeneratorService` | `/api/v1/csaf` | every issue |
| `CycloneDxGeneratorService` | `/api/v1/cyclonedx` | every issue |

`t_finding` is the raw-findings table the dimensioning view estimates at **~500,000 rows**. Reading
it whole to serve a page is not a slow query; it is a heap-sized answer to a screen-sized question.

**And until this week none of it was indexed.** `t_issue` carried no index at all — the schema
declared nine and not one was on the table every hot path reads. `(state, repo_id)`,
`(state, container_id)` and `(fingerprint)` were added, and `SchemaParityIntegrationTest` now
asserts they exist on every engine through `DatabaseMetaData`, so a refactor cannot drop them
quietly.

**Why this is a 7.8 and not lower.** The pattern is uniform, mechanical and now demonstrated
twice — each fix took one characterisation test, one query change and one mutation check. Nothing
about it is architecturally hard. It is a debt with a known repayment procedure, which is a far
better position than a subtle defect nobody can localise.

### Front end

Four Playwright suites, eleven cases, **all passing** as of this audit — and passing for the first
time, after the suites stopped assuming they were independent. Fifteen Angular unit specs cover the
pages thinly. The E2E set is the real coverage, and it is now honest: it runs serially because it
shares one account and one address with the server's anti-brute-force counters.

---

## 4. Regulatory Compliance & Standards — 8.2

### What is implemented

**Six frameworks**, not four: `NIS_2`, `ISO_27001`, `EU_CRA`, `DORA`, `PCI_DSS`, `SOC_2`
([`ComplianceFramework`](../../../vectispire-java/vectispire-common/src/main/java/com/asmolabs/vectispire/common/domain/compliance/ComplianceFramework.java)).
OWASP is present as its own reporting surface — a page and a PDF export — rather than as a
compliance framework, which is the right modelling: it is a vulnerability taxonomy, not a
regulation.

**The compliance score reads the platform's own posture, not only the fleet's.** A deployment with
no encryption key is capped at 60 on secrets management, one with no audit mirror at 70 on logging,
one without four-eyes at 75 on governance. The cap only lowers, so it cannot flatter.

**CycloneDX, CSAF, OpenVEX, EPSS and reachability are real and reachable**, each with a generator
service and a controller.

### The finding: SPDX is claimed and not produced

`Spdx` appears in six main-source files, which is why it reads as supported. What is actually
there:

* **SPDX licence *expressions* are parsed** — `Sbom.java` reads a component's `spdxExpression`
  field as a fallback to `value`. That is SPDX as a licence vocabulary.
* **No SPDX *document* is ever generated.** There is a `CycloneDxGeneratorService`, a
  `CsafGeneratorService` and a `VexGeneratorService`; there is no SPDX equivalent, and no
  `spdxVersion` or `SPDXRef` is written anywhere in the codebase.
* **The SBOM endpoint's own API description is wrong.** `GET /api/v1/scans/{id}/sbom` is annotated
  "CycloneDX / SPDX SBOM JSON document". It serves, verbatim, whatever Syft produced — and
  `DependencyScanner` invokes Syft with `-o json`, which is Syft's **native** format, neither
  CycloneDX nor SPDX. The document is correctly served unmodified, for the stated and good reason
  that a re-serialised SBOM is no longer what the cataloguer signed; the description of what it
  contains is simply not true.

A consumer reading the OpenAPI page and building an SPDX ingestion against that endpoint gets a
format they did not ask for and cannot parse.

---

## Recommendations, in the order I would take them

### 🔴 Now

1. **Correct the SBOM endpoint's API description** to name Syft's native JSON. One annotation, no
   behaviour change, and it stops an integrator building against a promise. Then decide, separately
   and explicitly, whether SPDX 2.3 output is in scope — and if it is not, stop listing it.
2. **Repair `BlastRadiusService`.** It is the worst of the seven: two whole-table reads of
   `t_finding` plus one of `t_issue`, on a page. The procedure is settled — characterisation test,
   scoped query, mutation check on rows loaded.

### 🟠 Next

3. **Work the remaining six whole-table readers**, in the order of the table in §3. They are
   mechanical; the value is that the pattern stops being the house style.
4. **Decide the CPU quota question.** Either apply one in `ContainerRunner` — a scanner that
   saturates a host is a denial of service delivered by a hostile repository — or record in an ADR
   why the timeout is judged sufficient. Both are defensible; leaving it undecided is not.
5. **Make `fingerprint` unique**, with a migration that first reports the duplicates it would
   break. Uniqueness is the real invariant and the index is already there.

### 🟡 Then

6. **Check published figures against the constants they name.** A small test that reads
   `ScannerLimits.DEFAULT` and asserts the dimensioning view quotes it would have caught
   `2.0 vCPUs`, `1.5 GB` and `10 minutes` the day they became wrong.
7. **Watch the first nightly run.** `nightly.yml` has never executed on a runner: the three-engine
   campaign, both Dockerfile images and the eleven browser cases all run for the first time
   tonight. Green locally is not green on a cold runner.
8. **Give the front end unit coverage.** Fifteen specs against twenty-seven pages leaves the E2E
   suite carrying the whole load, and eleven cases is thin for what it is being asked to defend.
