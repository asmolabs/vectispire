# In-Depth Audit Report: Documentation, Source Code & Security

* **Project:** Vectispire — ASPM & Software Security Control Plane
* **Date:** 26 August 2026, 14:30
* **Commit audited:** `8e122447` (`develop`)
* **Scope:** the five axes of [`PROMPT_AUDIT.md`](../../../PROMPT_AUDIT.md)

> **This audit was carried out without reading the previous ones.** That was the request. The
> scores below are therefore **not comparable** to the eight earlier reports: a rise or a fall
> would say nothing, for want of a shared basis. What is comparable is the findings by name.

---

## 0. What was executed

The prompt's method is "run it, do not read it". Here is what actually ran, with its output —
nothing else in this report rests on anything weaker.

| command | result |
|---|---|
| `./gradlew check` | **green** |
| `./gradlew integrationTestAll` | **green on all three engines** — MySQL, PostgreSQL, SQLite, 2 min 12 s |
| `npx ng test --no-watch` | **18 files, 119 tests** |
| `python3 scripts/check-doc-links.py` | **566 links, 0 broken** |
| `gitleaks detect` with the baseline | **no leaks**; a fresh key committed on top **fails** it |
| C4 fingerprint | recorded = actual (`8aa3fc9d…`) |
| file-set parity of `docs/{en,fr}` and the ADRs | **identical** |

What was **not** executed, and which no score may count as earned: the Playwright suite (CI-only),
and reachability across the `docker:dind` boundary, unverifiable from a workstation.

---

## 1. Summary

| Domain | Score | What sets it |
|---|:---:|---|
| **Documentation & Architecture** | **9.0 / 10** | Structure complete and *machine-checked*; the C4 drift control is weaker than it looks |
| **Security & Cryptography** | **8.3 / 10** | Everything the prompt names exists and runs — but a **24th unscoped route** remains |
| **Code Quality** | **8.4 / 10** | Twenty unbounded reads, two of them on hot paths |
| **Regulatory & Standards** | **9.2 / 10** | Engines and formats present; SPDX honestly declined (ADR-0016) |
| **Verification that runs** | **8.0 / 10** | The pipeline exists, runs, and found real defects — but only fires when somebody clicks |

---

## 2. Documentation & Architecture — 9.0

The five Florat views exist in both languages, the sixteen ADRs are paired en/fr with no gap,
and `docs/en` and `docs/fr` hold **identical** file sets — established with `diff`, not by eye.
The STRIDE model is present in both languages.

**What costs the points.**

**The C4 drift control does not check what its name promises.** The `c4-drift` job compares a
SHA-256 fingerprint of `workspace.dsl` against a recorded value. It therefore detects that
somebody changed the model without regenerating. It **cannot** detect that the committed
diagrams do not match the model — if the fingerprint was recorded without the script genuinely
running, the check is green forever. The CI file admits this ("weaker, stated"), which is to its
credit; this report still counts it as a partial guarantee.

**🟡 D1 — ADR-0001 carries no reasoning.** Fifteen lines, *Context* and *Decision*, nothing on
the alternative or the cost accepted. It is *superseded* by 0010, so the price is low — but this
is exactly the scenario the prompt describes: it was reversed, and there is no way to know
whether the reversal corrected a mistake or discarded a reason.

---

## 3. Security & Cryptography — 8.3

Tenant isolation is this project's story, so I did not take `AuthorizationCoverageTest` on
trust: I redid the sweep.

**At controller granularity the test holds.** Three of 44 controllers carry neither a role guard
nor a `VisibilityService` — `AuthController`, `CryptoController`, `TicketingWebhookController` —
and all three are in the test's justified list. No new hole by that rule.

### 🟠 A1 — `GET /api/v1/inventory/versions` returns the whole estate's inventory

```java
@GetMapping("/versions")
public List<String> versions(@RequestParam String name) {          // no principal
    return components.versionsOf("%" + name + "%", Limit.of(200))  // no Visibility
```

The query has **no** join to a scan or a target:

```sql
select distinct c.version from ComponentEntity c
 where lower(c.name) like :name or lower(c.purl) like :name
```

**And the sibling route, four lines above, filters.** `search` resolves a `Visibility` and
applies `allowed.permits(targetOf(occurrence))` to every row. Same controller, same data source,
one filters and the other does not: that is not a design choice, it is an omission.

What it hands a restricted reader is an oracle. *"Does anyone here run log4j 2.14.1?"* — the
answer arrives without access to a single repository. For a product whose job is knowing who is
exposed, that is the most interesting question anyone could ask.

### 🟡 A2 — `GET /api/v1/ai/status` publishes Ollama's internal URL

```java
public Map<String, Object> getStatus() {
    return Map.of("enabled", …, "ollamaUrl", aiReviewService.ollamaUrl(), …);
```

Reachable by any signed-in account. An internal service address is not a secret, but it is a
starting point, and nothing obliges this route to hand it over.

### 🟡 A3 — the rule that should prevent A1 cannot see A1

`AuthorizationCoverageTest` works at **controller** granularity: it requires that a controller
*mention* `VisibilityService`. `InventoryController` mentions it — and passes, with a route that
does not use it.

I attempted a **route**-level sweep to do better. It produced 30 candidates, of which **28 were
false positives**: filtering very often goes through a private helper
(`requireVisible(principal, …)`, `visible(principal, id)`, `requireVisibleIssue(…)`) that no
regex recognises. My tool was wrong, not the code — and that is the honest reason controller
granularity was chosen. The finding stands: **the rule is coarser than the defect class it
watches**, and A1 is the demonstration.

### What checked out

Container hardening (`cap_drop`, `read-only`, `network: none`, memory/PID/CPU ceilings) is held
by `ContainerHardeningTest`, which captures the real `HostConfig`. The agent's isolation is a
**fact about the build graph** — `vectispire-agent` depends only on `vectispire-common`, no JDBC
driver on its classpath — and `AgentIsolationTest` forbids the import. The audit chain, Argon2id,
AES-256-GCM, four-eyes approval and both rate limiters are covered by tests that run in `check`.

---

## 4. Code Quality — 8.4

Idiomatic Spring Boot 4.1 / JDK 25, six layers held by ArchUnit, ADR-0007 respected. The
three-engine campaign passes.

### 🟠 B1 — `ThreatIntelFeedService.syncThreatIntel` reads all of `t_issue`, then queries per row

```java
List<IssueEntity> allOpenIssues = issuesRepo.findAll().stream()
        .filter(i -> !"closed".equalsIgnoreCase(i.getState()) …)
for (IssueEntity issue : allOpenIssues) {
    Optional<ThreatIntelEntity> match = intelRepo.findByCveIdIgnoreCase(issue.getIdentifier());
```

Two defects stacked: the whole table loaded and then filtered **in Java** when state is an
indexed column, and an N+1 per issue. The job is administrator-triggered (`POST /epss/sync`), so
it is not a user path — but against the dossier's 500,000-row estimate it is the heaviest read
in the repository.

### 🟠 B2 — `SecurityScorecardService` reads every scan to answer yes or no

```java
boolean hasAttestation = scansRepo.findAll().stream()
        .anyMatch(s -> repoId.equals(s.getRepoId()) && "completed".equalsIgnoreCase(s.getStatus()));
```

Three times in one class, on a **per-HTTP-request** path (`GET /scorecards/…`). A derived
`existsByRepoIdAndStatus` does the same thing in one indexed lookup.

Twenty `findAll()` sites remain across the services. Not all are defects — `SettingsService` and
`TargetNaming` read tables bounded by the number of targets — but **nothing tells them apart
mechanically**: only four tests measure cost with the Hibernate counters.

### 🟡 B3 — 13 specs for 28 front-end pages

The 119 tests pass and cover what they cover. Fifteen pages have no spec at all, several of them
screens that publish aggregate figures — exactly where an error reads as data.

---

## 5. Regulatory & Standards — 9.2

`ComplianceService` carries CRA, NIS 2, DORA and the OWASP Top 10. CycloneDX 1.6 with embedded
VEX, CSAF 2.0, OpenVEX, EPSS and reachability are produced. **SPDX is not produced, and
ADR-0016 says so** rather than letting it be assumed — which is what earns the score here: a
format declined and recorded beats a format claimed and absent.

---

## 6. Verification that runs — 8.0

The youngest axis, and the one that moved most today.

**The pipeline exists and runs.** `.gitlab-ci.yml` carries thirteen jobs; `verify` holds eight
controls, `package` builds both images **and starts the control plane against a real MySQL**.
`.github/workflows/` is kept as a record and does not execute.

**The nightly jobs found real defects on their first execution** — a hard-coded host that does
not survive `docker:dind`, and a Playwright image thirteen minor versions behind. Both fixed the
same day. That is the best possible evidence that this axis was missing.

**What caps the score:** the three nightly jobs (`databases`, `dockerfiles`, `e2e`) are gated on
`$CI_PIPELINE_SOURCE == "schedule"`, and **no schedule exists**. Today they fire only from a
manual "Run pipeline". A control that depends on somebody remembering is precisely what this
axis exists to forbid.

---

## 7. Recommendations, by cost

| # | Action | How it was verified |
|---|---|---|
| 🟠 1 | Scope `GET /inventory/versions` like its sibling: take the principal, resolve the `Visibility`, join the scan | measured: the query has no target join; `search`, 4 lines above, filters |
| 🟠 2 | Replace the three `scansRepo.findAll()` in `SecurityScorecardService` with `existsByRepoIdAndStatus` | read in the code; **not measured with the counters** — do that before claiming victory |
| 🟠 3 | Bound `syncThreatIntel`: filter state in SQL, and join the intel in one batch | read in the code, not measured |
| 🟡 4 | Drop `ollamaUrl` from `/ai/status` | read in the code |
| 🟡 5 | Create the nightly schedule in the CI/CD settings | **asserted, not executed** — beyond an audit's reach |
| 🟡 6 | Give a spec to the pages that publish aggregate figures | measured: 13 / 28 |
| 🟡 7 | Write ADR-0001's reasoning, or mark it explicitly historical | measured by sweeping all sixteen ADRs |

**And one recommendation about the method itself:** `AuthorizationCoverageTest` should detect,
inside a controller that knows `VisibilityService`, a route that consults neither a `Visibility`
nor a recognised helper. My sweep failed to do this cleanly because of the private helpers; the
workable path is probably to name those helpers by convention (`requireVisible*`, `visible*`)
and let the rule rest on that convention. Otherwise the rule will keep letting through the
defect class it watches — A1 is the proof.
