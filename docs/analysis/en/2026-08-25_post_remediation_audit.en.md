# Post-Remediation Audit: Documentation, Source Code & Security (English)

* **Project:** Vectispire — ASPM & Software Security Control Plane
* **Analysis Date:** August 25, 2026 (second pass, after remediation)
* **Evaluator:** Claude (Anthropic) — automated code, security & documentation audit
* **Baseline:** [In-Depth Audit Report, same day](2026-08-25_in_depth_code_security_doc_audit.en.md) — 7.9 / 10, fourteen findings
* **Method:** Re-verification against the current tree, with the remediation itself treated as the primary object of scrutiny. Mechanical checks re-run from scratch; no finding is carried over as "fixed" on the strength of a commit message.

> **What this pass is for.** The first audit found controls that were correctly designed and incorrectly wired. Roughly a thousand lines were then changed across security, build and documentation to close them. **New code is where new defects are, and remediation code is written under the worst conditions for review — quickly, by whoever just found the problem, with the satisfaction of having found it.** This pass therefore begins with the remediation and only then widens.

---

## 📊 1. Executive Summary & Scores

| Evaluation Domain | Before | Now | Status |
|---|:---:|:---:|:---:|
| **Documentation & Architecture** | 7.5 | **9.0 / 10** | 🟢 **Restored to its structure** |
| **Security & Cryptography** | 7.0 | **8.8 / 10** | 🟢 **Wired, and tested against the chain** |
| **Code Quality & Architecture** | 8.5 | **8.7 / 10** | 🟢 **Enterprise Ready** |
| **Regulatory & Standards Compliance** | 8.5 | **9.2 / 10** | 🟢 **Now measures itself** |
| **Global** | **7.9** | **8.9 / 10** | 🟢 |

**All fourteen findings and both §5 caveats verify as closed.** The score does not reach higher for
three reasons, and they are the substance of this report: one new performance defect of a class the
project explicitly forbids elsewhere, two defects found *in the remediation itself* during this
pass, and a set of controls that are now correct but not yet proven in the environment that will
run them.

### Found in the remediation, during this pass

Both were introduced by the fixes for the earlier findings and are corrected in the same commit as
this report. They are listed first because they are the answer to "did the repair hold".

| # | Defect | Severity | Disposition |
|:--:|---|:--:|---|
| **P1** | `ComplianceService.platformPosture()` called `verifyAgainstMirror()`, which reads the **entire mirror file and every audit row** to compare them — on every compliance page load. It needed one boolean. | 🟠 **High** (performance) | ✅ Fixed: a new `AuditLogService.mirrorConfigured()` answers the question without the comparison. |
| **P2** | `finalizedBy(tasks.withType<JacocoReport>())` attached the coverage report to *every* Test task, so running `integrationTest` alone generated a report from `test.exec` — a coverage figure describing a different execution. | 🟡 **Medium** | ✅ Fixed: scoped to the `test` task. |

P1 is the more instructive. The fix for finding §3.6 needed to know whether an audit mirror
exists; the method that answered came with a full integrity comparison attached, and reaching for
it was free at the point of writing and expensive at the point of running. **A correctness fix
that quietly becomes a performance defect is the characteristic failure of remediation work**, and
it is why this pass exists.

### New finding in the pre-existing code

| # | Finding | Severity | Evidence |
|:--:|---|:--:|---|
| **N1** | `/api/v1/compliance/summary` issues **nine count queries per target** inside its per-target loop, plus a full audit-table scan for the chain verification. On a hundred targets that is ~900 round trips for one page. | 🟠 **High** | [ComplianceService.java:175](../../../vectispire-java/vectispire-core/src/main/java/com/asmolabs/vectispire/core/services/ComplianceService.java) |

This one deserves its wording carefully, because the project already knows the rule. `TriageEvents.findForIssues` carries this comment:

> *"One query for a page of issues, not one per issue. […] asking per row turns one page into hundreds of round trips, which is invisible on a demo database and is the difference between a screen and a timeout on a real backlog."*

That is exactly what the compliance summary does. The rule is stated in the codebase and violated
in the service that produces the report an auditor reads. It is invisible on the SQLite suite for
the reason the comment gives.

**Fix:** one grouped query per counter (`GROUP BY repo_id, container_id`) feeding a map, and
bounding the chain verification — see R5.

---

## 📚 2. Documentation & Architecture — 9.0

**Verified mechanically, not assumed:**

| Check | Before | Now |
|---|:---:|:---:|
| Relative links resolving | 252 / 305 | **325 / 325** |
| Absolute `file:///Users/...` paths in shipped docs | 4 | **0** |
| `ROTATION_AND_PURGE` FR / EN | 37 / 202 | **202 / 202** |
| `TECHNICAL_DOCUMENTATION` FR / EN | 212 / 513 | **518 / 514** |
| `COMPLIANCE_AND_REGULATORY` EN / FR | 204 / 266 | **302 / 308** |

The link checker is now a CI job, so the count is defended rather than merely corrected — and it
rejects any `file://` link by construction, which is the specific regression that produced the
leaked home directory.

The French technical documentation was not a shortened translation but a different document with a
different section plan; it now mirrors the English structure across all fourteen sections. Its two
compliance sections were dropped rather than translated, correctly: they duplicated
`COMPLIANCE_AND_REGULATORY.fr`, which is where that content belongs.

**What keeps this from 9.5:** `GETTING_STARTED.fr` remains 11% shorter than its English
counterpart (187 vs 211) — the structures differ where the French splits Docker deployment into
its own section. Content parity is reached; line parity is not, and the difference is cosmetic
rather than a coverage gap.

---

## 🛡️ 3. Security & Cryptography — 8.8

### Verified closed

- **MFA sign-in reachable.** `/api/v1/auth/mfa/verify` is `permitAll`, and — more durable than the fix — `RouteAuthorizationTest.anOpenRouteIsReallyReachableWithoutCredentials` walks every `@OpenToAnonymous` route and asserts a handler was reached rather than a status, since an open route may legitimately answer 401 itself. Re-verified by mutation during this pass: removing the `permitAll` fails the probe on `POST /api/v1/auth/mfa/verify → refused by the filter chain with 401`.
- **TOTP brute force bounded.** Three attempts per challenge, challenge destroyed on the last failure, identical message either way. Re-verified by mutation: disabling the destruction fails `exhaustedChallengeIsDestroyed`.
- **Rate limiter keyed on something the client cannot choose.** `X-Forwarded-For` is honoured only behind a configured trusted proxy, walked right-to-left to the first untrusted hop; buckets are a bounded LRU pruned on insertion rather than on the rejection path an attacker never takes.
- **Four-eyes counts people, not roles.** The approver is compared against the actor on the `PENDING_APPROVAL` event, read from the event log because `triagedBy` on the row has already been overwritten by then. Mutation-verified: without the check, self-approval returns 200.
- **Deployment fails closed.** `docker compose config` refuses to render without `ENCRYPTION_KEY`, the database password and the bootstrap password. `group_add` grants the socket group the Dockerfile already documented as necessary; the database binds to loopback.
- **Vault fails fast.** `kms-type=vault` without a reachable endpoint or token refuses to start rather than silently moving key custody to a local derivation.
- **Scanner containers run on a read-only root**, with `noexec` tmpfs scratch. Validated on a real daemon against all five pinned images, and asserted by four cases in the container integration campaign.

### What holds the score at 8.8

| # | Residual | Why it matters |
|:--:|---|---|
| **R2** | MFA has route tests but **no end-to-end coverage** — `auth.spec.ts` still contains no MFA case. | The original defect was a filter-chain/annotation divergence that only an HTTP request could reveal. That class is now covered by MockMvc; the browser path is not. |
| **R3** | The audit mirror remains **off by default**. | Justified — writing to a path by default fails on a read-only container filesystem — and its absence is now *visible* in the compliance score rather than silent. But the deleted-leaf case is open on a default install. |
| **R6** | Anonymous API-doc exposure is now a setting, **closed by default**; the underlying springdoc endpoints are also off by default. | Correct, and worth noting the near-miss: the first implementation looked right and did nothing, because the SPA deep-link rule matched `/v3/api-docs` first. It was caught only because the test asserted the refusal instead of the setting. |

**On the grype exception, which an assessor will ask about.** Every scanner container runs with a
read-only root filesystem except that its vulnerability database now lives on a disk-backed
writable mount. This is not a weakening: the database is ~1.9 GB, the scratch tmpfs is memory
counted against a 2 GB container ceiling, and the mount is the *only* writable path the container
has. Measured against the real daemon — the tmpfs-only version failed with `no space left on
device` and then `database does not exist`, which would have read as a scanner outage rather than
as a sizing mistake. Had it shipped on the strength of code review, every dependency scan would
have failed.

---

## ⚙️ 4. Code Quality & Architecture — 8.7

**Spring Boot 4.1.0 / JDK 25, 177 unit test classes, 7 integration classes, zero `TODO`/`FIXME` in
production sources.** ArchUnit's six rules still hold, including the empty-import guard that stops
an architecture suite passing vacuously.

**Coverage is now measured and defended.** JaCoCo emits XML, and a `jacocoTestCoverageVerification`
floor scoped to `common.domain` (80% instruction, 65% branch) is wired into `check`. Current:
**83.6% instruction, 69.4% branch** — above the floor with the margin a floor should have.
Mutation-verified: raising it to 95% fails the build at the measured figure. Scoping it to the pure
domain is right — it is the layer ArchUnit keeps framework-free precisely so it can be exhaustively
tested, and a floor over the plumbing would measure how many getters it has.

**CI now covers what it used to disclose it did not.** `nightly.yml` runs `integrationTestAll`
across four engines and the Playwright suites at 02:30 UTC. The E2E job boots the control plane on
SQLite first — which the earlier state could never have done, since Playwright's `webServer` starts
only `ng serve` and its proxy needs an API on `:3180`.

### What holds the score at 8.7

| # | Residual | Why it matters |
|:--:|---|---|
| **N1** | The compliance N+1 above. | The rule is stated in this codebase and broken in it. |
| **R1** | **`nightly.yml` has never executed.** It is syntactically valid and its logic is reasoned, but a scheduled workflow is a hypothesis until it runs once. | The E2E job in particular makes assumptions about boot time, SQLite behaviour under `ddl-auto: validate`, and Playwright on a bare runner. Trigger it once by hand (`workflow_dispatch`) before trusting the green tick. |
| **R5** | `AuditLogService.verify()` reads **every audit row** with no bound, and the compliance summary calls it on every page load. | Pre-existing, and the same shape as N1. On a mature instance the audit log is the largest table. |

---

## 📋 5. Regulatory & Standards Compliance — 9.2

This is where the largest genuine improvement sits, and it is not a documentation change.

**The engine now measures the control plane, not only the fleet.** The previous behaviour was
sharper than the first audit stated: an instance running with **no encryption key at all** —
holding deployment SSH keys it could not protect — reported *"Zero exposed plaintext credentials
detected"* and scored **100/100** on `DORA-ART13-SECRETS`, because the only evidence that control
consulted was Gitleaks' output on *other people's* repositories. The finding was true; the
conclusion was not.

A `PlatformPosture` input now carries what this deployment has switched on, and a control is capped
at **PARTIAL** when the capability underneath it is off:

| Category | Capped when | Ceiling |
|---|---|:---:|
| `SECRETS_MANAGEMENT` | no encryption key configured | 60 |
| `AUDIT_AND_LOGGING` | no audit mirror configured | 70 |
| `GOVERNANCE` | four-eyes disabled | 75 |

Three design decisions worth recording, because each removes a way for the control to lie:

1. **A separate input, not four more `PostureInput` fields.** One is a measurement of somebody else's code; the other is a property of this deployment. An assessor treats them differently and the type should too.
2. **No defaulted overload.** All five call sites state the posture explicitly; the compiler asks the question rather than a silent default answering it. This is what made the test suite fail to compile, which was the intended behaviour.
3. **The cap only lowers.** A control already failing on findings keeps saying so — reporting it as PARTIAL because a switch is off would be an improvement earned by a second defect. Asserted by `aCapNeverImprovesAnAssessment`.

**The audit trail's limits are now stated where an assessor reads them.** §5.1 of the compliance
document, in both languages, says what the chain proves (selective editing is detectable), what it
does not (the deletion of an entry nobody descends from is not), why that concession was taken
(a strictly linear chain made concurrent writers declare an honest log broken), and what closes it
(the mirror). An in-database checkpoint was considered and rejected in writing: whoever can write
the audit table can rewrite a checkpoint table consistently, so it would move the problem one level
up while looking like evidence.

**What keeps this from 9.5:** the deleted-leaf case remains open on a default installation, because
the mirror is off by default. That is now honest rather than hidden — the score says so — but
honest and closed are not the same thing.

---

## 🎯 6. Recommendations

### 🟠 Next
1. **Collapse the compliance N+1** into grouped queries, and bound the chain verification the summary triggers *(N1, R5)*.
2. **Run `nightly.yml` once by hand** via `workflow_dispatch` and fix what it finds, before the schedule makes its first green tick meaningful *(R1)*.
3. **Add an MFA case to `auth.spec.ts`** — the browser path of the defect that started all this *(R2)*.

### 🟡 Later
4. Bring `GETTING_STARTED.fr` to line parity, or accept the structural divergence explicitly.
5. Consider shipping a default mirror path for container deployments, where a writable volume already exists *(R3)*.
6. Extend the coverage floor beyond `common.domain` once the compliance service's query shape is settled.

---

## 7. Conclusion

The remediation holds. Every one of the fourteen findings and both §5 caveats verify as closed
under re-testing, and several were verified by mutation rather than by inspection — removing the
fix and watching the right test fail, which is the only evidence that a test defends what it
claims.

What this pass adds is the part a self-assessment usually omits. Two defects were introduced by
the repair itself — a full-table read placed on a page-load path, and a coverage report attached
to the wrong execution — and both were found here rather than in production. One pre-existing
defect of real consequence surfaced only because the compliance service was read closely for other
reasons: it breaks, in the service that produces an auditor's report, a rule this codebase states
in its own repository layer.

**8.9 / 10** is a codebase whose controls are now wired as designed, whose documentation is
mechanically defended, and whose compliance engine has stopped exempting itself from the standard
it applies to everyone else. What separates it from higher is not architecture: it is one query
shape, one workflow that has never run, and one browser path still untested.
