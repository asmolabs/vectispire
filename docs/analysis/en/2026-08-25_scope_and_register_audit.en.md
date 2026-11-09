# Scope & Register Audit: Documentation, Source Code & Security (English)

* **Project:** Vectispire — ASPM & Software Security Control Plane
* **Analysis Date:** August 25, 2026 (fifth pass)
* **Evaluator:** Claude (Anthropic) — automated code, security & documentation audit
* **Scope:** The four axes of [`PROMPT_AUDIT.md`](../../../PROMPT_AUDIT.md)
* **Preceding:** [In-Depth](2026-08-25_in_depth_code_security_doc_audit.en.md) 7.9 → [Post-Remediation](2026-08-25_post_remediation_audit.en.md) 8.9 → [Four Axes](2026-08-25_in_depth_audit_4_axes.en.md) 8.7 → [Verification](2026-08-25_verification_audit.en.md) 9.1

> **What is different about this pass.** The four commits since the last report mostly *removed*
> things — two database engines, a second secrets scanner, a documented setting that never existed.
> Deletion is the change most likely to leave something dangling and least likely to be noticed
> when it does, so this pass began by hunting orphans. It then went to ground none of the four
> earlier passes had covered: the gate verdict, and the front end.

---

## 📊 1. Score Summary

| Evaluation Domain | Verification | This pass | Status |
|---|:---:|:---:|:---:|
| **Documentation & Architecture** | 9.2 | **9.0 / 10** | 🟢 One measurement moved it down |
| **Security & Cryptography** | 9.1 | **9.3 / 10** | 🟢 The agent boundary now stated precisely |
| **Code Quality & Architecture** | 8.9 | **9.1 / 10** | 🟢 Scope narrowed to what is deployable |
| **Regulatory & Standards Compliance** | 9.3 | **9.3 / 10** | 🟢 Certification-capable |
| **Global** | 9.1 | **9.2 / 10** | 🟢 |

Documentation moves *down* while everything else moves up, and the reason is the finding below:
five architecture decisions were given their reasoning this session, which made it possible to
measure how many still have none.

### The finding

| # | Finding | Severity | Evidence |
|:--:|---|:--:|---|
| **D1** | **Nine of the fifteen ADRs are stubs of eleven lines or fewer**, and they are disproportionately the ones the code cites. [0007](../../architecture/en/decisions/0007-none-is-not-an-empty-list.md) — "none is not an empty list" — is 11 lines, and it is the rule referenced by `ScanRunner`, `ScannerContractTest`, both technical documents, and the remediation that closed the most serious finding of this whole audit series. | 🟠 **Medium** | Measured across `docs/architecture/en/decisions/` |

**Why this is worth a finding rather than a shrug.** The register is not decoration here: this
session used it twice as an argument.
[0015](../../architecture/en/decisions/0015-one-secrets-engine.md)
removed the second secrets engine *on the precedent of*
[0010](../../architecture/en/decisions/0010-one-scan-runner.md),
which is seven lines and states no reasoning at all — so the precedent had to be reconstructed
from the code rather than read. And the engine scope reversed three times in six days precisely
because no record explained the previous reversal.

The stubs, by how often the code leans on them:

| ADR | Lines | Cited by |
|---|:--:|---|
| **0007** — none is not an empty list | 11 | `ScanRunner`, `ScannerContractTest`, `ScanArtifacts`, both technical documents |
| **0010** — one scan runner | 7 | `ScanRunner`, and ADR 0015 as precedent |
| **0006** — semgrep rules written here | 11 | The STRIDE model, as a Tampering mitigation |
| **0005** — quality never blocks the gate | 11 | `PolicyGate`, `TriageStatus` |
| **0002** — the database carries the queue | 11 | `ScanQueue`, the pipeline documentation |

**Fix:** write 0007 first. It is the decision this project's most expensive defect came from
violating, and the one a reader is most likely to reach for.

**A smaller instance of the same thing:** [`PROMPT_AUDIT.md`](../../../PROMPT_AUDIT.md) still
asks
for "ADR 0001 through 0013". There are fifteen. The audit's own specification has drifted from
the
system it audits.

---

## 📚 2. Documentation & Architecture — 9.0

**Verified unchanged and sound:** Florat's five views at exact line parity (88/75/52/66/73),
STRIDE
complete (E1–E4, P1–P5, DS1–DS2, F1–F16, six categories, 171 lines each side), **402 relative
links
resolving, 0 broken**, and the C4 diagrams in step with `workspace.dsl` — checked by exporting
and
diffing, which is now also a CI job.

**What improved, and it is the largest documentation change of the series.** Five decisions
gained
their reasoning: [0003](../../architecture/en/decisions/0003-long-polling-for-agents.md) (11 →
57
lines), [0009](../../architecture/en/decisions/0009-four-engines.md) (7 → 32),
[0013](../../architecture/en/decisions/0013-flyway-multi-dialect-migrations.md) (7 → 40), plus
[0014](../../architecture/en/decisions/0014-two-engines-and-a-test-fixture.md) and
[0015](../../architecture/en/decisions/0015-one-secrets-engine.md) written new. Each records
what
was given up as well as what was gained, which is the half a decision record usually omits and
the
half the next reversal needs.

**What holds it at 9.0:** D1 above. The register is now half-argued, and the unargued half is
the
half in daily use.

---

## 🛡️ 3. Security & Cryptography — 9.3

### 3.1 The gate verdict, audited for the first time

[`PolicyGate`](../../../vectispire-java/vectispire-common/src/main/java/com/asmolabs/vectispire/common/domain/gate/PolicyGate.java)
produces the answer that fails somebody's build, and no earlier pass had read it. It holds up:

- **KEV takes precedence over severity**, and reports one violation per issue rather than two — the
  output stays actionable instead of duplicated.
- **Quality findings can never reach a verdict.** `gateParticipation()` makes it a property of the
  finding type rather than a policy flag, so no configuration can let them in.
- **AI review is opt-in**, because a local model handed the repository's own source can be steered
  by it.
- **`harden()` is a real security control and reads like one.** A pipeline can only *tighten* the
  stored policy; a request for `fail_on_severity: null` is refused, and — the part that matters
—
  **the refusal is reported back** rather than silently dropped, so a pipeline that believes it
  switched a rule off finds out that it did not. Nineteen tests.

### 3.2 The agent boundary, now stated as it actually is

The previous pass found that "the agent holds no credentials" was too strong. ADR 0003 now
records
the boundary in three parts: no database (enforced by the module graph, so the violation fails
to
compile), no `ENCRYPTION_KEY`, and deployment keys **only** in `DELEGATED` mode, sealed X25519 →
HKDF → AES-256-GCM to the key the agent announced at enrolment, audited on every send. It also
records that the agent refuses an envelope it cannot open rather than passing ciphertext to git,
and that an unknown mode reads as `LOCAL`.

That precision is the difference between a claim an assessor can verify and one they discount.

### 3.3 One secrets engine

The second engine is gone, and
[0015](../../architecture/en/decisions/0015-one-secrets-engine.md)
records why: it accepted only gitleaks-compatible images, that case is already covered by naming
the primary image, and nothing ever exercised it. What remains is the signature that makes the
original silent-data-loss defect **unexpressible** — `ran(…)` will not compile against a bare
`List`, and `ScannerContractTest` asserts it by reflection for any scanner added later.

---

## ⚙️ 4. Code Quality & Architecture — 9.1

**Spring Boot 4.1.0 / JDK 25**, zero `TODO`/`FIXME` in production sources, ArchUnit's six rules,
JaCoCo at **83.6% instruction / 69.4% branch** on `common.domain` against an 80/65 floor.

**The scope now matches what is deployable.** PostgreSQL and MySQL, with SQLite named as the
test
fixture it always was — it cannot boot the packaged application under `ddl-auto: validate`,
which
was known inside the test profile and never reflected in the supported set. Three migration sets
of
fourteen scripts each, no orphans left by the removal, and `integrationTestAll` green in 2m44
(from 3m58).

**The front end, audited for the first time.** 55 sources, 34 templates, TypeScript `strict` and
Angular `strictTemplates` both on, and **no sanitisation bypass anywhere** — the single
`innerHTML`
occurrence is a comment warning against one. The client is generated from `openapi.json`, so the
DTOs cannot drift from the API by hand.

**Residual:** 15 spec files against 55 sources. The unit coverage is the thinner half of the
test
strategy, and the E2E suites that would compensate have still never run on a runner.

---

## 📋 5. Regulatory & Standards Compliance — 9.3

Six frameworks evaluated in the pure domain; CycloneDX, SPDX, CSAF 2.0, OpenVEX, EPSS and
reachability all present. The engine still measures the control plane and not only the fleet — a
control is capped at `PARTIAL` when the capability beneath it is off — and the audit mirror is
now
on by default in compose, so the `AUDIT_AND_LOGGING` cap no longer applies to the shipped
deployment.

The grouped projection behind the summary is now exercised on every engine by
`ComplianceSummaryIntegrationTest`, which replaces the by-hand verification the previous pass
had
to perform.

---

## 🎯 6. Prioritised Recommendations

### 🟠 Next
1. **Write ADR 0007 properly**, then 0010, 0006, 0005 and 0002 *(D1)*. Start with 0007: it is the
   rule this series' most serious defect came from violating.
2. **Run `nightly.yml` and the new `images` job once on a runner.** Both were reasoned about and
   corrected locally; neither has executed where it will run.
3. **Update `PROMPT_AUDIT.md`** — it asks for ADRs 0001 through 0013, and there are fifteen.

### 🟡 Later
4. Raise the front-end unit coverage, or state deliberately that the E2E suites carry it.
5. Extend the JaCoCo floor beyond `common.domain` now that the query shapes have settled.
6. Consider whether `SecurityDebtService` and the notification outbox deserve the integration
   coverage the compliance summary just received — neither has been audited in five passes.

---

## 7. Conclusion

Five passes, and the shape of what they find has changed completely. The first found controls
wired wrongly. The second found defects introduced by the repair. The third found a silent
data-loss path in the handling of leaked credentials. The fourth ran the software and found the
fixes held on engines the tests never touch. This one hunted for what deletion left behind,
found
nothing, and had to go looking in the gate and the front end — both of which are in good order.

What it did find is a measurement that only became possible because the register was partly
repaired: **nine of fifteen architecture decisions still record what was chosen and not why**,
and
they are the ones the code cites. That is not a defect in the software. It is the difference
between a project that can explain itself to the next person and one that will reverse the same
decision a fourth time.

**9.2 / 10.**
