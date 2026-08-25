# In-Depth Audit — Four Axes: Documentation, Security, Code, Compliance (English)

* **Project:** Vectispire — ASPM & Software Security Control Plane
* **Analysis Date:** August 25, 2026 (third pass)
* **Evaluator:** Claude (Anthropic) — automated code, security & documentation audit
* **Scope:** The four axes of [`PROMPT_AUDIT.md`](../../../PROMPT_AUDIT.md), each verified against the tree rather than against the previous reports.
* **Preceding reports:** [In-Depth Audit](2026-08-25_in_depth_code_security_doc_audit.en.md) (7.9) → [Post-Remediation](2026-08-25_post_remediation_audit.en.md) (8.9)

> **Why a third pass, and what is new in it.** The two earlier reports covered security wiring and the remediation that followed. Several axes the prompt names had never been verified in depth: the C4 model's *reproducibility*, STRIDE completeness, the actual implementation of ADR-0007, the multi-scanner deduplication claim, SCIM/OIDC, and the supply-chain formats. This pass went at those, and **the two most consequential findings in this report come from that previously unexamined ground** — one of them a silent-data-loss path in the highest-severity finding type the product handles.

---

## ✅ 0. Remediation & Correction

**A1 is fixed** (same day, after this report was written). Both secret scanners now return
`Optional<List<…>>` and are routed through `ran(…)`; the `catch (Exception ignored)` is gone, and
the two results are merged outside the list construction so one engine's failure can never be
absorbed by the other's success. A failure now leaves the artifact absent and records the reason
on the scan, exactly as every other step does.

Pinned two ways. `ScannerContractTest` checks by reflection that every container-running scanner
returns `Optional` — a scanner added later is in scope the moment it exists. And the mutation
check produced a better result than a failing test: reverting `BetterleaksScanner` to a bare
`List` **no longer compiles**, because `ScanRunner.ran(…)` requires an `Optional`. The defect is
now unexpressible rather than merely tested.

### Correction to A2 — the mechanism stated below is wrong

Verified while implementing A1, and it should be recorded rather than quietly edited: the report
claims Gitleaks and Betterleaks "run different rule sets". **They do not.** `ScannerImages` aliases
`betterleaks` to the pinned `gitleaks` digest, and `BetterleaksScanner` passes the *same*
`gitleaks.toml`. By default the two are the same engine, same rules, same arguments — only the
report filename differs.

The consequences invert:

* **Deduplication works** on a default install. Identical rule sets produce identical identifiers,
  hence identical fingerprints. The duplicate-issue risk described in §4.2 does not materialise.
* **The real defect is redundancy.** The second pass costs one more container per scan and buys
  coverage of exactly nothing. That is now stated on `BetterleaksScanner` itself.
* **The duplication risk is conditional, not current.** It appears only if an operator points
  `betterleaks` at a genuinely different engine — at which point the shared `gitleaks.toml`, which
  another engine has no reason to understand, becomes the first problem.

**A2 is now settled, and the decision is this.** The seam stays — an operator may point
`betterleaks` at a different engine — but it costs nothing until they use it:

* `ScannerImages.hasDistinctSecretEngines()` compares the two images, and `ScanRunner` runs the
  second pass **only when they differ**. The default install stops analysing every tree twice for
  results equal by construction.
* When two real engines run, `SecretsScanner.merge` collapses **identical** findings. That is not
  tidiness: `IssueSyncService` increments `times_seen` once per finding, so a duplicate inside one
  scan makes an issue look twice as persistent as it is.
* Two engines flagging the same line under **different rule names stay two findings**, on purpose.
  Collapsing them would mean choosing whose rule identity survives, and that identity is what tells
  an analyst why the line was flagged — a disagreement between engines is information. The cost is
  named rather than hidden: `IssueFingerprint` includes the rule id, so one credential can become
  two issues. That cost is precisely why the redundant pass is *skipped* rather than deduplicated.

Five assertions in `SecretEngineMergeTest` pin all of it, including that the pinned image set has
no second engine.


---

## 📊 1. Score Summary

| Evaluation Domain | Post-remediation | This pass | Status |
|---|:---:|:---:|:---:|
| **Documentation & Architecture** | 9.0 | **8.8 / 10** | 🟢 Exemplary, one reproducibility defect |
| **Security & Cryptography** | 8.8 | **8.5 / 10** | 🟢 Strong, one secrets-loss path |
| **Code Quality & Architecture** | 8.7 | **8.3 / 10** | 🟢 Enterprise Ready, three defects named |
| **Regulatory & Standards Compliance** | 9.2 | **9.2 / 10** | 🟢 Certification-capable |
| **Global** | 8.9 | **8.7 / 10** | 🟢 |

**The score moves down, and that is the point of the pass.** Nothing regressed: three defects
that were always there are now visible. An audit that only re-confirms what the previous one
measured is measuring the previous audit.

### New findings

| # | Finding | Severity | Evidence |
|:--:|---|:--:|---|
| **A1** | The secrets step **swallows a Betterleaks failure** (`catch (Exception ignored) {}`) and reports Gitleaks-only results as a complete analysis. Per ADR-0007's own semantics, a non-null list is the positive claim "ran and found nothing", which **resolves** that type's issues. A Betterleaks outage can therefore silently resolve leaked-credential findings. | 🔴 **High** | [ScanRunner.java:140](../../../vectispire-java/vectispire-common/src/main/java/com/asmolabs/vectispire/common/scanning/ScanRunner.java) |
| **A2** | Cross-scanner deduplication is **not guaranteed**. `IssueFingerprint.of` includes the scanner's own `identifier` (rule id), and the two secret scanners run different rule sets — so one leaked credential found by both can produce two issues. | 🟠 **Medium** | [IssueFingerprint.java:77](../../../vectispire-java/vectispire-common/src/main/java/com/asmolabs/vectispire/common/domain/issues/IssueFingerprint.java) |
| **A3** | The committed C4 diagrams are **not reproducible** from the documented script: running `scripts/generate-c4-diagrams.sh` rewrites all six artifacts (364 lines changed) and deletes three stale tracked `.puml` files at the `c4/` root. | 🟡 **Low** | Verified by running the script |

---

## 📚 2. Documentation & Architecture — 8.8

### 2.1 Bertrand Florat model — verified complete and synchronised

All five self-contained views are present in both languages at **exact line parity**:

| View | EN | FR |
|---|:--:|:--:|
| Application | 88 | 88 |
| Security | 75 | 75 |
| Dimensioning | 52 | 52 |
| Infrastructure | 66 | 66 |
| Development | 73 | 73 |

### 2.2 STRIDE threat model — verified complete

Not asserted from the document's own table of contents but counted in the text: **entities
E1–E4, processes P1–P5, data stores DS1–DS2, and all sixteen data flows F1–F16**, with all six
STRIDE categories addressed (Spoofing 3, Tampering 7, Repudiation 1, Information Disclosure 8,
Denial of Service 2, Elevation of Privilege 6).
[EN](../../architecture/security/en/STRIDE_THREAT_MODEL.en.md) and
[FR](../../architecture/security/fr/STRIDE_THREAT_MODEL.fr.md) are 171 lines each — exact
parity.

### 2.3 C4 model — sound, but the artifacts are not reproducible (**A3**)

[`workspace.dsl`](../../architecture/c4/workspace.dsl) models five containers across three
levels with `autoLayout`, and the model matches the system as built (Angular UI, Spring control
plane, database, Docker daemon, remote agent).

**What was tested rather than read.** Running the repository's own
[`scripts/generate-c4-diagrams.sh`](../../../scripts/generate-c4-diagrams.sh) rewrites every
committed artifact. The drift is **format, not model** — the committed files came from an older
exporter emitting `<style>` blocks with base64 stereotype classes, while the documented command
produces `c4plantuml` `Person(...)`/`Rel(...)` primitives. The model content is equivalent.

It still matters, for the reason this project applies elsewhere: an artifact that cannot be
regenerated by the command that claims to generate it is not architecture-as-code, it is a
picture. And a script that produces a 364-line diff on every run is a script people stop
running. The three tracked `.puml` files at the `c4/` root were stale duplicates from an earlier
layout; the script deletes them, which is how they were found.

**Regenerated in this commit**, so the documented command and the committed state now agree.

### 2.4 ADRs and bilingual parity — verified

Thirteen ADRs in both trees, with the supersession chain intact (0011 → 0013). Documentation
links: **331 relative links, 0 broken**, defended by the `docs` CI job. Operational corpus
parity holds at 0–2% on the three reconciled documents; `GETTING_STARTED.fr` remains 11% shorter
on a structural divergence.

---

## 🛡️ 3. Security & Cryptography — 8.5

### 3.1 Verified controls

| Control | State |
|---|---|
| Rate limiting (`LoginRateLimitFilter`, Bucket4j) | ✅ Token-bucket ahead of Argon2id; `X-Forwarded-For` honoured only behind a configured trusted proxy; bounded LRU pruned on insertion |
| Argon2id, TOTP MFA | ✅ MFA reachable and attempt-capped (3 per challenge, destroyed on last failure); both mutation-verified |
| SCIM 2.0 | ✅ `/scim/v2/Users` and `/scim/v2/Groups`, `@RequiresAdministrator`, `application/scim+json` |
| OIDC group sync | ✅ `groups` claim mapped to team membership ([OidcConfiguration.java:164](../../../vectispire-java/vectispire-core/src/main/java/com/asmolabs/vectispire/core/api/security/OidcConfiguration.java)) |
| AES-256-GCM at rest, Vault KMS | ✅ Context bound to the row; `kms-type=vault` now refuses to start without a reachable endpoint |
| Scanner sandboxing | ✅ `cap_drop: ALL`, `no-new-privileges`, `network: none` by default, digest-pinned, **read-only rootfs** with `noexec` tmpfs, no Docker socket |
| Agent isolation | ✅ Enforced by the module graph, re-asserted by `AgentIsolationTest` |
| SHA-256 audit chain | ✅ Chained, with limits now stated in the compliance document (§5.1) |
| Four-eyes | ✅ Identity-distinct, mutation-verified |

### 3.2 A1 — the secrets step is where ADR-0007 is not applied 🔴

Every other scanner returns `Optional<List<…>>` and passes through `ran(…)`, which throws when
the analysis did not happen so the step records a failure and leaves the artifact `null`. The
secrets step does not:

```java
List<SecretsScanner.SecretFinding> allSecrets = new ArrayList<>(secrets.scan(workspace, subPath));
try {
    allSecrets.addAll(betterleaks.scan(workspace, subPath));
} catch (Exception ignored) {
}
artifacts.secrets(allSecrets);
```

`BetterleaksScanner.scan` **does** signal failure correctly — it throws
`ScannerFailureException.exited(...)` on a bad exit code. The caller discards it.

**Why this is the worst place for it.** ADR-0007 states that `[]` is the positive claim *"the
step ran and found nothing"*, which **resolves** that type's open issues, while `null` means
"did not run" and leaves the backlog alone. Here a Betterleaks failure produces a non-null list
— Gitleaks' results alone — so the step asserts a complete secrets analysis. Any leaked
credential that only Betterleaks detects is resolved, silently, with no error anywhere. The
finding type is leaked credentials, where a false resolution is the most expensive one the
product can produce.

Neither scanner returns `Optional`, so the step has no way to express "did not run" even if the
exception were not swallowed.

**Recommendation:** have both secret scanners return `Optional<List<…>>` and route them through
`ran(…)` like every other step, merging only when both succeeded. If a degraded mode is wanted,
it must be explicit — record the partial coverage on the scan rather than inferring completeness
from a non-null list.

### 3.3 What holds the rest

The audit mirror remains off by default, so the deleted-leaf case is open on a default install —
now visible in the compliance score rather than silent. MFA still has no end-to-end coverage.

---

## ⚙️ 4. Code Quality & Software Architecture — 8.3

### 4.1 Verified strengths

**Spring Boot 4.1.0 / JDK 25**, 177 unit test classes, 7 integration classes, **zero
`TODO`/`FIXME`** in production sources. ArchUnit enforces six rules including the empty-import
guard. Coverage is measured and defended: **83.6% instruction / 69.4% branch** on
`common.domain` against an 80/65 floor wired into `check`. Flyway carries 14 dialect-native
migrations across four engines, `ddl-auto: validate`, with `SchemaParityIntegrationTest` asking
each engine whether entities and schema agree — and `nightly.yml` now runs all four.

**ADR-0007 is implemented** in seven scanners through `ran(…)` — everywhere except §3.2.

### 4.2 A2 — the deduplication claim is narrower than stated 🟠

`IssueFingerprint.of` hashes target, type, **identifier**, purl-or-package, and file path.
`identifier` is *the scanner's own rule id*.

Gitleaks and Betterleaks share a pinned image but run **different rule configurations**. Two
rule sets naming the same secret differently produce two identifiers, hence two fingerprints,
hence **two issues for one leaked credential** — with `times_seen`, triage and VEX state tracked
separately on each.

Deduplication is real *within* a scanner and across scans; *between* scanners it holds only when
the rule ids coincide. No test covers the cross-scanner case: `IssueFingerprintTest` exists, but
nothing exercises a secret reported by both tools.

**Recommendation:** decide the intent explicitly. Either normalise secret identifiers to a
shared vocabulary before fingerprinting, or drop `identifier` from the secret fingerprint in
favour of file path plus a hash of the matched value. Then test it — the claim is in the product
documentation.

### 4.3 Carried open from the previous pass

| # | Finding | Note |
|:--:|---|---|
| **N1** | `/api/v1/compliance/summary` issues nine count queries per target plus an unbounded audit-table scan. | The rule `TriageEvents.findForIssues` states in its own comment, broken in the service producing an auditor's report. |
| **R1** | `nightly.yml` has never executed. | Trigger once via `workflow_dispatch` before its green tick means anything. |
| **R2** | No MFA end-to-end coverage. | `auth.spec.ts` still has no MFA case. |

---

## 📋 5. Regulatory & Standards Compliance — 9.2

**Regulatory engines verified present and evaluated in the pure domain:** NIS 2 (Art. 21), EU
CRA (Art. 10–11), DORA (Art. 9/11/13/16), ISO/IEC 27001, PCI-DSS v4.0 and OWASP — six
frameworks, scored by `ComplianceEngine` with no database, clock or framework dependency, hence
exhaustively testable.

**Supply-chain interoperability verified by class inventory:** CycloneDX (1.6), SPDX (2.3), CSAF
2.0, OpenVEX, EPSS and reachability all have dedicated domain packages and route tests.

**The differentiating property, confirmed.** The engine now measures the control plane and not
only the fleet: a control is capped at `PARTIAL` when the capability beneath it is off (no
encryption key → 60, no audit mirror → 70, four-eyes disabled → 75), and the cap only ever
lowers. §5.1 of the compliance document states what the audit chain proves, what it does not,
and what closes it.

**What keeps it from higher:** the deleted-leaf case remains open on a default install, and A1
above means a `SECRETS_MANAGEMENT` score can rest on an analysis that silently did not fully run
— a compliance figure resting on a finding that resolved itself.

---

## 🎯 6. Prioritised Recommendations

### 🔴 Before the next release
1. **Make the secrets step obey ADR-0007** — both scanners return `Optional`, routed through `ran(…)`, no swallowed exception. A partial secrets analysis must never present as a complete one *(A1, §3.2)*.

### 🟠 Next
2. **Settle the cross-scanner dedup intent and test it** *(A2, §4.2)*.
3. **Collapse the compliance N+1** into grouped queries and bound the chain verification *(N1)*.
4. **Run `nightly.yml` once by hand** and fix what it finds *(R1)*.
5. **Add an MFA case to `auth.spec.ts`** *(R2)*.

### 🟡 Later
6. Add the C4 regeneration to CI as a drift check, so the artifacts cannot silently diverge again *(A3)*.
7. Bring `GETTING_STARTED.fr` to line parity, or record the structural divergence.
8. Consider a default mirror path for container deployments.

---

## 7. Conclusion

The four axes hold up well under direct verification. The Florat model, the STRIDE model and the
ADR register are complete, synchronised and — unusually — accurate about their own limits. The
security controls are wired as designed and several are defended by tests that were shown to
fail when the fix is removed. The compliance engine measures itself, which is rare enough to be
the project's most distinguishing property.

Against that, this pass went at ground the earlier reports had not covered and found three real
defects, one of them serious: **the single step that handles leaked credentials is the one step
where the project's own rule against silent data loss is not applied**, and a scanner failure
there resolves findings rather than reporting an outage. It is a small fix — an `Optional` and a
removed `catch` — and it is the one thing in this report that should not wait.

**8.7 / 10.** The lower score is not a regression; it is what happens when an audit stops
re-reading its own previous conclusions and goes to look somewhere new.
