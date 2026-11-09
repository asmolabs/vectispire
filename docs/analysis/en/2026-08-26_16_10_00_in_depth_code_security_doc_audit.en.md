# In-Depth Audit Report: Documentation, Source Code & Security

* **Project:** Vectispire — ASPM & Software Security Control Plane
* **Date:** 26 August 2026, 16:10
* **Commit audited:** `f92f192d` (`develop`)
* **Scope:** the five axes of [`PROMPT_AUDIT.md`](../../../PROMPT_AUDIT.md)

> **Eleventh pass, hours after the tenth.** Part of this report therefore checks my own
> remediation, which is the worst possible angle from which to find a defect. The effort went
> elsewhere: cryptography, the audit chain, the fingerprint contract and the regulatory engines —
> named in the prompt for ten passes and never **probed**.

---

## 0. What was executed

| command | result |
|---|---|
| `./gradlew check` | **green** |
| `./gradlew integrationTestAll --rerun-tasks` | **green on all three engines**, 1 min 59 s |
| `npx ng test --no-watch` | **23 files, 146 tests** |
| `python3 scripts/check-doc-links.py` | 570 links, 0 broken |

**A method trap, met in this very pass.** The first `integrationTestAll` returned "BUILD SUCCESSFUL
in 549ms": Gradle judged it up to date and **ran nothing**. Counting that green as a campaign would
have been exactly the mistake axis 5 forbids — hence `--rerun-tasks`. Anyone reading a green
campaign should look at the duration first.

Not executed, and counted as such: the Playwright suite, and reachability across `docker:dind`.

---

## 1. Summary

| Domain | Score | What sets it |
|---|:---:|---|
| **Documentation & Architecture** | **9.2 / 10** | ADR-0001 gained its reasoning; the C4 control is still a fingerprint, not a regeneration |
| **Security & Cryptography** | **8.8 / 10** | The cryptography exceeds what the prompt claims; the 24th route is closed and proven |
| **Code Quality** | **8.2 / 10** | **The fingerprint contract is protected by no test** — demonstrated, not supposed |
| **Regulatory & Standards** | **9.3 / 10** | Six frameworks implemented where the prompt announces four |
| **Verification that runs** | **8.5 / 10** | The schedule exists; no nightly has gone green yet |

---

## 2. This pass's finding: 🟠 C1

**An issue's fingerprint is a data contract, and nothing pins it.**

The prompt has said so from the first day: *"anything entering the fingerprint is a data contract;
changing it resolves and recreates every issue, losing all triage"*. `IssueFingerprintTest` covers
that rule through **relational** properties: the same input fingerprints the same way twice, the
version is excluded, two targets separate, an empty purl falls back to the package name. All true,
all useful.

**None of them survives the question: did the value change?**

I reordered two fields in `IssueFingerprint.of` — `target` and `type` swapped, nothing else:

```java
Digests.sha256Fields(
        input.type().wireName(),          // swapped
        input.target().fingerprintKey(),  // swapped
        input.identifier(), …)
```

`./gradlew :vectispire-common:test --tests '*IssueFingerprint*'` → **BUILD SUCCESSFUL**.

Every relational property still holds: the function is still deterministic, still excludes the
version, still separates targets. And **every fingerprint in the estate has changed**. In
production that commit silently resolves every open issue and recreates it: triage lost,
exemptions lost, review dates lost, with no exception and no log line — and a dashboard that looks
cleaner afterwards.

It is the same shape of defect as `WebhookAuthenticity`, which *does* pin its HMAC vector
(`6e9ef29b…`). Here one is missing.

**Fixed the same day.** One vector — `44c39a41c912df031c920698f4698aa76cdcf27617f2e99f4f6759de1f97851d`
for a fixed input — and the class javadoc reconciled, because it argued *against* stored expected
values. That argument is half right: a *table* of golden hashes pins an algorithm without saying
what matters about it. But its premise — "red on a harmless change" — does not hold here: **there
is no harmless change to this function's output**.

So the test does not exist to forbid the change but to make it deliberate. Its own message says as
much: if it fails, you do not update the constant — you decide whether the estate's fingerprints
are being migrated, and if not, you put the fields back.

Verified both ways: the swap that passed this morning now fails on `ff706b4e…`.

---

## 3. Security — 8.8, and the cryptography is better than its description

What the prompt claims is true, and **incomplete**.

| claimed | measured |
|---|---|
| Argon2id | 19 MiB, **t=2, p=1**, 16-byte salt, 32-byte hash, PHC format — the parameters travel with the hash, so raising the cost later does not invalidate what is stored |
| AES-256-GCM | **12-byte** nonce, **128-bit** tag, **context AAD**, `v2:`-prefixed format |
| *(unmentioned)* | **`SealedEnvelope`: X25519 + HKDF + GCM** — hybrid encryption to an agent's ephemeral key, so the control plane sits outside the secret's trust boundary |

A dossier that undersells its own cryptography is a small problem, but it is one: an external
auditor scores what is written down.

**The 24th route is closed and the closure is proven.** `GET /inventory/versions` now joins the
scan and filters on the `Visibility`. Its test fails when the filter is removed
(`expected:<1> but was:<2>`) — verified by removing it.

**What remains:** `AuthorizationCoverageTest` still works at controller granularity. That is
justified — filtering runs through private helpers no regex follows — but the rule stays coarser
than the defect class it watches.

---

## 4. Code Quality — 8.2

Beyond C1, the tenth pass's remediation holds: `SecurityScorecardService` answers with an indexed
existence check instead of reading every scan, and `syncThreatIntel` filters in SQL and joins in
one batch. The scorecard's third full read remains, **and the code says why** — it asks about the
set of targets the caller may see, which no derived query can express.

### 🟡 C2 — two end-to-end cases cannot fail

`e2e/vex-triage.spec.ts` holds two tests whose entire assertion is:

```ts
const body = page.locator('body');
await expect(body).toBeVisible();
```

A `body` is visible on an error page, on a blank page, on a redirect back to sign-in. Those two
cases count towards "11 browser tests" and verify none of them.

### 🟡 C3 — front-end coverage: 16 pages of 28

Five specs added since the tenth pass, on the pages that *compute*. Twelve pages remain without
one, deliberately: they render an HTTP response as-is, and a test that mounts them proves the HTTP
client works.

---

## 5. Regulatory — 9.3

> **Refined after publication.** This report said "six frameworks implemented where the prompt
> announces four". True, and misleading in the other direction: `ComplianceEngine` switches on
> **the control's category alone** — seven categories — and projects that verdict onto the six
> frameworks. Any two frameworks whose controls share a category therefore receive the **same**
> result, differing only in identifier and wording. There is **one posture evaluator and six
> mappings**, not six engines. Corrected here and in the prompt: "six engines" oversells exactly
> as much as "four" undersells.

`ComplianceFramework` enumerates six frameworks — `NIS_2`, `ISO_27001`, `EU_CRA`, `DORA`,
`PCI_DSS`, `SOC_2` — which is **24 controls**, all evaluated, with the OWASP Top 10 in its own
controller. It is a mapping, and that is what a mapping should be: one posture expressed in each
framework's vocabulary.

What earns the score here is elsewhere, and it reads in `cappedByPlatform`: **a control cannot be
reported compliant on the strength of a mechanism that is switched off**. The javadoc says why —
"compliant" against a control whose mechanism is disabled hands the reader their own diligence
back as a conclusion. And **SPDX is declined and recorded** (ADR-0016) rather than claimed and
absent.

---

## 6. Verification — 8.5

The nightly schedule **exists** — I denied that in the tenth report, by inference rather than
measurement; the correction is visible there rather than edited away.

What remains undemonstrated: **no nightly pipeline has gone green yet**. Both runs on 26 August
were manual and both found real defects, since fixed. The first green nightly will be the proof.

---

## 7. Recommendations

| # | Action | How it was verified |
|---|---|---|
| ✅ 1 | ~~Pin a literal vector in `IssueFingerprintTest`~~ — **done**, `44c39a41…` | measured twice: the swap passed before, it fails now (`ff706b4e…`) |
| 🟡 2 | Give the two VEX cases an assertion capable of failing | measured: their assertion is `body` visible |
| 🟡 3 | Describe `SealedEnvelope` in the security view and in the prompt | measured: X25519+HKDF present, absent from the docs |
| 🟡 4 | Rest the authorization rule on a naming convention for the helpers | argued, not implemented |
| ℹ️ 5 | Read the **duration** of an `integrationTestAll` before believing its green | met in this pass: 549 ms |
