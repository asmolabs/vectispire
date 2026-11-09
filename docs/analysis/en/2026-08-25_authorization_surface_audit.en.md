# In-depth audit — the authorization surface, and what closing it broke

**Date:** 2026-08-25 · **Scope:** the four prompt axes · **Method:** claims verified by running;
this pass also audits the four fixes made since the previous report

## Scores

| Domain | Score | Movement | What decided it |
|---|:--:|:--:|---|
| Documentation & Architecture | **9.2** / 10 | ↗ from 9.0 | Sixteen ADRs, all argued; the register absorbed a new decision cleanly. Still nothing checks a published figure against the constant it names |
| Security & Cryptography | **8.0** / 10 | ↘ from 8.8 | Every named control is real, and Argon2id, SCIM, Vault and the audit chain all verify. **Twenty routes had no authorization at all**, one of them a privilege bypass, and the score follows the discovery rather than the repair |
| Code Quality & Architecture | **8.4** / 10 | ↗ from 7.8 | Whole-table readers down from twelve to five, each remaining one justified in place. The container scorecard was missed in its own fix and caught by re-sweeping |
| Regulatory Compliance | **8.8** / 10 | ↗ from 8.2 | SPDX decided rather than dropped ([0016](../../architecture/en/decisions/0016-no-spdx-document.md)), the SBOM endpoint describes what it serves, and the CRA control never over-claimed in the code |
| **Overall** | **8.6** / 10 | ↗ from 8.5 | |

**The security score falls while the security posture improves, and that is deliberate.** Twenty
routes accepted any authenticated caller; they are fixed, and the fix is verified by mutation. But
a score is a statement about what is known, and what this pass learned is that the authorization
surface had never been swept — six audits scored it on the controllers that happened to be read.
Scoring 8.8 again would say the gap was never there.

---

## 1. Documentation & Architecture — 9.2

Sixteen ADRs, all carrying their argument, and the register took the new one without a seam:
[0016](../../architecture/en/decisions/0016-no-spdx-document.md) records that CycloneDX with
embedded VEX is the generated SBOM and that SPDX 2.3 is not produced. It is worth reading as a
model of the form the register now holds itself to — it names what would have to change for the
decision to reverse (SPDX 3.0's security profile, or a customer's procurement requirement) rather
than only what was chosen.

Bilingual parity holds: no orphan in either tree, heading-for-heading agreement in the chapters and
the Florat views, and the C4 model still names exactly the five pinned scanner images.

**The gap is unchanged and is a process one.** Link checking and C4 drift run in CI. Nothing
compares a published number against the constant it names — which is how `2.0 vCPUs` survived for
weeks in a security document while no code applied a CPU limit. That finding is closed; the
mechanism that let it happen is not.

**The prompt this audit answers is itself slightly stale**, and it is the instrument, so it is
worth saying: it still lists SPDX 2.3 among supported formats, which [0016](../../architecture/en/decisions/0016-no-spdx-document.md)
retired; it says "no Docker socket mounted" where the truth is that *scanners* get none while the
control plane and the agent do — which is the whole reason the sandbox matters; and it names
`verifyIntegrity`, where the method is `verify()`.

---

## 2. Security & Cryptography — 8.0

### What verifies

| Control | Verified how |
|---|---|
| Argon2id | 19 MiB, t=2, PHC string format — the OWASP minimum, parameters travelling with the hash so they can be raised without invalidating stored passwords |
| Scanner sandbox | `ContainerHardeningTest` captures the `HostConfig` handed to the daemon and asserts `cap_drop ALL`, `no-new-privileges`, read-only root, network mode, memory, PID cap **and the CPU share** — added this week, after the document had claimed one for weeks and no code applied it |
| Agent isolation | ArchUnit forbids JDBC, JPA, Spring Data, Flyway and Liquibase in the agent module, with a non-empty-import guard |
| Audit chain | Two suites **mutate a stored row** and assert the chain reports it |
| SCIM 2.0 | `@RequiresAdministrator` on the provisioning controller |
| Vault KMS | `VaultKmsProvider` exists, is tested, and `EncryptionService` **refuses to start** when `kms.type=vault` is set and the endpoint or token is missing — a misconfiguration that silently fell back to a local key would be the worst of both |
| Rate limiting | Three credential-presenting endpoints, per-address bucket, now configurable, and the account throttle answers with the same `Retry-After` contract |

### The finding: twenty routes never asked who was calling

Prompted by the blast radius applying no `Visibility` at all, the whole controller surface was
swept route by route. `Visibility`'s own documentation says authorization spread across nine
controllers is nine chances to forget one, and that the forgotten one is the hole. It had been
forgotten twenty times, in three shapes.

**Five let an ordinary account change or destroy platform state.** They carried
`@RequiresAccount`, which every signed-in account satisfies — including `ROLE_USER`. The worst is
documented in its own OpenAPI summary as *"atomically deletes all endpoints and contracts across
the entire platform"*. Also reachable: ingesting a VEX document, which says "not affected" and
therefore silences findings estate-wide — the decision the four-eyes workflow exists to make
expensive when a human takes it through the interface.

**Six handed target-scoped data to whoever asked**, including four that export the *same scan* the
SBOM route has always guarded. Which document a caller requested decided whether the check
happened.

**Eight aggregates answered with the estate**, and one of those was not a visibility leak but a
**privilege bypass**: the certified evidence bundle contains the complete audit log, and
`/api/v1/audit-log` has always required a security lead while the bundle required a session. The
same data behind two doors with two different locks.

### What closing it broke, which this audit also found

**The interface still offered four controls the server now refuses.** The compliance page's VEX
import and evidence-bundle export, the EPSS synchronisation, and the notification test were
rendered for every account and none of those pages consulted the session's role. A button that
answers 403 tells a reader the product is broken rather than that the action is not theirs.

Fixed in the same pass, using the `isSecurityLead` computed that already existed in
`SessionStore`. The eleven browser cases still pass. **This is the shape of thing a security fix
produces and a security review misses**: the server and the interface were consistent before —
consistently wrong — and tightening one half without the other trades a vulnerability for a defect.

---

## 3. Code Quality & Software Architecture — 8.4

**Whole-table readers: twelve at the last audit, five now**, and each survivor is justified where
it sits.

| Remaining | Why it stays |
|---|---|
| `GateService.openIssuesByTarget` | The security overview shows every target; reading every target's issues is the question |
| `LicenseGovernanceService` ×2 | `@RequiresSecurityLead`, so no leak; the read is still unbounded and is the next candidate |
| `ThreatIntelFeedService` | The feed sync re-evaluates the backlog by design — a maintenance pass, not a per-caller read |

**One was missed inside its own fix.** The repository scorecard was narrowed and the container
scorecard, twenty lines below it, was not. Reading the diff did not catch it; re-running the sweep
did. That is the argument for sweeping by pattern rather than judging call sites one at a time,
and it applies to the person who wrote the pattern as much as to anybody else.

The layer rule, the scanner return-type contract enforced by reflection, the three-engine campaign
and the mutation-verified coverage floors all hold. 1249 unit tests; twenty-four of forty-one
controllers now resolve a `Visibility`, against roughly thirteen this morning.

**The front end is now genuinely covered by its E2E suite**, which is new: eleven cases, all
passing, running serially because they share one account and one address with the server's
anti-brute-force counters. Fifteen Angular unit specs against twenty-seven pages remains thin.

---

## 4. Regulatory Compliance & Standards — 8.8

Six frameworks — `NIS_2`, `ISO_27001`, `EU_CRA`, `DORA`, `PCI_DSS`, `SOC_2` — with the platform's
own posture capping the score it can claim: no encryption key caps secrets management at 60, no
audit mirror caps logging at 70, no four-eyes caps governance at 75. The cap only lowers.

**SPDX is now decided rather than quietly claimed.** The previous audit found it listed in four
documents and produced nowhere. [0016](../../architecture/en/decisions/0016-no-spdx-document.md)
records the reasoning: SPDX 2.3 has no vulnerability model, so an export would be the CycloneDX
inventory with the triage removed, under a second name. The SBOM endpoint's description now names
Syft's native JSON, which is what it has always served.

CycloneDX, CSAF, OpenVEX, EPSS and reachability are real, reachable — **and now scoped**, which
they were not: the three `aggregate.json` exports named every CVE on every target to any account.

---

## Recommendations

### 🔴 Now

1. **Watch the first nightly run.** `nightly.yml` has still never executed on a runner. The
   three-engine campaign, both Dockerfile images and the eleven browser cases all run for the first
   time tonight, against a week of changes. Green locally is not green on a cold runner.
2. **Re-read the four newly guarded routes with fresh eyes**, or have somebody else do it. They
   were changed and tested by the same person who found them, which is the weakest link in this
   whole week of work.

### 🟠 Next

3. **`LicenseGovernanceService`**, the last unjustified whole-table reader. No leak — the
   controller requires a security lead — but two full reads of `t_component` and `t_finding` on a
   page.
4. **Make `fingerprint` unique**, with a migration that first reports the duplicates it would
   break. The index is already there; uniqueness is the invariant.
5. **Check published figures against the constants they name.** A test reading
   `ScannerLimits.DEFAULT` and asserting the dimensioning view quotes it would have caught
   `2.0 vCPUs` the day it became wrong — and would now keep the corrected figures honest.

### 🟡 Then

6. **Give the front end unit coverage.** Fifteen specs against twenty-seven pages, with the E2E
   suite carrying the load at eleven cases.
7. **Correct `PROMPT_AUDIT.md`**, which is the instrument these audits run on: SPDX is retired,
   the Docker socket statement is imprecise, and `verifyIntegrity` is called `verify()`.
8. **Consider a route-coverage test** that fails when a new controller serving target-scoped data
   resolves no `Visibility`. The sweep found twenty; nothing stops the twenty-first.
