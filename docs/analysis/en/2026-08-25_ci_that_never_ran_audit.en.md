# In-depth audit — the pipeline that has never run

**Date:** 2026-08-25 · **Scope:** the four prompt axes · **Method:** claims verified by running

> **A recommendation from the previous three reports is withdrawn here.** Each of them ended with
> "watch the first nightly run". There will not be one. The repository's only remote is
> `git@gitlab.com:asmolabs_be/vectispire.git` and every workflow lives in `.github/workflows/`;
> there is no `.gitlab-ci.yml`. GitLab does not execute GitHub Actions. Confirmed with the
> maintainer during this pass.

## Scores

| Domain | Score | Movement | What decided it |
|---|:--:|:--:|---|
| Documentation & Architecture | **8.4** / 10 | ↘ from 9.2 | Sixteen ADRs still argue their case and parity holds — but the development view describes a CI pipeline that does not run, and the getting-started guide tells users to verify a signature against a workflow identity that has never signed anything |
| Security & Cryptography | **8.6** / 10 | ↗ from 8.0 | The twenty routes are closed and now genuinely verified; the last unverified guard was found by a route-name sweep rather than by re-reading |
| Code Quality & Architecture | **8.2** / 10 | ↘ from 8.4 | 1250 tests, four unbounded readers left, and the fingerprint is finally unique. Against that: **nothing runs any of it except a person deciding to**, and three assertions this week could not fail |
| Regulatory Compliance | **8.8** / 10 | = | Unchanged and holding |
| **Overall** | **8.5** / 10 | ↘ from 8.6 | |

---

## 1. The finding: the CI does not exist where the code does

**What is verifiable from inside the repository:**

* the only configured remote is GitLab;
* all three workflows — `ci.yml`, `nightly.yml`, `release.yml` — are GitHub Actions;
* there is no `.gitlab-ci.yml`, and none has ever been committed;
* the documentation references `https://github.com/Asmo1973/Vectispire`, so the project has a
  GitHub history it appears to have left.

**What that costs, concretely.** Every guarantee the last seven audits credited to CI is currently
enforced by nobody:

| Believed enforced | Actually |
|---|---|
| 544 documentation links check on every push | Only when somebody runs `scripts/check-doc-links.py` |
| C4 diagrams cannot drift from `workspace.dsl` | Only when somebody regenerates them |
| 1250 unit tests + ArchUnit gate a merge | Only when somebody runs `./gradlew check` |
| Both container images build | Never built by a machine |
| Three-engine campaign, nightly | Never run by a machine |
| Eleven browser cases, nightly | Never run by a machine |

This explains an observation three reports made without explaining it: `nightly.yml` "has never
executed on a runner". It has not, and on the current hosting it never will.

**Two documents assert it as fact**, which is worse than the absence:

* [05 — Development view](../../architecture/bflorat/en/05_development_view.md) opens section 3
  with *"The CI pipeline automatically executes the following verification steps"* and diagrams
  four of them.
* [`GETTING_STARTED.md`](../../en/GETTING_STARTED.md) tells a user to verify a release with
  `cosign verify-blob --certificate-identity "https://github.com/Asmo1973/Vectispire/.github/workflows/release.yml@refs/tags/v1.0.0"`.
  That command pins an identity that has signed nothing. A verification instruction that cannot
  succeed is worse than none: it teaches a user that the check passed the day they mistype it into
  passing.

**This is the highest-value item in the repository right now**, and it is not a refactor: the
workflows already describe what should run. They need a `.gitlab-ci.yml` that runs it, or a
GitLab-side push mirror to GitHub, and the decision between those is the maintainer's.

---

## 2. Security & Cryptography — 8.6

The twenty routes closed in the previous pass hold, and one of them is only now genuinely
verified. **A route-name sweep — every URL literal in the tests matched against every declared
mapping — found that the attestation case asserted `/api/v1/attestation/scans/{id}` where the
route is `/api/v1/attestations/…`, plural.** That assertion returned 404 because the route did not
exist, so the guard on `AttestationController` had never been exercised. It is correct; removing it
now fails the suite.

That is the third assertion this week that could not fail, and the three share a shape worth
naming: **a negative assertion is only as good as the thing it points at.** `isNotFound()` on a
mistyped path, `getIndexInfo(unique = true)` against a driver that ignores the flag, and a scorecard
path that was singular — each passed for a reason unrelated to what it claimed. None was caught by
re-reading; all three were caught by a second test or a mechanical sweep.

Everything else verifies: Argon2id at the OWASP minimum with parameters in the PHC string, the
sandbox flags asserted on the `HostConfig` handed to the daemon, agent isolation by ArchUnit, the
audit chain tested by tampering, SCIM behind an administrator guard, Vault refusing to start rather
than falling back to a local key.

---

## 3. Code Quality & Software Architecture — 8.2

**The fingerprint is unique at last**, and the migration merges rather than deletes: the oldest row
wins, children are repointed before the losers go. The race it closes was real and silent —
reconciliation's `toMap(…, (a, b) -> a)` can only fire on a fingerprint that is already duplicated.

**Whole-table readers: five to four.** The licence inventory took a filter and ignored it in every
read, which mattered more than it looked: a scan row carries its whole SBOM payload, so one
repository's licences parsed the estate's — and the scorecard called the unfiltered form on every
request.

Four remain and each is justified in place: the security overview needs every target, the threat
feed re-evaluates the backlog by design, and the portfolio scorecard reads the licence inventory
whole because that inventory takes a target rather than an allowance.

**The score falls anyway, and the reason is section 1.** 1250 tests, a three-engine campaign,
mutation-verified coverage floors and eleven browser cases are a strong suite by any measure — run
by a person who remembers to. Quality that depends on discipline is quality with a single point of
failure, and this week produced 22 commits' worth of changes that no machine has ever compiled.

---

## 4. Regulatory Compliance & Standards — 8.8

Unchanged since the previous pass and holding: six frameworks, the platform's own posture capping
what it can claim, SPDX decided by [0016](../../architecture/en/decisions/0016-no-spdx-document.md)
rather than claimed, and the aggregate exports now scoped to the caller.

One consequence of section 1 belongs here rather than there: **the CRA's supply-chain story depends
on a release pipeline.** Signed artefacts, an SBOM of the shipped jar, and a verification command a
customer can run are what `CRA-ART10` is about. The code to produce all three exists in
`release.yml`. Nothing runs it.

---

## Recommendations

### 🔴 Now

1. **Decide how this repository gets a pipeline** — a `.gitlab-ci.yml` mirroring what the three
   workflows describe, or a GitLab push-mirror to GitHub so the existing ones fire. Until then
   every other recommendation in every previous report is advice about a machine that is not
   listening.
2. **Correct the two documents that assert the pipeline as fact.** The development view's *"the CI
   pipeline automatically executes"* and the signature-verification command in
   `GETTING_STARTED.md`. A verification instruction that cannot succeed is the worst kind of
   security documentation.

### 🟠 Next

3. **Add the route-name sweep as a test.** It found a guard that had never been exercised, in a
   suite written specifically to exercise guards. A test asserting that every URL literal in the
   test tree matches a declared mapping would have caught all three of this week's vacuous
   assertions.
4. **Give the portfolio scorecard's licence read an allowance** rather than filtering its result.
   It is the last place where a filter is applied after the query rather than in it.

### 🟡 Then

5. **Front-end unit coverage**: fifteen specs against twenty-seven pages.
6. **Revisit `GateService.openIssuesByTarget`** if the overview ever needs to scale — it is
   justified today because the screen shows every target, and that stops being true the moment the
   screen is paginated.
