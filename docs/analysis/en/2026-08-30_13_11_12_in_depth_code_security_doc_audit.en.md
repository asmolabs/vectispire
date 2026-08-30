# In-depth audit — code, security, documentation

**30 August 2026, 13:11** · *Version française : [`2026-08-30_13_11_12_audit_approfondi_code_securite_doc.fr.md`](../fr/2026-08-30_13_11_12_audit_approfondi_code_securite_doc.fr.md)*

## Overall score: **8.4 / 10** — down from 8.7

**The drop is entirely mine, and from one audit ago.** Yesterday's audit concluded **10.0** on the
verification axis after reading the GitHub history. It read `verify` and `nightly`, which are green,
and did not ask whether the **other two** workflows had ever run. They have not: `docs` failed on
its only run, and **`release.yml` has never been triggered** — 0 tags, 0 releases, absent from all
19 runs. That is "an earlier audit scored what it had not measured", and the earlier audit is mine,
fifteen hours old.

**The headline finding is a gap between what the documentation promises of a release and what the
workflow produces.** `GETTING_STARTED` §8 announces, in both languages, *"four files: the jar, its
SBOM, and a Sigstore bundle for each"*. `release.yml` produces **two**, never mentions an SBOM, and
**creates no GitHub Release at all**: it uploads a workflow artifact with 90-day retention. That
same file's header warns against exactly this family of defect.

| Domain | Score | Movement |
|---|---|---|
| Documentation & Architecture | **8.0** | ↓ |
| Security & Cryptography | **8.5** | = |
| Code quality | **8.5** | ↑ |
| Compliance & Standards | **8.5** | = |
| **Verification that actually runs** | **8.5** | ↓↓ |

---

## 0. Remediation status — four of the seven recommendations are done

*Added after the audit. Verification: **1327 JVM tests** (1326 plus the redirect case), **0
failures**; checkov **380 Actions checks, 0 failures**; **774 links, 0 broken**.*

| # | Recommendation | Done by | Proof |
|---|---|---|---|
| 2 | Reconcile `GETTING_STARTED` §8 with the workflow | **The workflow, not the text.** `release.yml` now produces the SBOM of the signed jar (syft, at the digest `ci.yml` pins), signs **both** files and **verifies both** before publishing. The "four files" sentence becomes true: jar, its bundle, SBOM, its bundle. | `grep -ci sbom release.yml` → **12** (was 0); checkov parses and validates |
| 3 | Publish a real GitHub Release | `gh release create` on the tag, with all four files and the certificate identity in the notes. `permissions: contents: write`, commented in place as the only workflow that writes. **Guarded behind `if: startsWith(github.ref, 'refs/tags/')`**: the rehearsal runs from a branch and must publish nothing, which is what "publishes nothing" always meant. | checkov 0 failures; the 90-day artifact stays, so the rehearsal leaves something to inspect |
| 5 | Update `ROTATION_AND_PURGE` | Blockquote rewritten in both languages: the forge is GitHub, verified by `git remote -v`, and **the remaining action concerns the old repository, not the current one — two different repositories, not a rename**. §2.1 now carries the table of what was measured, and says why an unauthenticated 404 still settles nothing. | `grep -c 'remote is now GitLab'` → **0** in both files |
| 7 | Keep the redirect probe | `PinnedHttpSenderTest` carries a fifth case: a real server answers `302 Location:` to an unchecked host, and the test requires the 302 not to be followed. | **Removing `disableRedirectHandling()` fails that case** — it failed no test before |

### What the remediation taught

**§2 had two possible directions and the right one was the more expensive.** Correcting the text to
say "two files" was honest and immediate; producing the SBOM makes the sentence true and gives the
consumer the signed component list they read to decide whether an advisory applies to them. An
unsigned SBOM is a list anybody can rewrite, and it is the one file in the release whose content is
a claim about the rest.

**§3 reopened a permissions question.** `release.yml` carried `contents: read`, with this comment:
*"every other workflow in this repository is read-only"*. Publishing a release requires
`contents: write`. The comment was rewritten in place rather than deleted: this is exactly the kind
of widening that should be readable in the diff.

### What remains, and why

| # | Recommendation | Why it is not done here |
|---|---|---|
| 1 | Trigger `release.yml` | Needs `gh auth` and signs in the project's name — an outward action, not mine to take |
| 4 | Commit and push | The commit is ready; publishing is yours |
| 6 | Enable GitHub Pages | A repository setting requiring admin rights on `asmolabs/vectispire` |

**All three need your credentials or your decision, not code.** And it has to be said plainly: until
#1 is done, the signing path remains **asserted and not executed**. What the remediation changes is
what that path will do when it runs — it does not make it run.

---

## 1. What I executed

| Control | Command | Result |
|---|---|---|
| JVM suites, cold | `./gradlew build --rerun-tasks` | **1326 tests, 0 failures, 0 errors, 0 skipped** (260 suites, 35 tasks) |
| Multi-engine campaign | `./gradlew integrationTestAll --rerun-tasks` | **PostgreSQL 29, MySQL 29, SQLite 29 — 87 tests, 0 failures** |
| Containers at runtime | `:vectispire-common:integrationTest --rerun-tasks` | **14 cases, 0 failures**, live daemon |
| Browser suite | `npx playwright test` | **13 passed** in 2.2 min, real control plane |
| Restore drill | `bash scripts/restore-drill.sh` | **passed**, built-in mutation included |
| Angular suites | `npm test` | **146 tests, 23 files, 0 failures**, plus the i18n check: 54 keys, 2 bundles |
| `gitleaks` | pinned CI image | **377 commits, 16.1 MB, no leaks** |
| Dockerfile / Actions policy | pinned checkov image | **260 + 372 = 632 checks, 0 failures** |
| Relative links | `python3 scripts/check-doc-links.py` | **754 links, 0 broken** |
| C4 drift | `shasum -a 256` vs `.workspace.sha256` | **in step** |
| Bilingual parity | `find docs/{fr,en}` | **12 / 12**; ADRs **18 / 18**; bflorat **6 / 6** |
| Agent isolation | `:vectispire-agent:dependencies` | **0** JDBC / Hibernate / Flyway / JPA; `ENCRYPTION_KEY` absent from `src/main` |
| Compliance, by count | `grep -c` over the catalogue | **6 frameworks, 24 controls, 7 categories, 3 caps** |
| **GitHub run history** | public API | **19 runs** — see §3.1 and §4 |
| **Releases and tags** | `git tag`, `/releases` API | **0 and 0** — `release.yml` has never run |
| **Purge runbook** | its own commands, executed | see §3.2 |
| Branch gap | `git rev-list --count origin/main..develop` | **0** |
| Working tree | `git status --short` | **21 uncommitted files** — see §3.5 |

### A note on the prompt itself

`PROMPT_AUDIT.md` §5 describes `.gitlab-ci.yml` as *"the pre-move pipeline, kept and unmaintained"*.
**The file no longer exists** — removed by `3668dfe`. The prompt explicitly asks not to take that
paragraph on trust; checked, and it is right to ask.
`ci/gitlab/vectispire-gate.gitlab-ci.yml`, the template shipped to customers, is present and
remains valid.

---

## 2. Testing my own tests

Three mutations, all reverted, on rules this series had never mutated.

| Mutation applied | Expected | Observed |
|---|---|---|
| A class in `core` building its own `HttpClient` — the "seventh caller" the SSRF rule forbids | failure | **`ArchitectureTest` fails** — *"an outbound call goes through the door that validates and pins"*, 6 violations |
| `ComplianceEngine`: `cappedByPlatform` removed from the evaluation loop | failure | **3 tests fail** — secrets without a key, audit without a mirror, governance without four-eyes |
| `SealedEnvelope`: the ephemeral key removed from the AAD | failure | **1 test of 11 fails** — and not the one you would expect, see below |
| `PinnedHttpSender`: `disableRedirectHandling()` removed | failure | **no test fails** — all 1326 pass, see §3.4 |

### What the third mutation teaches

The test `refusesAnEnvelopeWhoseEphemeralKeyWasReplaced` carries this comment: *"The sender's key is
associated data, so swapping it has to fail authentication"*. **It does not fail when the AAD is
removed.** It passes for a different reason: swapping the ephemeral key changes the X25519 shared
secret, hence the session key, so GCM fails anyway. The AAD is a third belt over an already
double-fastened brace.

What does catch the removal is `anEnvelopeSealedByAnEarlierBuildStillOpens` — a **pinned literal
vector**. That is the **third** occurrence of this pattern in the project, after `IssueFingerprint`
and `SecretCipher`, and all three times it is the one holding the contract while the property tests
stay green. It deserves naming as a project pattern rather than as three coincidences.

---

## 3. Findings

### 3.1 🔴 The documentation promises four signed files; the workflow produces two, has no SBOM, and has never run

**Executed.** Three independent measurements, all agreeing.

```
git tag | wc -l                                   →  0
GET /repos/asmolabs/vectispire/releases           →  0 releases
GET /actions/runs (19 runs)                       →  release: absent
grep -ci 'sbom\|cyclonedx' .github/workflows/release.yml  →  0
grep -cE 'gh release|softprops|create-release'    →  0
```

**What the documentation says.** [`docs/en/GETTING_STARTED.md:161`](../../en/GETTING_STARTED.md) and
[`docs/fr/GETTING_STARTED.fr.md:186`](../../fr/GETTING_STARTED.fr.md), identically:

> *Each release carries four files: the jar, its SBOM, and a Sigstore bundle for each. Verify before
> running anything — a security tool you took on trust is a contradiction.*

**What the workflow does.** [`release.yml`](../../../.github/workflows/release.yml), final step:

```yaml
      - uses: actions/upload-artifact@…
        with:
          name: release
          path: |
            ${{ env.JAR }}
            ${{ env.JAR }}.cosign.bundle
          retention-days: 90
```

**Two** files. No SBOM is generated or signed anywhere in this workflow — the `sbom` job exists, but
in `ci.yml`, and its artifacts never reach a release. And there is **no GitHub Release at all**: a
workflow artifact is downloadable only by somebody signed in who can find the run, and it expires
after 90 days.

**Three false statements, then, in the section that teaches the reader to take nothing on trust:**
the file count, the existence of a signed SBOM, and the distribution channel.

**Why this is the heaviest finding.** `release.yml`'s own header warns against precisely this
defect, knowingly:

> *This project has already shipped documentation telling users to verify against an issuer that was
> not the one signing — an instruction that cannot succeed, which is worse than none: it teaches its
> reader that the check passed the day they mistype it into passing.*

And further down, on the verify step: *"this step is what makes the instruction in GETTING_STARTED a
tested claim rather than a hopeful one"*. That sentence is itself asserted and not executed: the
`workflow_dispatch` exists precisely as the rehearsal, and it has **never** been dispatched.

**What is right and must not be undone.** The `GETTING_STARTED` command is correct in shape: it pins
the workflow file **and** the tag in `--certificate-identity`, requires
`--certificate-oidc-issuer`, and uses a `--bundle`. The three paragraphs explaining why each part
matters are sound. It is the scenery around it that describes something other than what exists.

**Recommendation, in increasing order of cost.**
1. Trigger `release.yml` through `workflow_dispatch` — its stated reason for existing — so the
   signing path has run once before anything depends on it.
2. Correct the sentence in both `GETTING_STARTED` files to say two files, or add the SBOM and its
   signature to the workflow so the sentence becomes true. The second is better; the first is honest
   immediately.
3. Publish a real GitHub Release (`gh release create`) rather than a retention-bound artifact, or
   §8's procedure has no file to verify.

**Verification: executed** — commands above.

### 3.2 🟠 A security runbook points its reader at the wrong forge, and declares impossible a check that no longer is

**Executed.** [`docs/en/ROTATION_AND_PURGE.md:116`](../../en/ROTATION_AND_PURGE.md) and
[`docs/fr/ROTATION_AND_PURGE.fr.md:116`](../../fr/ROTATION_AND_PURGE.fr.md) carry the same
blockquote:

> *The project's remote is now GitLab, so anybody repeating the procedure needs GitLab's
> equivalent — its support request, its fork check.*

`git remote -v` → `git@github.com:asmolabs/vectispire.git`. **The remote is GitHub.** This document
is the only one in the tree still carrying that claim: grepping every `docs/*.md`, `README*.md` and
`SECURITY.md` returns only these lines, every other GitLab mention being a legitimate customer
integration. `GETTING_STARTED.md:186` in fact says correctly *"the project moved from GitLab to…"*.

**And §2.1 declares its own check impracticable:**

> *These commands could not be run conclusively here: `gh` is not authenticated on this machine and
> the repository is private, so the 404s obtained mean nothing.*

The repository **is no longer private**. Run today:

| Check | Result |
|---|---|
| `GET /repos/asmolabs/vectispire` | `visibility: public`, `forks_count: 0`, `network_count: 0`, created **2026-08-27** |
| The five old SHAs against the **current** repository | **422** × 5 — objects absent |
| `git rev-list --objects --all \| grep -iE '\.sqlite\|id_rsa\|\.pem$'` | **empty**, over 391 commits |
| `gitleaks` over 377 commits | **no leaks** |

**What that settles and what it does not.** The current repository is clean: created on 27 August,
carrying no artefact of the incident, with no forks. The open question in §2 concerns the **old**
repository `Asmo1973/Vectispire`, which answers 404 unauthenticated — and the document is right that
an unauthenticated 404 proves nothing. The action stays open; it is the facts around it that have
rotted.

**Why this is more than a typo.** This is a document describing a credential exposure whose sole
function is to point somebody at a remaining action. A reader following it today goes looking for a
GitLab support form for a project hosted on GitHub, on the strength of a sentence in the present
indicative.

**Recommendation.** Update the blockquote — the forge is GitHub, the current repository is public and
clean, and the remaining action concerns the old one — and replace §2.1 with what was measured here.
Keep the body of the procedure as it stands: the document is right not to rewrite an account into an
instruction. **Verification: executed.**

### 3.3 🟡 The fourth workflow still fails, and the site it publishes does not exist

Reported yesterday as an addendum, **unchanged and re-checked today**:

```
GET /repos/asmolabs/vectispire/pages   →  404   (Pages not enabled)
GET https://asmolabs.github.io/vectispire/  →  404
```

`docs` #1, 29 August 19:31 UTC, remains the workflow's only run and remains a failure at the
`actions/configure-pages` step. [`mkdocs.yml:1`](../../../mkdocs.yml) (and `site_url:` on line 16)
and [`.github/workflows/docs.yml:1`](../../../.github/workflows/docs.yml) still announce the site in
the present tense. It is a repository setting requiring admin rights — deliberately not done here.

### 3.4 🟡 Redirect refusal can be removed with no test moving — but the second belt holds

**Executed, and the result corrects what I was looking for.** Removing `.disableRedirectHandling()`
from [`PinnedHttpSender`](../../../vectispire-java/vectispire-core/src/main/java/com/asmolabs/vectispire/core/services/PinnedHttpSender.java)
leaves **all 1326 tests green**. `PinnedHttpSenderTest`'s four cases cover DNS pinning thoroughly and
none covers redirect refusal, which the code nonetheless asserts in bold.

**I assumed an SSRF hole and the measurement said no.** A probe written for the occasion: an
"approved" server answering `302 Location:` to a second server on an unchecked host.

| Configuration | Probe result |
|---|---|
| Shipped code | `status=302`, empty body — redirect not followed |
| Redirects re-enabled | **refused** — *"the request tried to reach a host that was never checked (elsewhere.invalid was not the checked host (approved.invalid))"* |

The pinned resolver catches what the disabled redirect would have let through, exactly as its javadoc
announces — *"a redirect somebody re-enabled"*. **This is defence in depth, claimed and now
measured.**

**What remains is minor and worth stating**: the outer layer leaves without a sound. A case that
issues a real 302 to an unchecked host and asserts the redirect is not followed costs fifteen
lines — the probe above, kept rather than thrown away. **Verification: executed.**

### 3.5 🟠 All of yesterday's remediation is uncommitted, so no runner has seen it

**Executed.** `git status --short | wc -l` → **21**. `git rev-list --count origin/main..develop` →
**0**.

This morning's nightly (#2, 30 August 08:29 UTC) ran on `dfbd7f8f`, the shared head of `main` and
`develop`. It therefore did **not** execute: the read-cost sweep `ReadCostSweepTest`, the three fixes
it guards (EPSS, scorecard, attack paths), the `check-i18n-keys.mjs` check, or the translated
provider labels.

This is not a product defect; it is precisely the gap this axis measures. A guarantee that has run
only on a workstation is stronger than a file re-read and weaker than a green pipeline.
**Recommendation:** commit and push. It costs nothing and moves four controls from "executed here"
to "executed on the runner".

---

## 4. What is verified sound

- **The pipeline that does run, runs well.** `verify` #16 on `main`: ten green jobs — `c4-drift`,
  `secrets`, `jvm`, `dockerfile-policy`, `npm-audit`, `frontend`, `links`, `images`, `sbom`,
  `vulnerabilities`. `nightly` has fired **twice from `main`**, green both times, the second this
  morning on the current head; its four jobs — `e2e`, `dockerfiles`, `restore`, `databases` —
  passed. Across 19 runs: 12 successes, 4 cancellations (concurrency), 3 failures, being the two
  first porting runs and `docs`.
- **The SSRF rule is architectural and it bites.** See §2. Only three classes may hold an HTTP
  client, the rule is written against the full name so anonymous classes are covered, and a fourth
  class fails it immediately.
- **Compliance capping is covered.** All three arms — secrets without a key, audit without a mirror,
  governance without four-eyes — fail a test each when removed. A control is never reported compliant
  on the strength of a switched-off mechanism, and that is tested.
- **Compliance, by count.** 6 frameworks, **24** `new ComplianceControl`, **7** categories in
  `evaluateControl`, **3** caps. "One posture evaluator, six mappings" is exact.
- **Encryption in transit.** `SealedEnvelope`: 11 cases, X25519 + HKDF + GCM, `sealed:v1:` prefix,
  one ephemeral key per envelope. Two seals of the same secret differ — verified.
- **Agent isolation.** 0 JDBC drivers, 0 Hibernate, 0 Flyway, 0 JPA on the runtime classpath;
  `ENCRYPTION_KEY` appears nowhere in `vectispire-agent/src/main`.
- **Clean history.** 391 commits, no `.sqlite`, no private key, no gitleaks finding.
- **Portability.** 87 tests across three engines; `SchemaParityIntegrationTest` green on all.
- **Documentation.** 754 links 0 broken, C4 in step, 12/12 per language, ADRs 0001→0017 in both
  languages, 6/6 bflorat views per language.
- **The read-cost sweep, auditing my own work of yesterday.** It runs inside the 1326, it enumerates
  Spring's route table rather than a list, and it counts entities **and** queries.

---

## 5. Verification that actually runs — 8.5, and why the score falls from 10.0

**The ground did not get worse.** Nothing stopped working between last night and today; `verify` and
`nightly` are exactly as green. What changed is that I asked a question I had not asked.

Yesterday's addendum read the history, found the two workflows it looked at green, and concluded
10.0 — *"every control the project claims is present and fires and passes"*. There are **four**
workflows. The other two:

- **`release.yml` has never been triggered.** It is the workflow that signs what users run, and the
  only one carrying `id-token: write`. Zero runs, zero tags, zero releases.
- **`docs` failed on its only run**, and will fail the next for the same reason.

A guarantee that is not executed is not a guarantee. A release's signing path — build, jar named
after the tag, cosign, verification with the user's own command — is entirely asserted and entirely
unexecuted. 8.5 is what two green workflows out of four are worth, when the most critical of them has
never started.

**And §3.5 has to be added to it**: yesterday's remediation is on no runner.

---

## 6. Recommendations, by priority

| # | Finding | Action | How it was verified |
|---|---|---|---|
| 1 | §3.1 | Trigger `release.yml` through `workflow_dispatch` — the rehearsal its own comment describes | **Executed** — 0 runs of 19, 0 tags, 0 releases |
| 2 | §3.1 | Reconcile `GETTING_STARTED` §8 with the workflow: either two files in the text, or the SBOM and its signature in the workflow | **Executed** — `grep -ci sbom release.yml` → 0, the upload step lists two paths |
| 3 | §3.1 | Publish a GitHub Release rather than a 90-day artifact, or §8 has nothing to verify | **Executed** — no release action in the workflow |
| 4 | §3.5 | Commit and push the 21 files, so the sweep and the three fixes run on a runner | **Executed** — `git status`, `git rev-list` |
| 5 | §3.2 | Update the blockquote and §2.1 of `ROTATION_AND_PURGE` in both languages | **Executed** — `git remote -v`, repo API, five SHAs, history |
| 6 | §3.3 | Enable Pages (`source: GitHub Actions`) then re-run `docs`, or correct the sentence in both files | **Executed** — Pages API 404, site 404 |
| 7 | §3.4 | Keep the redirect probe as a test case | **Executed** — mutation, 1326 green; probe, refused by the pin |

---

## 7. What this audit could not measure

- **The release path, end to end.** Triggering it would publish or sign in the project's name; that
  is an outward action I did not take. All of §3.1 is configuration reading and API querying, not an
  execution of the workflow.
- **`gh` is not authenticated.** Every forge figure in this report comes from the public API. That is
  enough for runs, tags, releases, Pages and the current repository's forks; it is not enough to rule
  on the **old** `Asmo1973/Vectispire`, whose 404 stays ambiguous — exactly what the runbook's §2.1
  already says.
- **Scale.** Read cost is measured at 220 issues on SQLite.
- **The agent, end to end.** Isolation proven by classpath; no agent process was started.
- **Jib image build** — unchanged, blocked on an unauthenticated Docker Hub pull.

---

*Working tree: this audit added a probe class and a redirect probe and then removed both, and applied
four temporary mutations, all reverted. `git status` shows the same **21** files as at the start —
the previous audit's remediation, still uncommitted. The final `./gradlew build --rerun-tasks`
executed all 35 tasks cold: 1326 tests, 0 failures.*
