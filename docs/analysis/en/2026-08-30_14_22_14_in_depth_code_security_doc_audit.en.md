# In-depth audit — code, security, documentation

**30 August 2026, 14:22** · *Version française : [`2026-08-30_14_22_14_audit_approfondi_code_securite_doc.fr.md`](../fr/2026-08-30_14_22_14_audit_approfondi_code_securite_doc.fr.md)*

## Overall score: **7.8 / 10** — down from 8.4

**The ground did not get worse. What changed is where the ground is.** The 13:11 audit fixed four
real things and committed them. Three hours later those five commits are on `develop` and **`main`
does not have them**. `main` is the default branch, which is the only branch GitHub fires a
scheduled workflow from: this morning's nightly, green, certified the tree *before* the fixes. The
remediation is written; it is not in force.

And the run that should have caught up was still going: the `verify` run for the tip of
`develop` sat `in_progress` for three hours. I first wrote that up as a hang; **it was not one —
it finished successfully in 67.3 minutes**, and running that long on every push turned out to be
the more interesting fact. See §3.2, which is a correction as much as a finding.

| Domain | Score | Movement |
|---|---|---|
| Documentation & Architecture | **7.5** | ↓ |
| Security & Cryptography | **8.0** | ↓ |
| Code quality | **8.5** | = |
| Compliance & Standards | **8.5** | = |
| **Verification that actually runs** | **6.5** | ↓↓ |

**Two of the five drops are "an earlier audit scored what it had not measured", and I say so
because that distinction is the point of the prompt.** The unpinned `cosign` fetch has been there
since the 27 August port (`8b56333`): four audits read it without seeing it. The README's "four
engines" has contradicted ADR 0014 since 25 August: five audits checked bilingual parity *by
counting files* without ever reading what the two files said.

---

## 0. Remediation status — five of the eight recommendations are done

*Added after the audit. Cold verification: **1328 JVM tests** (1327 + the AAD case), **0
failures**; **146 Angular tests**; checkov **260 + 384 = 644 checks, 0 failed**; **779 links, 0
broken**; `check-doc-facts.py` **23 numeric claims, 0 contradicted**.*

| # | Recommendation | Done by | Evidence |
|---|---|---|---|
| 2 | Bound the jobs, and fix what made one slow | **All seventeen jobs across all four workflows** carry a `timeout-minutes` — `release.yml` and `docs.yml` had none either. But a ceiling alone would only have turned run #17 red, so the **container-per-probe loops are gone too**: the database wait is now a `docker exec` into the running container, and the health probe is one container that retries internally instead of up to 90 that each retry once. Both bounds are wall-clock now, so the log and the ceiling share a unit. | `yaml.safe_load` over all four files: **0 jobs without `timeout-minutes`**. The probe was exercised locally on all three paths: healthy → **0**, nothing listening → **1** at the deadline +1 s, API-but-no-interface → **2**. The `exec` wait completed in **6 s** locally — and on the runner, **run #21 ran `images` in 2.4 min against 67.3** |
| 3 | Pin and verify `cosign` | Version **v3.1.3** — what `latest` resolved to at pinning time, so no behaviour changes — and digest `4629c757…` verified by `sha256sum -c` **before** `install`. Downloaded to `/tmp` rather than straight to `/usr/local/bin`: writing first and checking after leaves an unverified executable on `PATH` in the window between the two. | The digest was **obtained and then re-verified by actually downloading the binary**; checkov re-parses and passes |
| 6 | "four engines" and "840 tests" | **The README now says two deployable engines and a fixture, citing ADR 0014.** The test count is *removed* rather than corrected: a number that moves with every commit is the wrong kind of fact to write in prose. And parity now extends to figures — see below. | `grep -niE "four engines\|all four\|840"` → **0**; both READMEs cite 0014 |
| 7 | The i18n rule | **The floor of 40 becomes an exact count of 54**, plus a **ratchet** at 89 on hard-coded labels. A ratchet rather than a ban: `src/app` holds 89 across 14 files, and a rule that fails on its first run is a rule that gets switched off. | **Putting the two hard-coded labels back fails `npm test`, exit 1** — it went green this morning. The ratchet fires on its own: one label added without touching any key → **90 > 89, exit 1** |
| 8 | `SealedEnvelope`'s AAD | A case that **re-derives the session key independently** — same X25519 agreement, same HKDF salt — then decrypts the bytes `seal` produced twice: with the ephemeral key as AAD, then without. Same key, same nonce, same bytes; only the AAD varies. The neighbouring test's comment now says why it did not prove what its name announces. | Before: emptying the AAD failed **1 test out of 701**, the golden vector. After: **2 out of 702**, including the one named after the property |

### What the remediation taught

**The rule that checks documentation found a live defect on its first run, in the other
direction.** `scripts/check-doc-facts.py` was written for "four engines" — an oversell. It
immediately flagged `COMPLIANCE_AND_REGULATORY`, **in both languages**: *"five major
international regulatory frameworks"* above a list of **six**, and the evidence bundle naming
only five, SOC 2 dropped. Seven stale claims across four files, including "20 controls" against
24. §4 of the prompt says it exactly: underselling costs as much as overselling.

**And the first version of that rule was bad, which is the most useful thing here.** It demanded
equality on any number near "engines": **seventeen false positives**, because `un moteur` is a
French article and `0014-two-engines` inside a link target reads as a claim of fourteen engines.
Two corrections followed — read only the prose (fenced blocks and link targets blanked, offsets
preserved so line numbers stay true), and treat engines as a **ceiling** rather than an equality,
since that defect only ever inflates. A rule that cries wolf gets an exemption list, then gets
ignored, then gets deleted.

**The empty-rule guard fired before anything else did.** On its very first run
`check-doc-facts.py` refused to pass because one of its four claims matched nothing anywhere: the
documents say "assessment categories" where the code says `Category`. The rule did not go quiet —
it demanded a human. That is precisely what `check-i18n-keys.mjs` lacked.

### What remains, and why

| # | Recommendation | Why it is not done here |
|---|---|---|
| 1 | **Merge `develop` into `main`** | An outbound operation on the default branch. And this remediation **widens the gap**: it is now five commits plus this work |
| 4 | Trigger `release.yml` | Needs `gh auth` and signs in the project's name |
| 5 | Enable GitHub Pages | A setting requiring admin rights on `asmolabs/vectispire` |

**And it bears repeating, because the remediation makes it worse rather than better: until #1 is
done, everything above is fixed on a branch that nothing scheduled executes.**


## 1. What I executed

| Check | Command | Result |
|---|---|---|
| JVM suites, cold | `./gradlew build --rerun-tasks` | **1327 tests, 260 suites, 0 failures, 0 errors, 0 skipped** |
| Multi-engine campaign | `./gradlew integrationTestAll --rerun-tasks` | **PostgreSQL 29, MySQL 29, SQLite 29 = 87 tests, 0 failures** |
| Containers at runtime | `:vectispire-common:integrationTest` | **14 cases, 0 failures**, live daemon |
| Browser suite | control plane started by hand, then `npx playwright test` | **13 passed** in 2.2 min |
| Restore drill | `bash scripts/restore-drill.sh` | **passed**, its own mutation included |
| Angular suites | `npm test` | **146 tests, 23 files, 0 failures**; i18n **54 keys, 2 bundles** |
| `gitleaks` | CI image pinned by digest | **382 commits, 16.28 MB, no leaks** |
| Dockerfile / Actions policy | checkov image pinned by digest | **260 + 380 = 640 checks, 0 failed**, 2 skipped |
| Relative links | `python3 scripts/check-doc-links.py` | **774 links, 0 broken** — **778** after adding the two reports below, still 0 |
| C4 drift | `shasum -a 256` vs `diagrams/.workspace.sha256` | **in step** |
| Documentation site | `mkdocs build --strict` in a venv | **built**, 0.46 s — see §3.5 |
| Bilingual parity | `find docs/{fr,en}` | docs **12 / 12**; ADR **18 / 18**; bflorat **6 / 6**; STRIDE **2 / 2** |
| Agent isolation | `:vectispire-agent:dependencies` | **0** JDBC / Hibernate / Flyway / JPA; `ENCRYPTION_KEY` absent from `src/main` |
| Scanner sandbox | `ContainerRunner` + `docker-compose.yml` | `cap_drop` **all**, `no-new-privileges`, **read-only** rootfs, network `none`, memory/CPU/PID ceilings; `docker.sock` mounted **only** on `control-plane` and `agent` |
| Cryptography | `SecretCipher`, `SealedEnvelope`, `PasswordHasher` | `v2:` prefix, **12-byte** nonce, **128-bit** tag, context AAD, X25519+HKDF+GCM, Argon2id **PHC** |
| Compliance, by the count | `grep -c` over the catalogue | **6 frameworks, 24 controls, 7 categories, 3 platform caps** |
| GitHub history | public API | **20 runs** — see §2 |
| Releases and tags | `git tag`, `/releases` API | **0 and 0** — `release.yml` has still never run |
| Branch gap | `git rev-list --count origin/main..develop` | **5** — see §3.1 |
| Working tree | `git status --short` | **clean** |

### A note on the prompt itself

`PROMPT_AUDIT.md` §1 speaks of "ADR 0001 through 0016": there are **seventeen**, 0017
(*organisation-specific checks as container images*) dated 29 August. §5 still describes
`.gitlab-ci.yml` as kept and unmaintained; **the file no longer exists**, removed by `3668dfe`,
which the 13:11 audit already recorded. The prompt is drifting from the tree it audits. That is
benign, but a prompt describing the day-before-yesterday's repository ends up sending its reader
after things that are gone and past things that have arrived since.

---

## 2. The forge's actual state

`git remote -v` → `git@github.com:asmolabs/vectispire.git`. Default branch: `main`, public repo,
`has_pages: false`.

| Workflow | Runs | From | Last verdict |
|---|---|---|---|
| `verify` (`ci.yml`) | 17 | `develop` and `main` | success — but **#17 took 67 min in `images`** against 4 min for the next slowest, see §3.2 |
| `nightly` | 2 | `main`, `schedule` | success (29 Aug 09:17, 30 Aug 08:29) |
| `docs` | 1 | `main` | **failure**, see §3.5 |
| `release` | **0** | — | **never triggered** |

The nightly works: two scheduled firings, both from `main`, both green. The question open since
28 August is genuinely closed. It has been replaced by another, which is this audit's main
finding.

---

## 3. The findings

### 3.1 🔴 The branch GitHub schedules from is five commits behind, so nothing the last two audits fixed is in force

```
$ git rev-list --count origin/main..develop
5
$ git log --oneline -1 origin/main
dfbd7f8 docs(analysis): the two findings of the 16th audit are closed…
```

`origin/main` is still at the documentation commit of the **16th** audit. The five missing commits
are the entire remediation of the 17th and 18th passes:

| Commit | What `main` does not have |
|---|---|
| `fafb3cf` | `ReadCostSweepTest` — and the three read fixes (`/epss/priorities` N+1, `/scorecards/global`, `/attack-paths/overview`) |
| `e920718` | The i18n fix and `check-i18n-keys.mjs` |
| `014503a` | `release.yml` with SBOM, both signatures, both verifications and `gh release create` |
| `e716fe6` | The secret-exposure runbook corrected on the forge |
| `c4a6112` | The 17th and 18th audit reports |

Verified file by file:

```
$ git ls-tree -r --name-only origin/main | grep -cE "ReadCostSweepTest|check-i18n-keys"
0
$ git ls-tree -r --name-only origin/develop | grep -cE "ReadCostSweepTest|check-i18n-keys"
2
$ git ls-tree -r --name-only origin/main | grep -c ReadCostRoutesTest
1
$ git show origin/main:.github/workflows/release.yml | grep -ci sbom
0
```

`main` still carries `ReadCostRoutesTest`, the four-route enumeration `fafb3cf` removed precisely
because it could not see the other three. **And `main` still carries the three unfixed routes**,
including the N+1 at 468 queries for 620 issues.

**The consequence is the one §5 of the prompt describes exactly.** GitHub runs a scheduled
workflow from the default branch only. The 30 August nightly at 08:29 is green — and it exercised
the multi-engine campaign, the browser suite and the restore drill **on the pre-fix tree**. A
green on `main` today says nothing about what was repaired yesterday. This is the third time in
this series that a `main`/`develop` gap has turned a guarantee into scenery; the first two times
the gap was 75 commits, then 3.

**Recommendation 1 (blocking, and the only one that unblocks the others).** Merge `develop` into
`main`. Until that is done, everything the 18th audit measured as fixed is fixed on a branch that
nothing scheduled executes.

---

### 3.2 🔴 A smoke job counts container starts as if they were seconds, and took 67 minutes to do three and a half minutes of work

**Corrected after the fact, and the correction is the finding.** While this audit was running,
run #17 sat `in_progress` for three hours with its `images` job showing no completion, and I
wrote it up as hung — a job that would hold a runner to GitHub's six-hour ceiling while
reporting neither success nor failure. **It was not hung. It finished, successfully, in 67.3
minutes**, and I only know that because pushing the remediation made me look again:

```
$ curl .../actions/runs/33308940758/jobs
images   success   67.3 min      <- every other job: 0.1 to 4.2 min
jvm      success    4.2 min
frontend success    1.0 min
```

The ceiling claim was wrong. What is underneath it is worse than what I claimed, because a slow
green is invisible in a way a red never is — this job had been taking over an hour on every run
and nothing said so.

**The cause is in the waiting loops, and it is a units error.** Both of them spawn a *container
per attempt* while reporting attempts as seconds:

```yaml
for attempt in $(seq 1 120); do
  if docker run --rm --network smoke mysql:8 mysqladmin ping ...; then
    echo "database ready after ${attempt}s"; break        # <- an attempt is not a second
  fi
  sleep 1
done
```

An attempt costs a container create, start, run and remove. The health probe does the same with
`curlimages/curl`, up to 90 times. So a loop documented as bounded at 120 seconds is really
bounded at 120 × (1s + container overhead), and on a loaded runner that is an hour. Measured
locally, the same wait done by `docker exec` into the already-running database completes in
**6 seconds**.

**And `ci.yml` bounded no job at all**, while `nightly.yml` had bounded all four of its own since
it was written:

```
$ grep -n "timeout-minutes" .github/workflows/*.yml
nightly.yml:37,57,72,159   40, 30, 30, 30
ci.yml                     (nothing)
```

That is still worth fixing on its own — a job that genuinely hangs reports *nothing*, and nothing
is the one answer no procedure handles. But a timeout would only ever have turned this run red;
it would not have told anyone why.

**Recommendation 2.** Both halves. Bound every job, and fix the loops so the bound means what it
says: `docker exec` into the running database instead of a new client container per probe, and a
*single* probe container that retries internally instead of one per attempt. Then the number in
the log and the number in the ceiling are the same unit.

**Done, and measured on the runner rather than argued.** Run #21, the first to carry the fix:

| | run #17 (before) | run #21 (after) |
|---|---|---|
| `images` job | **67.3 min** | **2.4 min** |
| whole run | 71.7 min | **6.9 min** |

Twenty-eight times faster, same assertions, and the 30-minute ceiling that would have failed the
old run now sits an order of magnitude clear of the new one. A ceiling is only honest over a job
whose cost is understood.
---

### 3.3 🔴 The signing workflow downloads its signing tool from a mutable URL, unverified — inside the job that holds `id-token: write`

`.github/workflows/release.yml`, lines 75-79:

```yaml
      - name: install cosign
        run: |
          curl -fsSL -o /usr/local/bin/cosign \
            https://github.com/sigstore/cosign/releases/latest/download/cosign-linux-amd64
          chmod +x /usr/local/bin/cosign
```

No version. No checksum. No signature verified. `latest` names whatever its owner decides today.

**What makes this finding expensive is that the file states the rule it breaks, sixteen lines
earlier:**

> *"Every `uses:` here is pinned to a commit SHA. That matters more in this file than anywhere
> else: what a consumer verifies is 'this workflow, in this repository, on this tag', and an
> action swapped under a mutable tag runs inside the job that holds `id-token: write`."*

The reasoning is right and complete. It only covers `uses:`. The one binary in the job that is not
a GitHub Action is **the tool that manufactures the provenance**, and it is the one that arrives
unpinned.

**The consequence is not theoretical.** `cosign` signs here in keyless mode, with the workflow's
OIDC token. A substituted binary therefore signs with the project's **legitimate** identity, and
the bundles it produces pass the very command `GETTING_STARTED` §8 tells users to run — same
`--certificate-identity`, same `--certificate-oidc-issuer`. Consumer-side verification cannot see
the difference, because there is no difference to see: the certificate is authentic. All a
signature proves is that this workflow signed; if the signing tool is not the one you think, that
proof is exactly as good as the `curl`.

**Age.** `git log -S "cosign-linux-amd64"` returns one commit: `8b56333`, the 27 August port to
GitHub Actions. So it is an original defect, present through the four audits that followed, and
none saw it — **including yesterday's, which rewrote this very file to add the SBOM and the
publish step**. That is "an earlier audit scored what it had not measured", not a regression.

**Recommendation 3.** Pin the `cosign` version and verify its digest before `chmod +x`:

```yaml
      - name: install cosign
        env:
          COSIGN_VERSION: v2.4.1
          COSIGN_SHA256: <the digest published for that version>
        run: |
          curl -fsSL -o /tmp/cosign \
            "https://github.com/sigstore/cosign/releases/download/${COSIGN_VERSION}/cosign-linux-amd64"
          echo "${COSIGN_SHA256}  /tmp/cosign" | sha256sum -c -
          install -m 0755 /tmp/cosign /usr/local/bin/cosign
```

`sigstore/cosign-installer` pinned by SHA is the other route, and has the advantage of falling
under the rule the header already states for `uses:` — so there is no longer an exception to
explain.

---

### 3.4 🟠 `release.yml` has still never run

Unchanged since the 13:11 audit, and repeated here because §5 of the prompt asks that "asserted"
be separated from "executed" throughout:

```
$ git tag | wc -l
0
$ curl .../releases
[]
$ # 20 runs, none of them "release"
```

The whole signing path — the SBOM at the pinned syft digest, both signatures, both verifications,
`gh release create` — is **asserted and not executed**. The 18th audit made it truer; it did not
make it run. And §3.3 above adds a reason to run it *after* the fix rather than before: a
rehearsal that installs an unverified `cosign` rehearses that too.

**Recommendation 4.** Trigger `release.yml` by `workflow_dispatch` from `main` once §3.1 and §3.3
are settled. The rehearsal publishes nothing (`if: startsWith(github.ref, 'refs/tags/')`) and
leaves a 90-day artifact a human can inspect. This needs your credentials; it is not an action I
take on your behalf.

---

### 3.5 🟠 `docs` still fails, and I reproduced the exact cause

The single run's steps:

```
1-4  checkout, setup-python, pip install          success
5    mkdocs build --strict                        success
6    actions/configure-pages                      FAILURE
7    upload-pages-artifact                        skipped
     deploy                                       skipped
```

Reproduced locally in a venv from `ci/docs/requirements.txt`: `mkdocs build --strict` →
*Documentation built in 0.46 seconds*. **The documentation is sound.** The failure is downstream,
at `configure-pages`, and the repository API gives the reason in one field: `has_pages: false`.

This is not a code defect. It is a repository setting, open since the 17th audit, and it needs
admin rights on `asmolabs/vectispire`.

**Recommendation 5.** Enable Pages (source: GitHub Actions) then re-run `docs` by
`workflow_dispatch` — the workflow anticipates this case and comments on it.

---

### 3.6 🟠 The English README announces four database engines; there are two and a fixture, and its own ADR has said so for five days

```
README.md:348  Four engines are supported — PostgreSQL and MySQL, with SQLite as the test
               fixture — and **each is exercised by the full integration campaign**.
README.md:354  …running all four is the only way it gets found, and it found several.
README.md:438  **CI runs the first command and the Angular ones, and not the four-engine
               campaign**…
```

Sentence 348 contradicts itself inside its own parenthesis: it announces four engines and names
three, one of which it itself calls a fixture. And the same file writes, elsewhere:

```
README.md:174  …on all two engines.
README.md:433  ./gradlew integrationTestAll # all two engines — ten minutes, needs Docker
```

Measured rather than inferred:

```
$ grep -n "val engines" vectispire-core/build.gradle.kts
190:  val engines = listOf("postgres", "mysql", "sqlite")
$ ls src/main/resources/db/migration/
mysql  postgresql  sqlite          (16 migrations each)
$ ./gradlew integrationTestAll --rerun-tasks
PostgreSQL 29, MySQL 29, SQLite 29
```

Three targets, one of them a fixture. **The decision register, by contrast, is exact and honest:**

```
0009-four-engines.md   Status: **superseded** by 0014 on 2026-08-25
0014-two-engines…      Status: accepted · Supersedes: 0009
```

This is the case §4 of the prompt describes: *"calling it 'six engines' oversells exactly as much
as announcing four undersells."* Here it is an oversell, on the file a visitor reads first,
against a register that is right and that nobody reads first.

**And the bilingual parity check did not see it, because it counts files.** `README.fr.md` is
correct:

> *"Full, test-validated support for **PostgreSQL** and **MySQL**; **SQLite** serves as a test
> fixture and is not a deployable engine (decision 0014)."*

The two READMEs say two different things about a matter of record, and it is the English one —
the long one, the main one — that is wrong. Five audits validated "parity 12/12" by counting
files; none compared what two paired files asserted.

**A defect of the same family, four lines below:** `README.md:437` announces *"Around 840 unit
tests"*. Today's measurement gives **1327**. The figure is stale by about 40%.

**Recommendation 6.** Fix 348, 354, 438 and 437. And extend the parity check to the figures
quoted: a test that counts files cannot see two paired files contradicting each other, which is
precisely the defect parity claims to rule out.

---

### 3.7 🟡 The i18n rule added yesterday cannot see the defect it was written for

`e920718` is titled *"two hard-coded English labels on a translated screen, **and the rule that
would have seen them**"*. I tested that claim by putting the two literals back exactly:

```diff
   readonly aiProviders = computed(() => {
       this.i18n.translations();
       return [
-          { label: this.i18n.t('settings.ai_provider_ollama'), value: 'ollama' },
-          { label: this.i18n.t('settings.ai_provider_openai'), value: 'openai' }
+          { label: 'Ollama - a model on a host you run', value: 'ollama' },
+          { label: 'OpenAI-compatible API', value: 'openai' }
       ];
   });
```

```
$ npm test
i18n check: 52 keys referenced, all present in French and English.
Test Files  23 passed (23)
     Tests  146 passed (146)
$ echo $?
0
```

**Nothing fails.** `check-i18n-keys.mjs` verifies that *referenced* keys exist in both bundles; a
hard-coded label is not a referenced key, so it falls out of the rule's scope instead of into its
verdict. The counter drops from **54 to 52** without a word: the guard is a floor of 40, and 52
clears it comfortably.

The script deserves fairness: its own header comment is honest, and says it stops *"the next key
from being referenced without ever being added"*. That is true and it is useful. It is the
**commit title** that claims more than the file does — and that is the sentence a reader carries
away when deciding the subject is closed.

**Recommendation 7.** Two moves, one expensive and one free.
- Pin the count rather than floor it: `expect(referenced.size).toBe(54)` fails when a key
  disappears, which `> 40` never will. A number you must update in the same edit that removes a
  key is a number that asks the question at the right moment.
- Or, closer to the defect: refuse a non-empty literal in a `label`/`title` field of a component
  that calls `i18n.t` elsewhere. That is the rule the commit title describes.

---

### 3.8 🟡 `SealedEnvelope`'s AAD is still guarded only by a golden vector, and the test that claims to assert it passes without it

Carried over from the 18th audit, re-measured because it was not closed. Mutation: the ephemeral
key removed from the AAD, at both ends.

```diff
-  GCMModeCipher cipher = newCipher(sessionKey, nonce, ephemeralPublic, true);
+  GCMModeCipher cipher = newCipher(sessionKey, nonce, new byte[0], true);
-  GCMModeCipher cipher = newCipher(sessionKey, nonce, ephemeralPublic, false);
+  GCMModeCipher cipher = newCipher(sessionKey, nonce, new byte[0], false);
```

```
$ ./gradlew :vectispire-common:test
SealedEnvelopeTest > anEnvelopeSealedByAnEarlierBuildStillOpens() FAILED
701 tests completed, 1 failed
```

**One test out of 701, and it is not the one that carries the name.**
`refusesAnEnvelopeWhoseEphemeralKeyWasReplaced` — whose comment says *"the sender's key is
associated data, so swapping it must fail authentication"* — passes entirely with no AAD at all.
It passes for another reason: swapping the ephemeral key changes the X25519 shared secret, hence
the session key, hence GCM fails regardless.

What catches the mutation is `anEnvelopeSealedByAnEarlierBuildStillOpens`, the pinned literal
vector, and it fails because the **format** changed — not because the binding is asserted. Put
another way: if someone changed the AAD and regenerated the vector in the same commit, nothing
would object, and the test named after the subject would stay green.

So the protection exists, but it is incidental. This is not a vulnerability: it is an assertion
that cannot fail for the reason it announces, and the prompt makes that a category of its own for
good reasons.

**Recommendation 8.** A case that isolates the AAD without touching the shared secret: seal, then
rewrite only the ephemeral-key bytes *of the preamble* while leaving the key agreement intact —
or, simpler to write and just as probative, a test at the `newCipher` level that encrypts with the
AAD and decrypts without, and requires `InvalidCipherTextException`. Then rename
`refusesAnEnvelopeWhoseEphemeralKeyWasReplaced` after what it actually checks.

---

## 4. Testing my own tests

Four mutations, all reverted after measurement. Two confirm the rule bites; two open a finding,
and are handled in §3.7 and §3.8.

| Mutation applied | Expected | Observed |
|---|---|---|
| `getGlobalScorecard`: the `IssueRows.Posture` projection put back to a `findAll` of entities | failure | **`ReadCostSweepTest` fails** — *"/api/v1/scorecards/global loaded 224 entities at 220 issues against 24 at 20 (+200)"* |
| `ApiExceptionHandler`: `NOT_FOUND` → `FORBIDDEN` | failure | **18 tests fail**, among them *"an export of somebody else's target is 404, never 403"* |
| The two AI labels put back hard-coded | failure | **nothing fails** — see §3.7 |
| `SealedEnvelope`: AAD emptied at both ends | the named test fails | **1 failure out of 701, and not that one** — see §3.8 |

**What the first mutation teaches.** `ReadCostSweepTest`, shipped yesterday, is good work and I
verified it rather than read it. It asks Spring for its route table, measures entities *and*
queries, bounds the **slope** rather than the count, allows no exemption at all on the query
counter, and fails if it sweeps fewer than 25 routes — the guard against a rule that inspects
nothing, which is exactly what `check-i18n-keys.mjs` lacks. The failure message names the route,
both measurements and the growth. It is the precise opposite of §3.7: here the rule sees the
defect it was written for, and I made it fail to prove it.

**What the second teaches.** Eighteen tests on a single line, and their names state the rule
rather than the mechanism. Tenant isolation is the best-held part of this repository; the mutation
leaves no doubt about that.

---

## 5. What holds, and what was executed to say so

**Security.** Encryption at rest matches its description down to the detail:
`FORMAT_PREFIX = "v2:"`, `NONCE_LENGTH_BYTES = 12`, `TAG_LENGTH_BITS = 128`, context AAD passed to
`AEADParameters`. Argon2id through BouncyCastle, PHC output `$argon2id$v=19$m=…,t=…,p=…$`, so the
parameters travel with the hash and raising the cost invalidates nothing. `SealedEnvelope` is
indeed X25519 + HKDF + GCM to an ephemeral key the agent publishes.

**The sandbox.** `ContainerRunner` sets `withCapDrop(Capability.values())`,
`withSecurityOpts(["no-new-privileges"])`, `withReadonlyRootfs(true)`,
`withNetworkMode(… : "none")`, plus memory, CPU and PID ceilings. `docker-compose.yml` mounts
`/var/run/docker.sock` only on `control-plane` and `agent` — never inside a scanner, which is the
whole reason the sandbox matters.

**Agent isolation.** `:vectispire-agent:dependencies` on `runtimeClasspath`: **zero** occurrences
of JDBC, Hibernate, Flyway, JPA, PostgreSQL or MySQL. `ENCRYPTION_KEY` absent from all of the
agent's `src/main`.

**Compliance, counted.** 6 frameworks, **24** `new ComplianceControl(`, 7 categories in the enum
and 7 arms in `ComplianceEngine`'s switch, 3 `cappedByPlatform` ceilings (secrets without a key,
audit without a mirror, governance without four eyes). The distribution is uneven — 7 controls in
`VULNERABILITY_MANAGEMENT`, 1 in `GOVERNANCE` — which is exactly what a mapping produces, and why
any two controls sharing a category receive the same verdict. **One posture evaluator, six
mappings.** The prompt's description is right and the code holds it.

**Architecture.** `ArchitectureTest` carries 11 rules, including *"finds classes to check at all"*
— the guard against the empty rule — and *"an outbound call goes through the door that validates
and pins"*. The ADR register is complete, bilingual to the file, and its reversals are dated and
cross-linked (0008 → 0009 → 0014, 0011 → 0013).

**The restore drill** passes, and carries its own mutation: it replays the restore with the mirror
thrown away, shows `missingFromTable` falling back to 0 and the data loss becoming invisible, then
names the counter that still sees it. A script that traps itself is rare; this one does it and
explains why.

**And a note of method on the browser suite.** `npx playwright test` on its own gives **12
failures out of 13**: `playwright.config.ts`'s `webServer` starts only the Angular UI on 4280, and
nothing listens on 3180. After starting the control plane by hand the way the nightly's `e2e` job
does, **13 passed in 2.2 min**. My twelve failures were my environment, not a regression — I say
so because the same mistake was made and recorded in this series on 29 August, and because
swallowing a false positive costs more than writing it down.

---

## 6. Recommendations

| # | Recommendation | Priority | Verified how |
|---|---|---|---|
| 1 | **Merge `develop` into `main`** — without it, nothing the 17th and 18th audits fixed is executed by anything scheduled | 🔴 | `git rev-list --count origin/main..develop` → **5**; `git ls-tree origin/main`: `ReadCostSweepTest` and `check-i18n-keys.mjs` **absent**, `ReadCostRoutesTest` **present**, `sbom` **absent** from `release.yml` |
| 2 | Bound every job **and** fix the container-per-probe loops | 🔴 | jobs API: `images` **67.3 min** on a step bounded on paper at 3 min 30; the same wait by `docker exec` measured locally at **6 s**; `grep timeout-minutes` → 4 in `nightly.yml`, **0** in `ci.yml` |
| 3 | Pin and verify `cosign` | 🔴 | `release.yml:75-79` read; `git log -S` → introduced by `8b56333` on 27 August, never flagged since |
| 4 | Trigger `release.yml` (after 1 and 3) | 🟠 | **asserted, not executed** — 0 tags, 0 releases, absent from all 20 runs. Needs your credentials |
| 5 | Enable GitHub Pages then re-run `docs` | 🟠 | `mkdocs build --strict` **passes** locally; the failure is `configure-pages`, and `has_pages: false` |
| 6 | Fix "four engines" (README 348, 354, 438) and "840 tests" (437), then extend parity to quoted figures | 🟠 | `val engines = listOf("postgres","mysql","sqlite")`; 3 migration directories; campaign 3 × 29; ADR 0009 **superseded** by 0014; `README.fr.md` correct |
| 7 | Pin the i18n key count, or refuse the literal | 🟡 | mutation: both labels put back hard-coded → **146 tests green, exit 0**, counter 54 → 52 in silence |
| 8 | A case that isolates `SealedEnvelope`'s AAD | 🟡 | mutation: AAD emptied → **1 failure out of 701**, and it is the golden vector, not the test carrying the name |

**Recommendations 4 and 5 need your credentials or admin rights, not code.** The other six are
work in the tree. And it should be said as plainly as last time: **until 1 is done, 7 and 8 fix
tests that nothing scheduled executes.**

---

## 7. On the score dropping

The prompt asks that when a score drops, the report say whether the ground got worse or an earlier
audit scored what it had not measured. Both, and not in the same boxes.

**The ground moved in 3.1, and 3.2 is something else again.** Five unmerged commits is a state,
not a design defect, settled by a merge — but a state that hollows out everything a green board
asserts. 3.2 is a defect that had been shipping for as long as the job existed, passing green at
sixty-seven minutes a run, and I nearly filed it as a transient hang. **That I got it wrong on
the first pass is the part worth keeping**: I inferred a hang from a run that was merely slow,
and only measuring the completed job showed the units error underneath. The verification axis
falls to 6.5 for both.

**Three audits scored what they had not measured**, and it is better to name that than to spread
it around:
- the `cosign` curl survives four audits, including yesterday's, which rewrote that file;
- "four engines" survives five audits, all of which validated bilingual parity by counting files;
- `SealedEnvelope`'s AAD was correctly identified by the 18th audit and was not closed.

**Code quality, by contrast, does not move, and that is earned.** `ReadCostSweepTest` is the best
thing shipped in this series since `AuthorizationCoverageTest`: it replaces a list with a rule, it
carries its own guard against empty inspection, and it found three routes an enumeration could not
find. I made it fail on purpose to check. The contrast with `check-i18n-keys.mjs` — shipped in the
same batch and unable to see its own motivating case — is the most useful thing this audit has to
say about how this repository writes its rules: **a rule is judged by making it fail, never by
reading it.**
