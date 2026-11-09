# In-depth audit — code, security, documentation

**28 August 2026, 10:28** · *Version française : [`2026-08-28_10_28_20_audit_approfondi_code_securite_doc.fr.md`](../fr/2026-08-28_10_28_20_audit_approfondi_code_securite_doc.fr.md)*

## Overall score: **8.0 / 10** — down from 8.5

**The drop is not the product getting worse. It is a verification being lost.** On 25 August the
audit established that nothing had ever run on a machine; the GitLab pipeline written immediately
after closed that gap, and the 26 August audit counted it. The project has since moved to GitHub,
and **the ported pipeline has never once been green**. The ground did not deteriorate: the proof
was reset by the move and has not yet been re-established.

That is the distinction the prompt requires naming. This is not "an earlier audit scored what it
had not measured"; it is "what was measured is no longer measured".

| Domain | Score | Movement |
|---|---|---|
| Documentation & Architecture | **9.0** | ↑ |
| Security & Cryptography | **9.0** | ↑ |
| Code quality | **8.5** | = |
| Compliance & Standards | **8.5** | = |
| **Verification that actually runs** | **5.0** | ↓↓ |

---

## 1. What I executed

Everything below was run, not read.

| Control | Command | Result |
|---|---|---|
| JVM suites | `./gradlew build` | **1371 tests, 0 failures, 0 skipped** (276 result files) |
| Angular suites | `npx ng test --no-watch` | **146 tests, 23 files, 0 failures** |
| Relative links | `scripts/check-doc-links.py` | **616 links, 0 broken** |
| C4 drift | `workspace.dsl` fingerprint | **in step with the diagrams** |
| Secrets | `gitleaks` + baseline | **clean** — after a fix, §4 |
| Bilingual parity | tree comparison | **12 / 12**, no orphans |
| ADR registry | `ls decisions/` | **0001 → 0016**, both languages |
| Restore drill | `scripts/restore-drill.sh` | **passed**, assertions included |

## 2. Testing my own tests

The prompt makes this non-negotiable, and this is the project that has already shipped three
assertions incapable of failing. Four mutations, each breaking the code and demanding the test fall
over.

| Mutation applied | Expected | Observed |
|---|---|---|
| `IssueFingerprint`: swap `type` and `identifier` | failure | **1 test fails** — *"a known finding has a known fingerprint"* |
| `SecretCipher`: remove the context binding (AAD) | failure | **3 tests fail**, including both "must not decrypt" cases |
| `SealedEnvelope`: `HKDF_INFO` v1 → v2 | failure | **1 test fails** — an envelope sealed by an earlier build no longer opens |
| `AuditLogController`: remove `@RequiresSecurityLead` | failure | **2 tests fail** — authorization coverage **and** route granularity |
| `.gitleaks.toml`: inject a random secret (`openssl rand -hex 24`) | detection | **detected** |

The first deserves emphasis: it is **exactly** the mutation that on 26 August made no test fail.
The literal vector pinned since then closes the hole, and proves it.

The fourth produces a message that says what to do — *"resolve a Visibility, call a helper named
requireVisible…, or carry a role guard — and if the route genuinely names no target, add it to
NAMES_NO_TARGET with the reason"*. A security rule that does not explain how to comply is a rule
people route around.

## 3. The central finding: verification did not survive the migration

**Three facts, measured.**

**a. The GitHub pipeline has never been green.** One run, and it failed:
`accepts at most 1 arg(s), received 2`. The cause was a porting bug — on GitLab the first argument
to `docker create` is the *container's name*, consumed by a `shift`; moving to `docker run --rm`
removes the name, and the words `report` and `verdict` went into `"$@"`. The original comment
survived, so the code read as deliberate. Fixed (`8a7f1b25`), reproduced locally — syft finds 159
components, grype 5 fixable findings — and mutation-tested on the threshold: `--fail-on high` → 0,
`--fail-on medium` → 2, with the full table printed before the failure in both cases. **But the fix
is not pushed.**

**b. The nightly cannot fire.** GitHub runs a scheduled workflow from the **default branch** only.
`main` sits at `949f5130`, **75 commits behind**, and `nightly.yml` is not on it. All four nightly
jobs — `databases`, `dockerfiles`, `e2e`, `restore` — are declared and none can start. This is
GitLab's failure mode repeating for a different reason: there a schedule was missing from the
settings, here the branch is missing. Putting `cron:` in the file removed one way to forget, not
all of them.

**c. The fossil workflows are on the default branch.** `main` still carries the pre-port `ci.yml`
and `release.yml`, with `on: pull_request`. **The next pull request runs the stale pipeline.** Step
0 of the migration plan — "archive them before the first push, never after" — was done in the
history, but `main` never received it.

All three close with one action: fast-forward `main` to the head of `develop`. A push uses the
workflow files at the pushed ref, so the operation heals itself.

**What remains unexecuted, and must be counted as such:** `integrationTestAll` (40 minutes, two
real engines) was not run in this audit; `release.yml` has never run, so the GitHub cosign identity
and the `id-token: write` permission are **asserted, not executed**. A signature nobody has
produced is a signature that does not work.

## 4. A finding this audit produced, and it is mine

`gitleaks` with the baseline found **one leak**, introduced by `3fb0519d` — my own commit, one step
earlier: the restore drill's key, entropy 4.67, rule `generic-api-key`. A value whose plaintext
says "not-a-secret" does not read that way to a scanner.

Fixed by allowlisting **by value** in `.gitleaks.toml`, beside the KAT vector key, rather than by
baseline fingerprint: a fingerprint pins commit + file + line and does not survive a rebase.

A side detail is worth recording in the product's favour. The old value decoded to **30** bytes,
not 32, and the application started. That is not a defect: `EncryptionKey` accepts a raw key only
as base64 of *exactly* 32 bytes, so a 30-byte value falls through to the *passphrase* branch and is
stretched with scrypt (N=2¹⁵). **The design absorbed my mistake correctly.**

## 5. Security — what I could confirm

**Scanner sandbox.** `ContainerRunner` applies `withCapDrop(Capability.values())` — every
capability, not a list — `no-new-privileges`, a read-only root filesystem, `rw,noexec,nosuid` tmpfs
for `/tmp` and `HOME`, memory / nanoCPU / PID ceilings, and `NetworkMode("none")` unless explicitly
requested. And crucially: `ContainerHardeningTest` **pins those settings**, so a refactor cannot
quietly drop them.

**Agent isolation.** `./gradlew :vectispire-agent:dependencies --configuration runtimeClasspath`
→ **zero** occurrences of mysql, postgres, jdbc, hibernate or spring-data-jpa. No reference to
`ENCRYPTION_KEY` in its configuration. The isolation is real, not documentary.

**Argon2id.** `m=19456, t=2, p=1`, PHC format — and a test pins the prefix
`$argon2id$v=19$m=19456,t=2,p=1$`. `needsRehash` compares against current parameters, so raising
the cost does not break what is stored.

**Compliance.** `ComplianceEngine` does switch on **7** categories and project onto **6**
frameworks — 24 controls. "One evaluator, six mappings" is accurate.

## 6. Recommendations, most urgent first

| # | Action | How it was verified |
|---|---|---|
| 1 | **Push `develop`, then fast-forward `main`.** Closes all three findings in §3 at once. | Blocked: GitHub refuses write to both keys on this machine. `--dry-run` with `asmolabs_id_ed25519` → *Permission denied*; with `id_ed25519` → *denied to Asmo1973*. **An account-side action, not a code one.** |
| 2 | **Pin the five `uses:` to a SHA.** `actions/{checkout,setup-java,cache,upload-artifact,download-artifact}` are all on floating tags, and `release.yml` signs with them. A tag can be moved; a signature produced by a swapped action stays valid and proves nothing. | Measured: `grep -hoE 'uses: [^ ]+' .github/workflows/*.yml` → 5 actions, 0 SHAs |
| 3 | **Run `release.yml` via `workflow_dispatch` on a rehearsal tag.** The cosign identity and `id-token: write` are asserted and never executed; the failure would land at publication time. | Asserted, not executed |
| 4 | **Run `integrationTestAll` before any release.** The nightly cannot do it (§3b), so multi-engine portability is currently verified by nobody. | Not executed in this audit |
| 5 | Clean up the triple-nested defaults — `${VECTISPIRE_PASSWORD_LOGIN:${VECTISPIRE_PASSWORD_LOGIN:${VECTISPIRE_PASSWORD_LOGIN:true}}}` across six `application.yaml` properties. No effect, but it is the kind of residue that makes a reader doubt the rest. | Read, not run; no functional effect |

## 7. What I did not measure

- `integrationTestAll` — real PostgreSQL and MySQL, 40 minutes.
- The Playwright suite — it needs a running control plane; the nightly was meant to carry it.
- Behaviour under a wrong `ENCRYPTION_KEY` — the restore drill names it as its accepted gap
  (§4 of `BACKUP_AND_RESTORE`), and this audit did not close it.
- Any real execution on a GitHub runner: I have no write access to the repository.
