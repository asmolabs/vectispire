# In-depth audit — code, security, documentation

**29 August 2026, 20:04** · *Version française : [`2026-08-29_20_04_13_audit_approfondi_code_securite_doc.fr.md`](../fr/2026-08-29_20_04_13_audit_approfondi_code_securite_doc.fr.md)*

## Overall score: **8.1 / 10** — up from 8.0

Two movements in opposite directions, and they are not the same kind of information.

**The verification came back.** The 28 August audit scored verification 5.0 because `main` was 75
commits behind and `nightly.yml` was not on it, so GitHub could not fire the schedule. `main` is
now **3 commits behind** and carries `nightly.yml` with its `cron:` — the mechanism is in place.
That is ground genuinely recovered.

**The at-rest encryption of secrets is optional, and always has been.** Three settings carry a
dedicated route that encrypts them before storage — the tracker token, the tracker webhook secret,
and (in the working tree) the AI provider API key. **The generic `PUT /api/v1/settings` accepts all
three by name and writes them in the clear**, 200 OK, no warning. I did not reason this out; I
wrote the request and read the column back. Fifteen audits have credited encryption at rest for the
tracker token without ever writing it through the other door.

That second one is mostly *"an earlier audit scored what it had not measured"*, not *"the ground got
worse"* — the bypass predates the current work. What the current work adds is a third secret to it.

| Domain | Score | Movement |
|---|---|---|
| Documentation & Architecture | **8.5** | ↓ |
| Security & Cryptography | **8.0** | ↓ |
| Code quality | **8.5** | = |
| Compliance & Standards | **8.5** | = |
| **Verification that actually runs** | **7.0** | ↑↑ |

**Scope note.** The working tree carries 19 modified files and one new one — an unfinished feature
adding an **OpenAI provider to the AI review**. It is audited here because it is the most
consequential thing in the repository right now: it opens a path for the source code of every
scanned repository to leave the estate. Findings against it are marked *(working tree)* and are not
yet anybody's committed mistake.

---

## 0. Remediation status — all four findings closed

*Added after the audit, on the same day. Each line names what closes it and the mutation that
proves the assertion can fail. Full suite after the changes: **1320 JVM tests, 0 failures**
(1292 before), **146 Angular tests, 0 failures**, **730 links, 0 broken**.*

| # | Finding | Closed by | Proof it can fail |
|---|---|---|---|
| §3.1 | Secrets written in the clear by the generic route | **Not mine.** `Sensitivity.ENCRYPTED` splits "hide this" from "encrypt this"; the write path refuses the four credentials, the catalog withholds them from administrators too, and the tracker webhook secret — the one credential stored in the clear *by design* — gained the route it never had. `SettingTest.credentialsAreMarkedEncrypted` pins the list. | Re-ran the audit probe over HTTP: `PUT /api/v1/settings {"ticket_token":…}` → **400**, nothing stored. |
| §3.2 | Consent to send code off-site could not be withdrawn | A save that *removes* the acknowledgement skips the pre-save destination check — the resulting configuration is strictly less permissive, and `validatedUrl()` refuses it at every review anyway. `AiReviewConsentTest`, 5 cases. | Restored the unconditional check → **2 tests fail**. |
| §3.3 | The credential routes were guarded but untested | `SettingsRoutesTest`: every writing route answers 403 to a reader and 200 to an administrator, over the real filter chain. | Removed `@RequiresAdministrator` from `/ai-openai-key` → **1 test fails**. |
| §3.4 | The model review was absent from the STRIDE model | **E7** added as an entity with six rows, **TB5** and **F17** in the DFD, both languages. The flow table's heading no longer claims sixteen flows over five rows; it says what the section is and where the rest are analysed. | n/a — documentation. Bilingual parity checked by grep; 730 links still resolve. |

### And one new finding, found while closing §3.3

`POST /api/v1/settings/ollama-test` carried no method-level guard, so the class marker
`@RequiresAccount` applied: **any signed-in reader could run it**, and it answers with the
configured endpoint URL — the single value `ai_review_ollama_url` is marked `SECRET` to keep out of
exactly those hands. It also made the server open an outbound connection on a reader's say-so. Now
narrowed to the same roles that may write the setting. Verified by execution before and after; the
assertion fails when the guard is removed.

---


## 1. What I executed

Everything in this table was run. Nothing in it was inferred from reading a file.

| Control | Command | Result |
|---|---|---|
| JVM suites | `./gradlew build` | **1292 tests, 0 failures, 0 errors, 0 skipped** (255 suite files) |
| Angular suites | `npm test` | **146 tests, 23 files, 0 failures** |
| Relative links | `python3 scripts/check-doc-links.py` | **712 links, 0 broken** |
| C4 drift | `shasum -a 256 workspace.dsl` vs `.workspace.sha256` | **identical — in step** |
| Bilingual doc parity | `find docs/{fr,en} -name '*.md'` | **12 / 12** |
| ADR registry | `ls docs/architecture/{en,fr}/decisions/` | **0001 → 0017**, both languages |
| bflorat dossier | `ls bflorat/{en,fr}` | **5 views + README**, both languages |
| Agent isolation | `./gradlew :vectispire-agent:dependencies --configuration runtimeClasspath` | **180 deps, zero JDBC / JPA / Hikari / driver** |
| Compliance shape | count of enum constants and control literals | **7 categories, 6 frameworks, 24 controls** |
| Crypto parameters | source constants, `SecretCipher` / `PasswordHasher` | AES-256-GCM, **nonce 12 B, tag 128 bits, AAD, `v2:`**; Argon2id **19 MiB, t=2, p=1** |
| Secret storage bypass | `PUT /api/v1/settings` through MockMvc, column read back | **plaintext — §3.1** |
| AI acknowledgement | four saves through MockMvc | **works, and cannot be undone — §3.2** |
| Provider-key route | `PUT`/`GET /ai-openai-key` as reader and as admin | **403 / 200 / 200 — §3.3** |
| Branch gap | `git rev-list --count origin/main..develop` | **3** |
| Restore drill | `bash scripts/restore-drill.sh` | **not executed** — needs `vectispire:latest`, not built locally |
| GitHub run history | — | **not executed** — no `gh` CLI on this machine; see §5 |

### The count is 1292, and the previous audit said 1371

Not a regression. `find vectispire-java -name '*Test.java'` returns **201** files, and
`git ls-tree -r 73fbae5 | grep -c 'Test\.java$'` returns **201** as well — the same inventory as at
the previous audit's commit, with no deletions in `git diff --name-status 73fbae5 HEAD -- '*Test.java'`.
The 79-test difference is measurement scope (the earlier figure counted result files left over from
an `integrationTest` run in the same build directory), not lost coverage. Two numbers produced by
different scopes are not a trend, and reporting them as one would be exactly the error this prompt
exists to prevent.

---

## 2. Testing my own tests

Three mutations. Each breaks the code and demands the suite fall over.

| Mutation applied | Expected | Observed |
|---|---|---|
| `IssueFingerprint`: swap `target` and `type` in the digest | failure | **fails** — the pinned literal vector `44c39a41…851d` catches it |
| `ContainerRunner`: `withCapDrop(Capability.values())` → `withCapDrop(CHOWN)` | failure | **fails** — `ContainerHardeningTest` |
| `SettingsController`: delete `@RequiresAdministrator` from `PUT /ai-openai-key` | failure | **passes.** `./gradlew :vectispire-core:test --rerun-tasks` — BUILD SUCCESSFUL, 0 failures |

The first two confirm that the two assertions this project most depends on can actually fail. The
pinned fingerprint vector, added after the 26 August finding, does its job: reordering two fields
now breaks a test instead of silently re-keying every finding in the estate.

**The third is a finding, and it is §3.3.**

---

## 3. Findings

### 3.1 🔴 The encryption of stored secrets is optional — a second route writes them in the clear

**Executed.** Through `MockMvc`, authenticated as an administrator:

```
PUT /api/v1/settings
{"ai_review_openai_key":"sk-PROBE-openai-key",
 "ticket_token":"PROBE-jira-token",
 "ticket_webhook_secret":"PROBE-webhook-secret"}
→ 200
```

then reading the column back through `SettingsService`:

```
PROBE stored ai_review_openai_key   = [sk-PROBE-openai-key]    encrypted=false
PROBE stored ticket_token           = [PROBE-jira-token]       encrypted=false
PROBE stored ticket_webhook_secret  = [PROBE-webhook-secret]   encrypted=false
PROBE catalog leaks openai key      = true
PROBE catalog leaks jira token      = true
PROBE reader sees openai key        = false
```

**What is wrong.** Three settings have a dedicated route precisely so their value is encrypted
before it reaches the database — `PUT /settings/ticket-token`, `PUT /settings/webhook-secret`, and
(working tree) `PUT /settings/ai-openai-key`. Each calls `EncryptionService.encrypt` and stores a
`v2:` blob. The generic catalog route at `SettingsController.update`
([`SettingsController.java:157`](../../../vectispire-java/vectispire-core/src/main/java/com/asmolabs/vectispire/core/api/SettingsController.java))
validates the key against the catalog and then calls `settings.set(...)` with the raw string.
`SettingsService.set` writes text. There is no branch on `Sensitivity.SECRET` anywhere in the write
path — `isSecret()` is consulted in exactly one place in `vectispire-core`, and it is the *read*
side of the catalog.

`Sensitivity.SECRET` therefore means "do not show this to a non-administrator", never "encrypt
this". The doc comment on the new key setting says *"Stored encrypted, like a tracker token, and
never returned by any route"*. Both halves are false through this door: it is stored in the clear,
and `GET /api/v1/settings` returns it verbatim to every administrative role.

**Why it matters.** The tracker token can open Jira as Vectispire. The webhook signing secret lets
a holder forge inbound ticket events. The provider key can spend an OpenAI account. All three now
sit in `t_setting` in plaintext for anyone with a database backup, a read replica, or a DBA
account — which is the exact adversary `SecretCipher` was written for, in a class whose own comment
says *"someone able to write to the database"*.

**And it breaks the feature quietly.** `AiReviewService.authentication()` decrypts the stored value
and, on failure, deliberately sends no header rather than a ciphertext. A plaintext key does not
decrypt. The operator sets a valid key through the settings screen, gets a 200, and the connection
test reports the endpoint unreachable — sending them to debug a network path that is fine.

**Recommendation.** Refuse `Sensitivity.SECRET` keys in `SettingsController.update` with a message
naming the dedicated route, exactly as the two acknowledgement rows are already refused eight lines
above. Then assert it: one test per secret setting, written through the generic route, asserting
either a 400 or a stored value starting with `v2:`. **Verification: executed** — the probe above,
plus the two acknowledgement rows proving the refusal pattern already exists in this method.

### 3.2 🟠 The consent to send code off-site cannot be withdrawn *(working tree)*

**Executed.** Four saves in sequence, as administrator:

| Request | Status | Body |
|---|---|---|
| `{"ai_review_provider":"openai"}` | **422** | *"OpenAI URL: the host resolves to a public address (172.66.0.243)…"* |
| `{"ai_review_provider":"openai","ai_review_allow_remote_url":"true"}` | **200** | recorded `by=admin-… at=2026-08-29T17:59:35Z` |
| `{"ai_review_risk_acknowledged_by":"somebody-else", …_at:"1999-01-01…"}` | **400** | *"…is recorded by the server … and cannot be set here."* — record unchanged |
| `{"ai_review_allow_remote_url":"false"}` | **422** | *"OpenAI URL: the host resolves to a public address…"* |

The first three are the control working, and working well — the guard resolves the name rather than
pattern-matching it, and a client cannot forge whose acceptance it was.

**The fourth is backwards.** An operator who wants to *stop* sending source code to OpenAI is
refused. `requireLocalUnlessAcknowledged` is evaluated on the post-save state, so with the provider
still `openai` the resulting configuration is judged illegal and the whole save is rejected. The
only way out is to send the provider change and the switch in one request — and the error message
does not say so; it names the URL, which the operator did not touch.

**Why it matters.** A guard that refuses to let the configuration become *safer* is a guard
pointing the wrong way. And nothing is bought by the refusal: `AiReview.validatedUrl()` revalidates
on every single review, so a stored configuration of `provider=openai` + acknowledgement off simply
sends nothing. The safe state was already handled at the point where it matters.

**Recommendation.** Skip the pre-save check when the transition *removes* the acknowledgement, or
clear the provider along with it. Either way, keep the record: `clearRiskAcknowledgement` already
does the right thing once the save is allowed to happen.

### 3.3 🟠 The route that writes the provider key is guarded but untested *(working tree)*

**Executed.** With the code as written, `PUT /api/v1/settings/ai-openai-key` answers **403** to a
plain reader and **200** to an administrator. The control is correct today.

Then: delete `@RequiresAdministrator` from that method and run `./gradlew :vectispire-core:test
--rerun-tasks`. **BUILD SUCCESSFUL. Zero failures.** `AuthorizationCoverageTest` exempts
`SettingsController` by name — legitimately, since it serves nothing target-scoped — and the
exemption takes the whole file with it, new routes included.

**Why it matters.** This is the shape of defect the project has already shipped three times: a
control that works and an assertion that cannot notice when it stops. The one line standing between
a plain reader and the ability to overwrite or clear the AI provider key has nothing behind it.

**Recommendation.** A `SettingsControllerTest` — there is none — asserting 403-for-reader on both
writing routes. `ApiTestBase` already provides `asReader()` and `asAdmin()`; the probe that produced
the numbers above is four lines long.

### 3.4 🟠 The AI review is absent from the STRIDE model, and eleven of its sixteen flows have no row

**Executed.** `grep -i "ollama\|LLM\|\bAI\b\|model review"` over
[`STRIDE_THREAT_MODEL.en.md`](../../architecture/security/en/STRIDE_THREAT_MODEL.en.md) and
[`02_security_view.md`](../../architecture/bflorat/en/02_security_view.md) returns **zero matches in
both**.

The model enumerates six external entities (E1–E6), five processes (P1–P5) and two data stores. The
model-review endpoint — an external destination that receives **the complete source of a scanned
repository**, secrets still committed in it included — is none of them. It is the single highest-value
flow in the product and it is not in the formal threat model at all. The working tree extends that
flow to a named third party under their own retention policy and jurisdiction, which makes the
omission harder rather than easier to defend.

Separately, the flow table is headed *"Data Flows in Transit (Data Flows: F1 to F16)"* and contains
**five rows**: F1/F2, F12/F14, F15. Eleven declared flows carry no threat and no mitigation. A
register that names sixteen and analyses five reads, at a glance, as sixteen analysed.

**Recommendation.** Add the model endpoint as **E7** with its own row (Information Disclosure —
source code to a third party; mitigations: the outbound guard, `INTERNAL_REQUIRED` by default, the
recorded acknowledgement), and either fill in F3–F11/F13/F16 or renumber the heading to what is
actually covered.

### 3.5 🟡 The scanner sandbox is asserted where it is built, and nowhere it is deployed

`ContainerRunner` sets `withCapDrop(Capability.values())`, `no-new-privileges`,
`withReadonlyRootfs(true)`, `network=none` unless requested, memory / nanoCPU / PID ceilings, and a
`noexec,nosuid` tmpfs. `ContainerHardeningTest` asserts each of them, and §2 proves it fails when
one is removed. That is solid.

What is not covered: nothing asserts the flags *survive to a running container*. The only test that
launches a real daemon, `ContainerRunnerIntegrationTest`, sits in `src/integrationTest` and is
outside `./gradlew build`. The gap is small but it is the same gap as `nightly.yml` on the wrong
branch: an assertion that exists in a source set nobody runs by default.

### 3.6 🟡 A hardcoded English string on a screen that is otherwise translated *(working tree)*

[`settings.ts:133`](../../../vectispire-angular/src/app/pages/settings/settings.ts) builds the
provider dropdown from literals — `'Ollama — a model on a host you run'`,
`'OpenAI-compatible API'` — while every other label two lines above goes through `this.i18n.t(…)`.
The French bundle has no key for them, so the French UI shows English.

**Not a finding:** the 52 keys present in `fr.json` and absent from `en.json` are *by design*.
[`settings.ts:379`](../../../vectispire-angular/src/app/pages/settings/settings.ts) reads
`translated !== key ? translated : setting.label` — English falls back to the server's own English
label, and only French needs an override. I checked this before writing it down, because the key
counts alone (609 vs 661) look exactly like a parity break.

---

## 4. What verified clean

Executed, and correct.

- **Cryptography.** AES-256-GCM through BouncyCastle, **12-byte nonce, 128-bit tag, context AAD,
  `v2:`-prefixed** — `SecretCipher.java:33-36,153-156`. Argon2id at **19 MiB, t=2, p=1**, PHC
  format with the parameters travelling in the hash — `PasswordHasher.java:40-45,72`, and
  `needsRehash` compares against the current cost rather than assuming it.
- **In transit to an agent.** `SealedEnvelope` is X25519 + HKDF + GCM (`X25519Agreement`,
  `HKDFBytesGenerator`), keyed to an ephemeral public key the agent publishes on registration
  (`AgentProtocol.java:103`) — the control plane is outside the secret's trust boundary.
- **Agent isolation.** `./gradlew :vectispire-agent:dependencies --configuration runtimeClasspath`
  lists 180 dependencies and **not one** JDBC driver, JPA, or Hikari. `grep` for `jdbc`,
  `ENCRYPTION_KEY`, `DataSource` over `vectispire-agent/src/main` returns nothing. This is the
  strongest form of the claim — not "we do not use it" but "it is not on the classpath".
- **Scanner sandbox.** Verified above; no Docker socket reaches a scanner. The control plane and the
  agent mount one (`docker-compose.yml:81,125`), which is what the sandbox exists to contain.
- **Compliance shape.** `ComplianceEngine` switches on **seven** categories
  (`ComplianceEngine.java:125-131`); `ComplianceFramework` declares **six** frameworks holding
  **24** `new ComplianceControl(` literals. One evaluator, six mappings — the README's framing is
  accurate. `cappedByPlatform` (`:148-170`) demotes SECRETS_MANAGEMENT, AUDIT_AND_LOGGING and
  GOVERNANCE when the underlying mechanism is off, so a control cannot be reported compliant on the
  strength of something switched off.
- **Supply chain.** CycloneDX, CSAF, OpenVEX, EPSS and reachability all present in main sources;
  SPDX appears in three files and only as the documented absence (ADR 0016).
- **Documentation.** 712 relative links, 0 broken. C4 diagram fingerprint identical to
  `workspace.dsl`. 12/12 markdown files in each language tree. ADRs 0001→0017 in both languages —
  the prompt still says "0001 to 0016"; **0017** (custom checks as container images) landed in
  `83461b3`.
- **Forge.** `git remote -v` → `git@github.com:asmolabs/vectispire.git`. `.gitlab-ci.yml` is **gone**
  from `develop` (removed in `3668dfe`) though still on `main`; the customer-facing template
  `ci/gitlab/vectispire-gate.gitlab-ci.yml` remains, correctly. The prompt's §5 paragraph about the
  archived root pipeline is now stale for this branch.

---

## 5. Verification that actually runs — 7.0, and what the 3.0 is

**Recovered.** `origin/main` carries `.github/workflows/nightly.yml` with `- cron: '30 2 * * *'`
and all four jobs (`databases`, `dockerfiles`, `e2e`, `restore`). `main` is **3 commits behind**
`develop`, not 75. The structural reason the nightly could not fire is gone.

**Still asserted rather than executed, and named as such:**

- **No run history was checked.** There is no `gh` CLI on this machine, so I cannot say when the
  pipeline was last green. Every statement here about CI is about *files*, not *runs*. The previous
  audit's central finding — a declared job is not a job that ran — is therefore **not re-verified**,
  only made structurally possible. This alone caps the domain below 8.
- **The restore drill did not run.** `scripts/restore-drill.sh` stops at step 0: `vectispire:latest`
  is not present locally. The drill is real and its assertions are real; on this machine it is
  unexecuted.
- **E2E is nightly-only.** The five Playwright specs run in `nightly.yml`, not `ci.yml`. A pull
  request merges without a browser ever opening.
- **`docs.yml` is on `develop` and not on `main`.** Harmless for a `push`-triggered workflow, worth
  knowing before someone adds a schedule to it.

**Recommendation, in order.** (1) Merge `develop` into `main` so the nightly runs the current tree.
(2) Record the first green run's URL and date in `docs/analysis/`, so the next audit can verify the
claim instead of inheriting it. (3) Move at least `AuthorizationCoverageTest`, `RouteScopingTest`
and the hardening suite into a required PR check if they are not already gating.

---

## 6. Recommendations, prioritised

| # | Finding | Action | How it was verified |
|---|---|---|---|
| 1 | §3.1 | Refuse `Sensitivity.SECRET` on `PUT /api/v1/settings`; one test per secret setting | **Executed** — MockMvc write + column read-back |
| 2 | §3.3 | `SettingsControllerTest`: 403-for-reader on both writing routes | **Executed** — guard removed, full core suite stayed green |
| 3 | §3.2 | Let the acknowledgement be withdrawn in one request; fix the message | **Executed** — four sequenced saves, statuses and bodies above |
| 4 | §3.4 | Add the model endpoint as E7; complete or renumber F1–F16 | **Executed** — `grep` over both documents, zero matches |
| 5 | §5 | Merge to `main`; record the first green run | **Asserted, not executed** — no run history available here |
| 6 | §3.5 | Run `integrationTest` in the nightly, or fold the container case into `build` | Read the source set layout; **not executed** |
| 7 | §3.6 | Route the two provider labels through `i18n.t` | **Executed** — key-set diff plus the fallback at `settings.ts:379` |

---

## 7. What this audit could not measure

Said plainly, because an audit that lists only what it found reads as an audit that looked
everywhere.

- **CI run history** — no `gh` CLI. Nothing here says a pipeline passed.
- **The multi-engine campaign.** PostgreSQL and MySQL were not booted; `SchemaParityIntegrationTest`
  and the rest of `integrationTest` did not run. The 1292 figure is the SQLite fixture.
- **The restore drill**, above.
- **Playwright.** The five specs were not executed; no browser opened during this audit.
- **`gitleaks`** — not installed on this machine. The baseline and config were read, not run.
- **Runtime container behaviour.** The sandbox flags were verified as *requested*, never as
  *enforced by a daemon*.

---

*Working tree state: this audit made three temporary mutations and added one probe test, all of them
reverted. `git status` at the end is byte-identical to `git status` at the start — verified by
`diff` against backups of each mutated file.*
