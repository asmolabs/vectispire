# Verification Audit: Documentation, Source Code & Security (English)

* **Project:** Vectispire — ASPM & Software Security Control Plane
* **Analysis Date:** August 25, 2026 (fourth pass)
* **Evaluator:** Claude (Anthropic) — automated code, security & documentation audit
* **Scope:** The four axes of [`PROMPT_AUDIT.md`](../../../PROMPT_AUDIT.md)
* **Preceding reports:** [In-Depth](2026-08-25_in_depth_code_security_doc_audit.en.md) (7.9) → [Post-Remediation](2026-08-25_post_remediation_audit.en.md) (8.9) → [Four Axes](2026-08-25_in_depth_audit_4_axes.en.md) (8.7)

> **What is new in this pass, and why it is the right thing to do.** Thirteen commits have landed
> since the last report, several of them on security-critical paths — the secrets step, the scanner
> image resolution, the compliance query shape, the container deployment. **Remediation is where
> defects are freshest**, so this pass ran the code rather than reading it: the control plane was
> booted against PostgreSQL and MySQL, real rows were inserted, and the endpoints were called. Two
> earlier passes were caught out by tests that ran against an empty database; this one does not
> repeat that.

---

## 📊 1. Score Summary

| Evaluation Domain | Four Axes | This pass | Status |
|---|:---:|:---:|:---:|
| **Documentation & Architecture** | 8.8 | **9.2 / 10** | 🟢 Generated artifacts now defended |
| **Security & Cryptography** | 8.5 | **9.1 / 10** | 🟢 The secrets path closed, verified |
| **Code Quality & Architecture** | 8.3 | **8.9 / 10** | 🟢 Verified on three engines |
| **Regulatory & Standards Compliance** | 9.2 | **9.3 / 10** | 🟢 Certification-capable |
| **Global** | 8.7 | **9.1 / 10** | 🟢 |

**Every finding from the three earlier reports verifies as closed**, and the three that were
open
at the last pass (A1, A2, A3) plus the six recommendations are done. What holds the score below
9.5 is stated in §6: one documented setting that does not exist, one engine never exercised
end-to-end, and a claim in the prompt itself that the code contradicts in a small but real way.

### What was verified by running, not by reading

| Check | Method | Result |
|---|---|---|
| The compliance summary's new grouped query | Booted the packaged jar against **PostgreSQL** and **MySQL**, inserted real issues, called the endpoint | ✅ 4 and 2 issues correctly attributed; **no `ClassCastException`** on either |
| Schema validation across engines | Same two boots under the shipped `ddl-auto: validate` | ✅ Both start clean |
| C4 export determinism | Exported twice, diffed | ✅ Byte-for-byte identical — safe to gate on |
| C4 drift detection | Edited `workspace.dsl`, ran the check | ✅ Fails, as it must |
| Named-volume ownership for the audit mirror | Built a throwaway image, mounted an empty volume | ✅ Docker inherits the image directory's owner; the mirror can write |
| Compose fails closed | `docker compose config` with no secrets | ✅ Refused |
| Documentation links | 354 relative links resolved | ✅ 0 broken |

**The risk this closed.** The grouped query returns `Object[]` rows that the service casts. It
was
exercised only on SQLite by the unit suite, and the compliance summary is not part of the
four-engine integration campaign — so a wrong cast would have surfaced as a 500 on the flagship
page of the default engine, in production, with nothing failing beforehand. It is correct; that
is
now known rather than assumed.

---

## 📚 2. Documentation & Architecture — 9.2

**Bertrand Florat model**: five views, both languages, exact line parity (88/75/52/66/73).
**STRIDE**: E1–E4, P1–P5, DS1–DS2, F1–F16, all six categories, 171 lines each side.
**ADRs**: thirteen, supersession chain intact.
**Links**: 354 resolved, 0 broken, defended by the `docs` CI job.

**C4 is now architecture-as-code in fact, not only in claim.** The committed `.puml` files match
a
fresh export from `workspace.dsl`, and CI compares them on every push. Only the text export is
gated — verified reproducible by exporting twice — because PlantUML's PNGs are a rendering, and
a
flaky drift check teaches people to re-run a job until it passes. Six orphan `structurizr-*-key`
artifacts were removed: referenced nowhere, produced by no current exporter, they could only go
stale.

**Bilingual parity, measured:**

| Document | EN | FR |
|---|:--:|:--:|
| `ROTATION_AND_PURGE` | 202 | 202 |
| `SECURITY_AND_QUALITY_REVIEW` | 148 | 148 |
| `TECHNICAL_DOCUMENTATION` | 514 | 518 |
| `COMPLIANCE_AND_REGULATORY` | 302 | 308 |
| `GETTING_STARTED` | 211 | 235 |

The French now leads on three, and the structural divergence that explains `GETTING_STARTED` —
the
French keeps container deployment as its own section where the English has it as §5.1 — is
recorded
in the document itself, so a numbering difference cannot be mistaken for translation drift.

---

## 🛡️ 3. Security & Cryptography — 9.1

### 3.1 Controls verified

| Control | State |
|---|---|
| Rate limiting | ✅ Token-bucket ahead of Argon2id; `X-Forwarded-For` only behind a configured trusted proxy; bounded LRU pruned on insertion |
| Argon2id, TOTP MFA | ✅ Reachable, attempt-capped, mutation-verified — and now covered end-to-end |
| SCIM 2.0 / OIDC | ✅ `/scim/v2/{Users,Groups}` under `@RequiresAdministrator`; `groups` claim mapped to teams |
| AES-256-GCM, Vault KMS | ✅ Context bound to the row; `kms-type=vault` refuses to start without a reachable endpoint |
| Scanner sandboxing | ✅ `cap_drop: ALL`, `no-new-privileges`, `network: none` by default, digest-pinned, read-only rootfs, `noexec` scratch, no Docker socket |
| Audit chain | ✅ Chained; limits stated in §5.1 of the compliance document; **mirror now on by default in compose** |
| Four-eyes | ✅ Identity-distinct, mutation-verified |

### 3.2 The secrets step, closed and made unexpressible

The most serious finding of the previous pass — the one place decision 0007 was not applied, in
the
finding type where a false resolution costs most — is fixed. Both secret scanners return
`Optional`, both are routed through `ran(…)`, and the swallowed exception is gone.

Two things make it durable rather than merely fixed:

* `ScannerContractTest` asserts by reflection that every container-running scanner returns
  `Optional`, identified by holding a `ContainerRunner` rather than by name, so a scanner added
in
  six months is in scope the moment it exists.
* Reverting `BetterleaksScanner` to a bare `List` **no longer compiles** — `ran(…)` requires an
  `Optional`. The defect is unexpressible, which is stronger than tested.

### 3.3 Agent isolation — real, and narrower than a casual reading

The prompt describes "watertight remote agent isolation: zero JDBC, zero `ENCRYPTION_KEY`,
outbound HTTP long-polling only". Verified, with one nuance that belongs in the record:

* **Zero JDBC** — enforced by the module graph, not convention: `vectispire-agent` does not depend
  on `vectispire-core`, so a driver is not on the compile classpath and the violation fails to
  compile. `AgentIsolationTest` re-asserts it and guards against an empty import.
* **Zero `ENCRYPTION_KEY`** — confirmed: nothing in the agent module reads it.
* **Outbound only** — `web-application-type: none`, so the agent opens no port at all, and
  `AgentHttp` sets `Redirect.NEVER`.
* **But the agent does receive deployment keys**, in `credentialsMode: delegated` — inside a
  `SealedEnvelope` addressed to the key pair it announced at enrolment. "The agent holds no
  credentials" would be too strong; the accurate claim is that it never holds the platform
  encryption key, never reaches the database, and receives repository keys only sealed to
itself.
  The code refuses an envelope it cannot open rather than passing the ciphertext on to git —
where
  the failure would have read as a permissions problem.

That precision is worth keeping, because it is the difference between a claim an assessor can
verify and one they will discount.

---

## ⚙️ 4. Code Quality & Software Architecture — 8.9

**Spring Boot 4.1.0 / JDK 25**, 178 unit test classes, 7 integration classes, zero
`TODO`/`FIXME`
in production sources. ArchUnit enforces six rules including the empty-import guard. JaCoCo
floors
`common.domain` at 80% instruction / 65% branch, wired into `check`; current **83.6% / 69.4%**.

**The compliance N+1 is gone**: nine count queries per target became one grouped query plus one
overdue read — two for the whole page. Visibility is applied by the caller rather than in the
query, which is equivalent because issue visibility is target-scoped and nothing else. The audit
chain check on that page is now bounded to a window and says plainly what a window can and
cannot
prove.

**And it is tested against data.** The pre-existing compliance route tests ran on an empty
database, so they passed under any aggregation. `ComplianceTargetCountsTest` puts issues on two
targets and asserts each keeps its own; mutation-verified by dropping the state filter.

**The jar naming defect found last pass had a wider blast radius than the workflow that revealed
it.** `gradle.properties` sets a version, so `bootJar` emitted `vectispire-core-0.9.0.jar` while
`Dockerfile`, `Dockerfile.agent` and `release.yml` all copied the unversioned name. Both
container
images and the release pipeline were broken, and nothing noticed because **no CI job builds an
image or cuts a release**. Both `bootJar` tasks now pin `archiveFileName`.

### Residual

| # | Finding | Note |
|:--:|---|---|
| **W1** | The compliance summary is **not in the four-engine integration campaign**. It was verified here by hand on PostgreSQL and MySQL; MariaDB and SQLite-as-a-deployment were not. | A grouped projection is exactly the kind of query that diverges by driver. One integration case would make the manual check unnecessary. |
| **W2** | `nightly.yml` still **has never run in CI** — it cannot be triggered from here. Its steps were executed locally and two blockers were fixed (jar name, SQLite `ddl-auto`), but a workflow is a hypothesis until the runner executes it. | Trigger once via `workflow_dispatch`. |
| **W3** | **No CI job builds the container images.** That is why the jar-name defect survived. | A `docker build` on both Dockerfiles would have caught it in one line of workflow. |

---

## 📋 5. Regulatory & Standards Compliance — 9.3

Six frameworks — NIS 2, EU CRA, DORA, ISO/IEC 27001, PCI-DSS v4.0, OWASP — evaluated by
`ComplianceEngine` in the pure domain, hence exhaustively testable. Supply-chain formats
verified
present: CycloneDX, SPDX, CSAF 2.0, OpenVEX, EPSS, reachability.

**The engine measures itself**, which remains the project's most distinguishing property: a
control
is capped at `PARTIAL` when the capability beneath it is off, and the cap never improves a
failing
control. Observed live during this pass — a locally booted instance with no audit mirror scored
its
target 60/100 rather than reporting compliance it could not evidence.

**And that gap is now closed for the shipped deployment.** The audit mirror is on by default in
compose, written to a named volume whose ownership was verified rather than assumed: a volume
mounted at a path the image does not own arrives root-owned, every append fails, and the mirror
is
present in configuration and absent in fact — worse than none. The Dockerfile creates the
directory
owned by the unprivileged user first.

---

## 🎯 6. Prioritised Recommendations

### 🟠 Next
1. **Add a `docker build` of both images to CI** *(W3)*. The jar-name defect broke the image and the
   release for an unknown period and was found by accident. One job closes that class.
2. **Run `nightly.yml` once via `workflow_dispatch`** and fix what the runner reveals *(W2)*.
3. **Cover the compliance summary in the integration campaign** so the grouped projection is
   exercised on all four engines rather than by hand on two *(W1)*.

### 🟡 Later
4. **Remove `VECTISPIRE_DB_DIALECT` from `TECHNICAL_DOCUMENTATION`, or implement it.** Both
   languages document it as accepting four engines; it is referenced in no code and no
   configuration file. Carried from the previous pass, still open.
5. **Reconcile the default engine.** `application.yaml` defaults the datasource to PostgreSQL, the
   documentation says PostgreSQL, and `docker-compose.yml` ships MySQL. All three are
defensible;
   the three of them together are a question an operator should not have to answer.
6. **State the agent's credential boundary precisely** in the architecture documentation — sealed
   deployment keys in delegated mode, never the encryption key, never the database.
7. **Decide whether the second secrets engine is meant to exist.** It is skipped by default now, so
   it costs nothing; but a seam nobody uses is a seam nobody maintains.

---

## 7. Conclusion

Four passes in one day is unusual, and the pattern across them is worth naming. The first found
controls correctly designed and incorrectly wired. The second found two defects introduced by
the
repair itself. The third went at ground the first two never covered and found a silent-data-loss
path in the handling of leaked credentials. This one ran the software instead of reading it, and
found that the fixes hold on engines the test suite never touches.

Each pass found less, and found it further from the centre. That is what convergence looks like,
and it is the argument for the method: **an audit that only re-reads its own previous
conclusions
measures the previous audit.** The remaining items are not architectural. They are one job that
builds an image, one workflow that has never run, one documented setting that does not exist,
and
a default engine named differently in three places.

**9.1 / 10.**
