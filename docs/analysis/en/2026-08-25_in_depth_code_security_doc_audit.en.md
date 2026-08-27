# In-Depth Audit Report: Documentation, Source Code & Security (English)

* **Project:** Vectispire — ASPM & Software Security Control Plane
* **Analysis Date:** August 25, 2026
* **Evaluator:** Claude (Anthropic) — automated code, security & documentation audit
* **Method:** Direct source reading and mechanical verification (link resolution, parity measurement, CI task graph inspection, filter-chain reconstruction). Every claim below cites the file that supports it.
* **Scope:** Backend (`vectispire-java`), Frontend (`vectispire-angular`), Documentation (`docs/`), Architecture (`docs/architecture/`), CI (`.github/workflows/`), Deployment (`Dockerfile`, `docker-compose.yml`)

> **Reading note.** This audit deliberately re-verifies rather than reconfirms. Where the previous report ([August 24, 2026](2026-08-24_in_depth_code_security_doc_audit.en.md)) described an intended design, this one checks whether the code enforces it. Several controls that are correctly *designed* are not correctly *wired*, and the scores below reflect the wiring, not the intent.

## ✅ 0. Remediation Status

**The four 🔴 items of §6 were fixed on August 25, 2026 in commit `a9ad6fd`, after this audit was written.** The findings below are left exactly as they were reported — an audit is a record of what was true when it ran, not a live dashboard — and this section is the only thing added.

| # | Finding | Status |
|:--:|---|---|
| **F1** | `/api/v1/auth/mfa/verify` unreachable through the filter chain | ✅ `permitAll` added, plus an anonymous probe through the real chain for every `@OpenToAnonymous` route (`anOpenRouteIsReallyReachableWithoutCredentials`). Verified by mutation. |
| **§3.3** | TOTP brute force unthrottled | ✅ Three attempts per challenge, challenge destroyed on the last failure, expired challenges swept on write and the map capped. New `MfaVerificationRoutesTest`. |
| **F2** | Login rate limiter bypassable by `X-Forwarded-For`, unbounded map | ✅ Header honoured only behind `vectispire.security.trusted-proxies`; bounded LRU pruned on insertion; scope widened to the anonymous auth routes. |
| **§3.5** | `docker-compose.yml` shipping working secrets | ✅ The three secrets are required rather than defaulted, MySQL binds to loopback, `group_add` grants the socket group. `.env.example` carried the same values and was rewritten. |

**The five 🟠 items were fixed in the same session.**

| # | Finding | Status |
|:--:|---|---|
| **F3 / §2.2** | 53 of 305 relative links broken | ✅ All repaired (`decisions/` moved into `en/`+`fr/`, plus depth corrections). `scripts/check-doc-links.py` now runs as a CI job, so the count stays at zero. |
| **§2.2** | Four `file:///Users/lrb/...` paths in the STRIDE models | ✅ Replaced with relative paths. The checker treats any `file://` link as broken, so they cannot come back. |
| **§4.2** | `integrationTestAll` and Playwright never run in CI | ✅ `.github/workflows/nightly.yml` runs both at 02:30 UTC, plus `workflow_dispatch`. The E2E job now boots the control plane, which Playwright's `webServer` does not do. |
| **§3.4** | Four-eyes is role-based, not identity-based | ✅ The approver is compared against the requester recorded on the `PENDING_APPROVAL` event. Verified by mutation: without the check, self-approval succeeds with 200. |
| **§3.6** | Vault KMS falls back to a local key on a WARN | ✅ `kms-type=vault` without a reachable endpoint or token now refuses to start, rather than silently changing key custody. |

**The five 🟡 items were fixed in the same session, which closes every finding in §6.**

| # | Finding | Status |
|:--:|---|---|
| **§2.3** | FR/EN parity absent on the operational corpus | ✅ `ROTATION_AND_PURGE.fr` 37 → 202 lines (parity), `TECHNICAL_DOCUMENTATION.fr` 212 → 518, `COMPLIANCE_AND_REGULATORY.md` 204 → 262 (the reconciliation ran the other way, as the audit said it must), `GETTING_STARTED.fr` 126 → 187. |
| **§4.2** | No coverage instrumentation | ✅ JaCoCo XML reports, plus a `jacocoTestCoverageVerification` floor scoped to `common.domain` (80% instruction, 65% branch) wired into `check`. Verified by mutation: raising the floor fails the build at the measured 0.83. |
| **§3.7** | Scanner container root filesystem writable | ✅ `withReadonlyRootfs(true)` plus `noexec` tmpfs scratch for `/tmp` and `$HOME`. Validated against all five pinned scanner images on a real daemon, and asserted by four new cases in the container integration campaign. |
| **§3.7** | Anonymous Swagger exposure not configurable | ✅ `vectispire.security.anonymous-api-docs`, closed by default. The first attempt looked like it worked and did not — the SPA deep-link rule was matching `/v3/api-docs` first. |
| **§2.4** | Residual "changelog" vocabulary | ✅ Replaced with "migration" across README, CI, Gradle and `application.yaml`; `ChangelogTest` renamed `MigrationsTest`. |

**One thing measured rather than assumed.** Grype's vulnerability database is ~1.9 GB and the
scratch tmpfs is memory counted against a 2 GB container ceiling, so read-only rootfs broke it
outright with `no space left on device`. It now gets a disk-backed writable mount for that cache
alone. Had this shipped on the strength of the code review, every dependency scan would have
failed.

### The two §5 caveats, closed

| Caveat | Status |
|---|---|
| CRA Art. 10 / DORA evidence rested on unwired controls | ✅ Root cause addressed, not just the controls. `ComplianceEngine` measured the fleet and never the control plane: an instance with no encryption key scored 100/100 on `DORA-ART13-SECRETS`, because that control only counted secrets Gitleaks found in *other people's* repositories. A `PlatformPosture` input now carries what this deployment has switched on, and a control is capped at **PARTIAL** when the capability underneath it is off — secrets without an encryption key, audit without a mirror, governance without four-eyes. The cap never improves a failing control. |
| The audit trail's strongest property was under-claimed | ✅ §5.1 of the compliance document, in both languages, states what the chain proves, what it does not (leaf deletion is undetectable), why that concession was taken, and that the audit mirror closes it. The engine now reports it too rather than leaving it to the reader. |

**On detecting a leaf deletion.** The capability already existed and nothing pointed at it:
`verifyAgainstMirror()` returns `missingFromTable`, which *is* the deleted-leaf case. An
in-database checkpoint was considered and rejected — whoever can write the audit table can rewrite
a checkpoint table consistently, so it moves the problem one level up while looking like evidence.
The defect was never the missing mechanism; it was that the mechanism's absence was invisible.

---

---

## 📊 1. Executive Summary & Scores

| Evaluation Domain | Score / 10 | Status | Assessment Summary |
|---|:---:|:---:|---|
| **Documentation & Architecture** | **7.5 / 10** | 🟡 **Excellent structure, degraded integrity** | Bertrand Florat 5-view model, C4 DSL, STRIDE DFD and 13 ADRs are genuinely present and of rare quality — but **53 of 210 relative links are broken (25%)**, bilingual parity is measurably absent on 4 documents, and two files ship absolute `file:///Users/...` paths. |
| **Security & Cryptography** | **7.0 / 10** | 🟠 **Strong design, three wiring defects** | Argon2id, AES-256-GCM, Vault KMS, digest-pinned sandboxed scanners and a SHA-256 audit chain are real and well built. Against that: **MFA verification is unreachable through the filter chain**, the login rate limiter trusts an unauthenticated `X-Forwarded-For`, and the four-eyes gate is role-based rather than identity-based. |
| **Code Quality & Architecture** | **8.5 / 10** | 🟢 **Enterprise Ready** | ArchUnit enforces six real layering rules, the domain is provably framework-free, zero `TODO`/`FIXME` in production sources, 176 test classes, 4×14 dialect-native Flyway migrations. Weakened by: no coverage tooling, and the two most expensive suites never run in CI. |
| **Regulatory & Standards Compliance** | **8.5 / 10** | 🟢 **Certification-capable** | CRA, NIS 2, DORA and OWASP control catalogues are implemented as code, with CycloneDX 1.6, SPDX 2.3, CSAF 2.0, OpenVEX and EPSS support. The evidence chain is sound; the control gaps above are what a CRA/DORA assessor would challenge. |
| **Global** | **7.9 / 10** | 🟢 **Solid, with three items to fix before a release** | |

### The three findings that matter

| # | Finding | Severity | Evidence |
|:--:|---|:--:|---|
| **F1** | `POST /api/v1/auth/mfa/verify` is annotated `@OpenToAnonymous` but is **not** `permitAll`-ed in the filter chain, so `anyRequest().authenticated()` answers **401** to the anonymous caller that the MFA flow requires. Any account with MFA enabled cannot complete sign-in. | 🔴 **Critical** | [AuthController.java:171](../../../vectispire-java/vectispire-core/src/main/java/com/asmolabs/vectispire/core/api/AuthController.java) vs [SecurityConfiguration.java:154](../../../vectispire-java/vectispire-core/src/main/java/com/asmolabs/vectispire/core/api/security/SecurityConfiguration.java) |
| **F2** | The login rate limiter keys its buckets on an unvalidated `X-Forwarded-For` header, and its eviction runs **only on the rejection path**. A single client rotating that header both bypasses the limit entirely and grows an unbounded `ConcurrentHashMap`. | 🟠 **High** | [LoginRateLimitFilter.java:70](../../../vectispire-java/vectispire-core/src/main/java/com/asmolabs/vectispire/core/api/security/LoginRateLimitFilter.java) |
| **F3** | Documentation link integrity: 53 broken relative links, concentrated on `docs/architecture/decisions/` paths that moved into `en/` and `fr/` subtrees. | 🟠 **High** | Mechanically verified across all 210 relative Markdown links |

---

## 📚 2. Documentation & Architecture

### 2.1 What is genuinely exemplary

1. **Bertrand Florat Architecture Model** — [`docs/architecture/bflorat/`](../../architecture/bflorat/README.md) carries all five self-contained views in both languages, at **strict line-for-line parity** (88/88, 74/74, 52/52, 66/66, 73/73). This is the best-maintained part of the corpus.
2. **C4 architecture-as-code** — [`workspace.dsl`](../../architecture/c4/workspace.dsl) models three C4 levels, with committed PlantUML and PNG renderings under [`c4/diagrams/`](../../architecture/c4/) and a generator script at [`scripts/generate-c4-diagrams.sh`](../../../scripts/generate-c4-diagrams.sh).
3. **Formal STRIDE threat model** — [EN](../../architecture/security/en/STRIDE_THREAT_MODEL.en.md) / [FR](../../architecture/security/fr/STRIDE_THREAT_MODEL.fr.md), 171 lines each, at exact parity, covering entities, processes, data stores and 16 data flows.
4. **13 ADRs, with a live supersession chain** — [ADR 0011 (Liquibase)](../../architecture/en/decisions/0011-liquibase-rather-than-flyway.md) is correctly marked *superseded* by [ADR 0013 (Flyway multi-dialect)](../../architecture/en/decisions/0013-flyway-multi-dialect-migrations.md), in both languages. A superseded ADR that still claims to be current is the usual failure of an ADR registry, and it is avoided here.
5. **Comment quality as architecture documentation.** The prose inside [`AuditChain.java`](../../../vectispire-java/vectispire-common/src/main/java/com/asmolabs/vectispire/common/domain/audit/AuditChain.java) — including an explicit section titled *"What this no longer detects, and it has to be said"* — is a standard of intellectual honesty this audit found nowhere else in the corpus and considers the project's single strongest documentation asset.

### 2.2 Link integrity — 53 of 210 relative links are broken (25%)

Every relative Markdown link in the repository was resolved against the filesystem. The failures cluster into four causes:

| Cause | Count | Example |
|---|:--:|---|
| `docs/architecture/decisions/` referenced at the old, pre-bilingual path | ~30 | [`README.md`](../../../README.md) → `docs/architecture/decisions/0010-one-scan-runner.md` (now under `en/`) |
| Wrong depth after the `docs/en/` + `docs/fr/` reorganisation | ~15 | [`docs/en/TECHNICAL_DOCUMENTATION.md`](../../en/TECHNICAL_DOCUMENTATION.md) → `../vectispire-java/...`, which resolves to `docs/vectispire-java/...` |
| `decisions/…` referenced from `bflorat/` and `security/`, where no `decisions/` directory exists | 6 | [`04_infrastructure_view.md`](../../architecture/bflorat/en/04_infrastructure_view.md) → `decisions/0013-…` |
| Absolute local paths leaked into shipped documents | 4 | Both STRIDE files contain `file:///Users/lrb/Dev/Asmolabs/vectispire/…` |

The last row is the one to fix first: a published threat model that carries an auditor's home directory is both a broken link and an information leak.

### 2.3 Bilingual parity is asserted but not achieved

The claim of "strict bilingual synchronisation" holds for `bflorat/`, STRIDE, the API reference and `docs/architecture/{en,fr}/`. It does **not** hold for the operational corpus:

| Document | EN (lines) | FR (lines) | Gap |
|---|:--:|:--:|---|
| `ROTATION_AND_PURGE` | 202 | 37 | **FR is 82% shorter** — a stub against a full procedure |
| `TECHNICAL_DOCUMENTATION` | 513 | 212 | **FR is 59% shorter** |
| `GETTING_STARTED` | 203 | 118 | FR 42% shorter |
| `COMPLIANCE_AND_REGULATORY` | 204 | 263 | **EN 22% shorter** — the divergence runs both ways |
| `01-overview` | 112 | 95 | EN ahead |

The French content that exists is genuine translation, not machine filler ([`ROTATION_AND_PURGE.fr.md`](../../fr/ROTATION_AND_PURGE.fr.md) reads as native French) — the deficit is coverage, not quality. For a product sold on regulatory traceability into a Francophone market, a French rotation-and-purge procedure that is 18% of the English one is a compliance-evidence gap, not a translation backlog.

### 2.4 Residual Liquibase vocabulary

[ADR 0013](../../architecture/en/decisions/0013-flyway-multi-dialect-migrations.md) moved the project from Liquibase to Flyway, but the word *changelog* survives in the place that defines the rule — [`application.yaml:14`](../../../vectispire-java/vectispire-core/src/main/resources/application.yaml) (*"The schema belongs to the changelog"*) and [`README.md:446`](../../../README.md). Cosmetic, but it is exactly the kind of drift ADR 0013 exists to prevent.

---

## 🛡️ 3. Security & Cryptography

### 3.1 F1 — MFA verification is unreachable (🔴 Critical)

[`AuthController.verifyMfa`](../../../vectispire-java/vectispire-core/src/main/java/com/asmolabs/vectispire/core/api/AuthController.java) is annotated `@OpenToAnonymous` and is called by the SPA at [`api.service.ts:524`](../../../vectispire-angular/src/app/core/api.service.ts) with no bearer token — correctly, since the token is exactly what the call is trying to obtain.

But the filter chain in [`SecurityConfiguration.apiSecurity`](../../../vectispire-java/vectispire-core/src/main/java/com/asmolabs/vectispire/core/api/security/SecurityConfiguration.java) `permitAll`s `/api/v1/auth/login`, `/auth/methods` and `/auth/session/exchange` — **and not `/auth/mfa/verify`**. It therefore falls through to `anyRequest().authenticated()`, and Spring Security's `authenticated()` rejects the anonymous authentication token. The endpoint answers **401 before the controller is ever entered**.

**Consequence:** every account with `mfaEnabled` is locked out. Step 1 returns an `mfa_token`; step 2 cannot be called.

**Why no test catches it.** [`RouteAuthorizationTest`](../../../vectispire-java/vectispire-core/src/test/java/com/asmolabs/vectispire/core/api/RouteAuthorizationTest.java) enumerates the `@OpenToAnonymous` **annotations** and asserts the set — `/api/v1/auth/mfa/verify` is listed at line 104 and the suite is green. The one thing it does not do is issue an unauthenticated request through the real chain, which is precisely the divergence at issue. This is the audit's clearest example of a test that proves a rule is *stated* rather than *enforced* — the failure mode `ArchitectureTest` explicitly guards against elsewhere in this codebase.

Note also that the suite's own comment says *"The three below are the ways in"* while the assertion lists six — the comment stopped tracking the list.

**Fix:** add `.requestMatchers("/api/v1/auth/mfa/verify").permitAll()`, and add a MockMvc probe asserting that each `@OpenToAnonymous` route returns something other than 401 without credentials.

### 3.2 F2 — The login rate limiter is bypassable and unbounded (🟠 High)

[`LoginRateLimitFilter`](../../../vectispire-java/vectispire-core/src/main/java/com/asmolabs/vectispire/core/api/security/LoginRateLimitFilter.java) is well-placed — registered before `UsernamePasswordAuthenticationFilter`, so it fires ahead of any Argon2id derivation, which is the correct design for CPU-exhaustion defence. Three defects in the implementation:

1. **Spoofable key.** `resolveClientIp` returns the first element of `X-Forwarded-For` whenever the header is present, with no trusted-proxy check. An attacker sets `X-Forwarded-For: <random>` per request and receives a fresh 10-token bucket every time. The rate limit is a no-op against anyone who has read the source — which, for an Apache-2.0 project, is everyone.
2. **Eviction that never runs.** `evictOldBucketsIfNecessary()` is called **only inside the `!probe.isConsumed()` branch**. In the attack above no request is ever rejected, so eviction is never reached and `buckets` grows without bound — turning the anti-DoS control into a memory-exhaustion vector.
3. **Global reset as the eviction strategy.** When it does fire, `buckets.clear()` discards *every* tracked IP, including legitimately throttled attackers.

**Fix:** honour `X-Forwarded-For` only from a configured trusted-proxy list (or delegate to `ForwardedHeaderFilter` with `server.forward-headers-strategy`), falling back to `getRemoteAddr()`; move the eviction call onto the admission path; and replace `clear()` with a bounded LRU or a Caffeine cache with expiry.

### 3.3 TOTP brute force is unthrottled (🟠 High — latent behind F1)

`verifyMfa` applies **no attempt counter**, and a failed code does **not** invalidate the challenge: `mfaChallenges.remove` runs on success only. The challenge lives 300 seconds. An attacker holding valid credentials can therefore replay a 6-digit code against a 5-minute window at whatever rate the server sustains — and `/mfa/verify` is outside the rate limiter's single-path scope. This is currently masked by F1; **fixing F1 without fixing this converts a lockout into an MFA bypass**, so the two must ship together.

The `mfaChallenges` map is also an unbounded in-memory `ConcurrentHashMap` with no sweep for expired entries, and it is per-instance — MFA sign-in breaks behind a load balancer without sticky sessions, in a `STATELESS` chain that otherwise has no affinity requirement.

**Fix:** cap attempts per challenge (3), destroy the challenge on the last failure, sweep on write, and extend the rate limiter to cover the whole `/api/v1/auth/**` prefix.

### 3.4 Four-eyes approval is role-based, not identity-based (🟡 Medium)

[`IssueTriageService.resolveRequest`](../../../vectispire-java/vectispire-core/src/main/java/com/asmolabs/vectispire/core/services/IssueTriageService.java) downgrades `NOT_AFFECTED` to `PENDING_APPROVAL` when the actor lacks `Role.canApproveTriage`, and `canApprove` is derived purely from the caller's role at [`IssuesController.java:306`](../../../vectispire-java/vectispire-core/src/main/java/com/asmolabs/vectispire/core/api/IssuesController.java).

Nothing compares the approver's identity to the requester's. A Security Champion can raise an exemption and approve it in the same call, and an approver acting alone bypasses the queue entirely. That is a **maker-checker role gate**, which is a real control — but it is not four-eyes, and DORA Art. 9 / NIS 2 Art. 21 assessors read the term literally.

**Fix:** reject an approval whose `triagedBy` equals the `PENDING_APPROVAL` event's actor, and rename the setting to what it enforces.

### 3.5 Deployment defaults ship live secrets (🟡 Medium)

[`docker-compose.yml`](../../../docker-compose.yml) defaults `ENCRYPTION_KEY` to `dGVzdC1lbmNyeXB0aW9uLWtleS0zMi1ieXRlcyEh` (base64 for `test-encryption-key-32-bytes!!`), `VECTISPIRE_BOOTSTRAP_PASSWORD` to `AdminVectispire2026!`, and the database password to `vectispire_secure_db_pass`. A `docker compose up` with no `.env` produces a running instance whose every stored SSH deployment key and integration token is decryptable by anyone holding a copy of this public repository. It also publishes PostgreSQL on host `5432`.

Separately, [`Dockerfile:76`](../../../Dockerfile) correctly documents that the unprivileged `vectispire` user must be granted the host Docker socket group via `--group-add` — but `docker-compose.yml` mounts the socket **without** a `group_add:` entry, so the shipped compose file starts a control plane that cannot launch a single scanner.

**Fix:** drop the `:-` defaults for the three secrets and fail fast on absence; bind PostgreSQL to `127.0.0.1`; add `group_add: [docker]`.

### 3.6 The KMS fails open (🟡 Medium)

[`EncryptionService`](../../../vectispire-java/vectispire-core/src/main/java/com/asmolabs/vectispire/core/services/EncryptionService.java) logs `"Vault KMS requested but missing endpoint or token. Falling back to local encryption."` and continues. An expired Vault token at boot silently moves every subsequent write from Transit-managed keys to a local scrypt-derived key — a change of key custody announced only in a WARN line. A control that degrades silently is a control that is not audited.

**Fix:** when `kmsType=vault` is explicitly configured, refuse to start without a reachable Transit endpoint.

### 3.7 What is genuinely well built

- **Scanner sandboxing is real and closed-by-default.** [`ContainerRunner.run`](../../../vectispire-java/vectispire-common/src/main/java/com/asmolabs/vectispire/common/scanning/ContainerRunner.java) applies `withCapDrop(Capability.values())`, `no-new-privileges`, a memory cap, a PID cap, and `NetworkMode = "none"` unless the scanner explicitly asks. [`ContainerRun.of`](../../../vectispire-java/vectispire-common/src/main/java/com/asmolabs/vectispire/common/scanning/ContainerRun.java) makes the restrictive shape the default and `withNetwork()` / `runningAsRoot()` deliberate opt-ins. No Docker socket is mounted into a scanner. *Precision:* the container root filesystem is **not** `read_only` — only the bind mounts carry `:ro`. Adding `withReadonlyRootfs(true)` plus a `tmpfs` scratch would close the last gap.
- **Scanner images are digest-pinned** — six `sha256:` references in [`ScannerImages.java`](../../../vectispire-java/vectispire-common/src/main/java/com/asmolabs/vectispire/common/scanning/scanners/ScannerImages.java), and CI reuses the same digests rather than `:latest`.
- **Agent isolation is enforced by the module graph and re-asserted by a test.** [`AgentIsolationTest`](../../../vectispire-java/vectispire-agent/src/test/java/com/asmolabs/vectispire/agent/AgentIsolationTest.java) forbids `java.sql`, `jakarta.persistence`, `org.springframework.data`, Flyway, Liquibase and all of `core` on the agent classpath — and asserts the import is non-empty first, so a renamed package cannot silently empty the rule.
- **The audit chain is honest about its own limits.** `AuditChain.verifyChain` documents that a leaf-node deletion is undetectable and explains why that trade was taken (concurrent writers forking the chain produced false alarms). The NUL field separator and millisecond-canonical timestamps are correct hardening.
- **SSRF is centralised.** `ArchitectureTest.onlyTheOutboundDoorSpeaksHttpOutwards` forbids every class outside `PinnedHttpSender` / `OutboundPost` / `OutboundJson` from holding an HTTP client, matched on the fully-qualified name so anonymous inner classes count — and the rule's comment states plainly that `03-security.md` claimed this rule existed for as long as it did not.
- **CSP is well reasoned**, `frame-ancestors 'none'`, no `unsafe-eval`, with the absence of HSTS explicitly justified.

**One exposure to weigh:** `/v3/api-docs/**` and `/swagger-ui/**` are `permitAll`. For a control plane that inventories other people's attack surface, publishing its own complete endpoint catalogue to anonymous callers is a deliberate choice that should be a documented setting rather than a constant.

---

## ⚙️ 4. Code Quality & Software Architecture

### 4.1 Backend

**Spring Boot 4.1.0 / JDK 25 confirmed** ([`libs.versions.toml`](../../../vectispire-java/gradle/libs.versions.toml)), three modules, 585 Java sources, **176 test classes**, and **zero `TODO`/`FIXME` in production sources** — an unusually clean tree.

[`ArchitectureTest`](../../../vectispire-java/vectispire-core/src/test/java/com/asmolabs/vectispire/core/ArchitectureTest.java) enforces six rules, not one: the six-layer stack, domain purity (no Spring, JPA, Hibernate, JDBC, Flyway, Liquibase **or docker-java**), SQL confined to repositories, the outbound-HTTP door, entity purity — and, first, an assertion that classes were imported at all, which is the failure mode that makes an architecture suite pass vacuously. That guard appears in both architecture suites. It is the mark of someone who has been burned by a green suite before.

The dependency file also pins `httpclient5` / `httpcore5` **above** the Spring Boot BOM to clear three named GHSAs, with an instruction to remove the override once the BOM catches up — supply-chain hygiene applied to the project's own supply chain.

### 4.2 The two most expensive suites never run in CI

- **Four-engine integration campaign.** `integrationTestAll` ([`build.gradle.kts:207`](../../../vectispire-java/vectispire-core/build.gradle.kts)) fans out over PostgreSQL, MariaDB, MySQL and SQLite via Testcontainers, and 14 dialect-native Flyway scripts exist per engine (56 files). It is **not wired into `check`**, and [`ci.yml`](../attic/github-workflows/ci.yml) runs only `./gradlew build`. **To the project's credit, the CI file says so in a comment headed *"Point 3 is not run here, deliberately, and that is a gap worth naming"*, noting the suite caught five engine divergences during the port.** That is the right way to disclose a gap — but a portability regression still ships silently between manual runs.
- **Playwright E2E.** Four suites exist (`auth`, `four-eyes-approval`, `settings-audit`, `vex-triage`) and `test:e2e` is defined — but `playwright` appears nowhere in either workflow. The E2E suites are documentation of intent, not a gate. Note that `auth.spec.ts` contains no MFA coverage, which is the second reason F1 went undetected.
- **No coverage instrumentation at all** — no JaCoCo, no Istanbul threshold. With 176 test classes the coverage is probably good; nothing measures or defends it.

**Fix:** a nightly (not per-PR) workflow running `integrationTestAll` and `playwright test`, plus JaCoCo with a floor on `common.domain`, the layer the whole architecture argues is the one that must be exhaustively tested.

### 4.3 Frontend

Angular 21 confirmed, npm workspaces with a single root lockfile and `npm ci` in CI, `openapi-typescript` generating the client from `openapi.json` — the right way to keep DTOs honest. 15 `.spec.ts` files against 70 sources suggests unit coverage is the thinner half of the test strategy. Angular packages are declared as `^21` floating ranges; the lockfile makes builds reproducible, so this is a note rather than a defect.

---

## 📋 5. Regulatory & Standards Compliance

[`ComplianceFramework`](../../../vectispire-java/vectispire-common/src/main/java/com/asmolabs/vectispire/common/domain/compliance/ComplianceFramework.java) is a real control catalogue expressed as code, not a marketing table: NIS 2 Art. 21 (`VULN`, `SUPPLY`, `CRYPTO`, `GOV`), EU CRA Art. 10–11 (`SBOM`, `LIFECYCLE`, `VULN`, `NOTIF`), DORA Art. 9/11/13/16, and OWASP — evaluated by `ComplianceEngine` in the pure domain layer and therefore exhaustively testable ([`ComplianceEngineTest`](../../../vectispire-java/vectispire-common/src/test/java/com/asmolabs/vectispire/common/domain/compliance/ComplianceEngineTest.java)). Supply-chain interoperability (CycloneDX 1.6, SPDX 2.3, CSAF 2.0, OpenVEX, EPSS, reachability) is backed by dedicated domain packages and route tests.

Two caveats an assessor would raise:

1. **CRA Art. 10 / DORA evidence rests on controls this audit found unwired.** `DORA-ART13-SECRETS` is undermined by §3.5, and any four-eyes attestation is undermined by §3.4.
2. **The audit trail's strongest property is under-claimed.** `AuditChain` cannot detect leaf deletion — stated plainly in the code, absent from the compliance documentation. Better to state it there too: an assessor who finds it themselves discounts everything else.

---

## 🎯 6. Recommendations, Prioritised

### 🔴 Before the next release — **done, see §0**
1. **`permitAll` `/api/v1/auth/mfa/verify`**, and add an anonymous MockMvc probe for every `@OpenToAnonymous` route so annotation and chain can never diverge again *(§3.1)*.
2. **Cap TOTP attempts per challenge and destroy the challenge on final failure** — ship with item 1, never after it *(§3.3)*.
3. **Validate `X-Forwarded-For` against a trusted-proxy list, move eviction onto the admission path, replace `clear()` with a bounded LRU** *(§3.2)*.
4. **Remove the default `ENCRYPTION_KEY`, bootstrap password and database password from `docker-compose.yml`; add `group_add: [docker]`; bind PostgreSQL to loopback** *(§3.5)*.

### 🟠 Next iteration — **done, see §0**
5. **Fix all 53 broken links** — a one-time `docs/architecture/decisions/` → `docs/architecture/{en,fr}/decisions/` rewrite plus depth corrections — and **add the link checker to CI** so the count stays at zero *(§2.2)*.
6. **Strip the four `file:///Users/lrb/...` paths from both STRIDE documents** *(§2.2)*.
7. **Nightly workflow: `integrationTestAll` + `playwright test`** *(§4.2)*.
8. **Enforce identity-distinct four-eyes**, or rename the control *(§3.4)*.
9. **Fail fast when `kmsType=vault` cannot reach Transit** *(§3.6)*.

### 🟡 Backlog — **done, see §0**
10. Bring `ROTATION_AND_PURGE.fr` (37 vs 202 lines) and `TECHNICAL_DOCUMENTATION.fr` (212 vs 513) up to parity; reconcile `COMPLIANCE_AND_REGULATORY` in the other direction *(§2.3)*.
11. Add JaCoCo with a coverage floor on `common.domain` *(§4.2)*.
12. Add `withReadonlyRootfs(true)` + `tmpfs` scratch to scanner containers *(§3.7)*.
13. Make anonymous Swagger exposure a setting *(§3.7)*.
14. Replace the residual "changelog" vocabulary with "migration" *(§2.4)*.

---

## 7. Conclusion

Vectispire is a genuinely well-architected system. The layering is enforced rather than described, the domain is provably pure, scanner isolation is closed-by-default, the agent's inability to reach the database is a property of the module graph rather than a convention, and the code comments hold to a standard of self-criticism — including, in the CI file and in `AuditChain`, disclosing the project's own gaps — that this audit rates above the average of its industry.

What the previous evaluation missed is that several of these controls are correctly *designed* and incorrectly *wired*. MFA is unreachable, the rate limiter is bypassable by header, four-eyes is role-based, and a quarter of the documentation's links do not resolve. None of these is an architectural flaw; all four are a day's work. The **7.9 / 10** reflects a codebase whose ceiling is very high and whose current state has four things standing between it and that ceiling.
