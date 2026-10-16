# Plan: Porting the Control Plane to Rust

**Date:** 2026-10-16 · **Status:** proposal, no code · **Scope:** `vectispire-core` and the part of
`vectispire-common` the agent port does not already cover · **Target schema and contract:** the 0.11.1
line (`release/0.11.1-merge` b8bd7e8d0: Flyway V1–V91, `openapi.json` with 245 paths)

This plan is the step before any code. It measures what there is to port, fixes what must not change,
chooses the libraries, picks a migration strategy and a test oracle, and ends with a Phase 0 and Phase 1
task list that parallel agents can execute. It builds on the agent study
("Study: Porting the Remote Agent to Rust", 2026-10-16, on branch `docs/rust-agent-study`) and on the agent port under way
in `vectispire-rust/` (branch `feat/rust-agent`: crates `agent`, `protocol`, `crypto`, `git`,
`container`, `scanners`, `domain`, `tls`, `testkit`). The control plane joins that workspace.

## 0. What was decided before, and why this is different

On 2026-09-10 a port of this backend to NestJS was costed at **53 to 69 developer-weeks** and abandoned
the same day. Two security properties are enforced by the compiler here — the agent's isolation from the
database by the build graph ([0003](../../architecture/en/decisions/0003-long-polling-for-agents.md))
and the layering checked on the import graph — and in Node both degrade into conventions. The Java code
is itself the port of an earlier NestJS implementation, whose defects the decision register records.

Rust removes that objection: crate boundaries and `pub(crate)` enforce what Gradle modules, ArchUnit and
Spring Modulith enforce today, at least as strictly, and at compile time rather than in a test. **What
does not change is the cost.** The backend is large, its value is in its tests and its decision register,
and every defect those record must be carried over rather than rediscovered. The estimate below is larger
than the NestJS one, not smaller.

## 1. Inventory (measured on b8bd7e8d0)

Lines are non-blank, non-comment lines of Java. This codebase is comment-heavy by design; the comments
carry reasoning that the port must keep.

### 1.1 Size

| | Main files | Main lines | Test files |
|---|---|---|---|
| `vectispire-core` | 778 | 66,236 | 383 (+49 integration) |
| `vectispire-common` | 336 | 26,749 | 192 |
| `vectispire-agent` (being ported) | 7 | 1,006 | 9 |
| `vectispire-report-demo` (a plugin, not ported) | 5 | 590 | 3 |

About 6,400 lines of `vectispire-common` are already reached by the agent port (clone, container runner,
five scanners and their parsers, crypto), so **the control-plane port is about 86,000 lines**.

Tests, as Gradle counts them on the 0.11.1 line: core 2,338, common 2,093, agent 80, and
`integrationTestAll` 171 on each of MySQL and PostgreSQL. 172 of the core test files use **MockMvc**, i.e.
they run in-process and are not language-neutral (see §4.3). Only 2 start a real server.

### 1.2 Modules of `core`

| Module | Files | Lines | | Module | Files | Lines |
|---|---|---|---|---|---|---|
| access | 101 | 7,010 | | posture | 19 | 2,454 |
| checklists | 77 | 6,882 | | threatintel | 25 | 1,852 |
| forges | 50 | 5,306 | | agents | 17 | 1,929 |
| issues | 46 | 5,191 | | gate | 18 | 1,612 |
| compliance | 51 | 4,615 | | tickets | 18 | 1,589 |
| scanning | 52 | 4,443 | | exports | 12 | 1,400 |
| targets | 46 | 3,947 | | platform | 13 | 1,140 |
| reportplugins | 48 | 3,593 | | rules | 14 | 992 |
| inventory | 39 | 3,557 | | siem | 10 | 936 |
| plugins | 48 | 3,039 | | outbound | 7 | 864 |
| notifications | 13 | 824 | | audit | 13 | 751 |
| crypto | 7 | 600 | | outbox | 9 | 416 |
| ai | 4 | 375 | | reporting | 2 | 284 |
| settings | 8 | 234 | | config | 4 | 218 |
| maintenance | 6 | 170 | | | | |

Module dependencies (`@ApplicationModule(allowedDependencies)`), which fix the porting order:

- **No module dependency:** access, audit, outbound, settings, platform, maintenance, reporting; outbox → maintenance; crypto → outbound, settings; siem → access.
- **targets** → access · **scanning** → access, targets · **issues** → access, scanning, targets · **inventory** → access, scanning, targets.
- **rules** → access, inventory, issues, scanning · **gate** → access, issues, rules, scanning, targets · **notifications**, **threatintel**, **tickets**, **plugins**, **agents** → subsets of the above.
- **checklists** → access, inventory, issues, notifications, plugins, scanning, targets · **exports**, **posture**, **ai** → gate, inventory, issues…
- **forges** → access, checklists, targets · **compliance** → ai, exports, gate, posture, rules… · **reportplugins** → checklists, compliance, gate…

### 1.3 HTTP surface

- **245 paths, 311 operations, 422 schemas**, in a 657 KB `openapi.json`.
- The largest groups are projects (43 operations), repositories (20), forge connections (14), checklist templates, compliance and settings (12 each), auth (10), admin, rule sets and teams (9 each), the agent protocol (8), and SCIM (12, outside `/api/v1`).
- **71 controllers.** Actuator exposes `health` (with Kubernetes `liveness`/`readiness` probes), `info` and `metrics`.

### 1.4 Persistence

- **77 entities, 77 repositories**: 319 `@Query` methods (4 native), 4 classes using JPA `Specification`/`CriteriaBuilder` for dynamic filters, 1 using JDBC directly.
- **415 `@Transactional`** sites; 27 event listeners (Spring Modulith application events and transactional listeners).
- **Flyway 12.4.0** (from the Spring Boot 4.1.1 BOM): 46 files under `db/migration/common` and 44 under each of `mysql` and `postgresql`, V1–V91, about 78 tables. Locations `common` then `{vendor}`; default `outOfOrder=false`, `validateOnMigrate=true`, clean disabled, no baseline.
- Placeholders per engine (`MigrationDialect`, positional, all eight required):

| Placeholder | MySQL | PostgreSQL |
|---|---|---|
| `${ts}` | `datetime(6)` | `timestamp with time zone` |
| `${id}` | `bigint auto_increment primary key` | `bigint generated always as identity primary key` |
| `${bool}` | `bit(1)` | `boolean` |
| `${true}` / `${false}` | `b'1'` / `b'0'` | `true` / `false` |
| `${text}` | `longtext` | `text` |
| `${double}` | `double` | `double precision` |
| `${bytes}` | `longblob` | `bytea` |

  A `spring.flyway.placeholders.*` that tries to override one of them is refused at startup.

### 1.5 Scheduled and asynchronous work

- **28 `MaintenanceTask` implementations** on three fixed-delay turns (relay 60 s, scheduling 60 s, hourly), plus 8 other `@Scheduled` methods.
- There is no leader election: every task must tolerate running on every instance. `MaintenanceJobsTest` asserts the composition.
- An **outbox** carries notifications, SIEM events and ticket syncs.

### 1.6 Security machinery

- **Filter chain:** client address, request body limit, bearer authentication, bearer, login and webhook rate limits, credential confinement, password-change interceptor, actuator access, problem responses.
- **Sessions:** opaque 32-byte tokens; **the store holds only their SHA-256**. Sessions are stateless toward Spring (`SessionCreationPolicy.STATELESS`) and travel as bearer tokens, so **CSRF is disabled by design**. The CSP is set in the chain.
- **Passwords:** **Argon2id**, PHC string, m = 19 MiB, t = 2, p = 1, 16-byte salt, BouncyCastle. Weaker stored parameters are rehashed on sign-in; old bcrypt hashes are also recognised.
- **API keys:** `zsk_` plus 43 characters, a 12-character clear prefix to narrow candidates, the rest hashed. **Agent keys:** a separate kind. **SCIM:** its own token.
- **TOTP:** HMAC-SHA1 (RFC 6238). **OIDC:** Spring Security OAuth2 client (single sign-on, account linking rules).
- **Lockout and throttles:** Bucket4j. **Four-eyes**, the **role model** (`Role` flags), and **`Visibility`** resolved per account and credential and applied in queries (404, never 403).
- **Outbound:** every call goes through `PinnedHttpSender` and its guard (resolved address pinned, private and metadata ranges refused, redirects refused).
- **Crypto:**
  - encryption at rest with AES-256-GCM (BouncyCastle) under `ENCRYPTION_KEY`, with a context bound as associated data, and sealed envelopes to agents;
  - signatures ECDSA P-256/SHA-256 (cosign-compatible), document signing key, DSSE;
  - SHA-256 audit hash chain;
  - HMAC-SHA256 webhooks.

### 1.7 Outputs and integrations

- **PDF:** Apache **PDFBox 3.0.8** in five places: compliance report, OWASP report, posture report, triage history, report cursor.
- **Other formats:**
  - CSV;
  - SARIF;
  - OpenVEX and CSAF;
  - CycloneDX and SPDX ingestion;
  - the checklist **xlsx rendered byte for byte** from the stored template (vectispire-common `Workbook`, a zip of XML parts).
- **Notifications and SIEM:** mail through Spring Mail (plain text); SIEM over syslog in CEF (`SyslogSender`); Jira, GitLab and GitHub ticketing; forge connections (GitLab and GitHub APIs).
- **Containers:** the built-in worker and report plugins use docker-java through the socket proxy, which the agent port's `container` crate already covers.
- **Configuration:** about **70 `VECTISPIRE_*` environment variables** in `application.yaml` (303 lines), plus `/run/secrets` read as a config tree.

## 2. What must not change

1. **The OpenAPI document, byte for byte.** `ClientContractSpecTest` freezes it; the Angular client is
   generated from it; agents and integrations depend on it; `published-operation-ids.txt` lists the
   operation ids no release may rename; `api-compat` compares it to the last tag. The Rust control plane
   **serves the same bytes** and is checked against them, not against a regenerated approximation (§3.4).
2. **The database schema, exactly.** No migration is written for the port. The same files, the same
   `flyway_schema_history`, so an installation migrated by Java continues under Rust and, during the
   transition, back under Java (§3.3). `ddl-auto: validate` becomes a schema-parity check on both engines.
3. **MySQL and PostgreSQL**, both, from the first phase.
4. **The boundaries, at compile time.**
   - Each core module becomes a crate (`vectispire-cp-<module>`) whose public surface is its `lib.rs`. The equivalent of a module's root package and its named interfaces is `pub`; `web`, `internal` and `persistence` are `pub(crate)` modules.
   - `allowedDependencies` becomes the crate's `[dependencies]`, and a test reads `cargo metadata` and fails on an edge not in a checked-in list. That list is the review decision Modulith asks for today.
   - Layering inside a crate (`domain ← scanning ← persistence ← services ← web`) is enforced by module privacy plus a small `syn`-based test for what privacy cannot express, such as "no SQL type in a web module".
   - `CrossModuleQueriesTest` maps to a test that reads every SQL string and fails on another module's table outside a shrinking list.
5. **The security invariants of `AGENTS.md`.**
   - Visibility is applied in the query, and a refusal is a 404.
   - Fingerprints are a data contract.
   - Absent is never empty.
   - The outbound door is the only HTTP client.
   - The agent never links a database crate: the agent's isolation test already exists in the workspace, and the control plane's crates must never become a dependency of `vectispire-agent`.
6. **Everything stored stays verifiable.**
   - Argon2id PHC strings with the same parameters (and the bcrypt fallback).
   - API key hashes and prefixes, TOTP secrets.
   - AES-256-GCM envelopes with the same nonce layout and associated data.
   - Signatures by the same document key, the audit chain continued from the stored head.

   The agent port's `crypto` crate already proves byte-for-byte interop for envelopes and signatures; the control plane reuses it.
7. **Sessions survive the switch.** They are opaque tokens whose SHA-256 is stored, so a Rust control
   plane reading the same table accepts the same sessions. No sign-out at cut-over is required. This
   holds only if the Rust session lookup, idle and absolute lifetimes match `Sessions` exactly, which is
   one of the conformance cases.

## 3. Libraries

### 3.1 Choices

| Need | Choice | Rejected, and why |
|---|---|---|
| Runtime | **tokio** | the only runtime the rest of the stack assumes |
| HTTP server | **axum** + **tower** + **tower-http** | actix-web: its own actor runtime and middleware model; axum composes with tower layers, which map one to one onto the filter chain (§1.6) |
| Database | **sqlx** (MySQL + PostgreSQL drivers, rustls) for fixed queries, **sea-query** for the 4 dynamic-filter sites | SeaORM: an ORM over the same schema reintroduces the "two authorities" risk `ddl-auto: validate` was chosen to avoid; diesel-async: compile-time schema per backend means two schema modules to keep equal, and async support is a layer on top |
| Query checking | `sqlx::query!` checked offline against **both** engines (two `.sqlx` caches generated in CI from containers) | runtime-only strings would lose what the 319 `@Query` methods get from Hibernate's startup validation |
| Migrations | **an own crate, `vectispire-migrate`** (§3.3) | refinery, sqlx-migrate: their own history tables and checksums |
| OpenAPI | **the checked-in `openapi.json` drives**; a conformance test checks every route's request and response types against it (§3.4); utoipa only as a helper to generate schemas for that comparison | utoipa or aide as the source: regenerating the document would never reproduce 657 KB of springdoc output byte for byte |
| Serialization | **serde** + **serde_json** with `preserve_order`, and the agent port's `jackson` module for Jackson-compatible output (upper-case `\uXXXX` escapes, `Double.toString` numbers, `Instant`/`Duration` text) | plain serde_json output: differs from Jackson in escapes and number forms, which golden responses would show at once |
| Validation | **garde** | validator: older derive model, weaker for nested and conditional rules |
| Sessions and auth | own middleware over the DB session table (§2.7); **argon2** + **password-hash** (PHC); **bcrypt** for verification only; **totp-rs** (SHA-1, 30 s, 6 digits); **openidconnect** for SSO | tower-sessions: a cookie session model; the API uses bearer tokens |
| Rate limiting | **governor** keyed exactly as Bucket4j is (address, account, token prefix) | tower-governor alone: its keying does not cover the account and prefix cases |
| Config | **figment** with the same `VECTISPIRE_*` names, Spring's duration syntax (already ported in the agent), and `/run/secrets` as a config tree | config-rs: weaker provenance in error messages |
| Logging | **tracing** + tracing-subscriber, plain or JSON; the **audit file mirror** kept as its own writer | log + env_logger: no spans |
| Metrics and health | **metrics** + **metrics-exporter-prometheus** under `/actuator/metrics`; `/actuator/health`, `/liveness`, `/readiness` with the same JSON | OpenTelemetry SDK now: not needed for parity |
| Scheduling | tokio intervals, one task per `MaintenanceTask`, the same three cadences, each tolerant of several instances | an in-process cron crate: none of the tasks is calendar-driven |
| Mail | **lettre** (rustls, STARTTLS, the same `vectispire.mail.*` settings) | — |
| HTTP client | **reqwest** with rustls, wrapped by the outbound door ported from `PinnedHttpSender`: resolve once, pin, refuse private, metadata and redirects | hyper directly: more code for the same guarantee |
| Crypto | the workspace's **`vectispire-crypto`** (RustCrypto `aes-gcm`, `p256`/`ecdsa`, `sha2`, `hmac`) | ring alone: no P-256 PKCS#8 import as Java writes it; aws-lc-rs: C toolchain in the build |
| XML | **quick-xml** (xlsx parts, CycloneDX/SPDX XML) with entity expansion off | roxmltree: read-only |
| xlsx | the stored template rewritten part by part with **zip** (deterministic entry order and timestamps), as the Java `Workbook` does | rust_xlsxwriter or calamine: they generate or read, they do not preserve a template byte for byte |
| **PDF** | **the main library risk.** Candidates: **printpdf** (low level, like PDFBox's content streams) or **krilla** (higher level, used by typst). The PDFs are produced from code, not templates, so a low-level library matches the Java code best | typst as a document engine: a second language for five reports; headless Chromium: a browser in the control plane |
| Testing | **testcontainers** (MySQL 9.4 and PostgreSQL 17 by digest, as `Engine.java` pins), **insta** for golden files, **proptest** for parsers and fingerprints, **wiremock** for outbound stubs | — |
| Static analysis | clippy with `-D warnings` and a selected pedantic set; `unsafe_code = "forbid"` in every control-plane crate | — |

### 3.2 Serving the interface

The Angular build is served from the same origin by tower-http's `ServeDir`, with the same CSP, cache
headers and SPA fallback the Java configuration sets. `connect-src 'self'` stays true.

### 3.3 `vectispire-migrate`: a Flyway-compatible runner

This is its own crate in Phase 0, because the history table decides everything: a runner that keeps its
own table cannot continue an installation Java migrated.

**What it reads.** The existing files, unchanged:

- `db/migration/common` and `db/migration/{mysql,postgresql}`, embedded at build time;
- the version, and the description from the file name (`V91__checklist_contacts.sql` → `91`, "checklist contacts");
- the eight placeholders of §1.4, a direct port of `MigrationDialect`, with the same refusal of an override.

**What it writes.** Rows of `flyway_schema_history` that Flyway 12.4 would write:

- `installed_rank`, `version`, `description`, `type = SQL`, `script`;
- the **checksum**, `installed_by`, `installed_on`, `execution_time` and `success`.

**The checksum must be Flyway's own.** Flyway computes a CRC32 over the script read line by line, with
the line terminators dropped and a leading UTF-8 byte-order mark removed. It is believed to be computed
over the raw resource, before placeholders are replaced. That belief is the first thing the crate's tests
settle against the real Flyway, not something this plan asserts. The test:

1. Java migrates an empty database on each engine to V91.
2. The Rust runner recomputes every checksum from the embedded files and must equal every stored one.
3. The Rust runner migrates another empty database.
4. The real Flyway, with Java's configuration, validates it with no error, and `SchemaParityIntegrationTest` passes on it.

**Validation before serving.** As Flyway with `validateOnMigrate` and Spring's defaults:

- every applied checksum matches its file;
- no applied version is missing from the files, and no file version is older than the latest applied one (`outOfOrder=false`);
- no row has `success = false`;
- then pending migrations are applied, in order.

The control plane does not answer HTTP until this has passed.

**Transactions and lock.**

- Each migration runs in one transaction on PostgreSQL, whose DDL is transactional. On MySQL, DDL commits implicitly; Flyway's behaviour there (a failed migration leaves a `success = false` row and refuses the next start) is mirrored, not improved.
- Two instances starting together must not both migrate. The runner takes `pg_advisory_lock` on PostgreSQL and `GET_LOCK` on MySQL, under the key Flyway uses, so a Java and a Rust instance also exclude each other. The key is to be read from Flyway 12.4's source and pinned by a test.
- `clean` and `baseline` are not implemented at all.

**Layout and parity.**

- `MigrationLayoutTest` is ported: a version lives in exactly one of `common` or the vendor directory, and V1–V39 never move.
- The **schema-parity check** replaces `ddl-auto: validate`. Each persistence module declares its tables and columns (name, type family, nullability) next to its queries. A startup check, and an integration test on both engines, compare them with `information_schema`.

**Why not an existing crate.**

- **refinery:** its own `refinery_schema_history` and its own checksum (SipHash).
- **sqlx::migrate:** `_sqlx_migrations` and SHA-384.
- **barrel:** a DSL, not a runner.

None can read or write `flyway_schema_history` the way Flyway 12.4 does. The runner is small, about 600 to 900 lines with tests, and owning it is cheaper than patching a crate whose central design is its own table.

**Test plan.** Run with testcontainers on both engines:

- Java-migrated → Rust validates, both checksums and parity;
- Rust-migrated → Java and Flyway validate, and `integrationTestAll` passes against it;
- a modified file is refused;
- a missing applied version is refused;
- a `success = false` row is refused;
- out-of-order is refused;
- two Rust instances, and a Rust and a Java instance, start together: one migrates, the other waits.

### 3.4 The contract, kept identical

The served document is the checked-in `openapi.json`, embedded. A conformance suite checks, route by
route:

- that the router answers every path and method the document lists, and nothing else;
- that each handler's request and response types serialize to JSON valid against the document's schema;
- that the **golden responses** of §4.3 validate against it.

A route added without the document changing fails. A document changed by hand without the code fails
the golden replay.

## 4. Migration strategy

### 4.1 Options

- **(a) Parallel build, then switch.** The Rust control plane is built to completion, beside the Java
  one, and is not deployed until it passes the whole oracle (§4.3). An installation then switches by
  replacing the image. The database, sessions, keys and audit chain carry over (§2). Going back to Java
  stays possible for as long as no migration newer than the last Java release has run.
- **(b) Strangler.** A router sends some paths to Rust and the rest to Java, both on one database. The
  risks are concrete here:
  - two writers to the **audit chain**, whose head is taken under a lock;
  - two **outbox** relays;
  - two schedulers running the same maintenance tasks — tolerated today only within one implementation's semantics;
  - two caches of settings and visibility;
  - session lifetimes extended by one and expired by the other;
  - every cross-module transaction split across processes.

### 4.2 Recommendation

**(a), with module-level gates.** Each phase ends with its routes passing the oracle while the rest of
the application is still missing, so progress is measured continuously. No installation ever runs both.
A strangler would make every one of the risks above a production state that would have to be designed
for, and then removed.

### 4.3 The oracle

These are language-neutral, or made so:

1. **Contract identity** (§3.4).
2. **Recorded traffic.**
   - The Java HTTP suite (172 MockMvc test files) gets one shared `ResultHandler` that writes each request, the response status, headers and body, and a dump of the rows the test touched, to golden files.
   - Ids, timestamps and tokens are normalised.
   - The Rust suite seeds the same rows, replays the same requests over real HTTP, and compares. That makes the existing Java tests the oracle without porting their assertions one by one first.
   - A difference is either a Rust defect, or a Java behaviour that must be written down as intended and then reproduced.
3. **The Playwright e2e suite,** run against the Rust control plane.
4. **The drills,** with the Rust image in the place of "this commit's image":
   - `scripts/upgrade-drill.sh`: data written by the latest Java release, read back unchanged by Rust;
   - the restore drill;
   - `scripts/composition-scan-check.sh` with both agents.
5. **DB-state comparison:** after the same scenario, Java and Rust databases compared table by table, normalised.
6. **The guards, ported as tests:**
   - `AuthorizationCoverageTest` and `RouteAuthorizationTest` (every route declares its role and its visibility, or the build fails);
   - `ServicesRefuseHiddenTargetsTest`, `MaintenanceJobsTest`, `TableEmptyingTest`, `RefusalTypesTest`;
   - `ResponseNullabilityTest`, which on the Rust side follows from the schema conformance;
   - the reference sets of fingerprints.

## 5. Phases

Estimates are developer-weeks, for a team fluent in Rust / a team learning it. They count porting,
tests, oracle work and review. The order follows §1.2's dependencies.

| Phase | Content | Exit criteria | Weeks |
|---|---|---|---|
| 0. Foundations | workspace crates, `vectispire-migrate`, DB layer and schema parity, HTTP stack with the filter chain, config, errors as problem documents, Jackson-compatible JSON, outbound door, test harness, traffic recorder in the Java suite, contract conformance, CI security gates (§6) | migrate's two-way test green on both engines; an empty Rust app serves `/actuator/health` and the embedded contract; recorder produces golden files from the whole Java suite | 10–14 / 14–20 |
| 1. Access | users, sessions, passwords, API, agent and SCIM keys, TOTP and lockout, OIDC, roles, `Visibility`, four-eyes settings, audit chain, settings, platform | every `auth`, `users`, `api-keys`, `admin`, `security`, SCIM golden passes; sessions from a Java-migrated DB accepted; authorization guards ported; security review of the phase with nothing above low | 12–16 / 17–24 |
| **Go / no-go 1** | measured throughput against this plan; review of the two hardest parts done | | |
| 2. Targets and scanning | targets, solutions, projects, scans, ingestion (fingerprints), agents' protocol server side, outbox | ingestion reference sets byte-identical; agent protocol goldens; upgrade drill green for these tables | 14–20 / 20–28 |
| 3. Issues and decisions | issues, triage, four-eyes, exceptions, VEX/CSAF, inventory, rules, gate | goldens; fingerprint and triage-history drills | 14–19 / 20–27 |
| 4. Integrations | notifications, mail, SIEM, tickets, forges, threat intel, plugins, AI advisor | goldens with outbound stubs; SIEM wire format byte-identical | 12–17 / 17–24 |
| 5. Documents | checklists (xlsx byte for byte), exports, compliance, posture, reporting (PDF), report plugins | xlsx and every PDF compared with Java's on the same data: PDFs text-equal and structurally equal, not byte-equal unless proven feasible | 13–19 / 19–27 |
| 6. Cut-over | full oracle, both engines, two-week side-by-side on a staging copy, release pipeline (image, SBOM, signature unchanged identity) | every oracle item green; nightly green 14 days | 6–9 / 8–12 |
| **Total** | | | **81–114 / 115–162** |

**About AI-assisted throughput.** The agent port's foundations went faster than the agent study
estimated. Code was produced in hours, not weeks, and the checks were real. Code production is not the
bottleneck of this port, though. The bottleneck is:

- deciding what each Java behaviour means;
- reviewing security-relevant code;
- making the oracle trustworthy.

Those do not compress the same way. The plan does not count on a multiplier. If Phase 1 confirms one, the remaining phases are re-estimated at go/no-go 1, not before.

**The hardest parts, in order:**

1. **Access:** the role model, `Visibility` in every query, four-eyes, lockout keyed exactly, OIDC linking rules.
2. **Ingestion and fingerprints:** the data contract of every issue.
3. **Issues and triage:** state machine, approvals, expiry, VEX/CSAF semantics.
4. **Checklists:** the xlsx rendered byte for byte, measurements, sign-off.
5. **PDF:** no library equivalent to PDFBox.
6. **SIEM:** CEF over syslog, exact framing.

**Risks and mitigations.**

| Risk | Mitigation |
|---|---|
| A behaviour lost that only a Java test pinned | the traffic recorder makes all of them goldens before any phase starts |
| Checksum or lock incompatibility with Flyway | settled by `vectispire-migrate`'s first tests against the real Flyway; nothing else starts on the DB until it is green |
| PDF library gap | Phase 5 begins with a two-week spike on the five reports; fallback: keep a minimal PDF writer of our own over `printpdf` |
| Jackson output differences | the agent port's `jackson` module; golden responses catch the rest |
| Two codebases during the build | Java stays the product; Rust ships nothing until cut-over; every Java change during the build lands with its golden, so the oracle moves with it |
| Team skills | go/no-go 1 measures them, not this plan |

**Decision records.** One ADR at the start ("the control plane is ported to Rust behind a conformance
oracle; Java remains the product until cut-over"), amending 0028–0030 (modules become crates), 0013
and 0027 (the migration runner), and recording the PDF choice after its spike. A second ADR at cut-over.

## 6. Security controls

The Rust control plane must carry at least what the Java one does. The CI part for the existing
`vectispire-rust` workspace is being built separately on its own branch; this section lists what the
control plane needs from it and adds to it, it does not redesign it.

### 6.1 In code

- **`unsafe_code = "forbid"`** in every control-plane crate. The only `unsafe` in the workspace stays libgit2's two process-wide calls in the agent's `git` crate.
- **Input limits:**
  - the request body limit per route class, ported from `RequestBodyLimitFilter`;
  - JSON depth and size limits;
  - multipart limits;
  - limits on decompressed size (zip bomb) for xlsx, SBOM and archive uploads;
  - XML with external entities and DTDs disabled.
- **Authorization as a compile- or test-time guarantee.** Every handler is registered through one builder that requires its role requirement and its visibility mode, so a route without them does not compile. `AuthorizationCoverageTest` and `RouteAuthorizationTest` are ported as tests that walk the router and the contract: every route declared, every route naming a target resolving a `Visibility`, refusals answering 404.
- **Visibility in the query:** every query taking a target id takes a `Visibility` argument by type. The `sea-query`/`sqlx` helpers make a query without it a compile error in persistence modules.
- **Outbound:** the only HTTP client is the door; a workspace test fails on `reqwest::Client` construction outside it, porting `onlyTheOutboundDoorSpeaksHttpOutwards`.
- **Headers:** the same CSP, `X-Content-Type-Options`, `Referrer-Policy`, frame denial and HSTS, set once in a tower layer and asserted by a test on every route class.
- **Cookies and CSRF:** the API uses bearer tokens and keeps CSRF off as today. The single sign-on hand-off cookie keeps `Secure`, `HttpOnly` and `SameSite`, and `Secure` depends on the trusted-proxy rule of 0038.
- **Timing-safe comparisons** (`subtle`) for tokens, key hashes, HMACs and TOTP codes. Login timing is equalised for unknown accounts, as Java does.
- **Secret types that never print:** the agent's `Secret` type (`***` in `Debug`, no `Display`) for passwords, tokens, keys and the encryption key; `zeroize` on drop for key material.
- **Constant-time crypto:** RustCrypto primitives only; no RSA with a known timing advisory (the agent port already turned `rsa` off for RUSTSEC-2023-0071).
- **Rate limits:** login, bearer and webhook throttles keyed as today, with their tests ported.
- **Absent, never empty:** parsers return `Option`/`Result`, never a default; the 0.11.1 fix's cases are reference cases from the start.

### 6.2 In CI

The workspace job provides most of these; the control plane adds its crates to them:

- **Dependencies:**
  - `cargo deny` for advisories, licenses, bans (no database crate in the agent; no `openssl-sys` unless decided) and sources (crates.io only);
  - `cargo audit`;
  - a trust policy for new crates: **cargo-vet** with imported audits, or, if it costs too much, a reviewed allowlist with the same effect, so a new crate is a review decision as a new `allowedDependencies` line is today.
- **Static analysis:**
  - clippy with `-D warnings` plus security-relevant lints, including `unwrap_used` and `expect_used` in non-test code, `indexing_slicing` in parsers, `arithmetic_side_effects` in size computations, `mem_forget` and `undocumented_unsafe_blocks`;
  - **semgrep** with the Rust rules beside the existing ones.
- **Fuzzing** with `cargo fuzz` in the nightly: every parser and deserializer that reads untrusted input. That covers SARIF, CycloneDX, SPDX, OpenVEX, CSAF, xlsx, the agent protocol bodies, SCIM bodies and problem documents.
- **Supply chain:**
  - an **SBOM** from `cargo auditable` (embedded) and CycloneDX (published);
  - **Grype** on the image, at the digest `ScannerImages` pins;
  - **checkov** on the Dockerfile;
  - **gitleaks** as today;
  - **reproducible builds:** the image built twice to the same digest.
- **Release:** **cosign signing unchanged.** The identity names `release.yml`, not the language, so consumers keep verifying the same identity.
- **Reviews:** the **`security-audit` skill**, the four areas in parallel, run at the end of every phase. A phase does not exit with a finding above low.

## 7. Phase 0 and Phase 1 tasks

Each task owns its files, so parallel agents do not collide. Crates are under `vectispire-rust/crates/`.

### Phase 0, in parallel

| # | Task | Owns | Interfaces it provides |
|---|---|---|---|
| 0.1 | **`vectispire-migrate`**: embedded files, placeholders, Flyway checksum, history read/write, validation, per-engine lock, layout test, two-way tests on both engines | `crates/migrate/`, a Java test helper that migrates with the real Flyway | `migrate::run(&Pool, Engine) -> Result<Report>` and `migrate::validate(...)` |
| 0.2 | **DB layer**: pool per engine, `Engine`, transactions, `sqlx` offline caches for both engines in CI, sea-query helpers that require `Visibility`, schema-parity declarations and check | `crates/cp-db/` | `Db`, `Tx`, `Visibility`-typed query builders, `parity::check` |
| 0.3 | **HTTP stack**: axum app, the filter chain as tower layers (address, body limit, bearer, rate limits, confinement, password change, problem responses, headers), route builder requiring role and visibility | `crates/cp-http/` | `RouteBuilder`, `Problem`, `Caller` extractor |
| 0.4 | **Contract conformance**: embedded `openapi.json`, router-vs-document check, schema validation of handler types, golden replay runner | `crates/cp-contract/` | `contract::assert_router(&Router)`, `golden::replay(dir)` |
| 0.5 | **Traffic recorder on the Java side**: a shared MockMvc `ResultHandler` and row-dump helper writing normalised golden files; run over the whole Java suite | `vectispire-java/vectispire-core/src/test/.../golden/`, `vectispire-rust/golden/` | the golden file format |
| 0.6 | **Config and runtime**: figment with every `VECTISPIRE_*` name and `/run/secrets`, tracing, audit mirror writer, metrics and actuator endpoints, graceful shutdown | `crates/cp-runtime/`, `crates/cp-app/` (the binary) | `Settings`, `Telemetry`, `App::serve` |
| 0.7 | **Outbound door**: port of `PinnedHttpSender` and its guard over reqwest, with its tests | `crates/cp-outbound/` | `Outbound::send` |
| 0.8 | **Boundaries**: `cargo metadata` test with the checked-in edge list, `syn` layering test, cross-module SQL test, `unsafe_code` forbid check | `crates/cp-arch-tests/` | — |
| 0.9 | **CI for the control plane crates**: add them to the workspace security job (§6.2), sqlx caches for both engines, fuzz targets skeleton | the workspace CI files the separate CI task owns: coordinate with it | — |

Dependencies: 0.2 needs 0.1's `Engine`; 0.3 needs nothing; 0.4 needs 0.3's router type; 0.5 is Java
only. All start together; 0.2 and 0.4 rebase once on 0.1 and 0.3.

### Phase 1, in parallel after Phase 0 exits

| # | Task | Owns |
|---|---|---|
| 1.1 | **Accounts and passwords**: users, Argon2id PHC + bcrypt verify + rehash, password change rules, must-change | `crates/cp-access/src/accounts/` |
| 1.2 | **Sessions and tokens**: session store (SHA-256), lifetimes, bearer extraction, API keys (prefix + hash), agent keys, SCIM token | `crates/cp-access/src/credentials/` |
| 1.3 | **MFA and throttles**: TOTP, recovery, lockout, login/bearer/webhook rate limits keyed as Bucket4j is | `crates/cp-access/src/mfa/`, `crates/cp-http/src/limits.rs` |
| 1.4 | **OIDC**: openidconnect client, account linking rules (verified email, no privileged link), hand-off cookie | `crates/cp-access/src/sso/` |
| 1.5 | **Roles, visibility, four-eyes**: `Role` flags, `VisibilityService`, team and direct grants, credential restriction, four-eyes settings | `crates/cp-access/src/authz/` |
| 1.6 | **Audit and settings**: audit log with the hash chain continued from the stored head, file mirror, settings store and typed settings, platform | `crates/cp-audit/`, `crates/cp-settings/` |
| 1.7 | **Access routes**: `auth`, `users`, `teams`, `api-keys`, `admin`, `security`, SCIM, against the goldens | `crates/cp-access/src/web/` |
| 1.8 | **Phase 1 security review**: the `security-audit` skill on the phase's diff | — |

## 8. Recommendation

- **Phase 0 can start now.** It is mostly what any later decision needs anyway: a Flyway-compatible runner, the oracle, the boundaries.
- **The rest waits for go/no-go 1.**
- **During the whole build, Java stays the product.** Releases, fixes and features land in Java first, each with its golden, so the oracle follows the product instead of freezing it.
