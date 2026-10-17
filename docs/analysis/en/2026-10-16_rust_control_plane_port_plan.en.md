# Plan: Porting the Control Plane to Rust

**Date:** 2026-10-16 · **Status:** proposal, no code · **Scope:** `vectispire-core` and the part of
`vectispire-common` the agent port does not already cover · **Target schema and contract:** the 0.11.1
line (`release/0.11.1-merge` b8bd7e8d0: Flyway V1–V91, `openapi.json` with 245 paths)

This plan is the step before any code. It measures what there is to port, fixes what must not change,
chooses the libraries, picks a migration strategy and a test oracle, and ends with the Phase 0, 1 and 2
task lists that parallel agents can execute. It builds on the agent study
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
- The turns have no leader election: every task must tolerate running on every instance. `MaintenanceJobsTest` asserts the composition. The scan scheduler is the exception: its tick is leader-only, through a lease row (Phase 2, §7).
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

## 7. Phase 0, 1 and 2 tasks

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
| 1.5 | **Roles, visibility, four-eyes**: `Role` flags, `VisibilityService`, team and direct grants, credential restriction, four-eyes settings | `crates/cp-access/src/` at the crate root (`roles.rs`, `visibility.rs`, `rows.rs`, `four_eyes.rs`, `approvers.rs`), their statements in `persistence/`. Not `src/authz/`: `cp-arch-tests` admits a module's root, `web`, `internal`, `persistence` and its named interfaces as places, and refuses any other directory |
| 1.6 | **Audit and settings**: audit log with the hash chain continued from the stored head, file mirror, settings store and typed settings, platform. **The settings save writes all its changes in one transaction**, where Java commits each separately and a failure half-way leaves the earlier ones written. That is a deliberate divergence from Java, decided by the user at the Phase 1 merge on 2026-10-17 and recorded in `cp-platform`'s README | `crates/cp-audit/`, `crates/cp-settings/`, `crates/cp-platform/` |
| 1.7 | **Access routes**: `auth`, `users`, `teams`, `api-keys`, `admin`, `security`, SCIM, against the goldens | `crates/cp-access/src/web/` |
| 1.8 | **Phase 1 security review**: the `security-audit` skill on the phase's diff | — |

The *Owns* column names directories for readability. The same layout rule as 1.5 places each task's
files in its crate's root, `internal` and `persistence`, which is what 1.1 and 1.2 did.

### Phase 2, in parallel after Phase 1 exits

Phase 2 is targets and scanning: the estate an account declares, the queue that examines it, the agents
that take from the queue, and the ingestion that turns what they report into findings. It is where the
second of the hardest parts (§5) lives. The Java side is measured on **b8bd7e8d0**, the tip of
`release/0.11.1-merge` and the commit §1 measured; this branch's base (312b7cc8b) is 102 commits behind
it, so the 0.11.1 line is the more current. The Rust side is read on `rust/p1-merge` (44f36aff3).

#### What Phase 2 ports

| Module | Main files | Lines | Test files (unit + integration) | Tables |
|---|---|---|---|---|
| targets | 46 | 3,947 | 5 + 3 | `t_solution`, `t_project`, `t_repository`, `t_container`, `t_git_token`, `t_ssh_key` |
| scanning | 52 | 4,443 | 21 + 6 | `t_scan`, `t_finding`, `t_leader_lease` |
| agents | 17 | 1,929 | 5 + 2 | `t_agent` |
| outbox | 9 | 416 | 2 + 1 | `t_outbox_message` |
| maintenance | 6 | 170 | 2 + 0 | `t_one_shot_job` |
| crypto | 7 | 600 | 5 + 0 | none (the signing key is a `t_setting` row) |
| **Total** | **137** | **11,505** | **40 + 12** | **12 of 78** |

`crypto` and `maintenance` are not in the phase's title. They are part of Java's shared foundation, which
Phase 1 did not port, and Phase 2 cannot do without them: `targets` stores git tokens and SSH keys
encrypted, the dispatcher seals credentials to agents, and seven of the phase's jobs are
`MaintenanceTask`s.

- **`vectispire-common`, about 2,600 lines more:** `domain.targets`, `scans`, `agents`, `dependencies` (`DependencyGraph`), `sbom`, `scheduling`, `licenses`, `retention`; from `domain.issues`, the fingerprint and its vocabulary (`IssueFingerprint`, `FindingType`, `ToolKeys`); `Digests.sha256Fields`, `BoundedText`; `ScanArtifacts`, `PluginStep`, `ScanTask`. The agent port already holds `FailureReason`, `RepositoryUrl`, `Severity`, the sub-path rule, the writer of `ScanArtifacts`, and the Ed25519 and X25519 primitives.
- **Tests:** 240 test files of `core` import one of the six modules; **69 MockMvc files call a Phase 2 route**, and their recordings are the phase's goldens.
- **HTTP: 49 operations on 35 paths**, 16% of the 311. Targets 29 (solutions 5, projects 7, repositories 6, containers 5, git tokens 3, SSH keys 3), scans 3, the agent protocol 8, agent administration 9. The other nine paths under `/repositories` and `/solutions` belong to inventory, compliance and plugins, and wait for their phases.
- **Migrations:** 35 of the 91 versions touch these twelve tables (V1 to V86).
- **Scheduled work:**
  - seven `MaintenanceTask`s: the scheduling tick and the credentialed backlog on the scheduling turn, the notification relay on the relay turn, scan retention, orphaned target rows, repository identities and sent messages on the hourly turn;
  - the built-in worker's own poll;
  - two start-up repairs: withheld claims, and target deletions a stop interrupted.

  The order inside a turn is one `Sequence` across every module, so the Rust turns keep one ordered list
  rather than one per crate. **§1.5's "no leader election" holds for the turns, not for the scheduler.**
  The scheduling tick is leader-only through `t_leader_lease`, a conditional `UPDATE` whose row count
  names the winner, because two instances ticking together would scan every due target once per instance.

#### The data contracts it carries

1. **The fingerprint.** It is the lowercase hex SHA-256 of the UTF-8 bytes of five fields joined by NUL, with a null field joined as empty:
   - the target key, `repo:<id>` or `container:<id>`;
   - the type's wire name;
   - the identifier;
   - the purl, or the package name when the purl is null **or empty**;
   - the path.

   A tool-scoped type (plugin, imported) puts its tool key in the package's place. The function is
   called by `issues` (`IssueSyncService.fingerprintOf`) on the `Observation` the ingestor hands it,
   **before** the finding is clipped to its columns. Phase 2 therefore owns the function and every one of
   its inputs; Phase 3 owns the backlog that stores the result. Three Java behaviours must be reproduced,
   not improved:
   - `getBytes(UTF_8)` writes an unpaired surrogate as `?`;
   - `ToolKeys` trims with `String.strip()`, whose `Character.isWhitespace` excludes the no-break space that Rust's `char::is_whitespace` includes;
   - tool names are lower-cased with `Locale.ROOT`.
2. **Absent is never empty** ([0007](../../architecture/en/decisions/0007-none-is-not-an-empty-list.md)). A step's `Optional` decides whether its type is examined:
   - SAST and quality enter together;
   - end of life enters only when detection is on, an SBOM exists and the lookup succeeded;
   - licences enter as soon as a catalogue exists;
   - a plugin's scope enters only when the plugin produced.

   The set is kept on the scan (`examined_types`,
   [0032](../../architecture/en/decisions/0032-security-checklists.md)). The two API `Optional`s reach the
   inventory intact: Java flattened them once, and that emptied a repository's contracts.
3. **The scan status rule.** Every step absent with a failure recorded is `failed`: the target was never examined, and `completed` would say it was clean. Nothing observed and nothing failed stays `completed`, because a task asked to run no step is a configuration to look at, not an error. A project type absent from a result leaves the previous one alone. Detected languages are written even when null, and null reads as "unknown".
4. **Clipping comes after the fingerprint.** `BoundedText.clip` counts UTF-16 units and never splits a surrogate pair. The stored column is a display copy; the key is the scanner's whole value.
5. **The wire.**
   - `ScanArtifacts` is read as the Java agent's mapper reads it: unknown fields are passed over, and `null` means absent.
   - The contract number is compared strictly at hello, and a mismatch answers 409.
   - Results and failure reports are signed over the raw body.
   - A sealing key is believed only on the pinned signing key ([0031](../../architecture/en/decisions/0031-a-sealing-key-is-believed-only-on-the-pinned-key.md)).
6. **The outbox.**
   - A message is enqueued inside the caller's transaction, never one of its own ([0033](../../architecture/en/decisions/0033-internal-reactions-leave-through-the-outbox.md)).
   - Its id is stamped into the payload, because delivery is at least once.
   - Each message is settled in its own transaction.
   - A type nobody handles is retried and then abandoned with its reason, never skipped.

#### What it needs from Phase 1

| Piece | Used for | On `rust/p1-merge` |
|---|---|---|
| `cp-access` visibility: `VisibilityService`, `rows::NotFound`, `CallerScope` | every route naming a target, every scan read; 404, never 403 | merged (1.5) |
| `GrantableTargets`, `IssuerSees`: ports `access` declares | `cp-targets` implements them | declared, waiting for `cp-targets` |
| `AgentDirectory` (credentials) | an agent key resolves to its agent; `cp-agents` implements it | declared (1.2) |
| `cp-audit` | every administration service writes its record (targets: 14 imports, agents: 7) | merged (1.6) |
| `cp-settings` | retention, licence blocklist, default schedule | merged (1.6) |
| `cp-http`: route builder, `Caller`, body limits (agent result: 256 MB) | the routes | Phase 0 |
| `cp-outbound` | the Vault key provider | Phase 0 |

MFA (1.3), single sign-on (1.4) and the access routes (1.7) are not on `rust/p1-merge`, and Phase 2 does
not need them: the golden replay seeds sessions as rows, which 1.2 already reads. Go/no-go 1 still sits
between the phases. Phase 2 does not wait on them to be **ready**, only to be **decided**.

**One Phase 0 rule has to move first.** Java declares seven foundation modules shared on
`VectispireApplication`: `settings`, `outbound`, `crypto`, `audit`, `outbox`, `reporting` and
`maintenance`. Modulith allows them to every module without a line in `allowedDependencies`.
`cp-arch-tests/data/edges.toml` has no such notion: `targets` may use `access` alone, so `cp-targets`
depending on `cp-audit` fails today. The fix is the shared list as a rule, proven broken one way like the
others, not seven lines per module that would each read as a review decision nobody took.

#### What it needs from later phases, and the cut

Each of these is already a port in Java, since decision
[0029](../../architecture/en/decisions/0029-core-domains-become-modules.md). Each becomes a trait in the
crate that declares it. The binary composes a stand-in named after the module that will replace it. A
composition test lists Java's implementers and fails at cut-over while a stand-in remains, which is
`MaintenanceJobsTest`'s lesson: a missing caller is visible only at the level of the composition.

| Port (declared by) | Java implementer | Phase | Phase 2 stand-in |
|---|---|---|---|
| `ScanIngestor.Backlog` (scanning) | `issues` `IssueBacklog` | 3 | records the `Observation`, answers the `Reconciliation` Java recorded |
| `ScanIngestor.InventorySink` (scanning) | `inventory` `ScanInventory` | 3 | records the calls |
| `Enricher`, `EndOfLifeSource` (scanning) | `threatintel` | 4 | absent: Java's own "enrichment off" path; end of life is then not examined |
| `ScanRuleSets` (scanning) | `rules` | 3 | no active set: the bundled rules |
| `ScanPlugins` (scanning) | `plugins` | 4 | no plugin |
| `TargetBacklog` (targets) | `issues` | 3 | zero figures |
| `TargetPurge` listeners (targets) | access, issues, inventory, compliance, forges, gate, plugins, tickets, checklists, report plugins | 1, 3–5 | targets', scanning's and access's own |
| `OutboxHandler`, `NotificationChannel` (outbox) | notifications, SIEM, checklists, compliance | 4–5 | agents' audit delivery only |
| `RepositoryScanned` reactions | checklists, compliance | 5 | none |

The outbox stand-in carries a constraint. A relay with an incomplete registry abandons, after its
retries, every message whose type it does not know, and Java's rows would be destroyed in a drill on a
copied database. So the Rust binary does not start the relay turn until its handler registry equals
Java's. The relay is exercised in tests with the handlers that exist.

#### Phase 2, tasks

| # | Task | Owns | Interfaces it provides | Oracle |
|---|---|---|---|---|
| 2.1 | **Foundation and boundaries**: the shared-module rule; Phase 2's lines; `cp-maintenance` with three turns (30 s initial delay, a guard per cadence, a failing task ends its own run, not the turn), the global `Sequence` with later modules' slots reserved, one-shot jobs | `crates/cp-maintenance/`, `crates/cp-arch-tests/` (the one task editing `edges.toml`) | `MaintenanceTask`, `Cadence`, `Sequence`, `Turns`, `OneShotJobs` | `MaintenanceJobsTest` and `MaintenanceCompositionTest` ported; `t_one_shot_job` on both engines; the shared rule broken one way on the synthetic workspace |
| 2.2 | **Outbox**: enqueue in the caller's `Tx`, claim by conditional update, backoff, abandonment with its reason, pruning, counts | `crates/cp-outbox/` | `Outbox::enqueue(&mut Tx, …) -> Uuid`, `relay`, `prune_sent`, `counts`; `OutboxHandler`, `NotificationChannel` | `OutboxServiceTest`, `OutboxDatabaseTest`; `OutboxClaimIntegrationTest` with two relays racing on MySQL and PostgreSQL; row dumps against Java's |
| 2.3 | **Encryption at rest and sealing**: `EncryptionService` (AES-256-GCM, context as associated data), the key's sources (variable, file, `/run/secrets`, Vault through `cp-outbound`), the signing key; the sealing side added to the shared `crypto` crate | `crates/cp-crypto/`; an additive `seal` in `crates/crypto/`, reviewed by the agent stream | `Encryption::{encrypt, inspect}(text, context)`, `SigningKeys`, `crypto::seal` | a two-way reference set: Java decrypts and opens what Rust writes, and back, per context; `EncryptionServiceTest`, `EncryptionKeyFile*`, `VaultKmsProviderTest` against a wiremock Vault |
| 2.4 | **The fingerprint and the target vocabulary**, pure: `FindingType`, `ToolKeys`, the fingerprint, `ScanTarget`, `BoundedText`, `DependencyGraph`, `Sbom::is_catalogue`, `ScanStatus`, Spring's cron parser, licence blocklist, retention | new files in `crates/domain/src/`; `vectispire-rust/reference/{fingerprints,cron,…}/`; their Java writers in `vectispire-common/src/test/` | `fingerprint::{of, of_tool}`, `ScanTarget::fingerprint_key`, `clip`, `DependencyGraph::of`, `CronSchedule::next` | reference sets written by Java, byte-identical: `IssueFingerprintTest` and `ToolFingerprintTest` cases plus unpaired surrogates, no-break spaces, empty and null purls, astral characters at the clip; proptest corpora hashed by both sides; next fire times for a corpus of Spring expressions |
| 2.5 | **The protocol, server half**: typed reading of `ScanArtifacts` as Jackson reads it, with each `Option` kept; the claim, hello, sealing-key and failure bodies the server writes; a `client` feature the control plane leaves off, so it does not link the agent's HTTP client | `crates/protocol/`: additive, reviewed by the agent stream | `ScanArtifacts::read`, `AssignedTask` writer, the bodies | `reference/artifacts/` both ways, plus claim bodies written by Java; the Rust agent's `against_a_stub` suite; fuzz targets on the result body |
| 2.6 | **Targets**: the 29 routes; schedules, repository identity and duplicates, naming, imports; the two-phase deletion, resumed at start-up; the orphaned-rows and identity tasks | `crates/cp-targets/` | `TargetCatalog`; the `TargetScans`, `TargetBacklog` and `TargetPurge` traits; `GrantableTargets` and `IssuerSees` for `cp-access` | goldens of the 29; `TargetDeletionTest`, `TargetPurgeOrderTest`, `UnnamedTargetTest`, `CronExpressionsTest`; `RepositoryDuplicateIntegrationTest` and `TargetDeletionIntegrationTest` on both engines; the authorization-coverage rule on every route naming a target |
| 2.7 | **Queue, dispatch and schedule**: the claim (read, then a conditional update per candidate, labels and `notBefore` inside the selection, paged credential exclusion); the dispatcher (claim, sealing, heartbeat, result written in one transaction, failure, reclaim, attempts); the leader lease and scheduler; retention, purge, catalogue; the scans routes | `crates/cp-scanning/` except 2.8's files; it creates the crate and declares `ingestion` empty on day one | `ScanQueue::claim_within`; the `AgentClaimLock`, `ScanRuleSets` and `ScanPlugins` traits; `ScanDispatcher`; `TargetScans` for `cp-targets` | `ScanQueueIntegrationTest`, `ScanLabelsIntegrationTest`, `LeaderElectionIntegrationTest`, `SchedulerDatabaseTest`, `RetentionDatabaseTest` on MySQL and PostgreSQL; N claimants racing on both engines (each scan claimed once, nobody starved); `ScanDispatcherTest`'s cases; the 3 goldens |
| 2.8 | **Ingestion**: steps into findings, the examined set, enrichment applied before the write, the backlog handed the whole values, clipping after, the status rule, licences from the catalogue | `crates/cp-scanning/src/ingestion.rs`, `src/internal/ingestion/`, `src/persistence/findings.rs`; a Java reference writer under `vectispire-core/src/test/…/scanning/` | `ScanIngestor::{prepare, ingest}`; `Backlog`, `InventorySink`, `Enricher`, `EndOfLifeSource`, `LicenseSource`; `Observation`, `Reconciliation` | **the ingestion reference set** (below); `ScanIngestorTest`, `ExaminedTypes*`, `SecretsReportFateTest`, `NoOutboundDuringIngestionTest`, `EnrichmentOutsideTransactionTest`; `LongFindingIntegrationTest` on both engines |
| 2.9 | **Agents, server side**: the 8 protocol routes with the long poll and its concurrency header, and the 9 administration routes; hello's contract check; sealing key pinning; signatures verified on the raw body before parsing; credentialed backlog and its task; withheld-claim repair; the built-in worker as an executor the queue counts; the audit delivery handler | `crates/cp-agents/` | `AgentClaimLock` and `AgentDirectory` implementations; `AgentResultAuditDelivery` | goldens of 15 of the 17 (two deferred, below); `AgentSealingKeyIntegrationTest`, `WithheldClaimRepairIntegrationTest` on both engines; `AgentJobPollerTest`, `UnroutableWorkerTest`, `CredentialedBacklog*` |
| 2.10 | **The built-in worker**: the agent's scan pipeline moved out of the agent's binary (`agent/src/scan.rs`) into a library both programs use, and the worker's claim loop over it | `crates/runner/`, moved with the agent stream; `crates/cp-scanning/src/internal/worker/` | `Runner::run(task) -> ScanArtifacts` | **a started application with the worker on turns a queued scan into a completed one on both engines**: the wiring defect of `AGENTS.md`, which no unit test sees; `ScanWorkerOffloadTest`, `CloneFailureFateTest`; the agent's suites unchanged |
| 2.11 | **Composition and the oracle**: Phase 2 wired into the binary with its named stand-ins; the deferred list; the upgrade drill extended; both agents against the Rust image | `crates/cp-app/` (Phase 2's composition), `vectispire-rust/golden/deferred.txt`, `scripts/upgrade-drill.sh` | — | the phase's goldens replayed; the drill writes solutions, projects, repositories, containers, git tokens, SSH keys, agents and a scan through the last Java release's API, then reads them back through Rust on MySQL and PostgreSQL; `scripts/composition-scan-check.sh` with both agents; the twelve tables compared with Java's after the same scenario; the composition test of the stand-ins |
| 2.12 | **Phase 2 security review**: the `security-audit` skill on the phase's diff. Weight on whose estate a target route serves; that a reported scan belongs to the claiming agent; signature before parse; the sealing key's pinning; SSRF through repository URLs and image references; the 256 MB result limit; tokens and deployment keys never logged | — | — | no finding above low |

**The ingestion reference set.** Java runs `ScanIngestor` over a corpus with a recording `Backlog` and
writes, per case:

- the `Observation`, with every fingerprint;
- the finding rows;
- the examined set;
- the status.

The Rust ingestion must produce the same bytes. The corpus:

- the agent port's scanner reference outputs (dependencies 79, SAST 85, IaC 62, secrets 28);
- for each step, an absent case and an empty case;
- all steps absent with a failure;
- a plugin that produced, one not applicable and one refused;
- values past their columns;
- unpaired surrogates;
- an SBOM near the body limit.

This is "ingestion reference sets byte-identical" made executable. It is written before 2.8 starts,
because a reference written after the code tends to agree with the code.

Dependencies:

- **2.1 lands first, within a day.** Every crate's `Cargo.toml` is checked against its edge rule, and 2.2, 2.6, 2.7 and 2.9 implement its `MaintenanceTask`. Only 2.1 edits `edges.toml`; the others ask it for a line.
- **2.4 lands its types before their behaviour.** `FindingType`, `ScanTarget` and `ToolKeys` come first, so that 2.6 to 2.8 compile against them while the reference sets are being written.
- **2.3 and 2.5 publish their signatures first.** 2.6 needs `Encryption`; 2.7 needs `seal` and the claim body; 2.8 needs the typed artifacts; 2.9 needs the bodies.
- **2.7 owns `cp-scanning`'s `lib.rs`.** 2.8 owns only its declared files.
- **2.10 waits for the agent stream to agree to the runner's extraction.** Until then, 2.7's dispatcher is proven with remote agents only.
- **2.11 starts on day one**, since the goldens exist from task 0.5, and closes the phase. 2.12 comes last.

#### What cannot be cut, only deferred

1. **The issue ids on findings, and a scan's new and resolved counts.** They are the backlog's answers. Phase 2 compares them with the `Reconciliation` Java recorded; the real ones come with `issues` in Phase 3.
2. **`GET /agent/rules/{hash}` and `GET /agent/plugins/{id}/{digest}`.** Their content belongs to `rules` (Phase 3) and `plugins` (Phase 4). They are served through `ScanRuleSets` and `ScanPlugins`, so their goldens are deferred, as are claims naming a custom rule set or a plugin.
3. **The target listings' backlog figures.** Goldens recorded with open issues wait for Phase 3.
4. **A target deletion in full.** The rows of later modules wait for their purges; Phase 2's comparison of a deletion covers its twelve tables.
5. **Delivering what the outbox holds.** The scan-delta notifications are written by the backlog (Phase 3) and delivered by `notifications` (Phase 4), as are SIEM events.
6. **The agent port's crates.** `protocol`, `crypto` and the runner change in the agent's streams: additively, and reviewed there.

None of these makes a Phase 2 golden wrong. They make some of them later. `golden/deferred.txt` carries
one reason per golden and only shrinks, as `sql-known.toml` does.

#### Risks specific to Phase 2

| Risk | Why here | Mitigation |
|---|---|---|
| **A fingerprint drifts** | it fails nowhere: the backlog is resolved and recreated, with all triage lost (`AGENTS.md`). The difference hides in Java behaviour: `?` for an unpaired surrogate, `strip()` and the no-break space, null joined as empty, an empty purl falling back to the name | 2.4's reference set written by Java, with those cases; proptest corpora hashed by both sides; any difference fails the build, with no tolerance |
| **An `Optional` is flattened** | it silently resolves a type's whole history ([0007](../../architecture/en/decisions/0007-none-is-not-an-empty-list.md)); Java fixed it twice, for API contracts and for end of life | an absent case and an empty case per step in the ingestion reference set; in `cp-scanning`, no `unwrap_or_default` on an analyzer's `Option<Vec<_>>`, enforced by a lint rule |
| **Large SBOMs** | a result may reach 256 MB; a `serde_json::Value` tree costs several times the body, which must also be kept for the signature | verify on the raw bytes, then read the steps into typed structs and keep the SBOM as raw JSON; a memory test with a body at the limit; MySQL's `max_allowed_packet` in the engine tests |
| **Concurrent claims** | the claim is a read, then a conditional update per candidate, without a row lock. `SKIP LOCKED` was dropped for what it did on MySQL, and a wider window starved PostgreSQL. Both were seen only on real servers | racing claimants on MySQL and PostgreSQL, in `integrationTestAll`'s place. A test against a mocked database does not count as a claim test |
| **Two relays, at least once** | the outbox claim is a conditional update on `next_attempt_at`; a Rust relay missing a handler abandons Java's pending messages | `OutboxClaimIntegrationTest` on both engines; the relay is held back until the registry is complete; the drill checks `t_outbox_message` is unchanged |
| **Spring's cron** | schedules are stored as Spring `CronExpression` text: a seconds field, day of week 0 to 7, macros. No Rust crate reads them the same way | a port of the parser in `domain`, held to Java's next fire times and refusal messages |
| **UTF-16 lengths** | `BoundedText` and the length checks count UTF-16 units, where Rust counts bytes or characters | ported on UTF-16 units; reference cases with astral characters |
| **The agent's crates move** | `protocol` and `crypto` are shared; a change made for the server can alter the agent's bytes | additive only; the agent's reference sets stay in CI; the agent stream reviews |
| **Wired but not exercised** | the Java built-in worker claimed nothing for as long as it existed | 2.10 is accepted on a started application, not on a unit test |

## 8. Recommendation

- **Phase 0 can start now.** It is mostly what any later decision needs anyway: a Flyway-compatible runner, the oracle, the boundaries.
- **The rest waits for go/no-go 1.**
- **During the whole build, Java stays the product.** Releases, fixes and features land in Java first, each with its golden, so the oracle follows the product instead of freezing it.
