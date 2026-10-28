# Porting the control plane to Rust — what is left, and how to take a piece of it

This is the hand-over sheet for the port of `vectispire-core` and `vectispire-common` to Rust. It is
written for someone picking up **one task** without the history: what the rules are, what "done"
means, where things are, and what remains, in an order that lets several people work at once.

The reasoning lives elsewhere and is not repeated here:

- **The plan**: `docs/analysis/en/2026-10-16_rust_control_plane_port_plan.en.md` (French twin under
  `docs/analysis/fr/`), on branch `docs/rust-control-plane-plan` (34f4aab99). §2 is what must not
  change, §5 the phases and estimates, §7 the task tables for Phases 0, 1 and 2.
- **The workspace**: [`README.md`](README.md) — layout, conventions, the reference sets, the decisions
  of Phase 0, each crate's README for its own differences from Java.
- **The rules of the repository**: [`AGENTS.md`](../AGENTS.md). Its four traps apply to the port
  exactly as they apply to Java.

**Java stays the product during the whole port.** Releases, fixes and features land in Java first; the
Rust side follows them through the reference sets and the recorded traffic. Nothing here may slow the
0.11.x line.

## 0. Before delegating anything

These are prerequisites, not tasks. Until they are done, a new person cannot start.

1. **Nothing is pushed.** Every branch below exists only in the original clone. Push `rust/p1-merge`,
   `feat/rust-agent`, `docs/rust-control-plane-plan` and any task branch you hand over.
2. **The mutation scripts are in the repository** (done 2026-10-17): one script per task under
   `vectispire-rust/security/mutants/`, the mutants as data on `_runner.py`; `check.sh` runs every list's `--check`.
3. **The work trees were in a temporary directory.** The branches hold everything; recreate a work tree
   per task with `git worktree add`.
4. **The Java oracle tests run from a Java tree on the same branch.** Every task branch carries both
   `vectispire-java/` and `vectispire-rust/`; a reference-set test added in Java is committed with the
   Rust code that reads it.

## 1. What must not change

From the plan, §2. A task that breaks one of these is not finished, whatever its tests say.

1. **The OpenAPI document, byte for byte.** The Rust control plane serves the same `openapi.json`;
   `cp-contract` checks the router against it.
2. **The database schema, exactly.** No migration is written for the port. Same files, same
   `flyway_schema_history` (`crates/migrate`), so an installation can go from Java to Rust and back.
3. **MySQL and PostgreSQL, both**, in every engine test, from the first commit.
4. **The boundaries, at compile time.** One crate per Java module; its allowed dependencies are the
   lines of its file in `crates/cp-arch-tests/data/edges/` (`<module>.toml`); layering inside a crate is root / `internal` /
   `persistence` / `web`, checked by `cp-arch-tests`. A directory that is not a layer is refused.
5. **The security invariants of `AGENTS.md`.** Visibility is applied in the query and a refusal is a
   404; fingerprints are a data contract; absent is never empty; the outbound door is the only HTTP
   client; the agent never links a database crate.
6. **Everything stored stays verifiable** by Java: password hashes, key hashes, TOTP secrets,
   encrypted envelopes, signatures, the audit chain continued from its stored head.
7. **Sessions survive the switch.** A session opened by Java is accepted by Rust and back.

## 2. What "done" means for any task

A task is done when **all** of this holds, on its own branch, and the commit message says plainly
which check was not run, if any:

| Check | How |
|---|---|
| The workspace gate | `./check.sh` in `vectispire-rust/` — fmt, clippy `-D warnings`, every test, `cargo deny`, the unsafe check, the lint ceilings, `cargo vet --locked`, semgrep. **Docker is required**; its absence fails the run, it never skips. |
| Held to Java by a reference set | a Java test (`*ReferenceSetTest`) writes `vectispire-rust/reference/<area>/`, a Rust test reads it. Run the Java test in **check mode** (it fails when Java's answers differ from the committed files); regenerate only on purpose, never to make a test pass. Write the reference **before** the code: one written after tends to agree with the code. |
| On both engines | an engine test on MySQL 9.4 and PostgreSQL 17, migrated by `vectispire-migrate`. A test against a mocked database does not count for concurrency, dialect or schema behaviour. |
| Across the switch, where state is shared | a test against the published Java control plane on the same database: what Java writes, Rust reads, and back (see `cp-access/tests/across_the_switch.rs`, `cp-audit/oracle/`). |
| Replayed against Java's traffic | **any task that serves routes.** `crates/cp-contract/scripts/replay-goldens.sh <dir>` records the Java suite at the commit into `<dir>` (Docker and a JDK 25; about ten minutes), or reuses a recording already there, then runs `cp-contract replay-plan <dir>` and each served module's `tests/golden.rs` (`#[ignore]`d by a plain `cargo test`, which says so) on MySQL 9.4 and PostgreSQL 17. Every recording of a served route replays green on both engines — answer, headers, every row it changed — or its module's file in `golden/deferred/` names it with its reason; a line that has become green fails, so the task removes it and lowers that file's `ceiling`. A module that ports routes joins the replay in `cp-agents/tests/golden.rs` by being composed there (its routes are owed except those a `route` line still covers), or has a `tests/golden.rs` of its own that reads `VECTISPIRE_GOLDEN_DIR`, which the script finds — no line to add anywhere. A difference is fixed, or named as a stand-in with the task that ends it — never normalised away (`crates/cp-contract/README.md`, "The recorder's goldens"). |
| Checked queries | `sqlx::query!` / `query_as!` with offline caches; `crates/cp-db/scripts/sqlx-prepare.sh prepare <crate>` then `check`. The script checks every crate with a committed `.sqlx/`, so the first `prepare` is what enrols a new crate. A statement left unchecked says why in a comment. |
| No secret | gitleaks on a **fresh single-branch clone** of the branch, with CI's pinned image and `.gitleaks.toml`. A test fixture is allowed by `gitleaks:allow` or pinned in `.gitleaksignore`, never by widening the config. |
| The tests bite | a mutation check of the new logic: each guard broken, the suite goes red, sources restored identical. Every mutant killed; one that cannot be told apart is removed from the list with the reason, not counted as killed. |
| Wired, not just written | anything meant to run at start-up or on a schedule is proven on a **started** binary or by a composition test (the `MaintenanceJobsTest` lesson in `AGENTS.md`). |

Comments say why, not what. A deliberate difference from Java goes in the crate README's
"Differences from Java" section with the date and who decided it.

## 3. How to take a task

- **One task, one branch.** Phase 2's branches are stacked: `rust/p1-merge` → `rust/p2-1-shared` →
  `rust/p2-4-fingerprint` → `rust/p2-3-crypto` → `rust/p2-5-protocol` → `rust/p2-2-outbox` → `rust/p2-6-targets` → `rust/p2-11a-golden-replay` → `rust/p2-7-scanning`. Start a new
  Phase 2 task from the newest finished one.
  Name it `rust/p<phase>-<n>-<short-name>`.
- **A task owns its files.** The tables below say which. Touching another task's files is a
  conversation, not a commit. Shared agent crates (`protocol`, `crypto`, the runner) change only
  **additively**, and the agent stream reviews.
- **A port edits only its own module's file in `crates/cp-arch-tests/data/edges/`** — its `status`, and a new edge
  with its reason, which is a review decision like any line there; `_workspace.toml` (settings, infrastructure) is
  nobody's task to edit in passing.
- **Two or three ports can run at once.** The lists every port used to edit — the routes not ported, the deferred
  recordings, the edges, each with its ceiling — are one file per module, and the crate lists (workspace members, the
  replay tests, the checked-query crates, the mutation scripts) are found rather than written. What is still shared,
  and why, is in `.claude/skills/port-module/SKILL.md` §5b: `deny.toml`'s wrappers, the composition in `cp-app` and
  in the replay's router, `Cargo.lock`, and this file.
- **Publish interfaces first** when other tasks wait on them (types and trait signatures in a first
  commit, behaviour after).
- **Merging** is done by one person per phase, in a dedicated branch, rerunning the whole of §2 on the
  merged result. Expect conflicts in the composition (`cp-app`, the replay's router), `deny.toml`'s wrappers and
  `Cargo.lock` — not in the lists that shrink.

## 4. Where it stands (2026-10-21)

| | State | Branch |
|---|---|---|
| Phase 0 — foundations | done: migrate, cp-db, cp-http, cp-contract, traffic recorder, cp-runtime / cp-app, cp-outbound, cp-arch-tests | on `rust/p1-merge` |
| 1.1 Accounts and passwords | done | merged into `rust/p1-merge` |
| 1.2 Sessions, API keys, agent keys, SCIM token | done | merged |
| 1.5 Roles, visibility, four-eyes | done | merged |
| 1.6 Audit chain, settings, platform service | done | merged |
| Phase 1 merge | done, full gate green (771 tests) | `rust/p1-merge` (7474e7e72) |
| 2.1 Shared-module rule and maintenance turns | done (48/48 mutants) | `rust/p2-1-shared` (cf1b2aa22) |
| 2.4 Fingerprint, target vocabulary, Spring cron | done (109/109 mutants) | `rust/p2-4-fingerprint` (2d9ad0768), stacked on 2.1 |
| 2.3 Encryption at rest and sealing | done (63/63 mutants, 4 equivalents removed) | `rust/p2-3-crypto`, stacked on 2.4 |
| 2.5 The protocol's server half | done (119/119 mutants, 5 equivalents removed) | `rust/p2-5-protocol`, stacked on 2.3 |
| 2.2 Outbox | done (72/72 mutants, 4 equivalents removed) | `rust/p2-2-outbox`, stacked on 2.5 |
| 2.6 Targets | done: 29 routes, deletion and purge registry, identity, credentials (73/73 mutants, 7 equivalents removed); replayed by 2.11a | `rust/p2-6-targets`, stacked on 2.2 |
| 2.11a Golden replay | done: the recorder's format replayed on both engines; 7,148 recordings, 1,402 of the 1,480 of the 29 routes green on both | `rust/p2-11a-golden-replay`, stacked on 2.6 |
| 2.7 Queue, dispatch and schedule | done: `cp-scanning` — claim, dispatcher, leader lease, scheduler, retention, purge listeners; 102/102 mutants killed | `rust/p2-7-scanning`, stacked on 2.11a |
| 2.8 Ingestion | **not done**: oracle of 145 cases green; audited 2026-10-21 — licences wired and read per scan, enrichment and end of life named stand-ins, a `null` list element refused as Java does, the transaction mandatory (`rust/p2-8-ingestion-fixes`); 51/51 mutants killed (`p2-8-ingestion.py`). Open: an engine test over the real backlog and inventory, a check across the switch, the result route's golden replay (2.9) | `rust/p2-8-ingestion` |
| 2.9 Agents module | **not done**: 17 routes; audited 2026-10-21 — a failure answers 500 not 409, an undelivered claim goes back to the queue, the withheld-claim repair runs at start, the audit delivery is registered (`rust/p2-8-ingestion-fixes`). Authorization coverage and golden replay since 2026-10-22 (three differences fixed; 145 recordings named in `golden/deferred.txt`). Open: engine tests of the remaining routes, a reference set, the mutation list, checked queries (`crates/cp-agents/README.md`) | `rust/p2-9-agents` |
| 2.10 Built-in worker | **not done**: worker loop and shared runner; audited 2026-10-22 — the agents screen told whether the worker runs, the runner's images read from the settings, a runner that cannot be built refuses the start, and a **started binary runs a real repository scan** (`cp-app/tests/worker_runs_a_scan.rs`). Open: the runner scans no image and runs no plugin, trusts the compiled-in authorities only (`crates/cp-scanning/README.md`); a mutation list | `rust/p2-10-worker` |
| 2.11 Composition | done: control plane composition with named stand-ins (`35fe13f28`) | `rust/p2-11-composition` |
| 3.1 Rules | done: Semgrep rule sets, catalogue fetcher, rule coverage (`96154e9f9`) | `rust/p3-1-rules` |
| 3.2 Inventory | done: components, build SBOM imports, license governance (`f1833c188` / `33b675466`) | `rust/p3-2-inventory` |
| 3.3 Issues | done: triage, SLA, lifecycle, 10 OpenAPI endpoints, 86 routes composed (`de674ddee`) | `rust/p3-3-issues` |
| 3.4 Gate | **in progress**: quality gates, policies, evaluations, verdicts, exemptions (`fe0860336`) | `rust/p3-4-gate` |
| The agent (`vectispire-agent`) | foundations and three scanners done | `feat/rust-agent` |

In Java lines of `vectispire-core`: about 35,000 of 66,000 are ported or in progress. Most of
`vectispire-common` is handled by shared crates (`domain`, `protocol`, `crypto`, `runner`).

## 5. What is left

**The order, decided on 2026-10-28: three waves by risk, and nothing dropped.** A module stays out of the port only
when the product drops the feature; otherwise Java keeps running beside Rust for it, which costs more than porting
it. At most three ports run in parallel, each staged (domain → services → routes → replay) with one pull request per
stage, and each in a module of the current wave.

| Wave | Modules | Why in this place |
|---|---|---|
| 1 — the core | access, checklists, compliance, posture, platform; the end of siem | what the rest depends on, and most of the deferred recordings |
| 2 — integrations | forges, tickets, notifications, threatintel, ai | small, but each meets an outside service that is harder to test |
| 3 — the plugin system | plugins, reportplugins, exports | it runs third-party code, signed and verified: the most risk, and it reuses what the waves before settled |

The phases below keep their numbering and task breakdown; the waves decide which of them is taken next.

### 5.1 Phase 1 — Access (finish)

| # | Task | Owns | Notes |
|---|---|---|---|
| 1.3 | **MFA and throttles**: TOTP, recovery codes, lockout, login / bearer / webhook rate limits keyed as Bucket4j keys them | `crates/cp-access` (root / `internal` / `persistence` — not a `src/mfa/` directory), `crates/cp-http/src/limits.rs` | TOTP secrets are encrypted at rest: needs 2.3's `Encryption`, or a port stand-in until it lands. **Pure half done** (2026-10-28, `rust/access-domain`): `totp`, `login_throttle`, `ClientBuckets` in `cp-http`, `TeamRules` in the domain, held to `reference/sign-in/` and `reference/teams/`; the services follow with the routes (1.7) |
| 1.4 | **OIDC**: openidconnect client, account linking (verified e-mail only, never a privileged link), the hand-off cookie | `crates/cp-access`, outbound calls through `cp-outbound` only | a stub identity provider in tests; the session hand-off already exists in 1.2 |
| 1.7 | **Access routes**: `auth`, `users`, `teams`, `api-keys`, `admin`, `security`, SCIM — replayed against the recorded Java traffic | `crates/cp-access/src/web/` | after 1.3 and 1.4. Phase 1's exit: every golden of these routes passes |
| 1.8 | **Phase 1 security review**: the `security-audit` skill on the phase's diff | — | exit: nothing above low |

Follow-ups found during Phase 1, small enough to go with 1.7 or before it:

- **`cp-http` reads the session header leniently**: `bearer x` and `Bearer  x` open a session in Rust,
  not in Java. Make it strict, with a reference case.
- **`cp-http`'s `Principal` lacks the session hash.** The account id, the stored role, the key's restriction and the
  audit actor travel since 2.6 (`Principal::grounds`, filled by `Resolved::principal`, read by
  `cp_access::PrincipalGrounds`, which the binary composes as the chain's `PrincipalDirectory`).
- **The audit actor of an integration key** is `Principal::actor()` since 2.6: `user (API key name)`, as Java writes
  it; a principal built by a test double without grounds falls back to the account's username.
- **Two Argon2 PHC readers** in `cp-access` (`passwords` and `credentials::phc`): keep one.
- **`cp-platform`'s `Approvers`** is a trait the binary does not fill yet; wire it to `cp-access`'s
  `TriageApprovers`.
- **The audit log is not built by the binary yet** (`cp-app` has no database). Wire it.
- **`cp-db`'s comments promise** a test refusing a `query!` without its `/* mysql */` or
  `/* postgres */` tag. It does not exist: write it or remove the claim.
- **The Java-oracle suite of `cp-audit` and the mutation checks are not in `check.sh`.** Decide which
  belong in CI.
- **Session cleanup has no maintenance task.** `cp-access` has `purge_expired`, but Java's
  `SessionCleanupService.prune` does more; its slot is `SESSION_CLEANUP` in
  `crates/cp-maintenance/data/deferred.txt`.
- **The platform routes** (settings, audit log, crypto), the four credential-storing endpoints and the
  AI endpoint check wait for their modules.

### 5.2 Phase 2 — Targets and scanning

The plan's §7 "Phase 2, in parallel after Phase 1 exits" has the full table (owned files, interfaces,
oracle per task), the data contracts and the risks. Read it before taking a task. Summary:

| # | Task | Starts when |
|---|---|---|
| 2.1 | Shared-module rule, `cp-maintenance` turns and their global order | **done** |
| 2.2 | Outbox: enqueue in the caller's transaction, claim, backoff, abandonment, pruning | **done** |
| 2.3 | Encryption at rest (AES-256-GCM, key from variable / file / `/run/secrets` / Vault), signing key, an additive `seal` in `crates/crypto` | **done** |
| 2.4 | The fingerprint and the target vocabulary, pure, in `crates/domain`, with Java-written reference sets; Spring's cron parser | **done** |
| 2.5 | The protocol's server half in `crates/protocol`, additive, `client` feature off for the control plane | **done** |
| 2.6 | Targets: 29 routes, deletion and purge registry | **done**, replayed (2.11a) |
| 2.7 | Queue claim, dispatcher, leader lease, scheduler, retention, scans routes; owns `cp-scanning`'s `lib.rs` | **done** |
| 2.8 | Ingestion; the **ingestion reference set is written before the code** | **not done**: see §4 for what the audit left open |
| 2.9 | Agents, server side: 17 routes, long poll, signatures on the raw body, sealing-key pinning | **not done**: see §4 |
| 2.10 | Built-in worker over a runner moved out of `agent/src/scan.rs` into `crates/runner` (approved 2026-10-17) | **not done**: see §4 |
| 2.11 | Composition with named stand-ins, the upgrade drill extended, both agents against the Rust image; closes the phase | **done** (`rust/p2-11-composition`) |
| 2.12 | Phase 2 security review | last |

What the finished tasks leave to the others:

- **Maintenance slots.** All 28 of Java's slots are reserved in `cp-maintenance`'s `Sequence` and listed
  in `crates/cp-maintenance/data/deferred.txt`. A task implementing a `MaintenanceTask` registers it in
  `crates/cp-app/src/maintenance.rs` and removes its line from `deferred.txt` **in the same commit**.
  The binary does not start the turns yet (2.11, with `vectispire.jobs.initial-delay` mapped).
- **One-shot repairs** (withheld claims in 2.9, resumed deletions in 2.6) claim through
  `OneShotJobs::claim(&mut tx, name)`; on failure, roll back, then `has_run`.
- **2.7 (done):** `vectispire_domain::schedules` holds the whole rule (`is_due`, `offset`, `latest_slot`,
  `runs_at_least_every`, `in_force`) and `scan_queue` the queue's (`after_failure`, `retry_delay`, `lease_until`),
  both held to `reference/scanning/java-answers.json`.
- **2.8:** compute the fingerprint **before** clipping. The lone surrogate is decided (2.5): a result is
  read through `vectispire_protocol::jackson`, which writes an unpaired `\uD800` as `?` before `serde_json`
  sees it — what Java's `getBytes(UTF_8)` makes of it in the fingerprint and the database.

- **The protocol's server half (2.5), for 2.7, 2.8 and 2.9.** Depend on `vectispire-protocol` **without** its
  `client` feature (only the agent turns it on; `cargo tree -p vectispire-protocol -e normal` shows no
  `reqwest`, `hyper`, `rustls` or `tokio` without it). Everything is held to `reference/artifacts/java-read.json`
  and `server-wire.json`, written by `AgentWireReferenceSetTest` in `vectispire-core` with the application's own
  mappers — `CoreConfiguration`'s Jackson 2 bean for the bytes of the result and the failure report, Spring
  Boot's auto-configured Jackson 3 for every other body. They differ: Jackson 2 never reads past the first
  document and nests 1,000 deep; Jackson 3 refuses trailing content and nests 500 deep.
  - **2.8:** `ScanArtifacts::read(&body) -> Result<Received<'_>, Unreadable>`, on the bytes the signature was
    verified on. Every step stays an `Option`: `None` is absent, `Some(vec![])` ran and found nothing — never
    `unwrap_or_default` one. A `null` element of a finding list is kept as `None` (`Listed<T>`), because Java's
    record keeps it: decide what ingestion does with it as Java's ingestion does (it was not looked at here).
    The SBOM is `Cow<RawValue>` borrowed from the body (a 250 MB SBOM costs nothing more to read, measured in
    `tests/memory.rs`; a body that needs a rewrite costs one more body); it is **not** checked against
    `StreamReadConstraints` beyond depth, number and string lengths, which the reader applies everywhere —
    parse it as a stream, never into a `Value`. Coercions are Jackson's and pinned case by case: a number as
    text, text as a number in any Unicode digit, a decimal truncated to an `int`, an enum by name trimmed or
    by index, `"null"` as null for numbers and booleans; `ApiEndpoint` is normalised as its record is;
    `produced` without findings is `Absent` with Java's reason; a plugin step may come in the wrapper-array
    form `["absent", {…}]`. `duration` is a `JavaDuration` (seconds and a non-negative nanosecond part),
    including Java's wrap-around past a `long` for a decimal.
  - **2.9:** `Unreadable::Refused` is the route's 400 (`refusals::result_unreadable()`); `Unreadable::Null` is
    the body `null`, which Java's mapper returns as no result and `submitResult` then dereferences — a 500 in
    Java. Answer it as a 400 and record the difference in the crate README, or reproduce the 500 on purpose;
    either way decide it, it is not decided here. `server::{HelloRequest, SealingKeyRequest}::read` bind as
    Spring MVC binds (`Ok(None)` is the JSON `null`, which Spring answers 400 as a missing body);
    `FailureReport::read` reads as `reportFailure` does, an attempt below 1 or a `null` body included in the
    400. `contract_is_compatible` and `refusals::incompatible_contract` are the hello's 409; every other refusal
    of `AgentsController` is in `server::refusals` with its status. `HelloAnswer` and `FailureAnswer` write the
    answers byte for byte (`server::write` escapes control characters in upper-case hex, as Jackson does, and
    `iso_instant` writes `retryAt` in `ISO_INSTANT`'s groups of three digits). `SealingKeyRequest::has_usable_generation`
    is the service's first test; the key itself through `crypto::is_usable_sealing_key`.
  - **2.7:** `AssignedTask::to_body()` writes the claim as Spring MVC writes `AgentTask`; put the sealed envelope
    (`crypto::seal`) in `private_key` or `https.token`, never a key in the clear. Steps are written in the
    enum's order; Java writes `Set.copyOf`'s, which changes from one JVM start to the next — any order is the
    same set to the agent, and the reference set pins the enum's.
  - **Fuzzing:** `fuzz/fuzz_targets/result_body.rs` runs the result, failure, hello and sealing-key readers on
    any bytes, seeded with the reference bodies (1.18 million runs, 60 s, no failure, on 2026-10-17).
  - **Deliberate approximations**, each where no Java case could be cheap: a malformed UTF-16 body is decoded
    as the JDK's `UTF_16` decoder is understood to (U+FFFD, a high surrogate swallowing the unit after it; one
    case pinned); a root `null` followed by an identifier character is refused for ASCII letters, digits, `_`,
    `$` and anything past ASCII, where Java asks `Character.isJavaIdentifierPart`.

- **The outbox (2.2), for 2.9, Phase 4, Phase 5 and 2.11.** `crates/cp-outbox/README.md` has the semantics, the
  differences and the Java quirks reproduced.
  - **Enqueue** with `Outbox::enqueue(&mut tx, &payload, type, team_id)` inside the transaction that writes the state
    the message describes — never on a transaction of its own. The payload is a JSON object (anything else is refused);
    the returned id is the `message_id` stamped into it.
  - **2.9: the agents' audit delivery** is an `OutboxHandler` of type `agent_result_audit` (Java's
    `AgentResultAuditDelivery`), enqueued by the result route as `AgentProtocolService` does. Register it in
    `cp-app`'s `maintenance::outbox_registry()`. A failure is `DeliveryError::Failed { kind, message }` with `kind` the
    simple name of the exception Java's delivery throws; a destination that no longer exists is `DeliveryError::Gone`.
  - **The relay is held back** until `outbox_registry()` equals `reference/outbox/registry.json` — eleven types Java's
    started application relays: handlers `agent_result_audit` (2.9), `checklist_answer`, `owasp_report_after_scan`
    (Phase 5), `siem_event`, `token_alert`, `token_alert_audit` (Phase 4); channels `scan_delta`, `scan_delta_discord`,
    `scan_delta_mail`, `scan_delta_slack`, `scan_delta_teams` (Phase 4). Nothing else opens it: when the last one is
    registered, `NotificationRelayTask::is_held()` turns false and `crates/cp-app/tests/maintenance_composition.rs`'s
    assertion that it is held has to be dropped in that commit. A type added on the Java side regenerates the file
    (`OutboxRegistryReferenceSetTest`) and holds the relay again.
  - **Phase 4:** a `NotificationChannel` is handed the stored text, not a parsed `NotificationPayload` (the shape is
    yours to port); `is_configured` is for the enqueuer (`ScanDeltaNotifier`), the relay never asks it.
  - **2.11:** the composition is built over `Outbox::on_database(db, maintenance::outbox_registry(), clock)`; the
    relay task is composed and held, so starting the turns is safe on a database Java wrote. The upgrade drill should
    check `t_outbox_message` is unchanged across a Rust start (plan, risk "Two relays, at least once").
  - **Not done here:** a test against the published Java control plane on the same database. The rows are shown
    identical instead: every row `enqueue` writes is dumped column by column on both engines against the row Java's
    `enqueue` saves (`tests/engines.rs`), and the relay's calls are Java's call for call (`tests/reference.rs`).
- **Encryption (2.3), for everyone storing a secret.** `vectispire_cp_crypto::Encryption` is async:
  `encrypt(plain, context)` → `Result<String, EncryptionError>` (`MissingKey` is the 412 of
  `MissingEncryptionKeyException`), `inspect(stored, context)` → `Decrypted` (plain text as a `Secret`, and
  `SecretState`), `read_secret(stored, context, label)` for credentials that may predate encryption,
  `Encryption::is_ciphertext`. Build each context with the crate's functions (`private_key_context`,
  `git_token_context`, `forge_connection_context`), never inline: a context spelled twice is a secret that does not
  read. `crates/cp-crypto/README.md` has the format, the differences and what the reference set pinned.
- **1.3:** TOTP seeds are encrypted with `Encryption` under `TotpService`'s `TOTP_CONTEXT + ":" + user id` —
  the string is **`user:totp_secret:<user id>`**, not the constant's name. The reference set holds a seed under
  `user:totp_secret:5` both ways. Add a `totp_context` beside the others rather than formatting it in `cp-access`.
- **2.7 and 2.9:** `vectispire_crypto::seal(recipient_public, plain, &SealContext)` seals a deployment key or a
  token to an agent's announced key, byte for byte as `SealedEnvelope.seal` (`crates/crypto/tests/seal.rs`
  reproduces Java's envelopes from Java's randomness). It refuses a key that is not an X25519
  `SubjectPublicKeyInfo` with Java's sentence, and trims nothing — validate the announced key with
  `is_usable_sealing_key` when it is stored (2.9), seal at claim time (2.7).
- **2.11:** build `EncryptionConfig` from `cp_runtime::settings::Encryption` (same fields), and a `VaultDoor` from
  the outbound sender and guard; `Encryption::new` returns `StartupRefusal` for `kms-type=vault` without an
  endpoint or a token — the binary must refuse to start on it, as Java does. Build `SigningKeys` with
  `vectispire.signing.key` (cp-runtime's `signing_key`): a malformed or non-P-256 key is an error at start. **Open
  question for 2.11:** cp-runtime reads a blank `VECTISPIRE_ENCRYPTION_VAULT_TOKEN` as absent (refused at start);
  check what Spring's binding of an empty variable to `Optional<String>` gives Java before the composition test
  pins either.
- **`platform`'s `CryptoController`** (the public key, signature verification) waits with the other platform
  routes (follow-ups of 1.7); `SigningKeys::{public_key_pem, key_id, verify_with}` is its service. The exports
  (Phase 5) sign through `SigningKeys::{sign, wrap_and_sign_dsse}`.

- **Targets (2.6), for 2.7 to 2.11 and Phases 3 to 5.** `crates/cp-targets/README.md` has the differences and the
  Java quirks reproduced.
  - **2.7 implements `cp_targets::TargetScans`** (latest scan per repository and image, the languages of each
    repository's newest completed scan — a missing key is *unknown*, an empty set *none* — and `queue_repository` /
    `queue_container`, `AlreadyQueued` being the 409) **and scanning's two purge listeners**, `ScanPurge.purgeFindings`
    (`Phase::Findings`) and `ScanPurge.purgeScans` (`Phase::Scans`): implement `PurgeListener` (named exactly as in
    `deletion::JAVA_LISTENERS`, handed the deletion's `&mut Tx`, `TargetPurge::Orphans` included) and compose it with
    `PurgeRegistry::stand_ins().with(vec![…])`. The scheduler stamps through `Targets::stamp_scheduled(tx, …)` and reads
    rows through the catalog (`catalog_repositories`, `catalog_containers`, `carrying_credentials`); the dispatcher reads
    `stored_git_token` / `stored_ssh_key` — **still encrypted**, decrypted only where delivered.
    `vectispire_domain::schedules` holds `in_force`; `isDue`, the slot offset and `runsAtLeastEvery` go beside it.
  - **Phase 3 (issues)** implements `TargetBacklog` (stand-in: zero figures) and replaces the stand-ins of
    `IssuePurge` (three phases) and, with tickets, `TicketLinkPurge`; until then the foreign keys cascade and the orphan
    sweep finds nothing to sweep.
  - **2.11** composes `Targets` (`TargetsConfig`: the audit log, `Encryption`, the allow-list from
    `vectispire.git.allowed-hosts` — `GitHostAllowlist::parse` refuses the start on a malformed entry), adds
    `cp_targets::routes` to the registry with `CallerVisibility::new(VisibilityService::new(db, settings,
    TargetsForAccess(db)), PrincipalGrounds)`, **runs `Targets::purge_orphans()` once at every start** (Java's
    `ApplicationReadyEvent`; not a one-shot job), wires `IssuerSeesTargets` into the API keys' issuance. The 29 routes'
    recordings are replayed by `tests/golden.rs` (2.11a, below); `tests/routes.rs` (answers member for member, the
    coverage below) and `tests/contract.rs` (operation ids, parameters, the router probed) hold them too; the 29 left
    `not-yet-ported.txt` (ceiling 282).
  - **The authorization coverage** is `crates/cp-targets/tests/routes.rs`: it enumerates the module's router and asks
    every route naming a target, a project or a solution, as an unassigned `USER` and as an administrator's key
    restricted elsewhere, for a hidden and an absent identifier — same bytes, never a success, 404 where admitted.
    Copy its shape for 2.7's and 2.9's routes.
  - **1.7** gets `GrantableTargets::targets_in` only; Java's port also names grants, checks a project or target exists
    and labels targets — `naming`, `catalog` and `TargetsForAccess` hold those, to be added to the trait with the
    access routes.
  - `cp-arch-tests/data/edges.toml` still says `targets` is `pending`: flipping it to `ported` requires every listed
    edge to be used, and the crate reaches `access::security` only through `cp-access`'s root re-exports — task 2.1's
    file to decide.

- **The golden replay (2.11a), for every task with routes, and for 2.11.** `crates/cp-contract/README.md`, "The
  recorder's goldens", has the rules; `crates/cp-targets/tests/golden.rs` is the model to copy.
  - **What it found.** No difference in `cp-targets` itself: the 78 recordings not green are stand-ins and the
    recording's limits, each named in `golden/deferred.txt` — the backlog's zeros (`IssuesStandIn`, Phase 3, 26),
    "scan now" and the latest scan (`ScanningStandIn`, 2.7, 9), the `ProjectDeleted` and purge listeners of forges,
    plugins, checklists and report plugins (Phases 4, 5, 10), the SIEM event enqueued from an audit signal (Phase 4,
    3), an agent's key and long poll (2.9, 3), SSH keys the tests generate and the recorder hides (20), a test
    context's `vectispire.git.allowed-hosts` (2), a hidden digest (2) or a hidden secret's length (1), a 64 KiB sidecar
    body (1), and MockMvc's `Content-Type` sentence without the container's charset (1).
  - **For 2.11's composition.** The chain's own entries (`ACCESS_DENIED`, `BEARER_TOKEN_THROTTLED`) reach the audit log
    through nothing yet: the replay composes a `cp_http::credentials::Audit` over `AuditLog` itself (`ChainEntries` in
    `cp-targets/tests/golden.rs`, writing in the request as Java's filter does). The binary needs one, or every refusal
    differs by its missing row. The replay composes no `AgentDirectory` (2.9) and the default git-host allow-list.
  - **Not replayed yet, whatever the route:** a `concurrent` record, a binary or sidecar request body, an `https` scheme, a key or certificate the test sends (`«pem:…»`). Each
    stops its test there and is reported with its reason. A long poll's two `async` halves are played as one request
    since 2.9's audit (`replay::long_polls_merged`): its rows held to the first half, its answer to the second.
  - **In CI** (`rust-replay`): the suite recorded, the recording scanned by gitleaks, then `replay-goldens.sh`.

- **Scanning (2.7), for 2.8, 2.9, 2.10, 2.11 and Phases 3 to 5.** `crates/cp-scanning/README.md` has the map from Java,
  the ports and their stand-ins, the differences and the quirks reproduced.
  - **Composition order**: `target_scans(db, clock)` and `purge::listeners()` first, into `TargetsConfig`
    (`scans`, `PurgeRegistry::stand_ins().with(…)`); then `Scanning::new(ScanningConfig { targets, … })`;
    `vectispire_cp_scanning::tasks(scanning)` and `routes(scanning)` beside `targets`'.
  - **2.8 (ingestion)** fills `ports::ScanIngestor` (`prepare` outside the transaction, `ingest` in it after the
    row is held; `IngestError::Changed` is folded again, up to five times) in its declared files: `ingestion.rs`,
    `internal/ingestion/`, `persistence/findings.rs`. `Reconciliation::examined` is the set the scan keeps
    (`views::examined_types::write`); `None` leaves the column. The stand-in `IngestionStandIn` records the calls
    and folds nothing — the composition must not run real scans through it. The dispatcher already writes the status
    rule, the SBOM (as `JsonNode.toString()`), the project, the failure summary, the plugin outcomes and the
    languages.
  - **2.9 (agents)** implements `ports::AgentClaimLock` (`update t_agent set last_seen_at = ? where id = ?` in the
    caller's `&mut Tx`, as `AgentRepository.lockForClaim`) in place of `AgentsStandIn`, builds a
    `dispatcher::ClaimingAgent` from its row, and calls `ScanDispatcher::{claim_for_agent, return_undelivered,
    renew_agent_lease, accept_agent_result (with its outbox message as `Alongside`), report_agent_failure}`;
    `ClaimError::Withheld` is the 412, `AgentTask::assigned()` the body. `ScanCatalog` has what the credentialed
    backlog and the withheld-claim repair read (`waiting_repositories`, `waiting_with_attempts`, `refund_attempts`,
    the counts per claimant and label). The four recordings of `GET /api/v1/scans/{id}` that follow a long poll are
    deferred to 2.9's merge of the poll's two halves.
  - **2.10 (built-in worker)** implements `ports::ScanRunner` and passes it as `ScanningConfig::runner`; the worker's
    loop calls `ScanDispatcher::dispatch(worker, max_concurrent, labels)`, which already reclaims, counts this
    worker's room, renews before each run, keeps the lease while it runs and ends a failed attempt by the agents'
    rule (`tests/engines.rs`, "the built-in worker", with a fake runner).
  - **2.11** composes the above, maps `vectispire.scanning.*` onto `Policy` and `image_platform`,
    `vectispire.leader.lease` (at least a second) onto `leader_lease`, releases the scheduler's lease at shutdown
    (`LeaderElection::release_scheduler`), and keeps `ScanningStandIn` out of the binary. **Open:** the golden names
    of `ReadCostSweepTest` depend on the order the JVM walks the routes in (`--061-` in one recording, `--050-` in
    another), so `golden/deferred.txt`'s four lines for it match one recording only; the replay of this branch used
    the recording 2.11a made.

The two things that fail nowhere if they go wrong, and so need the most care:

- **The fingerprint.** Any change resolves every existing issue and recreates it, losing all triage.
  Reproduce Java exactly: `?` for an unpaired surrogate, `strip()` keeps the no-break space, null
  joined as empty, an empty purl falls back to the package name, UTF-16 lengths for clipping, clipping
  after the fingerprint — and lower-casing through `domain::java::to_lower_root`, never Rust's
  `to_lowercase`, which places the final sigma differently (task 2.4 found it; see
  `crates/domain/README.md`).
- **Absent is never empty.** An analyzer's `Option<Vec<_>>` is never `unwrap_or_default`-ed; an empty
  list resolves the backlog of that type.

### 5.3 Phase 3 — Issues, Rules, Inventory and Quality Gate (Detailed Breakdown)

Phase 3 ports the core decision and governance plane:
- **3.1 Rules (`crates/cp-rules`)** — **done** (`96154e9f9`): Semgrep rule sets, catalogue fetcher, rule coverage.
- **3.2 Inventory (`crates/cp-inventory`)** — **done** (`f1833c188`, `33b675466`): components, build SBOM imports, license governance.
- **3.3 Issues (`crates/cp-issues`)** — **done** (`de674ddee`): triage, SLA, lifecycle, 10 OpenAPI endpoints, 86 total routes composed.
- **3.4 Gate (`crates/cp-gate`)** — **in progress** (`fe0860336`): 1,612 Java lines, project gate policies, evaluations, verdicts and waivers.

#### Task 3.4 — Micro-tasks for `cp-gate` (Local / LLM-ready)

Each micro-task is atomic, touches 1 to 3 files, and is verified immediately:

| Subtask | Scope & Files | Action & Invariants | Verification command |
|---|---|---|---|
| **3.4.1 Domain & Types** | `cp-gate/src/policy.rs`, `verdict.rs`, `observation.rs`, `resolution.rs`, `cursor.rs`, `fields.rs`, `flag.rs` | Pure data models, Enums (`Verdict`, `SeverityThreshold`, `GateStatus`), Jackson wire serialization. `#![forbid(unsafe_code)]`, zero `unwrap()`. | `cargo check -p vectispire-cp-gate` |
| **3.4.2 Persistence** | `cp-gate/src/persistence/repository.rs`, `persistence/mod.rs` | Tables `t_gate_policy`, `t_gate_override`, `t_gate_evaluation`. Every SQL query tagged `/* mysql */` or `/* postgres */`. Implement `VisibleSelect` with `Visibility`. | `cargo test -p vectispire-cp-gate --test repository` (or `cargo check`) |
| **3.4.3 Evaluation Engine** | `cp-gate/src/gate.rs`, `service.rs`, `overview.rs` | Evaluate target issues against policy thresholds. Unwaived high/critical block the gate. Absent findings never evaluate as clean (`0007`). | `cargo test -p vectispire-cp-gate --lib` |
| **3.4.4 Purge & Maintenance** | `cp-gate/src/purge.rs`, `internal/tasks.rs` | Implement `PurgeListener` for project / target deletion. Register `GateEvaluationCleanupTask` in `maintenance.rs` and retire slot in `deferred.txt`. | `cargo test -p cp-app --test maintenance_composition` |
| **3.4.5 HTTP Routes & Views** | `cp-gate/src/web/routes.rs`, `web/read.rs`, `web/views.rs` | Axum routes (`GET /api/v1/projects/{id}/gate`, `POST .../overrides`). Require visibility (404 never 403 on missing or inaccessible project). | `cargo check -p vectispire-cp-gate` |
| **3.4.6 Composition & Contract** | `cp-app/src/main.rs`, `registry.rs`, `cp-contract/reference/not-yet-ported.txt` | Wire into router, lower `not-yet-ported.ceiling` by 7 routes. Run route authorization coverage and architectural boundary checks. | `cargo test -p cp-app --test route_authorization` & `cargo test -p cp-arch-tests` |

---

### 5.4 Phase 4 — Integrations (Micro-tasks Breakdown)

Java lines: ~18,000 lines across 7 vertical domains. Broken down into isolated crates:

| # | Task | Java lines | Owned files / crates | Key Invariants & Micro-steps |
|---|---|---|---|---|
| **4.1** | **Notifications (`cp-notifications`)** | 824 | `crates/cp-notifications` | **4.1.1** Channel types & settings (Slack, Teams, Discord, Mail).<br>**4.1.2** Outbox message handlers (`scan_delta_*`).<br>**4.1.3** Rate limiting & templating. |
| **4.2** | **SIEM Streaming (`cp-siem`)** | 936 | `crates/cp-siem` | **4.2.0** *Done*: the domain layer (`common.domain.siem`) in `crates/domain/src/siem/` — catalogue, `signalledBy`, CEF, syslog, endpoint, severity filter, triage signals, `CollectorCa` over `domain::pinned_ca` (the X.509 reading, BouncyCastle's answers); `TriageStatus` moved to `domain`; held to `reference/siem/`.<br>**4.2.1–4.2.3** *Done* (stage 2, `crates/cp-siem`): the services — `SiemExporterService` (save, view, connection test, stop notice), `SiemEvents` (the audit `Listener` and `ChainBrokenListener`, the `QueuedEvent` payload), `SiemDelivery` (the `siem_event` handler), `SiemSender`/`SyslogSender` (webhook through `cp-outbound`, syslog over UDP/TCP/TLS with the pinned collector CA), `t_siem_config` in checked statements; held to `reference/siem/module.json` (`SiemModuleReferenceSetTest`) on both engines. The table said "TLS client via `cp-outbound`": the syslog socket is the module's own (`SyslogSender`, as Java's), only the webhook goes through the pinned HTTP sender.<br>**4.2.4** *Done* (stage 3): the three routes (`web`, `RequestActors` ported into `cp_access::security`), the composition in `cp-app/src/siem.rs` (the handler in the outbox registry, the listener and chain-broken listener in the audit log, the sender over the start's guard and the runtime's trust) exercised by `tests/siem_composition.rs`, and the emitters' port, `cp_outbox::SecurityEvents`, wired into the issues (secret leak, SLA breach) and the gate (refusal); the threat feed's comes with its module.<br>**4.2.5** *Done* (stage 4): the routes' recordings replayed on both engines (142 of 146 green, four recording limits in `_recording.txt`), `golden/deferred/siem.txt` deleted; the recorder keeps certificates literal, and the issues' triage decisions signal their `TRIAGE_*` events. |
| **4.3** | **Tickets Sync (`cp-tickets`)** | 1,589 | `crates/cp-tickets` | **4.3.1** Issue link model & persistence (`t_ticket_link`).<br>**4.3.2** Jira & GitLab REST clients via `cp-outbound`.<br>**4.3.3** Purge listener for deleted targets. |
| **4.4** | **Threat Intelligence (`cp-threatintel`)** | 1,852 | `crates/cp-threatintel` | **4.4.1** EPSS & CISA KEV schema & SQLite/in-memory cache.<br>**4.4.2** Background refresh task.<br>**4.4.3** API routes (`/api/v1/threat-intel/...`). |
| **4.5** | **Forges Discovery (`cp-forges`)** | 5,306 | `crates/cp-forges` | **4.5.1** Connection credentials encryption context (`forge_connection_context`).<br>**4.5.2** GitHub / GitLab / Harbor repository discovery.<br>**4.5.3** Webhook HMAC verification and dispatch. |
| **4.6** | **Plugins Runtime (`cp-plugins`)** | 3,039 | `crates/cp-plugins` | **4.6.1** Manifest parser & Cosign image signature verification.<br>**4.6.2** Container / process runner protocol.<br>**4.6.3** Output bounds enforcement (10 MB ceiling). |
| **4.7** | **AI Assisted Triage (`cp-ai`)** | 375 | `crates/cp-ai` | **4.7.1** AI review consent & credentials guard.<br>**4.7.2** Prompt formatting & sanitized outbound calls. |

---

### 5.5 Phases 5 and 6 — Overview

| Phase | Modules (Java lines of `core`) | Exit | Key challenges |
|---|---|---|---|
| **5. Documents & Compliance** | checklists 6,882 · compliance 4,615 · reportplugins 3,593 · posture 2,454 · exports 1,400 · reporting 284 | xlsx byte for byte; PDF text-equal & structure-equal to Java | Starts with a 2-week spike on headless PDF generation (typst / printpdf / krilla) |
| **6. Cut-over & Hardening** | — | Every oracle green on both engines; 14-day nightly parity | Staging run side-by-side with production DB snapshot |

**Checklists (wave 1), `crates/cp-checklists`** — 10,100 lines of `core.checklists` and 7,700 of
`common.domain.checklists`; 35 routes, 101 deferred recordings at the start (59 after stage 0, the replay's
digest-prefix fix). One pull request per stage:

| Stage | What | State |
|---|---|---|
| 1a | The vocabulary: text, answers, items and pairing, contacts, reminders, rules and their canonical form, the evaluation and its evidence; the facts, a forge's review reading, Maven's order and ranges in `domain` | done, held to `reference/checklists/` |
| 1b | The workbook: the hand-written xlsx reader (`WorkbookReader`, `XmlCursor`, fuzzed), the layout and its proposal, the template version, the renderer and `DocumentZip` byte for byte, `ChecklistStatement` | next |
| 2 | The services and persistence; the `RepositoryScanned` listener, the `checklist_answer` handler, the reminders' maintenance task, the `ProjectDeleted` purge | needs `AccountDirectory` and `AccountNames` in `cp-access`; the plugins' import catalogue and the mail channel behind ports with absent-answering stand-ins until wave 2 and 3 |
| 3 | The 35 routes | |
| 4 | The replay of their recordings | |

---

### 5.6 The agent — finishing `feat/rust-agent`

From the workspace [`README.md`](README.md), "Remaining work, as independent streams":

| Stream | Done when |
|---|---|
| Workspace, census, API discovery | `LanguageCensus`, `ProjectManifest`, `ApiDiscoveryScanner` ported, each held to its own reference set |
| Plugins and bundled rules | plugin steps, bounded outputs, registry login, `ImageSignatureVerifier` through the pinned cosign image |
| Image export | `ExportImages` in the container crate (dependencies stream left it out) |
| Image and side-by-side conformance | reproducible image on both architectures; `scripts/composition-scan-check.sh MODE=agent` identical to the Java agent for two weeks in the nightly; only then does `release.yml` sign it |

---

## 6. Decided, and recorded where

| Decision | Date | Where |
|---|---|---|
| The settings save is one transaction (Java commits each change) | 2026-10-17 | `crates/cp-platform/README.md` |
| Authorization code at `cp-access`'s crate root, not `src/authz/` (the layering test refuses it) | 2026-10-17 | plan §7, row 1.5 |
| `crypto` and `maintenance` join Phase 2 (no phase had them) | 2026-10-17 | plan §7, Phase 2 |
| The scan runner moves to a crate shared with the agent (task 2.10) | 2026-10-17 | this file |
| One MySQL statement per crate may stay unchecked when its `in (…)` list varies in length; the reason is beside it | 2026-10-17 | `cp-access`, `cp-audit` READMEs |
| Agent-key fall-through is an equivalent mutant, removed from the list | 2026-10-17 | `p1c-mutate.py` |
| Port order in three waves by risk; nothing dropped unless the product drops the feature | 2026-10-28 | this file, §5 |
| The switch-over starts with a comparison on a staging copy (Java answers, Rust's answers are compared), never on production | 2026-10-28 | the internal deployment repository |
| A module raises a SIEM event through `cp_outbox::SecurityEvents` (Java's `SecurityEventRaised`/`Apart`), not through `domain` (no `Tx` there) nor `cp-siem` (an edge Java does not have) | 2026-10-28 | `crates/cp-siem/README.md` |

---

## 7. Playbook for Local LLM Development (OpenCode, Gemma, Qwen, Ollama)

When working locally with OpenCode and open-weight models (e.g. Qwen 2.5 Coder 14B/32B or Gemma 2 9B/27B on Apple Silicon 32 GB), follow this structured feedback loop to ensure compliance with Vectispire's strict safety and architectural rules.

### 7.1 The 5-Step Micro-Task Loop

Never prompt the model to "port the entire module". Execute one micro-task at a time:

```text
[1. Domain Types]   --> cargo check -p <crate>
        │
[2. Persistence]    --> cargo check -p <crate>
        │
[3. Business Logic] --> cargo test -p <crate> --lib
        │
[4. HTTP Routes]    --> cargo check -p <crate>
        │
[5. App Composition]--> cargo test -p cp-app && cargo test -p cp-arch-tests
```

### 7.2 Strict Rules to Provide in Local Prompts (System Prompt Additions)

Always enforce these 5 negative constraints in your OpenCode prompt context:
1. **Never use `.unwrap()` or `.expect()`**: Always bubble up errors with `?` or map them into the crate's `Error` enum.
2. **Never leave an `Option` unresolved as empty**: `None` means absent, `Some(vec![])` means ran and clean. Never `unwrap_or_default()`.
3. **Never bypass layers**: Web routes call services, services call repositories. Web routes never import persistence repositories directly.
4. **Tag every SQL statement**: Add `/* mysql */` or `/* postgres */` to query strings so offline query caching works.
5. **Always deny unsafe**: Ensure `#![forbid(unsafe_code)]` remains at the crate root.

### 7.3 Reference Files to Provide as Few-Shot Context

When porting a new submodule, feed OpenCode with the corresponding file from an already-completed crate:
* For **domain types & enums**: point to `crates/cp-issues/src/decision.rs` or `crates/cp-rules/src/rule.rs`.
* For **SQLx repositories**: point to `crates/cp-issues/src/persistence/repository.rs`.
* For **maintenance jobs**: point to `crates/cp-issues/src/internal/tasks.rs`.
* For **Axum HTTP handlers**: point to `crates/cp-issues/src/web/routes.rs`.

### 7.4 Verification Checklist before Committing

Run from the root of `vectispire-rust`:
```bash
# 1. Fast compile & type check
cargo check -p <crate_name>

# 2. Crate unit tests
cargo test -p <crate_name>

# 3. Layering & architecture test
cargo test -p cp-arch-tests

# 4. Route authorization & maintenance composition
cargo test -p cp-app --test route_authorization
cargo test -p cp-app --test maintenance_composition
```

