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
| 2.8 Ingestion | **done** (2026-11-15, `rust/p2-8-ingestion-wired`): oracle of 145 cases green; audited 2026-10-21 — licences wired and read per scan, enrichment and end of life named stand-ins, a `null` list element refused as Java does, the transaction mandatory; 51/51 mutants killed (`p2-8-ingestion.py`). Closed since: the golden replay composes the binary's ingestion over the real backlog and inventory, and every result recording it reached replays green on MySQL but for what other modules owe (checklists' `checklist_answer` message, Wave 1; end of life, Phase 4; the OWASP report, Phase 5 — their lines moved to those lists); **across the switch** (`cp-app/tests/ingestion_across_the_switch.rs`): Java 1.0.0-rc.2 and this binary take turns on one MySQL — the issue Java opened is found again by Rust on the same row, the one it no longer sees resolved, and Java finds Rust's new issue by its fingerprint | `rust/p2-8-ingestion-wired` |
| 2.9 Agents module | **done** (2026-11-15, `rust/p2-9-finish`): 17 routes; audited 2026-10-21 — a failure answers 500 not 409, an undelivered claim goes back to the queue, the withheld-claim repair runs at start, the audit delivery is registered. Authorization coverage and golden replay since 2026-10-22. Finished: the administration **held to Java's answers** by a reference set written before the fixes (`reference/agents/administration.json`, 64 cases — it found Java's `String.trim` kept a no-break space where `str::trim` did not, here and in `crates/crypto`'s key decoding); a removal revokes the key first and fails on a failed revocation; the claim's `wait` bound as Spring binds it; a database failure at authentication a 500, not a 401; **engine tests** of hello, the signs of life, the long poll, the heartbeat and failure reports (`tests/protocol_lifecycle.rs`); **checked statements** on `t_agent` (`.sqlx/`, 34); 19/19 mutants killed (`security/mutants/p2-9-agents.py`). Across the switch: `cp-app`'s `ingestion_across_the_switch` has Rust claim and submit as the agent Java declared. Not run: PostgreSQL | `rust/p2-9-finish` |
| 2.10 Built-in worker | **done** (2026-11-15): worker loop and shared runner; audited 2026-10-22 — the agents screen told whether the worker runs, the runner's images read from the settings, a runner that cannot be built refuses the start. Finished: the runner **scans images** (`ContainerRunner::export_image`, Java's one dependencies step), honours `host-ssh: false` and `bundled-rules` (refused at start before), and clones with the **runtime's trust** (`VECTISPIRE_TLS_CA_BUNDLE`). Verified on a **started binary** against MySQL, the test forge and the real scanner images (`cp-app/tests/worker_runs_a_scan.rs`, 5 cases: a repository over SSH, the same over HTTPS behind a private authority, `host-ssh` off refused, an image exported and scanned, a runner that cannot be built refusing the start); 17/17 mutants killed (`security/mutants/p2-10-worker.py`). **Plugins stay with 4.6**: the shared runner records them absent, but no task the worker claims can name one while the composition's `ScanPlugins` is `NoPlugins` — as on a Java install with none turned on. **Found, shared with Java**: an image's save names no platform, so on Docker's containerd store a non-host `image-platform` inventories the host's variant (`crates/cp-scanning/README.md`); to fix in Java first | `rust/p2-10-worker` |
| 2.11 Composition | done: control plane composition with named stand-ins (`35fe13f28`) | `rust/p2-11-composition` |
| 2.12 Phase 2 security review | **done** (2026-11-15): the `security-audit` skill's four areas over what Phase 2 ported, every finding verified in the code (`security/reviews/2026-11-phase-2.md`). **Fixed**, each with a test red before it: the agent protocol found the agent **by name**, so a disabled agent's key acted as a namesake (H1); the runner let the scanned repository **configure its own scanners** — Java's `ScannerConfigurationFiles` was not ported (H2); a repository URL could name **Vectispire's own endpoints** (M1); keys **of small order** were accepted by the Ed25519 check and the X25519 sealing (M2, M3); two parity slips (L5, L6); 22/22 mutants killed (`security/mutants/p2-12-security.py`). **Listed, not fixed**: four lows (a key lookup's database failure a 401, swallowed failures in `hello`, the route test's `names_no_target()` exemption, the gate's dropped visibility proof) and three shared with Java, to fix there first | `rust/p2-12-security-review` |
| 3.1 Rules | done: Semgrep rule sets, catalogue fetcher, rule coverage (`96154e9f9`) | `rust/p3-1-rules` |
| 3.2 Inventory | done: components, build SBOM imports, license governance (`f1833c188` / `33b675466`) | `rust/p3-2-inventory` |
| 3.3 Issues | done: triage, SLA, lifecycle, 10 OpenAPI endpoints, 86 routes composed (`de674ddee`) | `rust/p3-3-issues` |
| 3.4 Gate | **done** (2026-11-15): seven routes served and composed; every recording replays green on MySQL — `POST /api/v1/gate` left `golden/deferred/`, whose `gate.txt` is gone; engine tests on MySQL; route authorization held by `cp-app`'s registry test (the verdict route resolves a `Visibility`, 404 never 403); Java's domain tests ported (`tests/domain.rs`, 70 cases); 41/41 mutants killed (`p3-4-gate.py`); persistence is SeaORM, so no `.sqlx/` to regenerate. Seven whitespace/parsing parity slips fixed (`crates/cp-gate/README.md`). Not run: the replay on PostgreSQL | `rust/p3-4-gate-done` |
| Platform stage 2 | **done** (2026-11-15): `GET` and `PUT /api/v1/settings` served — the catalog and its save — over two narrow seams `cp-platform` holds (`tickets`' CA pinning, `ai`'s destination guard and acknowledgement record: `src/seams.rs`, README says why narrow) and `access`' `TriageApprovers`, now wired in the binary (`cp-app/src/settings_screen.rs`, `tests/settings_composition.rs`). The save **held to Java's answers** by a reference set written first (`reference/platform/settings-save.json`, 86 cases, real `AiReviewService` over a real guard, `PinnedCa` itself): all 86 equal. Every recording of the two routes replays green on MySQL (both lines left `not-yet-ported/` and `golden/deferred/`, ceilings 12 → 10). Found by the replay and fixed: the **recorder sorted a request's members**, so a save replayed in an order Java never received (its audit entry and its first refusal follow the body's order) — it now keeps the order sent (`TrafficRecorder`, with a test); the replay's chain ignored a test class's `vectispire.security.trusted-proxies`; `AiReviewConsentTest` depended on live DNS for `api.openai.com` (its 422 quoted the day's address) — it names a public literal now. 20/20 mutants killed (`security/mutants/p2-platform-stage2.py`); no new statement, so no `.sqlx/` to regenerate. Not run: PostgreSQL. The ten other routes of `SettingsController` wait for `tickets`, `notifications` and `ai` | `rust/platform-stage2` |
| W1 Posture | **done** (2026-11-16, `crates/cp-posture`): all eighteen routes served and composed (dashboard, trends and analytics, quality, remediation debt, coverage, distribution and fixes, attack paths, scorecards, simulation, badges) — `not-yet-ported/posture.txt` is gone; the weekly digest fills maintenance slot `WEEKLY_DIGEST`. **Held to Java's answers** by a reference set written first (`reference/posture/decisions.json`, `PostureReferenceSetTest`): formula, grades, cap, badge SVG, series, analytics, distribution, coverage, versions, the report's text. Posture owns no table: its aggregates over `t_issue` are `cp-issues`' (`persistence/aggregates.rs`, engine-tested), the completed scans and recent history `cp-scanning`'s, the scopes `cp-targets`', the licence violations `cp-inventory`'s. **Replay on MySQL**: 98 of posture's 128 recordings green; 7 recordings and the two series routes (21) listed in `_recording.txt` — their figures of time are drawn over seeded instants the recorder hides — `golden/deferred/` 326 → 317. Found and fixed: sea-orm's derive ignores `from_col` (a 500 on debt, coverage and attack paths); Java fixed rather than reproduced — `Map.of`/`Map.copyOf`/`HashMap` orders on the wire, the digest's locale, and `Math.exp` (now `StrictMath.exp`; `arithmetic::strict_exp` is fdlibm, bit-identical to the JDK on 200,019 arguments). `notifications` is a port (`DigestChannels`) with `NotificationsStandIn` answering "no destination" — no recording reaches it, so no deferred line names it; wave 2 plugs it in (`edges/posture.toml` stays `pending` until then). 57/57 mutants killed (`security/mutants/w1-posture.py`), four equivalent ones left out with their reason. Not run: PostgreSQL | `rust/w1-posture` |
| W1 Compliance | **in progress** (2026-11-17, `crates/cp-compliance`). **Stage 0 done**: the reads compliance needs in `cp-issues` and `cp-scanning`, the four tables with their purges and three retention tasks, and the pure decisions (frameworks, engine, statement of applicability, history, scope, manifest — `cp-compliance`'s root files, not `vectispire-domain`: a sentence of the engine names the encryption key, which nothing the agent links may) and the OWASP grid in `vectispire-domain`, held to `reference/compliance/` (`ComplianceReferenceSetTest`). Two parity defects of `cp-issues` fixed on the way: the `owasp_category` placement and the backlog's date clauses (half open, reopenings read). **Stage 1 done**: the matrix's four routes (summary, framework, project, solution) served and composed, the deployment's controls read through two ports the binary answers. **Replay on MySQL**: green — 2662 of 2754 recordings, the rest listed; seeded audit entries now carry the hash their fields make (`Bindings::seal_audit_entry`), which made the audit-log verification recording green too. **Stage 2 done**: the governance — the statement of applicability (every framework, one, the lapsed reviews, a declaration written and audited), the certified scope (read, a repository's or an image's membership set and audited) and the history read — eight routes, held by `tests/governance.rs` on MySQL. **Stage 3 done**: the OWASP grid — the categories with their declarations, as CSV (English or French reasons), week by week (the weekly record where captured, reconstructed from the issues' dates where not), and a category declared — four routes, with the two hourly captures (`OWASP_WEEKLY_COVERAGE` behind its six-hour gate, and `COMPLIANCE_HISTORY`, which reads the grid's reach of code analysis), held by `tests/owasp.rs` on MySQL. The replay seeds a recorded `week_start` as its own week's Monday; twelve weekly recordings whose dates the recorder hid (a window relative to the test's today, issues first seen weeks before) are listed in `_recording.txt`. **Stage 4a done**: the OWASP report read — `GET /api/v1/repositories/{id}/owasp-review`, the latest review with its status as of now (running past its deadline reads failed, with the reason, before the hourly sweep writes it), the model's Markdown in blocks (`markdown.rs`, written by hand — Java's emphasis rule looks behind, and its `\s` and `.` are not Rust's — held to `reference/compliance/markdown.json`, 2916 parses and the status either side of a deadline, all equal), the ten categories' figures as the backlog's own count, and links only from the identifiers the model was shown; held by `tests/report.rs` on MySQL. Replay on MySQL green — 2762 of 2868, all fourteen report recordings among them. Found on the way: `cp-contract`'s probe read a path's unported `POST` beside its served `GET` as served — without a credential the chain answers 401 before routing and only the 405's `Allow` is left; it now reads such an answer as the method fallback (with a test). 23/23 mutants killed (`security/mutants/w1-compliance-4a-owasp-report-read.py`). **Stage 4b waits for `ai`**: the request (`POST`), the evidence digest and the after-scan writer only produce a report through a model client, which is that module's; the two PDFs and the evidence bundle wait for the PDF spike and `exports` | `rust/w1-compliance` |
| W2 Forges | **done** (2026-11-18, `crates/cp-forges`): all fourteen routes of `/api/v1/forge-connections` served and composed — `not-yet-ported/forges.txt` and `golden/deferred/forges.txt` are gone — with the maintenance slots `FORGE_TOKEN_WATCH` and `CHANGE_REVIEWS`, the discoveries' worker (every instance, its own loop), the import's purge listener, the checklists' `ReviewEvidence` port in place of `NoReviews`, and the forge tokens' census line. The domain (`vectispire_domain::forges`, `rate_limit`, `token_alert`) carries Java's `common.domain.forges` with each test class's cases; `cp-outbound` gains `OutboundJson` and `OutboundPager` (threatintel, tickets and ai use them too); the five tables are SeaORM entities held by the parity suite, no `.sqlx/` cache. **The replay's stub forge**: the recorder now keeps every answer a test's `ForgeStub` gave (`outbound` in the manifest) and `ForgeStub.fixture()` pins a fixed CA key, so `golden.rs` stands up a TLS forge under the CA the test pinned and answers Java's stub's answers. **Replay on MySQL** (full recording at this commit): green — 5706 of 5935 recordings of the routes, the rest listed; `golden/deferred/` 357 → 345. Eleven recordings moved to `_recording.txt`: one quotes the JDK's PKIX sentence for an unknown issuer, five read change-review evidence the recorder seeded with `«instant»` inside its JSON, five page forge connections the test wrote behind the API, whose `«sealed»` token no key opens. Java fixed rather than reproduced: an IPv6 forge address bracketed twice. Known differences (crate README): first scans queued after the import commits; the token alert's audit entry without the channels until `notifications` lands. 15/15 mutants killed (`security/mutants/w2-forges-1.py`). Not run: PostgreSQL | `rust/w2-forges` |
| W2 Notifications | **done** (2026-11-18, `crates/cp-notifications`): both routes served and composed (`GET /api/v1/notifications/channels`, `POST /api/v1/notifications/test/{channelType}`) — `not-yet-ported/notifications.txt` and `golden/deferred/notifications.txt` are gone. The five channels (generic webhook global and per team, signed over the bytes sent; Teams, Slack, Discord; mail) are outbox channels under Java's types, listed and queued in Java's bean order; each asks the registry first — held from the outbox, 409 otherwise. `ScanDeltaNotifier` is `issues`' new `ScanDeltaSink` (one row per listening channel, one webhook copy per owning team with a channel, through the project too); `TokenAlertSink` (cp-outbox, beside `SecurityEvents`) is how `tickets` and `forges` raise a token's change, queued as `token_alert_audit` and one `token_alert` per channel; `NotificationChannelInUse` joins the registry's in-use refusals, which made the 21 channel-switch recordings green. The domain half is in `vectispire_domain::notifications` (payload, selection, chat escaping, the renderings, the webhook signature, `TokenAlert`), with `cp_outbound::OutboundPost` (Java's `OutboundPost` and `OutboundJson` lookups). Posture's weekly report (`ChannelsDigest`) and the checklists' reminder send through it from their own crates: `posture` is now ported. **Mail has no SMTP relay in this build**: the channel reads unconfigured, as a Java deployment without a mail host, and a named host is warned about at start. Not run: PostgreSQL | `rust/w2-notif-tickets` |
| W2 Tickets | **done** (2026-11-18, `crates/cp-tickets`): the three routes served and composed (the links attached by hand, the tracker's webhook) — `not-yet-ported/tickets.txt` and `golden/deferred/tickets.txt` are gone; slots `TICKET_SWEEP` and `TICKET_TOKEN_CHECK` filled (`cp-maintenance` FILLED 24). The tracker client (GitLab, GitHub, Jira, ServiceNow) through `OutboundPost` with the pinned CA checked current at every use; the token refused while the tracker is suspended; its health announced once per change; the sweep gated by the policy of the issue's scope (`GateIssue::of_view`, now shared with the gate) and claimed first; `TrackerTicketReferences` handed to the issues' attach decision (which now refuses in Java's order); `TicketLinkPurge`; the settings save asks tickets' own `caToPin` (cp-platform's `TrackerCaPinning` stays for its own tests). The issues' owner APIs (ticket catalogue, the V95 claim, the scan delta's sink, `PurgedIssues`) landed first, with the fold keeping the findings' first-appearance order as Java's. Both services join the encryption census. The replay's chain now counts the tracker webhook in `t_rate_window`, as `main` does. Engine tests run the sweep against a GitLab stand-in through the real outbound door. **Replay on MySQL green**: 5813 of 6023 recordings, the rest listed — every recording of the five routes and the 21 channel-switch ones among the green. Four moved to `_recording.txt` (a test's own loopback receiver; two GitHub signatures over bodies the recorder hides; the flood's 301st delivery, refused by the bucket in Java and by the shared minute window in the slower replay); `golden/deferred/` total 22 lower (26 lines gone, 4 moved in). Found by the replay: Java lists and queues the channels in its bean order (mail, webhook, Discord, Slack, Teams), and the replay's chain lacked `main`'s shared webhook window, now counted on the answering clock. `MfaRoutesTest/disablingIsThrottledLikeSignIn--004` (listed, access) replays green or not depending on the one-time-code step the clock lands on — left listed. 24/24 mutants killed (`security/mutants/w2-notifications-1.py`, `w2-tickets-1.py`). Not run: PostgreSQL. Left: the platform's ten settings routes (tickets' and notifications' states), which are the platform's | `rust/w2-notif-tickets` |
| W2 Threatintel | **done** (2026-11-19, `crates/cp-threatintel`): the five routes served and composed (the feeds' status, the EPSS priorities, a CVE's record, the two syncs) — `not-yet-ported/threatintel.txt` and `golden/deferred/threatintel.txt` are gone — with the KEV catalogue and the EPSS file synchronised whole (`KEV_CATALOGUE`, `EPSS_SCORES` in the hourly turn), `CRITICAL_KEV_DETECTED` raised once per promoted issue, and enrichment and end of life composed into the scan ingestion, no stand-in left. Held to Java's reference set (`reference/threatintel/`); 21 + 17 + 17 mutants; the syncs' recordings that rest on a Mockito source listed in `_recording.txt` with that reason |
| W2 Ai | **done** (2026-11-19, `crates/cp-ai`): the three advisor routes served and composed (`GET /api/v1/ai-advisor/status`, the explanation of an issue and of a CVE) — `not-yet-ported/ai.txt` and `golden/deferred/ai.txt` are gone — with the configured model asked through the guard only when the review is on and its provider switched on (409 `integration-disabled` otherwise, the other provider never asked), and the product's own advice when it does not answer. 14 mutants; one status recording that read a fake Ollama listed in `_recording.txt` |
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
| 1.3 | **MFA and throttles**: TOTP, recovery codes, lockout, login / bearer / webhook rate limits keyed as Bucket4j keys them | `crates/cp-access` (root / `internal` / `persistence` — not a `src/mfa/` directory), `crates/cp-http/src/limits.rs` | TOTP secrets are encrypted at rest: needs 2.3's `Encryption`, or a port stand-in until it lands. **Pure half done** (2026-10-28, `rust/access-domain`): `totp`, `login_throttle`, `ClientBuckets` in `cp-http`, `TeamRules` in the domain, held to `reference/sign-in/` and `reference/teams/`. **Services done** (2026-10-28, `rust/access-signin`): the throttle's reservations, `AuthService.login`, `AuthenticationFlowService` without the federated sign-in (1.4), `TotpService` (encrypted under Java's contexts, crossing the switch both ways against 0.11.0-rc.3), `SignInMethodPolicy`, `RateWindows` composed as the chain's shared webhook window, and `SESSION_CLEANUP` composed; every statement checked and run on both engines, the races included (`crates/cp-access/README.md`). The routes are 1.7's. A Java defect found: the MFA challenge's user agent is not clipped (500 for an agent past 255 characters) |
| 1.4 | **OIDC**: openidconnect client, account linking (verified e-mail only, never a privileged link), the hand-off cookie | `crates/cp-access`, outbound calls through `cp-outbound` only | a stub identity provider in tests; the session hand-off already exists in 1.2 |
| 1.7 | **Access routes**: `auth`, `users`, `teams`, `api-keys`, `admin`, `security`, SCIM — replayed against the recorded Java traffic | `crates/cp-access/src/web/` | after 1.3 and 1.4. Phase 1's exit: every golden of these routes passes. **Administration stage served** (2026-11-16, `rust/w1-access`, wave 1): the 24 routes of `UsersController`, `AccountRequestsController`, `TeamsController` and `ApiKeysController`, over Java 1.0's four-eyes on account administration (V100: requests filed, approved under the request's lock, rejected; `ApproverIndependence`, also asked by the issues' triage approval, which compared names only) and the second factor's reset; `CredentialTables` and `IssuerVisibility`, the two production ports nothing implemented; a team's webhook refused and held while `notification.webhook` is off; every recording of the routes green on MySQL but twelve listed in `golden/deferred/_recording.txt` (a session seeded before its token is sent, Mockito spies, a gesture aged behind the API). **Sign-in stage served** (2026-11-16): `AuthController`'s ten routes over 1.3's services; the session hash on the principal; the replay computes one-time codes. **SCIM stage served** (2026-11-17): the twelve routes of `ScimUsersController` and `ScimGroupsController`, `/scim` confined to the SCIM token as Java confines it, SCIM's audit entries as Java 1.0 writes them (`SCIM provisioning`, the account's id); every SCIM recording green on MySQL. **Every access route is served** (`rust/w1-access`); single sign-on's own endpoints (1.4) are outside the contract and not ported. **Administration services done** (2026-10-29, `rust/access-admin`, stage 2b, no route): an account's grants, `TeamAdministrationService` and `TeamChannels`, `ApiKeyAdministrationService`, `GrantTargets`, `AccountNames` and `AccountDirectory`; `GrantableTargets` carries Java's four other questions, answered by `cp-targets`; every statement checked and run on both engines (36/36 mutants, 3 equivalents removed). Two Java defects reported, not reproduced silently (`crates/cp-access/README.md`). **SCIM's service done** (2026-10-29, `rust/access-scim`, stage 2c, no route): `ScimProvisioningService` — users, groups, the filter grammar, the pages, the refusals — with its pure rules in `vectispire_domain::scim`, held to `reference/access/scim/` (`ScimReferenceSetTest`), every statement checked and run on both engines, one transaction per gesture (63/63 mutants). Two more Java defects corrected here and reported (an `externalId` held by another account, a PATCH member value that is an object: both 500) |
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
- ~~**`cp-platform`'s `Approvers`** is a trait the binary does not fill yet.~~ Filled since platform stage 2 by
  `cp-app`'s `settings_screen::AccessApprovers` over `cp-access`' `TriageApprovers`, held by
  `cp-app/tests/settings_composition.rs`.
- ~~**The audit log is not built by the binary yet.**~~ It is (`cp-app/src/main.rs`, with its mirror and the SIEM's
  listeners), and its reader serves the audit-log routes since the platform port's first stage.
- **`cp-db`'s comments promise** a test refusing a `query!` without its `/* mysql */` or
  `/* postgres */` tag. It does not exist: write it or remove the claim.
- **The Java-oracle suite of `cp-audit` and the mutation checks are not in `check.sh`.** Decide which
  belong in CI.
- **The platform routes**, in stages (2026-10-28): the audit log's and crypto's six are served and replayed
  (`rust/platform-stage1`); the settings catalog and save are served and replayed since stage 2 (2026-11-15,
  `rust/platform-stage2`), with `tickets`' CA pinning and `ai`'s destination guard as narrow seams `cp-platform` holds
  (`crates/cp-platform/README.md` says why narrow) and `access`' `TriageApprovers` wired; the four credential-storing
  endpoints, their state reads, the tracker CA and the AI endpoint check wait for `tickets`, `notifications` and `ai`
  (wave 2).

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
| 2.8 | Ingestion; the **ingestion reference set is written before the code** | **done** (2026-11-15): see §4 |
| 2.9 | Agents, server side: 17 routes, long poll, signatures on the raw body, sealing-key pinning | **done** 2026-11-15: see §4 |
| 2.10 | Built-in worker over a runner moved out of `agent/src/scan.rs` into `crates/runner` (approved 2026-10-17) | **done** 2026-11-15: see §4 |
| 2.11 | Composition with named stand-ins, the upgrade drill extended, both agents against the Rust image; closes the phase | **done** (`rust/p2-11-composition`) |
| 2.12 | Phase 2 security review | **done** 2026-11-15: see §4 and `security/reviews/2026-11-phase-2.md` |

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
  `user:totp_secret:5` both ways. Built by `cp-crypto`'s `totp_secret_context` (and `backup_codes_context` for the
  backup codes), which `cp-access`'s second factor uses (done with 1.3's services).
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
- **`platform`'s `CryptoController`** (the public key, signature verification) is served since the platform port's
  first stage, over `SigningKeys::{public_key_pem, key_id, verify_with}`, which the binary now keeps. The exports
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
  - **1.7**: `GrantableTargets` carries Java's five questions since the access administration (stage 2b) —
    `TargetsForAccess` answers `named`, `project_exists`, `exists` and `labels` from `naming` and the persistence.
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
- **3.4 Gate (`crates/cp-gate`)** — **done** (2026-11-15, `rust/p3-4-gate-done`): policies, evaluations, verdicts, the register and the overview; replayed green, mutation-checked (see §4).

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
| 1b | The workbook: the hand-written xlsx reader (`WorkbookReader`, `XmlCursor`, fuzzed), the layout and its proposal, the template version, the renderer and `DocumentZip` byte for byte, `ChecklistStatement` | done (2026-11-16, `rust/w1-checklists-1b`), held to `reference/checklists/workbooks*.json`: 186 workbooks read or refused in Java's words, every render and trial the same bytes, `checklist.json` as Java writes it; zip and XML read as the JDK reads them (`flate2` on zlib), fuzzed (`checklist_workbook`); `w1-checklists-1b.py`. One Java defect fixed first: a row's `spans=":"` threw out of the renderer |
| 2 | The services and persistence; the `RepositoryScanned` listener, the `checklist_answer` handler, the reminders' maintenance task, the `ProjectDeleted` purge | done (2026-11-17, `rust/w1-checklists`): every repository in checked queries for both engines, the owners' readings (`ScanCatalog`, `IssueCatalog`, `ComponentCatalog`, `Targets`) behind the measurer's ports; the plugins' imports and reviews and the mail channel are absent-answering stand-ins until waves 2 and 3; `w1-checklists-2.py` |
| 3 | The 35 routes | done (2026-11-17): served from `cp-checklists`, composed in `cp-app`; `not-yet-ported/checklists.txt` deleted |
| 4 | The replay of their recordings | done (2026-11-17): of 5,356 recordings replayed, 5,149 green; `golden/deferred/checklists.txt` down to one line (compliance's OWASP report message), the rest moved to the module or recording limit that keeps them red — the plugins' stand-in, forges' change review, signed packages' bytes. Replay fixes on the way: binary request bodies, the recorder's late-secret digests (Java `TrafficRecorder`), `oneOf` read as `anyOf` |

---

### 5.6 The agent — finishing `feat/rust-agent`

From the workspace [`README.md`](README.md), "Remaining work, as independent streams":

| Stream | Done when |
|---|---|
| Workspace, census, API discovery | **done** 2026-11-19 (branch `claude/rust-agent-census-api-156251`): `LanguageCensus`, `ProjectManifest`, `ApiDiscoveryScanner` ported and wired in the runner, held to `reference/workspace/` (176 trees, `WorkspaceReferenceSetTest`); the census is handed on for the plugins stream |
| Plugins and bundled rules | **done** 2026-11-19 (branch `claude/rust-agent-plugins-cosign-18a640`): plugin steps, the bounded output holder, registry login and pull credentials, `ImageSignatureVerifier` through the pinned cosign image — held to `reference/plugins/` (written by `PluginsReferenceSetTest` and `PluginRunsReferenceSetTest`), proved with a real keyless-signed plugin and real refusals, `security/mutants/agent-plugins.py`; applicability decided on the workspace stream's census |
| Image export | **done** 2026-11-15 (2.10): `ContainerRunner::export_image`, behind `ExportImages` |
| Kubernetes executor (decision 0045) | **done** 2026-11-19 (branch `claude/rust-agent-kubernetes-1d5565`): `crates/kubernetes`, chosen by `VECTISPIRE_AGENT_EXECUTOR`, held to `reference/kubernetes/` and run on k3s (`tests/on_k3s.rs`). Registry logins and bounded outputs ported 2026-11-20 (branch `rust/agent-k8s-plugins`, `security/mutants/agent-kubernetes-plugins.py`): plugins run on it. In a cluster through the chart 2026-11-20 (branch `rust/agent-in-cluster`): `AGENT=rust scripts/kubernetes-scan-check.sh` green on k3s, nightly `rust-agent-in-cluster`; the trust store reaches it as a PEM form beside the PKCS12 (`agents.trustStore.pemKey`), and the store alone refuses the start (`security/mutants/agent-in-cluster.py`). The matcher on its real 3.5 GB database 2026-11-23 (branch `rust/agent-real-matcher`): downloaded through the Kubernetes executor and Docker, the same findings as Docker's and as the Java agent's, nightly `real-matcher`. Left: image targets, and `agents.knownHosts` (its init container needs `sh`) |
| Image and side-by-side conformance | reproducible image on both architectures; `scripts/composition-scan-check.sh MODE=agent` identical to the Java agent for two weeks in the nightly; only then does `release.yml` sign it. **Drop-in on Compose, publishable: done** 2026-11-20 (branch `rust/agent-compose-dropin`): `/app/LICENSE`, `/app/NOTICE`, `/app/THIRD-PARTY-LICENSES` (generated from `Cargo.lock`, committed, held current by `security/third_party_licences_test.py`, `security/mutants/agent-compose-dropin.py`) and the standard library's notices, the build still reproducible; `agent-work-dir` runs the control plane's image, so no shell and no `AGENT_WORK_DIR_IMAGE`. |

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

