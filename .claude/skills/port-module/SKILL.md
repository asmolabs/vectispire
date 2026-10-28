---
name: port-module
description: Porting one module or task of the Java control plane to Rust (vectispire-rust/, the cp-* crates) end to end — reading the Java side, placing the code, the parity rules the replay keeps catching, persistence, wiring into the binary and the replay, verification, and the stacked branch and pull request. Use when asked to port a module, a task of MIGRATION.md, or a set of routes to Rust.
---

# Porting a module of the control plane

The port is held to the Java side by **what runs**, not by reading: the reference sets, the Flyway
oracle, the checked queries, the contract and the replay of the Java suite's recorded traffic. A module
is ported when its routes leave `crates/cp-contract/reference/not-yet-ported.txt` and their recordings
replay green on MySQL and PostgreSQL — not when it compiles. The `rust-porter` agent carries the
invariants; this is the sequence. Replaying and shrinking the deferred list is the `golden-replay` skill.

## 1. Read before writing

- `vectispire-rust/MIGRATION.md` §4–5 for the task, its branch and what was decided; the crate README of
  every crate you will touch. **Where MIGRATION.md and the code disagree, the code is right** — the table is
  dated; say so in your report.
- The Java module: `package-info.java` (its `allowedDependencies` and why), every class of `core/<module>/`,
  **and its tests** — the tests are the behaviour to reproduce, case by case. Types in
  `vectispire-common/.../domain/<module>/` too.
- `crates/cp-arch-tests/data/edges.toml` (`[module.<module>]`: status, allowed edges, reason) and
  `tables.toml` (which tables it owns). The edges are Java's; a new one is a decision for review, with
  its reason, never the edit that makes the build pass.
- What the Rust side already prepared: grep the module's name across `crates/` — hooks are often waiting
  (cp-audit's `Listener` and `Signal` for the SIEM, cp-outbox's `OutboxHandler`/`NotificationChannel`,
  stand-ins named in `golden/deferred.txt` with the task that ends them).

## 2. Where the code goes

- **Types other modules build or raise → `crates/domain`** (`vectispire_domain`), as Java keeps them in
  `vectispire-common`. A module that raises another's events must not depend on that module: the
  vocabulary is shared, the service is behind a trait the owning module implements and `cp-app` hands in.
- **The module → `crates/cp-<module>`**, laid out root / `internal` / `persistence` / `web`, never
  `pub` below the root — `cp-arch-tests` reads the layers with `syn` and fails a service naming a query
  API or a route naming persistence. `#![forbid(unsafe_code)]`.
- **Outbound calls** only through `cp-outbound` (`OutboundUrlGuard`, `PinnedHttpSender`, `PinnedCa`):
  no other HTTP client, no redirect, no proxy.
- **The agent's isolation is a graph fact.** `crates/domain` is linked by the agent: nothing there may
  pull a database, a server stack, or name the encryption key. A dependency added to `domain` is the
  agent's dependency too.

## 3. Parity: what the replay has caught, so check it before it does

Each of these was a real divergence from Java, found by replaying recorded traffic after the code
"looked right":

- **Order of refusals**: role (403), then the target's visibility (404, never 403), then the body
  (400). A body check before the visibility check tells a caller the target exists.
- **A service's `AccessDeniedException`** is not the handler's 403: answer through
  `vectispire_cp_http::chain::denied(reason)`, which audits `Access denied: <reason>` and answers the
  chain's sentence. Answered by the handler, it left no audit entry and shifted the audit hash chain.
- **What Jackson refuses before the controller runs** (an unknown enum, an unparsable date) is
  `vectispire_cp_http::extract::UNREADABLE`, not a message of your own.
- **Fixed messages**: Java's not-found texts do not carry the id ("Issue not found."). Copy messages
  from the Java source, never from memory.
- **Lengths are UTF-16 units** (`String.length()`): `vectispire_domain::bounded_text` (`too_long`,
  `within`, `TEXT_MAX`, `SEARCH_MAX`), never `str::len()` (bytes) nor `chars().count()`.
- **Time to the nanosecond**: `ChronoUnit.DAYS.between` truncates a nanosecond difference toward zero;
  whole Unix seconds gave 30 where Java says 29. `Instant.toString` is
  `vectispire_cp_audit::iso_instant`, not `Display`.
- **Collections**: `Set.copyOf`/`HashMap` order is salted per JVM run — if Java's order leaks into an
  answer, fix the Java side (`EnumSet`, sorted) rather than chase it; `LinkedHashMap.put` keeps the first
  position of a re-put key. A list Java sends unsorted is unordered in the contract only if the replay
  compares it as a set.
- **Paging**: `ListWindow.requested(limit, offset)` refuses what Java refuses (limit outside 1–500, an
  offset not a multiple of the limit, an offset without a limit) — clipping silently answered a list.
- **Fail-open**: an evaluation that cannot be made (a gate with no scan, an absent analysis) refuses, as
  Java does — decision 0007 applies to every module, not only the scanners.

## 4. Persistence

- **Per engine, checked**: `sqlx::query!` with the engine's placeholders and its tag (`/* mysql */`,
  `/* postgres */`), the offline caches kept by `crates/cp-db/scripts/sqlx-prepare.sh`.
- **Dynamic repositories → SeaORM, hybrid** (decided 2026-10-26): entities and statement builders only,
  run by `vectispire_cp_db::orm` on the port's own `Tx` (`fetch_all`, `fetch_optional`, `fetch_count`,
  `fetch_rows`, `execute`, `insert_returning_id`); a target's rows through `orm::Visible`, which cannot be
  built without a `Visibility`. Each entity is held to the schema by `orm::entity_table` in the module's
  parity test, on both engines.
- **A MySQL `in (?, …)` whose length follows the input** stays hand-built from placeholders, documented
  in the module (cp-access, cp-audit): MySQL has no array parameter, and the spellings that fake one
  compare under another collation. Not a leftover to port.
- `ddl-auto` stays `validate` on the Java side; the schema is the migrations'. A port never adds one.

## 5. Wiring — a wiring not exercised is not wired

- Compose the module in `crates/cp-app/src/main.rs` (and its registry/maintenance composition), hand it
  the outbox handlers and audit listeners it implements, and assert the composition in a test
  (`maintenance` composition, route authorization coverage) — `IssueTriageService.expireStale` was called
  by nothing for months with every unit test green.
- Routes: the type-state builder (`Route::get(..).requires(..).scoped()|.names_no_target()`), and the
  routes leave `not-yet-ported.txt` **in the same commit**, lowering `not-yet-ported.ceiling`.
- Add the routes to the replay (`crates/cp-agents/tests/golden.rs`, the phase's replayed list) only once
  they replay green — see `golden-replay`.

## 6. Verify

- The Java behaviour as a **reference set** when outputs leave the system (formats, parsers, messages): a
  Java test that writes `reference/<module>/inputs.json` + `java-answers.json`, a Rust test that replays
  them. Regenerate the Java side on purpose, never to make a test pass.
- Every test that pins a guard is **mutation-checked** (quality-gate §7) and listed in
  `security/mutants/`. Restoring a file from a backup keeps its old modification time and cargo reuses
  the mutant's build: `touch` the file after restoring, or the next run tests the mutant.
- `./check.sh`, then what it does not run (quality-gate §4b): the Flyway oracle, `sqlx-prepare.sh check`,
  the contract summary, and the replay as CI runs it.

## 7. Deliver

- One task, one branch, **stacked** on the previous Rust branch, as a **draft** pull request whose base
  is that branch (the Rust line is not in `develop`; `ci.yml` runs on any pull request). Push the task
  branch once its checks are green; never `develop` or `main`, never force — merge the lower branch into
  an upper one instead of rebasing a pushed branch.
- Commit messages in the repository's style (`feat(rust-<module>): …`), the body saying what was wrong
  or missing, what changed, and how it was verified.
- A Java defect found while porting is fixed on the Java side in its own commit (and test), not
  reproduced silently; one that is reproduced on purpose is named in the module's README.
