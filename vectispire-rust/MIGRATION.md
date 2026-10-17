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
2. **The mutation scripts are not in the repository.** Each task's mutation check was run with a
   throwaway script (`p1acc-mutate.py`, `p1c-mutate.py`, `mutate-authz.py`, `p1aud-mutate.py`,
   `p1merge-mutate.py`, `p2-1-mutate.py`) kept in a session scratch directory. Move them under
   `vectispire-rust/security/mutants/` with a short README, or the next person cannot rerun them.
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
   lines of `crates/cp-arch-tests/data/edges.toml`; layering inside a crate is root / `internal` /
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
| Checked queries | `sqlx::query!` / `query_as!` with offline caches; `crates/cp-db/scripts/sqlx-prepare.sh prepare <crate>` then `check`. Add a new crate to its `crates_with_queries` list. A statement left unchecked says why in a comment. |
| No secret | gitleaks on a **fresh single-branch clone** of the branch, with CI's pinned image and `.gitleaks.toml`. A test fixture is allowed by `gitleaks:allow` or pinned in `.gitleaksignore`, never by widening the config. |
| The tests bite | a mutation check of the new logic: each guard broken, the suite goes red, sources restored identical. Every mutant killed; one that cannot be told apart is removed from the list with the reason, not counted as killed. |
| Wired, not just written | anything meant to run at start-up or on a schedule is proven on a **started** binary or by a composition test (the `MaintenanceJobsTest` lesson in `AGENTS.md`). |

Comments say why, not what. A deliberate difference from Java goes in the crate README's
"Differences from Java" section with the date and who decided it.

## 3. How to take a task

- **One task, one branch, from `rust/p1-merge`** (or from the merged result of the phase before).
  Name it `rust/p<phase>-<n>-<short-name>`.
- **A task owns its files.** The tables below say which. Touching another task's files is a
  conversation, not a commit. Shared agent crates (`protocol`, `crypto`, the runner) change only
  **additively**, and the agent stream reviews.
- **Only Phase 2 task 2.1 edits `edges.toml`.** A task that needs a new dependency asks for a line,
  with its reason.
- **Publish interfaces first** when other tasks wait on them (types and trait signatures in a first
  commit, behaviour after).
- **Merging** is done by one person per phase, in a dedicated branch, rerunning the whole of §2 on the
  merged result. Expect conflicts in the crate manifests, `lib.rs`, `deny.toml` and `Cargo.lock`.

## 4. Where it stands (2026-10-17)

| | State | Branch |
|---|---|---|
| Phase 0 — foundations | done: migrate, cp-db, cp-http, cp-contract, traffic recorder, cp-runtime / cp-app, cp-outbound, cp-arch-tests | on `rust/p1-merge` |
| 1.1 Accounts and passwords | done | merged into `rust/p1-merge` |
| 1.2 Sessions, API keys, agent keys, SCIM token | done | merged |
| 1.5 Roles, visibility, four-eyes | done | merged |
| 1.6 Audit chain, settings, platform service | done | merged |
| Phase 1 merge | done, full gate green (771 tests) | `rust/p1-merge` (7474e7e72) |
| 2.1 Shared-module rule and maintenance turns | in progress | `rust/p2-1-shared` |
| The agent (`vectispire-agent`) | foundations and three scanners done | `feat/rust-agent` |

In Java lines of `vectispire-core`: about 10,000 of 66,000 are ported or partly ported. Most of
`vectispire-common` (about 20,000 lines) is still ahead, spread over the phases.

## 5. What is left

### 5.1 Phase 1 — Access (finish)

| # | Task | Owns | Notes |
|---|---|---|---|
| 1.3 | **MFA and throttles**: TOTP, recovery codes, lockout, login / bearer / webhook rate limits keyed as Bucket4j keys them | `crates/cp-access` (root / `internal` / `persistence` — not a `src/mfa/` directory), `crates/cp-http/src/limits.rs` | TOTP secrets are encrypted at rest: needs 2.3's `Encryption`, or a port stand-in until it lands |
| 1.4 | **OIDC**: openidconnect client, account linking (verified e-mail only, never a privileged link), the hand-off cookie | `crates/cp-access`, outbound calls through `cp-outbound` only | a stub identity provider in tests; the session hand-off already exists in 1.2 |
| 1.7 | **Access routes**: `auth`, `users`, `teams`, `api-keys`, `admin`, `security`, SCIM — replayed against the recorded Java traffic | `crates/cp-access/src/web/` | after 1.3 and 1.4. Phase 1's exit: every golden of these routes passes |
| 1.8 | **Phase 1 security review**: the `security-audit` skill on the phase's diff | — | exit: nothing above low |

Follow-ups found during Phase 1, small enough to go with 1.7 or before it:

- **`cp-http` reads the session header leniently**: `bearer x` and `Bearer  x` open a session in Rust,
  not in Java. Make it strict, with a reference case.
- **`cp-http`'s `Principal` lacks** the account id, the session hash and the key's restriction (they are
  in `cp-access`'s `Resolved`). Without the restriction, visibility cannot intersect the credential's
  grant — this one is a security property, not a nicety.
- **The audit actor of an integration key** is the account in `cp-http`, `user (API key name)` in Java;
  `Resolved::actor` already matches Java.
- **Two Argon2 PHC readers** in `cp-access` (`passwords` and `credentials::phc`): keep one.
- **`cp-platform`'s `Approvers`** is a trait the binary does not fill yet; wire it to `cp-access`'s
  `TriageApprovers`.
- **The audit log is not built by the binary yet** (`cp-app` has no database). Wire it.
- **`cp-db`'s comments promise** a test refusing a `query!` without its `/* mysql */` or
  `/* postgres */` tag. It does not exist: write it or remove the claim.
- **The Java-oracle suite of `cp-audit` and the mutation checks are not in `check.sh`.** Decide which
  belong in CI.
- **The platform routes** (settings, audit log, crypto), the four credential-storing endpoints and the
  AI endpoint check wait for their modules.

### 5.2 Phase 2 — Targets and scanning

The plan's §7 "Phase 2, in parallel after Phase 1 exits" has the full table (owned files, interfaces,
oracle per task), the data contracts and the risks. Read it before taking a task. Summary:

| # | Task | Starts when |
|---|---|---|
| 2.1 | Shared-module rule, `cp-maintenance` turns and their global order | **first** (in progress) |
| 2.2 | Outbox: enqueue in the caller's transaction, claim, backoff, abandonment, pruning | after 2.1 |
| 2.3 | Encryption at rest (AES-256-GCM, key from variable / file / `/run/secrets` / Vault), signing key, an additive `seal` in `crates/crypto` | after 2.1; publishes `Encryption` early |
| 2.4 | The fingerprint and the target vocabulary, pure, in `crates/domain`, with Java-written reference sets; Spring's cron parser | after 2.1; ships the types before the behaviour |
| 2.5 | The protocol's server half in `crates/protocol`, additive, `client` feature off for the control plane | after 2.1; publishes the bodies early |
| 2.6 | Targets: 29 routes, two-phase deletion, purge registry | after 2.3, 2.4 |
| 2.7 | Queue claim, dispatcher, leader lease, scheduler, retention, scans routes; owns `cp-scanning`'s `lib.rs` | after 2.3, 2.4, 2.5 |
| 2.8 | Ingestion; the **ingestion reference set is written before the code** | after 2.4, 2.5; files declared by 2.7 |
| 2.9 | Agents, server side: 17 routes, long poll, signatures on the raw body, sealing-key pinning | after 2.5, 2.7 |
| 2.10 | Built-in worker over a runner moved out of `agent/src/scan.rs` into `crates/runner` (approved 2026-10-17) | after 2.7; agent stream reviews the move |
| 2.11 | Composition with named stand-ins, `golden/deferred.txt`, the upgrade drill extended, both agents against the Rust image | from day one; closes the phase |
| 2.12 | Phase 2 security review | last |

The two things that fail nowhere if they go wrong, and so need the most care:

- **The fingerprint.** Any change resolves every existing issue and recreates it, losing all triage.
  Reproduce Java exactly: `?` for an unpaired surrogate, `strip()` keeps the no-break space, null
  joined as empty, an empty purl falls back to the package name, UTF-16 lengths for clipping, clipping
  after the fingerprint.
- **Absent is never empty.** An analyzer's `Option<Vec<_>>` is never `unwrap_or_default`-ed; an empty
  list resolves the backlog of that type.

### 5.3 Phases 3 to 6 — not broken down yet

Each needs a task breakdown like Phase 2's (inventory measured on the Java line, dependencies cut into
ports with named stand-ins, a task table with owned files and an oracle per task, the risks) **before**
anyone writes code. Writing that breakdown is itself a task to delegate, one per phase.

| Phase | Modules (Java lines of `core`) | Exit | Plan estimate, dev-weeks (fluent / learning) |
|---|---|---|---|
| 3. Issues and decisions | issues 5,191 · inventory 3,557 · gate 1,612 · rules 992 — triage, four-eyes, exceptions, VEX/CSAF | goldens; fingerprint and triage-history drills | 14–19 / 20–27 |
| 4. Integrations | forges 5,306 · plugins 3,039 · threatintel 1,852 · tickets 1,589 · siem 936 · notifications 824 · ai 375 | goldens with outbound stubs; SIEM wire format byte-identical | 12–17 / 17–24 |
| 5. Documents | checklists 6,882 · compliance 4,615 · reportplugins 3,593 · posture 2,454 · exports 1,400 · reporting 284 | the xlsx byte for byte; every PDF text-equal and structurally equal to Java's. **Starts with a two-week spike on the five PDF reports** | 13–19 / 19–27 |
| 6. Cut-over | — | every oracle item green on both engines; two weeks side by side on a staging copy; nightly green 14 days; release pipeline (image, SBOM, signature identity unchanged) | 6–9 / 8–12 |

**Go / no-go 1** sits between Phase 1 and the rest in the plan: measured throughput, review of the two
hardest parts, re-estimate. Phase 2 was started before it, on 2026-10-17; the decision is still owed.

### 5.4 The agent — finishing `feat/rust-agent`

From the workspace [`README.md`](README.md), "Remaining work, as independent streams":

| Stream | Done when |
|---|---|
| Workspace, census, API discovery | `LanguageCensus`, `ProjectManifest`, `ApiDiscoveryScanner` ported, each held to its own reference set |
| Plugins and bundled rules | plugin steps, bounded outputs, registry login, `ImageSignatureVerifier` through the pinned cosign image |
| Image export | `ExportImages` in the container crate (dependencies stream left it out) |
| Image and side-by-side conformance | reproducible image on both architectures; `scripts/composition-scan-check.sh MODE=agent` identical to the Java agent for two weeks in the nightly; only then does `release.yml` sign it |

## 6. Decided, and recorded where

| Decision | Date | Where |
|---|---|---|
| The settings save is one transaction (Java commits each change) | 2026-10-17 | `crates/cp-platform/README.md` |
| Authorization code at `cp-access`'s crate root, not `src/authz/` (the layering test refuses it) | 2026-10-17 | plan §7, row 1.5 |
| `crypto` and `maintenance` join Phase 2 (no phase had them) | 2026-10-17 | plan §7, Phase 2 |
| The scan runner moves to a crate shared with the agent (task 2.10) | 2026-10-17 | this file |
| One MySQL statement per crate may stay unchecked when its `in (…)` list varies in length; the reason is beside it | 2026-10-17 | `cp-access`, `cp-audit` READMEs |
| Agent-key fall-through is an equivalent mutant, removed from the list | 2026-10-17 | `p1c-mutate.py` |
