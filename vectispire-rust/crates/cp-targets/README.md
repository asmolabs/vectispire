# vectispire-cp-targets

The control plane's `targets` module, `core.targets` of the 0.11.1 line (b8bd7e8d0; this branch's Java tree is
identical for the module) — **Phase 2, task 2.6** of the port. Not shipped: the Java control plane is the product.

Solutions and projects; repositories and container images; HTTPS tokens and SSH deployment keys, encrypted under
Java's contexts; schedules (`ScheduleChoice`, the schedule in force); a repository's identity, its duplicates and the
keying of rows filed before V73; the import's batch (decision 0037, for `forges`); `TargetCatalog` and `TargetNaming`
for the modules above; and a target's deletion, atomic with every row that names it.

| Place | What |
|---|---|
| root | [`Targets`] and one file per Java service: `repositories`, `containers`, `solutions`, `tree`, `credentials`, `deletion`, `identity`, `catalog`, `naming`, `imports`, `schedule`; the ports `TargetScans` / `TargetBacklog` and their stand-ins (`ports`) |
| `internal` | the two maintenance tasks, `TargetsForAccess` (`GrantableTargets`) and `IssuerSeesTargets` (`IssuerSees`) |
| `persistence` | every statement on the six tables, `sqlx::query!` per engine, cached in `.sqlx/` (116 files) |
| `web` | the 29 routes, the bodies read as Jackson binds them, the answers written as Jackson writes them |

## What it is held to

- **`reference/targets/rules.json`**, written by `TargetRulesReferenceSetTest` before this crate: 559 cases in
  `vectispire_domain`, and here the schedule choice, the cron refusal, the required label, the private-key header and
  the token's white space (`tests/rules.rs`).
- **Both engines** (`tests/engines.rs`, MySQL 9.4 and PostgreSQL 17, migrated by `vectispire-migrate`): a
  repository's and an image's deletion take their rows and nobody else's (`TargetDeletionIntegrationTest`), the
  listeners run in phase order with the grants revoked before the first and the target deleted after the last
  (`TargetPurgeOrderTest`), a failing listener rolls everything back, seventy thousand issues past PostgreSQL's bind
  ceiling all go, two creations racing for one identity — one wins, the other is refused naming it, read from the
  committed row — and three rows filed before V73 keyed `(1, 2)` (`RepositoryDuplicateIntegrationTest`), and the
  credentials stored encrypted, bound to their rows.
- **The routes through the real chain on both engines** (`tests/routes.rs`): the authorization coverage enumerated
  from the router (below), then one scenario through every route with the answers compared member for member.
- **The contract** (`tests/contract.rs`): the 29 routes left `cp-contract`'s list of routes not yet ported; every one is
  documented under its method, path, operation id and query parameters, and the router answers each.

### The authorization coverage

`AGENTS.md`'s first trap. Every route of the table whose path names a repository, an image, a project or a solution is
asked, by an account with no grant in `assigned` mode and by an administrator's key restricted to another repository,
for one that exists and is hidden and for one that does not exist. The two answers must be the same bytes, never a
success, and a 404 wherever the route admits the caller. Sixteen routes, thirty-two probes, counted from the table —
a route added with a target parameter is covered without being listed, and the count changes. The lists are held to
the same callers: no hidden target in `/repositories`, `/containers` or the solutions tree.

## Differences from Java, decided 2026-10-17 (task 2.6)

- **The deletes refuse through the visibility.** Java's `DELETE /repositories/{id}`, `/containers/{id}`, and the
  solutions' and projects' administration apply none: only an administrator's session reaches them, and its
  allowance is everything. Here every route naming a target refuses a caller who cannot see it, in the sentence an
  absence gets — the same answers for every caller Java admits, and no route left to forget it when who may call
  changes.
- **One transaction per write, committed before its entry.** Java's administration opened none of its own (each
  `save` carried the repository's). The entry is still recorded once the write has committed.
- **A listing is narrowed in the statement** (`cp-db`'s `VisibleSelect`), where Java read every row and filtered in
  memory; the page is still cut from what the caller sees.
- **A list of identifiers is one parameter** (`json_table` on MySQL, `= any($1)` on PostgreSQL), still a thousand per
  statement.
- **`findByNameIgnoreCase` with two matches** (PostgreSQL's case-sensitive index allows `A` and `a`): Java's Spring Data
  throws, a 500; here the oldest is taken.
- **Bodies are read field by field** with Jackson's coercions for the fields these records have (a number or a
  boolean as a string, a numeric string as a number, a decimal truncated, `""` as `null` for a number or a boolean);
  anything else is the one 400 sentence `ApiExceptionHandler` answers. A record that is not a JSON object, `null`
  included, is that 400 — Spring's missing body.
- **The start-up sweep is `Targets::purge_orphans`**, run at every start as Java runs it on `ApplicationReadyEvent`
  and on the hourly turn. It is not a one-shot job: Java's is not either.

## Java quirks found, reproduced

- A path variable is converted by `NumberUtils.parseNumber`: white space anywhere is removed, `0x10` and `#10` are 16,
  any Unicode decimal digit reads. `UUID.fromString` takes short groups and masks long ones (`1-1-1-1-1`).
- `SshKeysController.create` dereferences its body without the `null` check the others have — unreachable, since
  Spring refuses a `null` body first.
- `RepositoryUrl.shortName("https://gitlab.example.org")` is `https/gitlab.example.org`; a blank name with a no-break
  space is not blank to `isBlank` and is shown as written.
- `String.CASE_INSENSITIVE_ORDER` folds by the simple case mappings: `ß` sorts after `SS`, `İ` with `i`.

## What waits for other tasks

- **`TargetScans`** is scanning's since task 2.7 (`vectispire_cp_scanning::target_scans`, built before `Targets`);
  `ScanningStandIn` stays for this crate's own suites, which cannot depend on `scanning`. **`TargetBacklog`** (issues,
  Phase 3) is `IssuesStandIn`: zero figures.
- **The purge's listeners** are Java's fourteen as named stand-ins (`PurgeRegistry::stand_ins`, held to
  `JAVA_LISTENERS`), scanning's two replaced by its own since 2.7 (`PurgeRegistry::stand_ins().with(
  vectispire_cp_scanning::purge::listeners())`); issues', tickets', inventory's, compliance's, gate's, plugins' and
  forges' later. The foreign keys cascade on both engines meanwhile, so a deletion still takes those rows; the orphan
  sweep finds nothing to do until the owners' listeners land. `ProjectDeleted`'s listeners (checklists, plugins,
  report plugins) likewise.
- **The recorded Java traffic is replayed** by `cp-agents/tests/golden.rs` since task 2.9's audit (it was this crate's,
  task 2.11a, then `cp-scanning`'s from 2.7): the 29 routes with scanning's three and the agents' seventeen, composed as the binary composes them, since the listings answer
  with scanning's `TargetScans`. `crates/cp-contract/scripts/replay-goldens.sh` runs it; what is not green is named
  in `golden/deferred/`. The replay found no difference in this crate.
- `GrantableTargets` in Rust declares `targets_in` only; Java's port also names grants, checks a project or a target
  exists and labels targets — `naming`, `catalog` and `TargetsForAccess` hold those for 1.7's access routes.
