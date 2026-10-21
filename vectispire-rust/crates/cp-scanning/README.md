# vectispire-cp-scanning

The control plane's `scanning` module — `core.scanning` of the Java control plane, ported in Phase 2, task 2.7
(`MIGRATION.md`). Ingestion is task 2.8's, in the files this crate declares for it (`src/ingestion.rs`,
`src/internal/ingestion/`, `src/persistence/findings.rs`).

| Java | Here |
|---|---|
| `internal.ScanQueue` | `ScanQueue` (`src/internal/queue.rs`): `claim`, `claim_within`, the releases, the reclaim |
| `ScanDispatcher` | `ScanDispatcher` (`src/dispatcher.rs`), over the ports `DispatchQueue`, `TargetRows`, `SastSwitch` |
| `internal.LeaderElection`, `LeaderLeaseRepository` | `LeaderElection` (`src/internal/leader.rs`) |
| `SchedulerService` | `Scanning::schedule_at` (`src/scheduler.rs`), on `domain::schedules` |
| `RetentionService` | `Scanning::{prune, find_prunable, payload_count}` (`src/retention.rs`) |
| `ScanTriggerService`, part of `ScanCatalog` | `ScanCatalog` (`src/trigger.rs`, `src/catalog.rs`) |
| `ScanQueryService`, `web.ScansController` | `src/query.rs`, `src/web/` — the three routes |
| `ScanPurge`, `PurgedScans` | `src/purge.rs`: the two listeners `cp-targets` publishes to |
| `internal.TargetScanFigures` | `TargetScanFigures`, built by `target_scans(db, clock)` before `Targets` |
| `SchedulingTickTask`, `ScanRetentionTask` | `src/internal/mod.rs`, composed in `cp-app`'s `maintenance.rs` |
| `ScanView`, `PluginOutcome`, `DetectedLanguages`, `ExaminedTypes` | `src/views.rs` |
| `common.domain.scans.ScanQueue`, `common.domain.scheduling.Schedules` | `vectispire_domain::{scan_queue, schedules}` |

## Held to Java by

- `reference/scanning/java-answers.json`, written by `ScanningReferenceSetTest` **before** this crate: the scheduling
  rule (1,080 cases of `isDue` and `inForce`, 720 of `runsAtLeastEvery`, the SplitMix offsets, the default's slots), the
  queue's rules (`afterFailure` under four policies), the sentences, the three columns read back, and 21 claims — what
  `claimForAgent` hands an agent, sealed credentials opened under the context they were sealed for. `domain`'s
  `tests/scanning_reference_set.rs` and this crate's `tests/reference.rs` read it.
- `tests/engines.rs` on MySQL 9.4 and PostgreSQL 17: `ScanQueueIntegrationTest`, `ScanLabelsIntegrationTest`,
  `LeaderElectionIntegrationTest`, `SchedulerDatabaseTest` and `RetentionDatabaseTest` case for case, the forced
  interleavings included, and sixteen claimants racing over two hundred scans (each claimed once, every round serving, the queue drained).
- `tests/routes.rs`: the authorization coverage of the three routes; `tests/golden.rs`: the recorded traffic.

## Ports and their stand-ins

| Port | Owner | Stand-in until then |
|---|---|---|
| `AgentClaimLock` | agents (2.9) | `AgentsStandIn`: no agent exists, nothing is claimed for one |
| `ScanRuleSets` | rules (Phase 3) | `BundledRules`: no active set, the bundled rules' languages (`python`) |
| `ScanPlugins` | plugins (Phase 4) | `NoPlugins` |
| `ScanIngestor` | ingestion (2.8), composed by `cp-app::ingestion` | `IngestionStandIn` in this crate's own tests only |
| `ingestion::Enricher` | threatintel (Phase 4, task 4.4) | `EnrichmentStandIn`: answers nothing, so no vulnerability is exploited — **the one stand-in that changes a gate verdict** |
| `ingestion::EndOfLifeSource` | threatintel (Phase 4, task 4.4) | `EndOfLifeStandIn`: switched off, so the type is never examined and end-of-life issues stay as they are |
| `RepositoryScanned` | checklists, compliance (Phase 5) | none composed |
| `ScanRunner` | the built-in worker (2.10) | none: `dispatch` claims nothing, as Java's does without a runner |

`ClaimingAgent` is what the dispatcher reads of an agent's row (`AgentView`); 2.9 builds it.

## Differences from Java

- **A scan row is read without its payloads** (2026-10-18, task 2.7). Java's history and detail loaded every scan's
  SBOM and CVE list to show none of them; here the rows carry `has_sbom` and the SBOM is read by the route that serves
  it. Same answers.
- **The candidate reads and each take are transactions of their own**, as Java's are; a read here is a `READ ONLY`
  transaction committed at once, so MySQL's REPEATABLE READ snapshot is fresh at every read, as Java's outside any.
- **A negative retention setting reads as zero.** The settings' validation refuses one, and has since it existed; a row
  written behind it would make Java's purge treat the age as a cutoff in the future. Not reproduced.
- **The SBOM is stored as Java stores it, `JsonNode.toString()`**: read as a tree and written back compact by `wire`
  (Jackson's escapes, Java's doubles, a duplicate member keeping its first place and its last value). An integer past
  64 bits becomes a double here where Jackson keeps a `BigIntegerNode` — no cataloguer writes one. The tree costs
  memory a 256 MB SBOM makes noticeable; 2.8 or 2.12 may stream it.
- **Ingestion takes the scan's transaction, never an `Option` of one** (2026-10-21, 2.8 audit). Java's is
  `Propagation.MANDATORY`. The port took `Option<&mut Tx>`, and its real implementations answered `None` by committing a
  transaction of their own — the API inventory did so every time — so a write rolled back (a failure, a fold repeated after
  a triage) kept its inventory. The behaviour is now Java's; the guarantee is the type.
- **A `null` element of a result list refuses the result**, as Java's `NullPointerException` does (2026-10-21, 2.8
  audit): the finding lists, the API lists (dereferenced by the inventory in Java), a plugin's findings. The element was
  skipped, and the scan written as Java would not have. A `null` plugin step is passed over in both. The reference set's
  `null-element:` cases hold it. Not reproduced: Java counts a `null` endpoint towards the inventory's ceiling of
  1,000 before it dereferences one, so a list past the ceiling that carries a `null` is read as absent there and
  refused here.
- **Not ported: `PlatformMetrics`** (the scan duration timers), which belong to the runtime's metrics (2.11).
- **Not ported yet: `ScanCatalog`'s readings of later phases** (inventory's SBOMs, compliance's examinations, the
  checklists' plugin runs, exports' outlines and languages, the graph queries). Each comes with its phase.

## Java quirks reproduced

- A `null` element in `plugin_steps` throws past `PluginOutcome.read`'s catch (`List.copyOf`): the scan's detail answers
  500 for that row. Reproduced (`NullOutcome`), pinned by the reference set.
- A `null` element in a result's failures is a `NullPointerException` in the write: the result is not written and the
  attempt ends as a write that failed. Reproduced.
- A reason cut at 2,000 UTF-16 units inside a surrogate pair stores `?`, what the JDBC drivers make of the half.
