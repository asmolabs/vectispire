# vectispire-cp-maintenance

The control plane's maintenance module in Rust — `core.maintenance` (plan, Phase 2 task 2.1). In progress, not
shipped: the Java control plane is the product. A **shared** module, as Java declares it on `VectispireApplication`:
every module may use it without a line in `edges.toml`, and it uses none.

## The port and the one order

A module with periodic work implements `MaintenanceTask` in its own crate, beside the service it calls, and names its
**slot** — a `Sequence` variant. The slots are Java's `MaintenanceTask.Sequence`, all twenty-eight, those of modules
not ported yet included, and each fixes its value, the Java task that fills it, its module and its `Cadence`. Java
sorts every task by `@Order` across every module before splitting them by cadence, and the order matters (the triage
expiry before the digest and the compliance capture, the orphaned rows last), so the Rust turns keep one list too,
not one per crate. `tests/reference.rs` holds every slot to `reference/maintenance/composition.json`, which
`MaintenanceReferenceSetTest` writes from the Java tasks themselves — their `@Order`, their own `cadence()`, and the
`@Scheduled` of the method that runs each turn.

## The turns

`Turns` is `MaintenanceJobs`: three turns (relay and scheduling every minute, maintenance every hour, Java's
`vectispire.jobs.*` defaults), each waiting thirty seconds before its first run and then a fixed delay after the end
of the previous one; one guard per cadence, so a turn called while its cadence's is running does nothing, released
however the turn ends; a task that returns an error **or panics** ends its own run, not the turn, logged in Java's
sentence (`maintenance: ScanRetentionTask failed, the turn goes on: …`). `tests/turns.rs` is `MaintenanceJobsTest`'s
cases over recording tasks, on a paused clock for the intervals.

**No leader election here**: every instance runs every turn. A task that must run once elects inside its service —
the scan scheduler's lease is scanning's (task 2.7), the relay claims each message (task 2.2).

## The composition

`composition::check` is `MaintenanceCompositionTest` for a port that lands one module at a time: every slot is filled
by a task of the binary's composition (`crates/cp-app/src/maintenance.rs`, checked by
`crates/cp-app/tests/maintenance_composition.rs`) or named in `data/deferred.txt` with who fills it — never both,
never neither. The list is therefore exactly the slots still missing, and it shrinks by one line in the commit that
registers a task. Twenty-eight today.

## One-shot jobs

`OneShotJobs::claim` inserts the job's name into `t_one_shot_job` in the caller's transaction (`&mut Tx`: Java's
`MANDATORY` as a type); the primary key decides between instances. A failed claim says nothing about why, so the
caller rolls back and asks `has_run`, on a connection of its own. `tests/engines.rs` runs it on MySQL and PostgreSQL,
two instances claiming at once included. The statements are checked against both engines while compiling
(`crates/cp-db/scripts/sqlx-prepare.sh check cp-maintenance`).
