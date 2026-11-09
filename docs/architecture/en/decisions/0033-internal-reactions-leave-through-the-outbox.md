# 0033 — A reaction between modules that must survive a commit leaves through the outbox, not Modulith's registry

**Date:** 2026-10-01 · **Status:** accepted · **Amends:** [0030](0030-modulith-verifies-the-module-boundaries.md), [0025](0025-siem-events-leave-through-the-outbox.md) · **Decider:** Laurent Boucher

## Context

Step 7 of the move to Spring Modulith was planned on 2026-09-26 as "Modulith's JPA publication
registry for events between modules, the in-house outbox for what leaves the application". It was
written down as decided before anyone had measured either half. This record is the measurement, and
it reverses that plan.

**What is lost today.** A survey of every effect that follows a scan, an import, an audit entry and a
gate verdict (2026-10-01) found four that run *after* the commit of the work that caused them, as a
direct call, with nothing to redo them if the process stops in between:

| Effect | Where | Recovered by |
|---|---|---|
| A checklist's automatic answers after a scan or an import | `ScanDispatcher.announce` → `RepositoryScanned`; `ReportedRepositories` → `RepositoryReported` | the next scan of a repository in that project, or a revision opened, moved or reopened — nothing else |
| Every SIEM event an audit entry signals | `AuditLogService` after-commit synchronisation → `SiemEvents.recorded` (`REQUIRES_NEW`) | nothing |
| `SECURITY_GATE_FAILED` | `GateService` → `SiemEvents.publish`, after the verdict's own write | nothing |
| The agent path's `AGENT_RESULT_SUBMITTED` audit entry | `AgentProtocolService.submitResult`, after `record` | nothing — a re-submission is answered `NoLongerYours` |

Everything else that follows a scan is already atomic with it: issue reconciliation, inventory and
findings are direct calls in the scan's transaction, and notifications and leak events are outbox rows
written in that transaction ([0025](0025-siem-events-leave-through-the-outbox.md)).

**What the outbox already guarantees.** `t_outbox_message` is written in the caller's transaction
(`MANDATORY`), claimed by a conditional update that every instance may race for and only one wins
(5-minute claim window), retried with a 60 s × 2ⁿ backoff capped at an hour, abandoned after eight
attempts with its last error kept, abandoned at once on a destination that is gone, deduplicated by
the receiver on `message_id`, pruned after seven days — on PostgreSQL, MySQL and the SQLite fixture.
It already dispatches to an in-process `OutboxHandler` (`SiemDelivery`), not only to a channel.

**What Spring Modulith 2.1.1's registry would bring**, read in its 2.1.1 sources and issues:

- **It does not start on SQLite.** The JDBC registry's `DatabaseType` knows H2, HSQLDB, MySQL,
  MariaDB, PostgreSQL, SQL Server and Oracle, and throws for anything else, from a bean that is not
  conditional. The JPA registry ships no DDL and its entity has had repeated `validate` mismatches
  (#1057, #1389, #1543); the maintainers recommend the JDBC one "even with JPA-based applications".
- **No retry, backoff, attempt cap or dead letter.** A failed publication stays `FAILED`; the
  application schedules `FailedEventPublications.resubmit(...)` itself and writes its own cap. An
  `ABANDONED` state arrives in 2.2.0-M2 (#1764). Automatic retry is an open request (#1439).
- **At-least-once, with a weaker claim than ours.** Resubmission claims a row by moving it to
  `RESUBMITTED` only; a stale list on a second instance can re-claim a row the first one has already
  moved to `PROCESSING`. The maintainers' answer to concurrent resubmission is a distributed lock
  (ShedLock, Spring Integration) (#926, #663).
- **Fragile identities.** A listener's id defaults to its method signature, so renaming one orphans
  its pending rows; completion falls back to matching the serialized event, so two identical events
  complete each other (#486, #1008) and a non-round-tripping one is never completed (#556).
- **2.1.1 marks retries stale against the original publication date** (#1837, fixed in the unreleased
  2.1.2). Its starters put `spring-modulith-core` — ArchUnit included — back on the runtime
  classpath that step 6 emptied (`ModulithRuntimeInertTest`).

Adopting it would mean writing, around it, the retry, cap, abandonment, purge and multi-instance
claim the outbox already has — and keeping two answers to "did this effect happen", which is the
drift [0026](0026-services-are-grouped-by-domain.md) and [0030](0030-modulith-verifies-the-module-boundaries.md)
refused it for. The one condition under which that reason would lapse — the outbox no longer being
enough — has not occurred: every gap in the table above is a call made *after* a commit, not a
limit of the outbox.

## Decision

**A reaction of one module to another that must survive a commit is an outbox message, written in
the transaction of the work that causes it, and handled in-process by an `OutboxHandler` of the
reacting module.** It inherits the claim, backoff, cap, abandonment and purge every message has. Its
handler is idempotent, because delivery is at-least-once: a checklist's automatic answer already
rewrites a line only when what it states changes.

**Spring Modulith's event publication registry is not adopted.** [0030](0030-modulith-verifies-the-module-boundaries.md)'s
"still not taken" stands, now with its measurement.

**A reaction that must be atomic with its cause stays a synchronous `@EventListener` in the
publisher's transaction**, as the `TargetDeleted` purges are: the deletion and its purge commit or
roll back together, which no after-commit delivery can offer.

**A module that only needs to tell another one something, in the same transaction, publishes a
domain event instead of calling it.** `issues`, `gate` and `threatintel` list `siem` among their
dependencies for one call each; a synchronous event that `siem` listens to, enqueuing in the same
transaction, removes those lines from `allowedDependencies` without changing what is durable.

**What leaves the application is unchanged** ([0025](0025-siem-events-leave-through-the-outbox.md)).

## The work, in lots

1. **The scan's `beforeCommit` hook, under test first.** `IssueSyncService` catches a failing
   notification hook "so the scan's results are kept", but the hook calls transactional proxies; an
   exception crossing one marks the scan's transaction rollback-only, and the scan would be abandoned
   rather than kept. A test decides which is true before anything is built on it. *Settled
   2026-10-01: the rollback is real (`IssueSyncHookDatabaseTest`); the catch is removed and the scan
   and its notifications commit together or not at all, which is what had always happened.*
2. **SIEM events from the audit log and the gate, in the transaction that caused them.** The audit
   entry and its outbox row commit together; so do a verdict and its `SECURITY_GATE_FAILED`. *Done
   2026-10-01: together first; if that cannot commit, the entry or the verdict is written alone and the
   event published after it — the old path, kept as the fallback.*
3. **A checklist's automatic answers as a `checklist_answer` message**, enqueued in the scan's or the
   import's transaction, handled by `checklists`. *Done 2026-10-02: `ChecklistAnswerDelivery`; the ports
   are called inside the owners' transactions and only queue, and the answers arrive with the relay's
   next pass.*
4. **`AGENT_RESULT_SUBMITTED` in the result's transaction.** *Done 2026-10-02, through the outbox rather
   than written there: a concurrency test showed that the audit chain forked under concurrent writers,
   fixed by serialising them on `t_audit_chain_head` (V66) — and an entry written inside a scan's
   transaction would then have held that lock for the scan's length. The entry is queued with the result
   and written by `AgentResultAuditDelivery`, dated in its description to the moment of acceptance.*
5. **Domain events in place of the calls into `siem`**, and `notifications` → `issues` examined the
   same way; each removed `allowedDependencies` line is a line of the review. *Done 2026-10-02:
   `SecurityEventRaised` (in the publisher's transaction, `MANDATORY` on the listener) and
   `SecurityEventRaisedApart` (the gate's fallback) live in `vectispire-common` beside `CefEvent`, so no
   module names `siem` to raise one; `siem` is out of the `allowedDependencies` of `issues`, `gate` and
   `threatintel`. A per-module event type was not used: `siem` would then have depended on all three,
   the arrow reversed rather than removed. `notifications` → `issues` stays: it is `issues`' own port,
   `ScanDelta.Sink`, implemented above it — the direction the layering wants.*

Each lot carries its tests on the three engines of the campaign, a mutation check of every new test,
and its documentation in both languages.

## Alternatives considered

- **Modulith's registry for internal events** (the 2026-09-26 plan). Refused for the reasons above;
  reconsider when a release ships retry with a cap, an abandoned state and a claim that excludes
  in-flight rows, *and* the test fixture is an engine it supports — see
  [0034](0034-mysql-replaces-the-sqlite-fixture.md), which removes the second obstacle and not the first.
- **Moving the after-commit calls into the transaction as direct calls.** It closes the loss, but
  couples the cause to the reaction's failures: a checklist that cannot be answered would roll back
  the scan. A message decouples the failure while keeping the durability.
- **A sweep that re-derives what was lost** (the way tickets are reconciled hourly). Right for state
  that can be recomputed from scratch; wrong for an audit-driven SIEM event, which is a fact about a
  moment and cannot be re-derived later.

## Consequences

- Four effects stop being lost on a stop at the wrong moment, without a second delivery mechanism.
- Internal messages share the relay's cadence (60 s by default): a checklist's automatic answers
  arrive up to a minute after the scan instead of at once. Accepted: a checklist is read by a person,
  on the scale of a review, not of a minute.
- The relay serves internal reactions as well as webhooks; its `MAX_PER_PASS` and the health of
  `t_outbox_message` now concern both. A message type is named per reaction, so the outbox counts by
  type still say which is behind.
- Three `allowedDependencies` lines disappear once lot 5 lands, and their disappearance is the
  executable evidence the decoupling happened.
