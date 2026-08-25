# 0002 — The database carries the queue

**Date:** 2026-08-08 · **Status:** accepted

## Context

The scan queue was a module-level `ThreadPoolExecutor`. Three things followed from that, and all
three were defects rather than trade-offs:

* **A restart lost the work in flight.** A queued scan existed only in a JVM's heap, so nothing
  recorded that it had been asked for.
* **A second instance could not help.** Two control planes each had their own executor and their
  own idea of what was pending.
* **A remote agent could not exist at all.** There was nothing for it to claim.

## Decision

**A scan is a row.** Triggering one inserts `t_scan` with status `pending` and returns
immediately; a worker loop claims and runs it. Claiming is transactional — `SELECT … FOR UPDATE
SKIP LOCKED` where the engine has it, a conditional update where it does not — and carries a
**lease**: `claimed_by`, `claimed_at`, `lease_expires_at`, `attempts`.

## Consequences

**The queue survives everything the process does not.** A crash mid-scan leaves a row whose lease
expires, and the next tick picks it up with `attempts` incremented. Nothing is lost and nothing is
retried forever.

**This is what makes agents possible**, and [0003](0003-long-polling-for-agents.md) rests on it: an
agent claims the same rows over HTTP that the built-in worker claims over JDBC. There is one queue
and one claiming rule, not a local path and a remote one that drift.

**The lease is asked for inside the writing transaction, never before it.** A worker that checked
its lease and then wrote would be checking a fact that can expire between the two statements — and
the window is exactly when a slow scan is being taken over.

**No row lock, and that was measured rather than assumed.** `SELECT … FOR UPDATE SKIP LOCKED` with
an `ORDER BY … LIMIT` takes next-key locks on MySQL: it produced "Deadlock found when trying to get
lock" under eight concurrent claimants, and it counts skipped rows against the `LIMIT`, so a
claimant whose candidates are all locked comes back empty while rows remain — and the queue stops
draining. The conditional take that replaced it is one path on every engine. Both defects were
found by running ten concurrent claimants against a real server; neither is visible on SQLite or to
a careful reading.

**A short batch is a throughput characteristic, not a correctness defect.** A worker asking for two
scans may get one. No row is ever handed to two workers — that is the property the campaign checks
— and the rest goes out on the next tick.

**A table rather than a broker.** Vectispire already requires a database and does not require a
queue server; adding one would be a second thing to operate, back up and secure for a workload
measured in scans per hour. The same reasoning made `leader_lease` a table rather than an advisory lock: it is
**observable**, and an operator asking "who holds the tick" can answer it with a query.
