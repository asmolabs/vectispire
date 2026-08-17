# 0002 — The database carries the queue, not a broker

**Date:** 2026-08-06 · **Status:** accepted

## Context

The scan queue was a module-level `ThreadPoolExecutor`: it lived inside whichever process
had received the request. A second instance therefore could not take the work, and a
restart lost whatever was in flight.

## Decision

Scans are rows with a status, and the database is the source of truth. Claiming is
**transactional**: `SELECT … FOR UPDATE SKIP LOCKED` then the status change in the *same*
transaction. Either an instance holds the row and the row says so, or neither.

Triggering a scan no longer executes: it inserts a `pending` row and returns.

A lease (`claimed_by`, `lease_expires_at`, `attempts`) makes takeover possible without one
instance's startup killing the other's scans.

## What was rejected

**A message broker** — RabbitMQ, Kafka, NATS. Two reasons.

A broker introduces a **dual write** between the scan row and the message: message
published then transaction rolled back, or transaction committed and publication failed.
The standard fix is a *transactional outbox*, which is **more machinery than the queue it
replaces**.

And a broker does not remove the need for the lease. A consumer that dies holding a
message needs a *visibility timeout* — the same work under another name.

The day a broker becomes justified — one task consumed by several subscribers with
different concerns, several thousand messages per second, or replaying an event history —
the database queue stays the source of truth and the broker bolts on beside it.
**Starting with the database closes no door; starting with the broker commits you to the
outbox immediately.**

## Consequences

`SKIP LOCKED` does not exist on SQLite, which keeps a conditional `UPDATE` — correct for
the threads of one process, which is all SQLite allows. The dialect check is explicit
because SQLAlchemy's SQLite dialect **drops `FOR UPDATE` silently**: asking without
checking would have produced a claim that looked transactional, green in development,
handing the same scan to two processes in production.

A concurrency guarantee has to be executed against a real server to be a guarantee: see
[04](../04-runtime-and-deployment.md) for what ten concurrent claimants revealed.
