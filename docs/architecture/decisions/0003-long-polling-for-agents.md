# 0003 — Agents speak HTTP long-polling, never to the database

**Date:** 2026-08-06 · **Status:** accepted

## Context

Moving scan execution onto remote machines — another network, another architecture, a
machine allowed to reach a private repository the control plane cannot.

The question asked was about transport. The real question was access to secrets.

## Decision

`GET /api/v1/agents/jobs?wait=30` returns a task or 204. The agent claims, executes, sends
a heartbeat, reports the result. It **only talks to the API**.

Four reasons, in order of importance.

**The agent does not need database access.** An agent with a PostgreSQL connection would
also need the database credentials *and* `ENCRYPTION_KEY` — hence everything needed to
decrypt **all** the SSH keys of every target, not just the ones it scans. Over HTTP it
presents nothing but an `agent`-scoped key, and it reuses the authentication, the scopes,
the quota and the audit trail that already exist.

**Flow control happens by itself.** The agent asks for work when it has capacity. A broker
that pushes does not know what the agent is doing.

**Latency is not at stake.** A scan takes one to two minutes; a thirty-second long-poll
costs a few percent.

**A useful consequence:** since only the control plane touches the database, **agents work
even on SQLite**. The simplest deployment shape gains the most advanced feature, which was
not planned.

## What was rejected

**The agent holds `ENCRYPTION_KEY` and reads the database.** The least work, and the
consequence is in the table above: any agent can decrypt every SSH key. An agent is by
nature the most exposed piece — it runs elsewhere, often on a machine whose posture is
less under control. Backing out afterwards would mean rotating every secret.

**A plugin SDK for agents.** The extension point already exists and is at the right level:
[`ScannerEngine`](0001-pluggable-scan-layer.md). An agent is a *transport* for that
interface, not an additional abstraction.

## Consequences

`ScanProcessor` had to be cut in two: `ScanRunner`, which runs the analyzers and knows
nothing of the database, and `ScanIngestor`, which reads the artifacts and writes. The cut
is not tidying, it is the formalization of the agent's contract.

An import test guarantees that the agent module cannot import the database layer. Without
it, the guarantee would be a convention.

**A replayed report would skew the history.** The fingerprint makes reconciliation
idempotent, but the issue sync increments `times_seen` on every call — a replayed report
would inflate the counters without creating a visible duplicate. Hence a deduplication
inbox (`processed_message`), with the identifier inserted **inside the transaction that
applies the effect**.

**A compromised agent can skew a verdict** by reporting false results. Reports are audited
the way a triage is; they are not proven. That is this decision's open limit.
