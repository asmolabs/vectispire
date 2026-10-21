# `vectispire-cp-agents`

The control plane's `agents` module — `core.agents` of the Java control plane, ported in Phase 2, task 2.9 of
the Rust port (plan, §7).

## What it owns

- **`t_agent`**: the registered scan executors, remote and built-in alike.
- **Protocol**: `/api/v1/agent/*` (8 routes), with long polling, raw body signature verification before parse,
  sealing-key pinning (`POST /api/v1/agent/sealing-key`).
- **Administration**: `/api/v1/admin/agents/*` (9 routes), with paging, activity, non-routables, and credentialed backlog.
- **Ports implemented**:
  - `ports::AgentClaimLock` for `cp-scanning`: serialized row write before taking scans.
  - `credentials::AgentDirectory` for `cp-access`: key resolution to agent.
- **Maintenance & Outbox**:
  - `CredentialedBacklogTask`: cadence `Scheduling`, order `CREDENTIALED_BACKLOG`.
  - `WithheldClaimRepair`: one-shot startup repair (`withheld-claim-repair`).
  - `AgentResultAuditDelivery`: outbox handler `agent_result_audit`.

## Differences from Java

- **The delivery receipt is the answer's body** (2026-10-21, 2.9 audit). Java learns from `DeferredResult.setResult`
  whether the request is still there; here the claim's answer carries a `Receipt` that gives the scan back to the queue
  unless the server took the answer's bytes to write them — the request dropped while waiting, or its answer dropped
  unread. A connection that fails after the bytes were taken counts as delivered, as it does in Java. Held by
  `tests/protocol.rs` on both engines.

## Fixed by the 2.9 audit (2026-10-21)

- A failure of the dispatcher on a result or a failure report answered the 409 "no longer yours", which tells the
  agent to drop the result; it is the 500 quoting a reference, as Java's exception is. The 500s of the heartbeat, the
  rule sets and the plugins no longer write the error's own text into the answer.
- `WithheldClaimRepair` ran nowhere; `cp-app`'s `startup::ready_jobs` runs it at start, held by
  `tests/startup_composition.rs`.
- `AgentResultAuditDelivery` was not registered in the outbox; `cp-app`'s `maintenance::outbox_registry` holds it.

Still open, from the audit: authorization coverage and the golden replay of the 17 routes, engine tests of hello,
the long poll's wait, heartbeat and failure, a reference set for the refusals and audit descriptions, the mutation
list, checked queries, and the smaller differences it lists (hello's descriptors untrimmed, `?wait=` unparsable read
as 0, a database error at authentication answered 401).
