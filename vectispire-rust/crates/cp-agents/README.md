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

## Held to Java's traffic (2026-10-22)

- `tests/routes.rs`: the authorization coverage, enumerated from the router — every protocol route an agent's key's
  alone, every administration route an administrator's, and one agent's scan refused to another.
- `tests/golden.rs`: the Java suite's recorded traffic, replayed for the agents' seventeen routes together with
  `targets`' and `scanning`'s (it moved here from `cp-scanning`). It found three differences, fixed: hello's descriptors
  were stored untrimmed, the protocol's audit entries named no actor where Java names the agent, and a failure
  report's entry spelt its kind `PERMANENT` where Java writes `permanent`. What does not replay is named in
  `golden/deferred/` (one file per module whose port ends the line), one recording a line: the secrets the recorder hides (sealing keys, attestations), timestamps a
  test rewinds behind the recorder's back, and the stand-ins of later phases (plugins, SIEM, ingestion's backlog,
  checklists).

Still open, from the audit: engine tests of hello, the long poll's wait, heartbeat and failure beyond the replay, a
reference set for the refusals and audit descriptions, the mutation list, checked queries, and two smaller
differences (`?wait=` unparsable read as 0 where Java answers 400, a database error at authentication answered 401).
