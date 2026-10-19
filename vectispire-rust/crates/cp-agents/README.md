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
