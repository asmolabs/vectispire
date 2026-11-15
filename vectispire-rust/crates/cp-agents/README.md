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
- `tests/golden.rs`: the Java suite's recorded traffic, replayed for the agents' nineteen routes together with
  `targets`' and `scanning`'s (it moved here from `cp-scanning`). It found three differences, fixed: hello's descriptors
  were stored untrimmed, the protocol's audit entries named no actor where Java names the agent, and a failure
  report's entry spelt its kind `PERMANENT` where Java writes `permanent`. What does not replay is named in
  `golden/deferred/` (one file per module whose port ends the line), one recording a line: the secrets the recorder hides (sealing keys, attestations), timestamps a
  test rewinds behind the recorder's back, and the stand-ins of later phases (plugins, SIEM, ingestion's backlog,
  checklists).

## Finished (2026-11-15, task 2.9)

- **Held to Java's answers**: `reference/agents/administration.json`, written by `AgentAdministrationReferenceSetTest`
  over the real service — 64 declarations, changes, pinned and removed signing keys, sealing-key resets and removals,
  each with its refusal, its audit sentences in order and the row as saved — read by `tests/administration_reference.rs`
  on a real database. It found names, credentials modes and signing keys trimmed by `str::trim` where `String.trim`
  keeps a no-break space, an unknown mode quoted trimmed where Java quotes it as sent, and in `crates/crypto` a signing
  key padded with a no-break space pinned where Java refuses it and a sealing key read trimmed where Java reads it as is.
- **A removal revokes the key first**, and a failed revocation fails the request. Java deletes the row and revokes the
  key in one transaction; the key is `access`'s, written through its service, so here they are two writes, ordered so
  that a failure between them leaves an inert agent rather than a working key with no agent behind it.
- **The claim's `wait` is bound as `@RequestParam int` is** (`web/read.rs`): Spring's sentence, a 400, before the agent
  is authenticated. An unreadable value used to be read as no wait.
- **A database that cannot be read while authenticating is a 500** quoting a reference; it was the 401 telling the
  agent its key was wrong.
- **Engine tests beyond the replay** (`tests/protocol_lifecycle.rs`): hello, the signs of life (an idle poll, a lease
  renewal, a recent sign not rewritten), the long poll's wait served and cut short, the heartbeat's owner, failure
  reports requeued, permanent, applied once and the lease holder's alone.
- **Checked statements**: every statement on `t_agent` is `sqlx::query!` per engine, cached in `.sqlx/`. An `id` that is
  not a UUID is a failure where it was read as the nil UUID.
- **Mutation list**: `security/mutants/p2-9-agents.py`.
