# 04 — Runtime and deployment

## Three shapes, and only one that almost everybody uses

**One instance, one file.** One process, SQLite, the Docker socket. This is not a degraded
mode: it is what lets someone try Zanshin in a quarter of an hour, which is what decides
whether a free tool gets adopted. Everything that follows is optional.

To be set explicitly — `ZANSHIN_DB_DIALECT=sqlite` — because the code's default is
PostgreSQL, which is what a lasting deployment wants. This shape was in fact **announced
without existing** for the whole of the port: the dialect was listed among the supported
engines, its driver was not installed, and no connection was possible. All four engines
now pass the entire integration campaign, each with its own set of migrations.

**Several instances.** Possible since the queue, the scheduler and the counters stopped
living in memory. Requires PostgreSQL. The API is stateless and the
session lives in the database, so that requirement is gone.

**Remote agents.** One web instance, executors elsewhere — another network, another
architecture, a machine allowed to reach a private repository the control plane cannot.
Works **even on SQLite**, because an agent never touches the database.

## What the engine tells you at startup, and why

[`001-baseline.yaml`](../../zanshin-java/zanshin-core/src/main/resources/db/changelog/001-baseline.yaml)
declares what each engine can and cannot do, and the startup path emits a warning for
every capability that is missing, each one naming the consequence rather than the
capability. Saying it early beats letting the problem be discovered as a corrupted
database or as users logged out at random.

| Capability | Missing on | Consequence named at startup |
|---|---|---|
| Transactional claiming | SQLite | claiming falls back to a conditional `UPDATE`; correct within one process, unsafe across several |
| Complete claim batches | MySQL | a claimant can come back empty while the queue is not; throughput, not correctness |
| Microsecond timestamps | *(none today)* | the audit chain covers the timestamp, so truncation makes every entry fail its own check |
| `NULLS LAST` | MySQL, MariaDB | ordering puts nulls at the other end; the queries compensate explicitly |
| Concurrent writers | SQLite | a second instance on the same file does not run slowly, it corrupts |

These are warnings, not refusals. An earlier design additionally refused to boot a second
instance on SQLite, detecting its peer through the built-in agent rows; that guard, and
the `ZANSHIN_ALLOW_MULTI_INSTANCE_SQLITE` escape hatch that muted it, were not carried
over by the port. **Nothing currently stops you from pointing two instances at one SQLite
file**, and the consequence is data corruption rather than slowness. See "still open".

## The queue, and how it is claimed

Scans are rows with a status. What was missing was **transactional claiming**.

On **PostgreSQL**: `SELECT … FOR UPDATE SKIP LOCKED` then the status change in the *same*
transaction. Either an instance holds the row and the row says so, or neither.

On **MariaDB**: identical, and **measured**. Two concurrent claimants against four queued
scans — the second receives a full batch, as under PostgreSQL. Its capabilities had been
inherited from MySQL "out of caution, not observation", and three of the four were wrong.

On **MySQL**: `SKIP LOCKED` works, but skipped rows count against the `LIMIT`, so a batch
comes back short under contention — sometimes empty while the queue is not. Throughput,
not correctness: nothing is served twice, the rest goes out on the next round.

On **SQLite**: a conditional `UPDATE ... WHERE status = 'queued'` whose affected-row count
names the winner. Correct for threads within one process, which is all SQLite allows
anyway.

**The choice is made on a declared capability, not on the engine's name** — and that
capability is finally read. It had described the behaviour from the start without
producing it: claiming issued `FOR UPDATE` unconditionally.

The `better-sqlite3` driver **refuses** `FOR UPDATE` rather than ignoring it, which is
preferable: a driver that drops it silently produces a claim that looks
transactional, green on the developer's machine, and handing the same scan to two
processes in production.

### The lease

`claimed_by`, `claimed_at`, `lease_expires_at`, `attempts`. An executor renews while it
works; an executor that dies stops, and the scan is taken over after expiry. The lease is
generous (20 minutes by default) because a single step — pulling a large image, running
Grype over a large SBOM — takes minutes, and a lease shorter than the step would declare
healthy executors dead.

After three takeovers the scan **fails** instead of being requeued: a target that jams
whatever picks it up would otherwise occupy the entire fleet, and an operator would see a
scan forever "about to start".

### What a real concurrency test found

Ten concurrent claimants, separate connections, against a real server: no scan ever
claimed twice — safety held from the first version — but **six claimants out of ten came
back empty-handed** while twenty scans waited. A throughput problem, not a safety one,
whose production shape is an agent polling the queue for thirty seconds while work sits
there.

The obvious fix — widen the selection window then truncate it — **makes things worse**: a
claimant that locks rows it will not take starves the others for as long as it holds them.
What works is asking for exactly what you need and retrying, with a measured budget.

This is exactly the class of defect the testing strategy predicted: invisible on SQLite
and to a careful reading. **A concurrency guarantee not executed against a real server is
not a guarantee.**

## Remote agents

```mermaid
sequenceDiagram
    participant A as Agent
    participant API as Zanshin API
    participant DB as Database

    A->>API: POST /register (capabilities, max_concurrent)
    loop while it has capacity
        A->>API: GET /jobs?wait=30
        API->>DB: claims (lease)
        API-->>A: task, or 204
        A->>A: clone, analyze (agent's own Docker)
        A->>API: POST /jobs/{id}/heartbeat
        A->>API: POST /jobs/{id}/result (chunked)
    end
```

**Long-polling, not a broker.** The agent asks for work when it has capacity: flow control
happens by itself, whereas a broker that pushes has no idea what the agent is doing.
Latency is not at stake — a scan takes one to two minutes, a thirty-second long-poll costs
a few percent. And the main reason remains the trust boundary
([decision 0003](decisions/0003-long-polling-for-agents.md)).

**The queue is routed by label.** A target can require a label, and only agents carrying
it see its scans — `ZANSHIN_WORKER_LABELS` on the executor side. Without this, any
registered agent claimed any scan, which defeats the point of placing an agent in a
less-trusted segment.

**A replayed report must break nothing.** An agent that retries must not insert 421
findings twice. The fingerprint is not enough: it makes reconciliation idempotent, but the
issue sync increments `times_seen` on every call, so a replayed report **would skew the
history without creating a visible duplicate**. Hence a message identifier, a
`processed_message` table with a uniqueness constraint, and the insertion of that
identifier **inside the transaction that applies the effect**.

**Large payloads are chunked.** 421 findings and an 18 MB SBOM do not fit in a comfortable
request. This is chunking, not batching — batching would buy nothing measurable at this
rate and would delay the one thing somebody is waiting for.

## What goes out

Notifications go through an **outbox**: a row written in the transaction that produces the
scan result, relayed by the tick. Before, the webhook fired *after* the commit — if the
process died in between, the notification was lost silently.

Spaced retries, abandonment after eight attempts with an audit entry, a `message_id` in
the payload so a receiver can deduplicate an at-least-once delivery.

There is **no outbox for the scan queue**: there is no second system, the database is
enough.

## The settings that matter

| Variable | What it decides |
|---|---|
| `ZANSHIN_DATABASE_URL` / `ZANSHIN_DB_PATH` | where the data lives. A path is enough for the common case |
| `ZANSHIN_DB_DIALECT` | `postgres` (default), `mysql`, `mariadb` or `sqlite`; selects the migration set and the column types |
| `ENCRYPTION_KEY` | without it, nothing can be encrypted. No default value |
| `ZANSHIN_PREVIOUS_ENCRYPTION_KEYS` | rotation: the old keys stay readable |
| `ZANSHIN_EMBEDDED_WORKER` | whether this process also runs scans, or only serves the API |
| `ZANSHIN_WORKER_LABELS` | which labelled targets this executor is allowed to claim |
| `ZANSHIN_QUEUE_LEASE`, `ZANSHIN_QUEUE_MAX_ATTEMPTS` | the lease and the takeover budget described above |
| `ZANSHIN_LEADER_LEASE` | how long the tick's holder keeps it without renewing |
| migration | Liquibase applies the changelog at startup, under the leader lease, so one instance migrates and the others wait |
| `ZANSHIN_SEMGREP_RULES_DIR` | operator-supplied rules, merged with the bundled ones |

Three variables earlier versions needed are gone, and are listed here because their
absence is the answer to "where did it go": ~~`REDIS_URL`~~ (the API is stateless, the
session lives in the database), ~~`ZANSHIN_ALLOWED_ORIGINS`~~ (there is no websocket to
authorize any more), and ~~`ZANSHIN_AUTO_MIGRATE`~~ (migrations are an explicit step).

## Still open

- **Nothing refuses a second instance on SQLite.** An earlier version detected a
  live peer through the built-in agent rows and refused to boot; the port did not carry
  the guard over. The failure mode is corruption, not slowness, which makes this the
  heaviest item on this list.
- **`ZANSHIN_ROLE`** (separating a `web` role from an `agent` role in one artifact) is
  described and not done. Remote agents cover the real need; the remaining gain would be
  taking the Docker client out of the network-exposed process.
- **Capability-based routing** does not exist. Label-based routing does, which covers the
  security need; picking between two agents on what they can *do* is still open.
- **`Dockerfile.agent` has never been built.**
