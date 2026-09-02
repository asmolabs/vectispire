# Architecture Document — 03. Dimensioning & Performance View

* **Project:** Vectispire — ASPM & Security Control Plane
* **Template:** `bflorat/modele-da` — Architecture Document Template (Bertrand Florat)
* **Status:** Approved · **Version:** 1.3 (2026-08-25 — the CPU quota now exists)

---

## 1. Non-Functional Performance Requirements (NFR)

1. **Quality Gate Response Time (`POST /api/v1/gate`)**: $< 300\text{ ms}$. The rule itself —
   `PolicyGate.evaluate` — is a pure in-memory function of the issues handed to it, and **getting
   those issues now costs one indexed read of that target's open backlog**. Until 2026-08-25 it
   read *every* open issue in the deployment and discarded all but one target's, on the endpoint
   every pipeline calls on every build; the cost tracked the estate rather than the target. Both
   halves were repaired together, because a per-target query against an unindexed `state` column
   would only have moved the scan.
2. **Scan Ingestion Throughput**: Asynchronous background scan processing without blocking HTTP
   thread pools.
3. **Horizontal Scaling**: Conflict-free across multiple instances, by two different mechanisms —
   the scan **scheduler** holds a lease in `t_leader_lease` because it *creates* work, and the scan
   **worker** needs none because claiming a queued row is itself the concurrency control. See §3.
4. **Docker Resource Stability**: Enforced memory, process-count **and CPU** caps on scanner
   containers. The CPU share was listed here for weeks and applied by no code; it exists as of
   2026-08-25 and `ContainerHardeningTest` asserts every one of these flags on the request handed
   to the daemon.

---

## 2. Volumetrics & Database Sizing

| Entity / Table | Volumetric Estimate (100 Targets, 10,000 Scans) | Management & Optimization Strategy |
|---|---|---|
| **`t_scan` (Scan history)** | ~ 100,000 rows / year | Pruning old scan execution metadata via `RetentionService`. Added 2026-09-02: `(repo_id, id)` and `(container_id, id)`, because "the latest scan per target" is a correlated subquery — with no index on `repo_id`, the repository list was quadratic in the number of scans. |
| **`t_finding` (Raw findings)** | ~ 500,000 rows | Transient data, purged periodically by retention task. Added 2026-09-02: `(scan_id)`, `(package_name)` and `(issue_id)`. **The largest table in the schema carried nothing but its primary key** — `scan_id` was declared by an inline `references`, a form that creates no index on any of the three engines. |
| **`t_issue` (Reconciled backlog)** | ~ 10,000 to 50,000 unique issues | `(state, repo_id)` and `(state, container_id)` for the gate and the compliance summary, `(fingerprint)` for the per-finding identity lookup at ingestion, and `(identifier)` since 2026-09-02 because the CycloneDX generator and the VEX ingestor look up by CVE inside a loop. Added 2026-08-25: this table had carried **no index at all** while this document claimed three, and `SchemaParityIntegrationTest` now asserts they exist on every engine, so a refactor cannot drop them quietly. |
| **`t_audit_log` (Sealed log)** | ~ 50,000 audit entries / year | Immutable, compact SHA-256 hash storage. |

---

## 3. Scale Coordination & Leader Leases (`t_leader_lease`)

**One job takes a lease, not all of them.** Four periodic jobs run in every instance: the scan
worker (15 s), the scan scheduler (60 s), the notification relay (60 s) and hourly maintenance.
Only the **scheduler** is elected, because it is the only one that creates work — two instances
independently deciding a nightly scan is due would queue it twice. The relay and the maintenance
pass are idempotent, and the worker claims rows.

**The mechanism is a compare-and-swap, not a row lock.** No `SELECT … FOR UPDATE` is ever issued;
acquisition is a conditional `UPDATE` that succeeds for exactly one instance:

```sql
update t_leader_lease
   set holder = :holder, expires_at = :expiresAt, acquired_at = :at, updated_at = :at
 where name = 'scheduler' and holder = :previousHolder and expires_at = :previousExpiry;
```

- **Guarantee**: the update matches zero rows for every instance but one, so exactly one becomes
  leader — without holding a lock across the pass, which is what a `FOR UPDATE` would do and what
  would turn a slow scheduling round into a blocked one everywhere else.
- **Failover**: a leader that stops renewing lets its lease expire, and the next instance to try
  the swap matches the expired row and takes over.

---

## 4. Resource Caps & Memory Constraints (JVM / Docker)

### 4.1 JVM Sizing (Spring Boot Control Plane)
- **Recommended Heap RAM**: `2 GB` to `4 GB` (`-Xms1024m -Xmx4096m`).
- **Garbage Collector**: G1GC optimized for JDK 25 low-latency pauses.

### 4.2 Per-Container Resource Caps (`ContainerRunner`)
Every container execution is constrained to prevent host memory exhaustion:
- **Maximum Container Memory**: `2 GB` (`ScannerLimits.DEFAULT`). A container that exceeds it
  dies; the host does not.
- **Maximum Process Count**: `512` PIDs. This is what turns a fork bomb into a dead container, and
  it is the cap this document previously omitted.
- **Maximum Execution Timeout**: `15 minutes` per scanner step. Exceeding it triggers forced
  container termination.
- **CPU Quota**: **every core but one**, floored at one. Not a fixed number, because a fixed one
  is wrong on both a two-core VM and a sixty-four-core builder, and because the harm is not that a
  scanner works hard — semgrep and grype are CPU-bound, and starving them turns a five-minute scan
  into a timeout, which is a denial of service delivered by the defence. The harm is that a
  repository nobody controls takes the *last* core and leaves the control plane unable to answer a
  gate call for fifteen minutes. Leaving one core is what separates those two.

  This entry claimed `2.0 vCPUs` for weeks while no CPU limit of any kind was applied. It is now
  applied, and asserted: nothing had ever checked any of these flags, which is how a control stays
  documented and absent at the same time.

  **The core count is the daemon's, not the JVM's** (2026-09-02). The limit was derived from
  `availableProcessors()`, which counts the cores of the machine running the control plane — while
  the container runs on the machine running the daemon. The two differ whenever Docker Desktop is
  in the way, whenever `DOCKER_HOST` points elsewhere, and whenever the control plane is itself
  containerised with a quota of its own. Asking the wrong machine is not a conservative error:
  Docker does not round down, it refuses the create with *"Range of CPUs is from 0.01 to N"* and no
  scan starts at all. `ContainerRunner` now asks `docker info` and clamps to all but one of the
  daemon's cores. Size the **daemon's VM**, not the host.
