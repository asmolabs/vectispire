# Architecture Document — 03. Dimensioning & Performance View

* **Project:** Vectispire — ASPM & Security Control Plane
* **Template:** `bflorat/modele-da` — Architecture Document Template (Bertrand Florat)
* **Status:** Approved · **Version:** 1.0

---

## 1. Non-Functional Performance Requirements (NFR)

1. **Quality Gate Response Time (`POST /api/v1/gate`)**: $< 300\text{ ms}$ (deterministic in-memory evaluation).
2. **Scan Ingestion Throughput**: Asynchronous background scan processing without blocking HTTP thread pools.
3. **Horizontal Scaling**: Conflict-free coordination across multiple instances using database leader leases (`t_leader_lease`).
4. **Docker Memory Stability**: Enforced CPU and memory caps on scanner containers to prevent host RAM exhaustion.

---

## 2. Volumetrics & Database Sizing

| Entity / Table | Volumetric Estimate (100 Targets, 10,000 Scans) | Management & Optimization Strategy |
|---|---|---|
| **`t_scan` (Scan history)** | ~ 100,000 rows / year | Pruning old scan execution metadata via `RetentionService`. |
| **`t_finding` (Raw findings)** | ~ 500,000 rows | Transient data, purged periodically by retention task. |
| **`t_issue` (Reconciled backlog)** | ~ 10,000 to 50,000 unique issues | Indexing on `target_id`, `status`, `fingerprint` for fast lookup. |
| **`t_audit_log` (Sealed log)** | ~ 50,000 audit entries / year | Immutable, compact SHA-256 hash storage. |

---

## 3. Scale Coordination & Leader Leases (`t_leader_lease`)

In a multi-instance distributed deployment, background task coordination (cron scheduling, retention purges, outbox relay) is managed via `t_leader_lease`:

```sql
SELECT * FROM t_leader_lease WHERE lease_name = 'SCHEDULER' AND expires_at > NOW() FOR UPDATE;
```

- **Guarantee**: Only one active instance (*Leader*) executes a background task at any given time.
- **Failover**: If the active leader fails to renew its lease, the lease expires and another node acquires leadership automatically.

---

## 4. Resource Caps & Memory Constraints (JVM / Docker)

### 4.1 JVM Sizing (Spring Boot Control Plane)
- **Recommended Heap RAM**: `2 GB` to `4 GB` (`-Xms1024m -Xmx4096m`).
- **Garbage Collector**: G1GC optimized for JDK 25 low-latency pauses.

### 4.2 Per-Container Resource Caps (`ContainerRunner`)
Every container execution is constrained to prevent host memory exhaustion:
- **Maximum Container Memory**: `1.5 GB` RAM.
- **CPU Quota**: `2.0 vCPUs`.
- **Maximum Execution Timeout**: `10 minutes` per scanner step. Exceeding timeout triggers forced container termination.
