# Architecture Document — 04. Infrastructure & Deployment View

* **Project:** Vectispire — ASPM & Security Control Plane
* **Template:** `bflorat/modele-da` — Architecture Document Template (Bertrand Florat)
* **Status:** Approved · **Version:** 1.0

---

## 1. Deployment Topology & Physical Architecture

Vectispire supports two complementary deployment topologies:

```mermaid
flowchart TB
    subgraph Mono["Monolithic Mode (Single Instance)"]
        Ctrl1["Control Plane (Spring Boot + UI)"]
        Docker1["Local Docker Daemon"]
        DB1[("Embedded SQLite or External DB")]
        Ctrl1 --> Docker1
        Ctrl1 --> DB1
    end

    subgraph Dist["Distributed Multi-Agent Mode"]
        Ctrl2["Clustered Control Plane (PostgreSQL / MySQL)"]
        DB2[("Enterprise RDBMS (PostgreSQL / MySQL)")]
        AgentA["Remote Agent Site A"]
        AgentB["Remote Agent Site B"]
        
        Ctrl2 --> DB2
        AgentA -.->|"HTTP Long-Polling (/api/v1/agents/jobs)"| Ctrl2
        AgentB -.->|"HTTP Long-Polling (/api/v1/agents/jobs)"| Ctrl2
    end
```

---

## 2. Database Compatibility Matrix & Flyway Migrations

Vectispire supports 4 relational database engines using dialect-specific native SQL migration
scripts (`src/main/resources/db/migration/{vendor}/`) managed by **Flyway** ([ADR
0013](../../en/decisions/0013-flyway-multi-dialect-migrations.md)):

| RDBMS Engine | Min. Supported Version | Flyway Dialect | Target Usage |
|---|---|---|---|
| **PostgreSQL** | 14+ | `postgresql` | Recommended production (Enterprise Cluster) |
| **MySQL** | 8.0+ | `mysql` | Alternative production (Cloud / RDS environments) |
| **SQLite** | 3.35+ | `sqlite` | Demos, local evaluation, and embedded single-instance mode |

### 2.1 Schema Integrity & `ddl-auto`
Hibernate's `ddl-auto` setting is strictly set to `validate`. Flyway maintains sole authority over
DDL migrations to prevent schema drift or silent data loss.

---

## 3. Host Docker Daemon Interaction & Confinement

1. **Docker Socket Mounting (`/var/run/docker.sock`)**: Only the control plane (or agent process)
   interacts with the Docker daemon via the host socket.
2. **Ephemeral Analyzer Containers**: `ContainerRunner` instantiates isolated containers that
   terminate and self-destruct immediately after execution.

---

## 4. Remote Agent Architecture (`vectispire-agent`)

Remote agents offload scanning closer to isolated corporate network zones:

- **Network Protocol**: Outbound unidirectional communication via HTTP Long-Polling (`GET
  /api/v1/agents/jobs?wait=30`).
- **Zero Database Dependencies**: `vectispire-agent` has zero JDBC drivers on its classpath.
- **Key Isolation**: Agent never possesses master `ENCRYPTION_KEY` ([ADR
  0003](../../en/decisions/0003-long-polling-for-agents.md)).
