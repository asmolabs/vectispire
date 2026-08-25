# 04 — Runtime and deployment

## Overview

Vectispire supports single-instance local deployments as well as distributed multi-agent setups.

| Mode | Database | Scanners Location | Docker Socket Holder |
|---|---|---|---|
| Single Instance | Embedded SQLite or External DB | Same process | Control Plane |
| Multi-Agent | PostgreSQL / MySQL | Remote Agents | Remote Agents |

## Leader Lease & Concurrency

Background ticks (cron schedules, retention purges, outbox relay) are coordinated via database leader leases in `t_leader_lease` to ensure active-passive worker safety across scaled instances.
