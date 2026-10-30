# Sizing

What a control plane needs for the estate it serves, from the first load test, run on 1.0.0-rc.1: 300
targets, 75,000 issues of which 60,000 open, a million component rows, people, pipelines and agents at work
together. The full report, with every figure and how to rerun it, is in the repository
(`docs/analysis/en/2026-10-30_load_test_1.0.0-rc.1.en.md`, and the harness in `load/`). These are starting
values from one machine; measure yours.

## What limits it

**The database's CPU, then the control plane's heap.** On the test's four-core database, the slowest
screens' statements kept MySQL busy long before the control plane was: at fifty very active users MySQL
held its four cores at more than 80 % while the control plane used under a fifth of one core. Every
request then waited for a database connection, and every route slowed together.

"Very active" means one screen a second per person, without pause. People at work open a screen every ten
to thirty seconds, so the test's ten users stand for about a hundred people at a human pace, and its fifty
for several hundred.

## Starting values

| Estate | Database | Control plane | Connection pool |
|---|---|---|---|
| Up to ~100 targets, a team | 2 cores, 4 GiB, buffer pool 1 GiB | 2 GiB memory limit (1.5 GiB heap) | 10 (the default) |
| ~300 targets, 60,000 open issues, ~100 people | **4 cores**, 8 GiB, buffer pool ≥ the data size | **2 to 3 GiB limit** (1.5 to 2.25 GiB heap) | 10 to 20 |
| Several hundred people at once, or more targets | 8 cores or more | 4 to 5 GiB limit (3 to 4 GiB heap) | 20 to 30, with the cores |

The middle row is the one measured; the first and the last are drawn from it, not tested.

- **The heap** is 75 % of the container's memory limit in the published image (`MaxRAMPercentage=75`), so the
  Helm chart's default 2 GiB limit gives 1.5 GiB. That held fifty very active users on the test's estate; at
  a hundred the heap filled and the JVM ran full collections. Raise `resources.limits.memory` in the chart,
  or the container's memory in the composition.
- **The connection pool** is Hikari's default of ten and no shipped setting changes it. Ten connections were
  never the limit on four database cores: raise it only with the database's cores, since a larger pool hands
  the same cores more statements at once. Set it with
  `SPRING_DATASOURCE_HIKARI_MAXIMUM_POOL_SIZE` (Spring's `spring.datasource.hikari.maximum-pool-size`),
  and keep it under the server's `max_connections` (151 by default).
- **The buffer pool**: the shipped composition leaves MySQL's default of 128 MiB. The test estate's data was
  875 MB; give InnoDB a buffer pool near the data size (`--innodb-buffer-pool-size`) so the screens' reads
  stay in memory.

## How big the database grows

Measured on the test estate (875 MB in all):

| What | Size |
|---|---|
| A stored SBOM | its document: 340 KB in the test, often 1 to 5 MB for a real image's Syft SBOM. The retention purge drops SBOMs past their window (see [Rotation and purge](maintenance.md)) |
| A component row (one package of one scan) | about 0.3 KB with its indexes; a scan of an image of 1,600 packages adds 0.5 MB. **Kept** — the inventory's history is not purged |
| An issue | about 1 KB with its indexes |
| A finding (one observation of an issue by a scan) | about 0.35 KB |
| A triage decision | about 0.3 KB |

So an estate of 300 targets scanned weekly, each scan of about 1,000 packages, adds about 300 × 52 ×
0.3 MB ≈ **4.7 GB a year of component rows**, plus the SBOMs within the retention window. Plan the volume,
the backups and the buffer pool from that.

## Scans and agents

Four agents handed back 300 scan results of 420 KB (1,600 components, 200 vulnerabilities each) in
70 seconds — about four results a second, 0.8 s each, some 15,000 an hour — while ten users worked at the
screens. Ingestion is not what limits an installation of this size; the agents' own scanners are.

## Upgrading an existing installation to 1.0.0-rc.1

V96 and V98 rebuild `t_component` and `t_scan` once, at the first start: 10 s together on the test
estate's million component rows and 300 MB of SBOMs. The time grows with the inventory and the SBOMs kept;
the control plane answers its health probe only once the migrations are done, so give the startup probe
room (the chart allows five minutes).
