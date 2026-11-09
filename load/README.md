# Load test

A reproducible load test of the control plane: a seeded estate the size of a real one, a scripted mix of
the routes people, pipelines and agents call, and the measurements that say what the server did under it.
Written for 1.0.0-rc.1, where it was first run; the results and the sizing guidance drawn from them are in
[`docs/analysis/en/2026-10-30_load_test_1.0.0-rc.1.en.md`](../docs/analysis/en/2026-10-30_load_test_1.0.0-rc.1.en.md)
and on the site, *Administration → Sizing*.

**It is not part of CI.** A run takes about half an hour and a machine to itself; see the report for the
smoke version proposed for the nightly.

## What it needs

Docker, a JDK 25 and Python 3.9 or later (standard library only). The control plane runs from its boot
jar on the host; MySQL and the load generator run in containers.

| | |
|---|---|
| Database | `mysql:9.4` or `mysql:8.4` by digest (`env.sh`), in a container and a volume of its own |
| Control plane | the boot jar of the checkout, `-Xmx1536m` (the Helm chart's default limit), Hikari's default pool of 10 |
| Load generator | `grafana/k6:1.3.0` by digest (`run.sh`) |

**k6 rather than Gatling**: a single static binary in a pinned image, scenarios in a script short enough to
review, and an open-model executor (`constant-arrival-rate`) for the machines — pipelines and agents arrive
at their own rate whatever the server answers, which a closed loop of virtual users cannot model. Gatling
would need a JVM build of its own beside the one under test.

## Nothing here touches what is not the harness's

- The database is `vectispire-loadtest-<engine>` with the volumes `vectispire-loadtest-<engine>-data` and
  `-snapshot`, all labelled `com.asmolabs.vectispire.loadtest`; `env.sh` refuses to start on a container or
  volume of that name it did not create. It never uses `docker-compose.yml`, whose volume names are fixed
  and are the operator's.
- The test suites' `vectispire-test-mysql` is never used.
- `env.sh stop` and `down` stop the PID the script started, nothing else.

## Run it

From the repository root:

```bash
(cd vectispire-java && ./gradlew :vectispire-core:bootJar -x test)
load/env.sh up                                       # MySQL, then the control plane on :3190
python3 load/seed/seed.py --governor-password "$(cat load/.state/bootstrap_password)"
load/env.sh snapshot                                 # the seeded rows, kept aside
load/env.sh app
load/probe.sh                                        # each route alone, three times: the unloaded cost
LEVELS="1 10 50 100" DURATION=90s load/run.sh mylabel
load/env.sh down                                     # container, volumes and state removed
```

`load/env.sh restore` puts the snapshot back, so a second campaign — after a change — starts from the
same rows: a run triages issues and rescans targets.

`LOAD_ENGINE=mysql84` runs the same on MySQL 8.4; `LOAD_HEAP` and `LOAD_POOL_SIZE` change the JVM heap
and the connection pool, to measure their effect.

## The dataset (`seed/seed.py`)

Everything goes through the API, and nothing is written by SQL:

- **Accounts and visibility**: a governor (the bootstrap account), an administrator, a CISO, a security
  champion, an auditor and `--readers` restricted readers (24); six teams, each granted a sixth of the
  targets, with the readers spread over them.
- **Targets**: `--targets` (300), two repositories for one image, on manual scans.
- **Scans**: `--rounds` (3) per target. A declared agent claims each one through `GET /api/v1/agent/jobs`
  and hands back a synthetic `ScanArtifacts` through `POST /api/v1/agent/jobs/{id}/result`: a Syft SBOM
  (900 components a repository, 1,600 an image, drawn from 12,000 packages with their licences and a
  dependency graph), vulnerabilities on those packages, and for a repository code-analysis,
  infrastructure and secret findings. Each round after the first changes `--drift` (8 %) of each, so a
  rescan resolves issues and opens others, as a real one does. Static analysis and a licence blocklist
  are switched on first, as an estate that uses them would.
- **Triage**: a quarter of the open backlog, in batches of a hundred through the bulk route, with five
  statuses, then a second decision on a fifth of them, one by one.
- **Integration keys**: ten, each restricted to its repository, with the `scan` scope the gate needs.

With the defaults: 300 targets, ~75,000 issues (60,000 open), ~180,000 findings, ~1,000,000 component
rows, 900 scans holding 300 MB of SBOMs, 21,000 triage events; 760 MB of data. Seeding takes five minutes.
Every name is invented, and the data is the same for the same `--seed`.

`seed/bodies.py` writes the result bodies the scenario's agents hand back during a run (one per target,
one drift further), into `.state/bodies.json`; `run.sh` writes it when it is missing.

## The scenario (`k6/scenario.js`)

Four scenarios at once, for `DURATION`:

| Scenario | Model | What it does |
|---|---|---|
| `people` | `VUS` virtual users, think time `THINK` (1 s, jittered) | two thirds administrators or leads: issue list (first page, filtered, searched, a deep page), an issue's detail, a triage, the dashboard, trends, security overview, scorecards, posture analytics, inventory search, licences, OWASP grid, remediation debt, scans, targets, a target's CSV export. One third restricted readers: their issue list, filtered, a detail, the dashboard, their repositories |
| `pipelines` | `GATE_RATE` per second (2) | `POST /api/v1/gate` with a key restricted to its repository |
| `signins` | `LOGIN_RATE` per second (0.5) | a sign-in and a sign-out |
| `scan_triggers` + `agents` | `SCAN_RATE` per second (0.2), `AGENTS` long-polling agents (4) | a scan asked for, claimed by an agent and its result ingested |

Each request is tagged with its route, and the summary prints p50, p95, p99, the request count and rate,
and the failure rate per route.

## What a run leaves (`results/<date>-<label>/`, not committed)

- `environment.txt` — machine, Docker, JVM flags, MySQL version and settings, dataset size.
- `vus-<n>/summary.txt` and `summary.json` — k6's per-route table and its full summary.
- `vus-<n>/metrics.csv` and `metrics.json` — Hikari's active and pending connections, acquire time and
  timeouts, heap, GC pauses and CPU, sampled through Actuator every two seconds (`sample.py`).
- `vus-<n>/digests.txt` — the 25 statements MySQL spent most time on during that level
  (`performance_schema`, reset before each level).
- `slow.log` — every statement over 200 ms during the whole run.

`load/explain-route.sh <path>` lists the statements one call of a route runs and what each cost, and
`load/sql.sh` opens a SQL session on the harness's database: that is how the defects in the report were
found.
