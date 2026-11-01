# Monitoring

The control plane publishes its metrics in the Prometheus text format at `/actuator/prometheus`: the
queue, the scans' outcomes and the agents, plus what Spring Boot already measures — the JVM, the HTTP
requests and the database connection pool. Every series carries an `application` label naming the
instance, so a fleet's numbers are not summed into one line.

## Who may scrape

The page is **never anonymous**. It answers:

- **the scrape token**, sent as a bearer: `Authorization: Bearer <token>`. It is recognised on
  `/actuator/prometheus` and nowhere else — on any other route it is an unknown token, refused like one;
- **an administrator's session**, for a look by hand. No other session, agent key or integration key
  opens it.

The health probes (`/actuator/health`, `/actuator/health/liveness`, `/actuator/health/readiness`) stay
open to anyone: a container's probe has no credential. `/actuator/metrics`, which lists the same meters
one by one, stays an administrator's only.

Set the token, at least 32 characters, one of three ways:

| Where | How |
|---|---|
| Environment | `VECTISPIRE_METRICS_SCRAPE_TOKEN` |
| A file — **prefer this in production** | `VECTISPIRE_METRICS_SCRAPE_TOKEN_FILE=/run/secrets/scrape_token` |
| Helm | a Kubernetes secret named by `secrets.metricsScrapeToken.secretName` (key `metrics-scrape-token`) |

Generate one with `openssl rand -base64 32`. A shorter token stops the application at start, and so does a
file that cannot be read. The file is read again at each scrape, so a rotated secret takes effect without
a restart. Unset, the page answers an administrator's session only.

## Scraping it

```yaml
# prometheus.yml
scrape_configs:
  - job_name: vectispire
    metrics_path: /actuator/prometheus
    scheme: https
    authorization:
      type: Bearer
      credentials_file: /etc/prometheus/vectispire-scrape-token
    static_configs:
      - targets: ["vectispire.example.org"]
```

Each instance keeps its own figures, so scrape every replica rather than the load balancer in front of
them: a scrape through the balancer reads one instance at random.

**Kubernetes.** The chart ships no `ServiceMonitor` — it would need the Prometheus Operator's resource
definitions on every cluster the chart is installed on. With the operator, apply one beside the release,
reading the same secret as the control plane:

```yaml
apiVersion: monitoring.coreos.com/v1
kind: ServiceMonitor
metadata:
  name: vectispire
  namespace: vectispire
spec:
  selector:
    matchLabels:
      app.kubernetes.io/name: vectispire
      app.kubernetes.io/component: control-plane
  endpoints:
    - port: http
      path: /actuator/prometheus
      interval: 30s
      authorization:
        type: Bearer
        credentials:
          name: vectispire-metrics      # the secret secrets.metricsScrapeToken names
          key: metrics-scrape-token
```

With `networkPolicy.enabled`, add the Prometheus namespace to `networkPolicy.ingressFrom`, or the scrape
never reaches port 3180.

## The metrics

Names as Prometheus shows them. No label names a repository, a target, a user or an agent: each label
takes two or three values whatever the size of the estate.

### The queue

| Metric | Labels | What it says |
|---|---|---|
| `vectispire_scans_queued` | `kind` (`repository`, `container`) | Scans waiting to be claimed, those waiting out a retry delay included. Summed over `kind`, the queue. |
| `vectispire_scans_queued_oldest_age_seconds` | `kind` | How long the oldest waiting scan has waited since it was queued; 0 when none waits. The number to alert on: a queue can be short and stuck. |
| `vectispire_scans_running` | | Scans claimed and not yet reported. |
| `vectispire_scans_credential_unserved` | | Waiting scans of repositories carrying a credential that no executor able to be handed it can take — see [Agents](agents.md). 0 is healthy; anything else waits for an operator. |
| `vectispire_outbox_pending` | | Notifications accepted but not yet delivered. |

### The scans

| Metric | Labels | What it says |
|---|---|---|
| `vectispire_scans_started_total` | `kind`, `executor` (`embedded`, `agent`) | Attempts handed to an executor: the built-in worker starting one, or an agent receiving its task. A scan retried three times counts three. |
| `vectispire_scans_completed_total` | `kind`, `executor` | Attempts that ended with their results written. |
| `vectispire_scans_failed_total` | `kind`, `executor`, `final` (`true`, `false`) | Attempts that ended without a result. `final="true"`: the scan failed for good — permanently, or its attempts are spent. `final="false"`: it went back to the queue, or another worker had taken it over. |
| `vectispire_scans_lapsed_total` | `final` | Scans whose executor stopped reporting until the lease lapsed, reclaimed by the control plane: back in the queue, or failed for good. No executor reports these, so nothing else counts them. |
| `vectispire_scans_duration_seconds` | `kind`, `executor`, `outcome` (`completed`, `failed`) | Wall-clock time from the claim to the result (count, sum and max). |

Every counter exists at 0 from the start, so a `rate()` alert fires on the first failure rather than on the
second. An attempt claimed for an agent that hung up before receiving it is counted in
`vectispire_agents_claims_total{outcome="undelivered"}`, not here.

### The agents

| Metric | Labels | What it says |
|---|---|---|
| `vectispire_agents_enabled` | | Agents an administrator has enabled. |
| `vectispire_agents_online` | | Enabled agents heard from within the last two minutes — the **Agents** screen's rule. |
| `vectispire_agents_last_seen_age_seconds` | | How long the least recently seen enabled agent has been silent — since its creation if it never polled; 0 when none is enabled. One agent that stopped is the case to alert on, and an average would hide it. |
| `vectispire_agents_polls_total` | `outcome` (`job`, `idle`) | Long polls answered with a task, or with nothing. |
| `vectispire_agents_claims_total` | `outcome` (`delivered`, `undelivered`, `withheld`) | What became of a scan claimed for an agent: delivered; claimed after the agent hung up and put straight back (a proxy cutting the long poll short, when it climbs); or refused with a 412 because the agent holds no verified key for the credential it would need. |

### How fresh the figures are

The gauges that count rows — the queue, the running scans, the outbox, the agents — **do not query the
database at the scrape.** They report what the control plane's scheduling tick counted, once a minute
(`vectispire.jobs.scheduler-interval`), and a scrape reads that without a connection: a scrape that needed
one would wait on the pool exactly when the pool is exhausted, and the series would vanish during the
incident they exist for. The ages are computed at the scrape, so the oldest waiting scan keeps ageing
between two ticks.

| Metric | Labels | What it says |
|---|---|---|
| `vectispire_metrics_snapshot_age_seconds` | `source` (`scans`, `agents`) | How old those figures are. It stays under a minute and a half; growing, the tick has stopped, and the figures above are the last it read. |

Before the first tick, half a minute after start, those gauges read `NaN`: not measured yet.

### What Spring Boot adds

`jvm_*` (memory, garbage collection, threads, classes), `process_*` and `system_*`, `hikaricp_*` (the
database connection pool: `hikaricp_connections_pending` above zero means requests are waiting for a
connection — see [Sizing](sizing.md)), `http_server_requests_seconds` (by route template, method and
status), and `application_ready_time_seconds`.

## Suggested alerts

```yaml
groups:
  - name: vectispire
    rules:
      - alert: VectispireQueueStuck
        expr: max by (instance) (vectispire_scans_queued_oldest_age_seconds) > 3600
        for: 15m
      - alert: VectispireAgentSilent
        expr: vectispire_agents_last_seen_age_seconds > 600
        for: 5m
      - alert: VectispireScansFailingForGood
        expr: sum(rate(vectispire_scans_failed_total{final="true"}[1h])) > 0
      - alert: VectispireCredentialUnserved
        expr: vectispire_scans_credential_unserved > 0
        for: 30m
      - alert: VectispireMetricsStale
        expr: vectispire_metrics_snapshot_age_seconds > 300
```
