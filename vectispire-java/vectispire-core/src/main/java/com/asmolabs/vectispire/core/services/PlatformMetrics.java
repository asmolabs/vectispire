package com.asmolabs.vectispire.core.services;

import com.asmolabs.vectispire.core.repositories.Agents;
import com.asmolabs.vectispire.core.repositories.Outbox;
import com.asmolabs.vectispire.core.repositories.ScanQueue;
import io.micrometer.core.instrument.Counter;
import io.micrometer.core.instrument.Gauge;
import io.micrometer.core.instrument.MeterRegistry;
import io.micrometer.core.instrument.Tags;
import io.micrometer.core.instrument.Timer;
import jakarta.annotation.PostConstruct;
import java.time.Clock;
import java.time.Duration;
import java.time.Instant;
import java.util.List;
import java.util.concurrent.atomic.AtomicReference;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.stereotype.Service;

/**
 * What an operator can see about this control plane while it is running.
 *
 * <p><b>The audit log is not telemetry.</b> It records what people did, deliberately and
 * durably, and it is the wrong instrument for asking whether the queue is draining. Until this
 * class there was no right one: {@code /actuator} exposed only {@code health}, so the questions
 * an incident actually raises — is work piling up, are the agents connected, is the outbox
 * behind, how long does a scan take now — had no answer short of a SQL client. A defect like the
 * shared scheduler, where a local scan silently stopped the fleet being served, presents as
 * "notifications are late sometimes", which is not a lead.
 *
 * <h2>What is measured, and what deliberately is not</h2>
 *
 * <p>Six meters, each tied to a question somebody asks at three in the morning. Rate-limit
 * refusals are <em>not</em> among them: the bearer filter already writes an audit entry when its
 * ceiling is reached, and turning that into a counter means changing two filters' constructors —
 * one of which is being edited elsewhere. Worth adding once that work lands. There is no
 * per-repository or per-target tag anywhere: a control plane watching a thousand repositories
 * would turn one gauge into a thousand time series, and the cost of that lands on whoever runs
 * the monitoring rather than on whoever added the tag.
 *
 * <p><b>Gauges read the database when they are scraped.</b> Three indexed counts on a scrape
 * interval — fifteen seconds at the most aggressive — is cheaper than the cache that would avoid
 * them, and a cached gauge that lags a minute answers the wrong question during an incident.
 *
 * <h2>Getting them out of the process</h2>
 *
 * <p>Micrometer's core arrives with the actuator, so these meters exist and
 * {@code /actuator/metrics} serves them. Shipping them to Prometheus is one dependency —
 * {@code io.micrometer:micrometer-registry-prometheus}, version managed by Spring Boot's BOM —
 * and a lockfile refresh; the endpoint is then {@code /actuator/prometheus}. That is left as a
 * deployment's decision rather than taken here, because this repository locks its dependencies
 * on purpose and a scanner's own supply chain is not the place for an unasked-for addition.
 *
 * <p>Everything under {@code /actuator} except {@code health} requires authentication — see
 * {@code SecurityConfiguration}. A metrics endpoint names internal structure and volumes; it is
 * not a health probe.
 */
@Service
public class PlatformMetrics {

    private static final Logger log = LoggerFactory.getLogger(PlatformMetrics.class);

    /** One prefix, so an operator can find them all without knowing what to look for. */
    private static final String PREFIX = "vectispire.";

    private final MeterRegistry registry;
    private final ScanQueue queue;
    private final Outbox outbox;
    private final Agents agents;
    private final Clock clock;

    /**
     * The last value each gauge read, kept so a database that is briefly unreachable reports the
     * previous number rather than dropping the series.
     *
     * <p>A gauge that throws is a gauge Micrometer stops publishing, and a missing series and a
     * series reading zero look identical on a dashboard six hours later. Holding the last known
     * value keeps the line continuous and lets the {@code health} endpoint be the thing that says
     * the database is down — which is its job, and not this class's.
     */
    private final AtomicReference<Double> lastQueued = new AtomicReference<>(0.0);
    private final AtomicReference<Double> lastRunning = new AtomicReference<>(0.0);
    private final AtomicReference<Double> lastOutbox = new AtomicReference<>(0.0);
    private final AtomicReference<Double> lastAgents = new AtomicReference<>(0.0);

    public PlatformMetrics(MeterRegistry registry, ScanQueue queue, Outbox outbox, Agents agents, Clock clock) {
        this.registry = registry;
        this.queue = queue;
        this.outbox = outbox;
        this.agents = agents;
        this.clock = clock;
    }

    @PostConstruct
    void register() {
        Gauge.builder(PREFIX + "scans.queued", this, self -> self.safely(lastQueued, queue::countPending))
                .description("Scans waiting for a worker or an agent to claim them")
                .register(registry);

        Gauge.builder(PREFIX + "scans.running", this, self -> self.safely(lastRunning, queue::countRunning))
                .description("Scans claimed and not yet reported")
                .register(registry);

        Gauge.builder(PREFIX + "outbox.pending", this, self -> self.safely(lastOutbox, this::pendingMessages))
                .description("Notifications accepted but not yet delivered")
                .register(registry);

        Gauge.builder(PREFIX + "agents.enabled", this, self -> self.safely(lastAgents, this::enabledAgents))
                .description("Remote agents an operator has enabled")
                .register(registry);
    }

    /**
     * How long a scan took, and whether it ended well.
     *
     * <p>Tagged by outcome and by who ran it — the built-in worker or a remote agent — because
     * the interesting question is rarely the average: it is whether one of the two has stopped
     * finishing anything.
     *
     * <p><b>Measured from the claim, and the clock is this class's.</b> The caller passes the
     * instant the scan was claimed and nothing else: a dispatcher that had to know the time to
     * report a metric would be carrying a clock for the monitoring's benefit, and every test
     * that builds one would have to stub it. A null claim — a scan already gone by the time its
     * result arrived — records nothing rather than an invented duration.
     */
    public void scanFinishedSince(Instant claimedAt, boolean succeeded, boolean byAgent) {
        if (claimedAt == null) {
            return;
        }
        record(Duration.between(claimedAt, clock.instant()), succeeded, byAgent);
    }

    private void record(Duration took, boolean succeeded, boolean byAgent) {
        Timer.builder(PREFIX + "scans.duration")
                .description("Wall-clock time from claim to result")
                .tags(Tags.of(
                        "outcome", succeeded ? "completed" : "failed",
                        "executor", byAgent ? "agent" : "embedded"))
                .register(registry)
                .record(took);
    }

    /** An agent asked for work and was answered — with a job, or with nothing. */
    public void agentPolled(boolean gotWork) {
        Counter.builder(PREFIX + "agents.polls")
                .description("Long polls answered")
                .tag("outcome", gotWork ? "job" : "idle")
                .register(registry)
                .increment();
    }

    private double safely(AtomicReference<Double> last, java.util.function.LongSupplier read) {
        try {
            double value = read.getAsLong();
            last.set(value);
            return value;
        } catch (RuntimeException unavailable) {
            log.debug("Metric read skipped, reporting the previous value: {}", unavailable.getMessage());
            return last.get();
        }
    }

    private long pendingMessages() {
        long pending = 0;
        for (Object[] row : outbox.countByStatus()) {
            if (!"SENT".equalsIgnoreCase(String.valueOf(row[0]))) {
                pending += ((Number) row[1]).longValue();
            }
        }
        return pending;
    }

    private long enabledAgents() {
        List<?> enabled = agents.findByEnabledTrue();
        return enabled.size();
    }

}
