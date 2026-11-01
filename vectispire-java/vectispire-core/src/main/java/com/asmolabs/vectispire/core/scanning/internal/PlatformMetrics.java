package com.asmolabs.vectispire.core.scanning.internal;

import com.asmolabs.vectispire.core.outbox.OutboxService;
import com.asmolabs.vectispire.core.scanning.persistence.ScanEntity;
import com.asmolabs.vectispire.core.scanning.persistence.WaitingScansRow;
import io.micrometer.core.instrument.Counter;
import io.micrometer.core.instrument.Gauge;
import io.micrometer.core.instrument.MeterRegistry;
import io.micrometer.core.instrument.Tags;
import io.micrometer.core.instrument.TimeGauge;
import io.micrometer.core.instrument.Timer;
import jakarta.annotation.PostConstruct;
import java.time.Clock;
import java.time.Duration;
import java.time.Instant;
import java.util.EnumMap;
import java.util.Map;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicReference;
import java.util.function.ToDoubleFunction;
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
 * <p>The queue and the scans' lives here; the agents in {@code agents}' {@code AgentMetrics}, which
 * moved with the agent row (decision 0029). Rate-limit refusals are <em>not</em> among them: the
 * bearer filter already writes an audit entry when its ceiling is reached. <b>No tag names a
 * repository, a target, a user or an agent</b> — a control plane watching a thousand repositories
 * would turn one gauge into a thousand time series, and the cost of that lands on whoever runs the
 * monitoring rather than on whoever added the tag. Every tag here takes two values, three at most.
 *
 * <h2>The gauges read a snapshot, not the database</h2>
 *
 * <p>They used to count at every scrape, on the argument that three indexed counts every fifteen
 * seconds were cheaper than a cache. With {@code /actuator/prometheus} served, a scrape is routine —
 * every Prometheus of an HA pair, every replica — and the counts run on the scraping request's thread
 * with a connection from the application's pool. That pool is exactly what is exhausted during the
 * incident the gauges exist for: the scrape then waits for a connection until the pool's timeout, the
 * scraper gives up first, and the series vanish when they are needed most. The counts now run once per
 * scheduling tick ({@code ScanMetricsTask}, a minute by default) and a scrape reads what the last one
 * found, without a query. A minute's lag is the price; {@code vectispire.metrics.snapshot.age} says
 * how old the figures are, so a tick that stopped reads as stale rather than as a quiet queue. Before
 * the first tick the gauges read NaN: not measured yet, which a zero would hide.
 *
 * <p>An age is computed at the scrape from the instant the snapshot kept, so the oldest waiting scan
 * keeps ageing between two ticks instead of standing still for a minute.
 *
 * <p>Everything under {@code /actuator} except {@code health} requires an administrator's session,
 * and {@code /actuator/prometheus} also accepts the scrape token — see {@code ActuatorAccess}. A
 * metrics endpoint names internal structure and volumes; it is not a health probe.
 */
@Service
public class PlatformMetrics {

    /** One prefix, so an operator can find them all without knowing what to look for. */
    private static final String PREFIX = "vectispire.";

    /** What was scanned — a repository or a container image. Two values, whatever the estate. */
    enum Kind {
        REPOSITORY("repository"),
        CONTAINER("container");

        private final String tag;

        Kind(String tag) {
            this.tag = tag;
        }

        static Kind of(ScanEntity scan) {
            return scan.getRepoId() != null ? REPOSITORY : CONTAINER;
        }
    }

    /** Who ran the attempt: the built-in worker of a control plane, or a remote agent. */
    public enum Executor {
        EMBEDDED("embedded"),
        AGENT("agent");

        private final String tag;

        Executor(String tag) {
            this.tag = tag;
        }
    }

    /** What the last tick read; the instant is the tick's, by this class's clock. */
    record Snapshot(Instant at, Map<Kind, WaitingScansRow> waiting, long running, long outboxPending) {}

    private final MeterRegistry registry;
    private final ScanQueue queue;
    private final OutboxService outbox;
    private final Clock clock;

    /**
     * Null until the first tick. A tick that fails leaves the previous one in place: a gauge that
     * throws is a gauge Micrometer stops publishing, and a missing series and a series reading zero
     * look identical on a dashboard six hours later. The snapshot's age is what says it is stale.
     */
    private final AtomicReference<Snapshot> snapshot = new AtomicReference<>();

    public PlatformMetrics(MeterRegistry registry, ScanQueue queue, OutboxService outbox, Clock clock) {
        this.registry = registry;
        this.queue = queue;
        this.outbox = outbox;
        this.clock = clock;
    }

    @PostConstruct
    void register() {
        for (Kind kind : Kind.values()) {
            // `queued` kept its name when it gained the tag: summed over `kind` it is the number it was.
            Gauge.builder(PREFIX + "scans.queued", this, read(s -> s.waiting().get(kind).count()))
                    .description("Scans waiting for a worker or an agent to claim them, retry delays included")
                    .tag("kind", kind.tag)
                    .register(registry);
            TimeGauge.builder(PREFIX + "scans.queued.oldest.age", this, TimeUnit.SECONDS,
                            read(s -> ageInSeconds(s.waiting().get(kind).oldestCreatedAt())))
                    .description("How long the oldest waiting scan has waited since it was queued; zero when none waits")
                    .tag("kind", kind.tag)
                    .register(registry);
        }

        Gauge.builder(PREFIX + "scans.running", this, read(Snapshot::running))
                .description("Scans claimed and not yet reported")
                .register(registry);

        Gauge.builder(PREFIX + "outbox.pending", this, read(Snapshot::outboxPending))
                .description("Notifications accepted but not yet delivered")
                .register(registry);

        TimeGauge.builder(PREFIX + "metrics.snapshot.age", this, TimeUnit.SECONDS,
                        read(s -> ageInSeconds(s.at())))
                .description("How old the figures the database gauges report are; it grows when the tick stops")
                .tag("source", "scans")
                .register(registry);

        // **Every counter's series exists from the start, at zero.** Registered at its first event, a
        // counter is absent until then, and `rate()` over an absent series is no line at all — the
        // alert on failures stays silent through the first one, which is the one it was written for.
        for (Kind kind : Kind.values()) {
            for (Executor executor : Executor.values()) {
                started(kind, executor);
                completed(kind, executor);
                failed(kind, executor, true);
                failed(kind, executor, false);
            }
        }
        lapsed(true);
        lapsed(false);
    }

    /**
     * Reads the figures the gauges report — the tick's work, never a scrape's. Throws what the
     * database throws, and the tick logs it; the previous figures stay.
     */
    public void refresh() {
        Map<Kind, WaitingScansRow> waiting = new EnumMap<>(Kind.class);
        waiting.put(Kind.REPOSITORY, queue.waitingRepositoryScans());
        waiting.put(Kind.CONTAINER, queue.waitingContainerScans());
        snapshot.set(new Snapshot(clock.instant(), waiting, queue.countRunning(), pendingMessages()));
    }

    /**
     * An attempt began on an executor: the built-in worker started running it, or an agent was
     * handed its task. Counted with the attempt, so a scan retried three times counts three.
     */
    public void scanStarted(ScanEntity scan, Executor executor) {
        started(Kind.of(scan), executor).increment();
    }

    /**
     * An attempt ended with a result written, and how long it took.
     *
     * <p><b>Measured from the claim, and the clock is this class's.</b> The caller passes the row as
     * it read it before the write, which clears the claim: a dispatcher that had to know the time to
     * report a metric would be carrying a clock for the monitoring's benefit. A null row — a scan
     * already gone by the time its result arrived — records nothing rather than an invented duration.
     */
    public void scanCompleted(ScanEntity claimed, Executor executor) {
        if (claimed == null) {
            return;
        }
        completed(Kind.of(claimed), executor).increment();
        recordDuration(claimed, executor, "completed");
    }

    /**
     * An attempt ended without a result: the executor's failure, or a result refused because another
     * worker had taken the scan over.
     *
     * @param finalFailure the scan failed for good — permanently, or its attempts are spent; false
     *     when it went back to the queue, or when it was no longer this attempt's to fail
     */
    public void scanFailed(ScanEntity claimed, Executor executor, boolean finalFailure) {
        if (claimed == null) {
            return;
        }
        failed(Kind.of(claimed), executor, finalFailure).increment();
        recordDuration(claimed, executor, "failed");
    }

    /**
     * Scans whose executor went quiet until their lease lapsed, put back by the reclaim or failed by
     * it. Not tagged by kind: the reclaim answers ids, and a lookup per row to tag a counter is what
     * this class exists not to do. Nothing else counts these: no executor reported them.
     */
    public void scansLapsed(int requeued, int failed) {
        lapsed(false).increment(requeued);
        lapsed(true).increment(failed);
    }

    private Counter lapsed(boolean finalFailure) {
        return Counter.builder(PREFIX + "scans.lapsed")
                .description("Scans whose lease lapsed, reclaimed from an executor that stopped reporting")
                .tag("final", String.valueOf(finalFailure))
                .register(registry);
    }

    private Counter started(Kind kind, Executor executor) {
        return Counter.builder(PREFIX + "scans.started")
                .description("Scan attempts handed to an executor")
                .tags(tags(kind, executor))
                .register(registry);
    }

    private Counter completed(Kind kind, Executor executor) {
        return Counter.builder(PREFIX + "scans.completed")
                .description("Scan attempts that ended with their results written")
                .tags(tags(kind, executor))
                .register(registry);
    }

    private Counter failed(Kind kind, Executor executor, boolean finalFailure) {
        return Counter.builder(PREFIX + "scans.failed")
                .description("Scan attempts that ended without a result; final when the scan will not be retried")
                .tags(tags(kind, executor).and("final", String.valueOf(finalFailure)))
                .register(registry);
    }

    /**
     * Tagged by outcome, by who ran it and by kind, because the interesting question is rarely the
     * average: it is whether one executor, or one kind of scan, has stopped finishing anything.
     */
    private void recordDuration(ScanEntity claimed, Executor executor, String outcome) {
        if (claimed.getClaimedAt() == null) {
            return;
        }
        Timer.builder(PREFIX + "scans.duration")
                .description("Wall-clock time from claim to result")
                .tags(tags(Kind.of(claimed), executor).and("outcome", outcome))
                .register(registry)
                .record(Duration.between(claimed.getClaimedAt(), clock.instant()));
    }

    private static Tags tags(Kind kind, Executor executor) {
        return Tags.of("kind", kind.tag, "executor", executor.tag);
    }

    /** A gauge's reading of the snapshot, NaN until the first tick. */
    private ToDoubleFunction<PlatformMetrics> read(ToDoubleFunction<Snapshot> figure) {
        return self -> {
            Snapshot current = self.snapshot.get();
            return current == null ? Double.NaN : figure.applyAsDouble(current);
        };
    }

    private double ageInSeconds(Instant since) {
        return since == null ? 0.0 : Math.max(0.0, Duration.between(since, clock.instant()).toMillis() / 1000.0);
    }

    /**
     * Every message not sent, abandoned ones included — through the relay's own count, not its
     * repository, which this class read until the outbox became a module and hid it (decision 0029).
     */
    private long pendingMessages() {
        long pending = 0;
        for (Map.Entry<String, Long> count : outbox.counts().entrySet()) {
            if (!"SENT".equalsIgnoreCase(String.valueOf(count.getKey()))) {
                pending += count.getValue();
            }
        }
        return pending;
    }
}
