package com.asmolabs.vectispire.core.agents;

import com.asmolabs.vectispire.core.agents.persistence.AgentEntity;
import com.asmolabs.vectispire.core.agents.persistence.AgentRepository;
import io.micrometer.core.instrument.Counter;
import io.micrometer.core.instrument.Gauge;
import io.micrometer.core.instrument.MeterRegistry;
import io.micrometer.core.instrument.TimeGauge;
import jakarta.annotation.PostConstruct;
import java.time.Clock;
import java.time.Duration;
import java.time.Instant;
import java.util.List;
import java.util.Objects;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicReference;
import java.util.function.ToDoubleFunction;
import org.springframework.stereotype.Service;

/**
 * The meters about agents: how many are enabled and how many are online, how long the most silent
 * of them has been, how their long polls and claims are answered, and how many scans wait for an
 * agent able to be handed their credential — see {@link CredentialedBacklog}.
 *
 * <p><b>Here since the agent row became this module's</b> (decision 0029). They were two of {@code
 * scanning}'s {@code PlatformMetrics}, which counted the enabled agents through the agent repository;
 * {@code agents} claims through the queue, so the queue's module cannot read the agents' table. The
 * names, descriptions and tags are the ones dashboards were written against, and did not change.
 *
 * <p><b>The gauges read a snapshot the scheduling tick takes</b> ({@code AgentMetricsTask}), never
 * the database at a scrape, for the reason {@code PlatformMetrics} gives: a scrape that needs a
 * connection fails when the pool is exhausted, which is when it is needed. NaN before the first tick.
 * No tag names an agent: an estate of a hundred agents would be a hundred series per gauge, and the
 * agents screen already names them — these say whether to go and look.
 */
@Service
public class AgentMetrics {

    /** What the last tick read; the instant is the tick's. */
    record Snapshot(Instant at, int enabled, int online, Instant leastRecentlySeen, long unserved) {}

    private final MeterRegistry registry;
    private final AgentRepository agents;
    private final CredentialedBacklog backlog;
    private final Clock clock;

    /** Null until the first tick; a failed tick leaves the previous one, and its age says so. */
    private final AtomicReference<Snapshot> snapshot = new AtomicReference<>();

    public AgentMetrics(MeterRegistry registry, AgentRepository agents, CredentialedBacklog backlog, Clock clock) {
        this.registry = registry;
        this.agents = agents;
        this.backlog = backlog;
        this.clock = clock;
    }

    @PostConstruct
    void register() {
        Gauge.builder("vectispire.agents.enabled", this, read(Snapshot::enabled))
                .description("Remote agents an operator has enabled")
                .register(registry);

        Gauge.builder("vectispire.agents.online", this, read(Snapshot::online))
                .description("Enabled agents heard from within the last two minutes, as the agents screen counts them")
                .register(registry);

        // The least recently seen, not an average: one agent that stopped polling is the case to
        // alert on, and an average over a healthy fleet hides it.
        TimeGauge.builder("vectispire.agents.last.seen.age", this, TimeUnit.SECONDS,
                        read(s -> ageInSeconds(s.leastRecentlySeen())))
                .description("How long the least recently seen enabled agent has been silent — since its "
                        + "creation if it never polled; zero when none is enabled")
                .register(registry);

        // Beside the queue's gauge rather than inside it: a scan that waits for an executor able to
        // be handed its credential is queued like any other, and on a dashboard it looks like a busy
        // fleet. Zero is the healthy value; anything else waits until an operator acts.
        Gauge.builder("vectispire.scans.credential.unserved", this, read(Snapshot::unserved))
                .description("Waiting scans needing a credential that no executor able to be handed it can take")
                .register(registry);

        TimeGauge.builder("vectispire.metrics.snapshot.age", this, TimeUnit.SECONDS, read(s -> ageInSeconds(s.at())))
                .description("How old the figures the database gauges report are; it grows when the tick stops")
                .tag("source", "agents")
                .register(registry);

        // From the start, at zero, for the reason `PlatformMetrics` gives: a counter registered at its
        // first event is absent until then, and an alert on its rate silent through that event.
        polls(true);
        polls(false);
        for (Claim claim : Claim.values()) {
            claims(claim);
        }
    }

    /** Reads the figures the gauges report — the tick's work. Throws what the database throws. */
    public void refresh() {
        Instant now = clock.instant();
        List<AgentEntity> enabled = agents.findByEnabledTrue();
        int online = (int) enabled.stream()
                .filter(agent -> AgentAdministrationService.isOnline(agent, now))
                .count();
        Instant leastRecentlySeen = enabled.stream()
                .map(agent -> agent.getLastSeenAt() != null ? agent.getLastSeenAt() : agent.getCreatedAt())
                .filter(Objects::nonNull)
                .min(Instant::compareTo)
                .orElse(null);
        snapshot.set(new Snapshot(now, enabled.size(), online, leastRecentlySeen, backlog.unserved().scans()));
    }

    /** An agent asked for work and was answered — with a job, or with nothing. */
    public void agentPolled(boolean gotWork) {
        polls(gotWork).increment();
    }

    private Counter polls(boolean gotWork) {
        return Counter.builder("vectispire.agents.polls")
                .description("Long polls answered")
                .tag("outcome", gotWork ? "job" : "idle")
                .register(registry);
    }

    /** What became of a scan claimed for an agent. */
    public enum Claim {
        /** The task reached the agent's open poll. */
        DELIVERED("delivered"),
        /** The poll had ended or the agent hung up first: the scan went straight back to the queue. */
        UNDELIVERED("undelivered"),
        /** Refused with a 412: the agent holds no verified sealing key for the credential it would need. */
        WITHHELD("withheld");

        private final String tag;

        Claim(String tag) {
            this.tag = tag;
        }
    }

    /**
     * A claim's fate. Undelivered claims climbing mean polls ending before their answer — a proxy
     * timing out under the long poll; withheld ones mean an agent nobody has finished setting up.
     */
    public void agentClaimed(Claim outcome) {
        claims(outcome).increment();
    }

    private Counter claims(Claim outcome) {
        return Counter.builder("vectispire.agents.claims")
                .description("Scans claimed for an agent, by what became of the claim")
                .tag("outcome", outcome.tag)
                .register(registry);
    }

    private ToDoubleFunction<AgentMetrics> read(ToDoubleFunction<Snapshot> figure) {
        return self -> {
            Snapshot current = self.snapshot.get();
            return current == null ? Double.NaN : figure.applyAsDouble(current);
        };
    }

    private double ageInSeconds(Instant since) {
        return since == null ? 0.0 : Math.max(0.0, Duration.between(since, clock.instant()).toMillis() / 1000.0);
    }
}
