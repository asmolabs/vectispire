package com.asmolabs.vectispire.core.agents;

import com.asmolabs.vectispire.core.agents.persistence.AgentRepository;
import io.micrometer.core.instrument.Counter;
import io.micrometer.core.instrument.Gauge;
import io.micrometer.core.instrument.MeterRegistry;
import jakarta.annotation.PostConstruct;
import java.util.concurrent.atomic.AtomicReference;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.stereotype.Service;

/**
 * The meters about agents: how many are enabled, how their long polls are answered, and how many
 * scans wait for an agent able to be handed their credential — see {@link CredentialedBacklog}.
 *
 * <p><b>Here since the agent row became this module's</b> (decision 0029). They were two of {@code
 * scanning}'s {@code PlatformMetrics}, which counted the enabled agents through the agent repository;
 * {@code agents} claims through the queue, so the queue's module cannot read the agents' table. The
 * names, descriptions and tags are the ones dashboards were written against, and did not change.
 */
@Service
public class AgentMetrics {

    private static final Logger log = LoggerFactory.getLogger(AgentMetrics.class);

    private final MeterRegistry registry;
    private final AgentRepository agents;

    /**
     * The last count read, reported while the database is briefly unreachable — for the reason
     * {@code PlatformMetrics} gives: a gauge that throws stops being published, and a missing series
     * reads like a zero six hours later.
     */
    private final AtomicReference<Double> lastEnabled = new AtomicReference<>(0.0);
    private final AtomicReference<Double> lastUnserved = new AtomicReference<>(0.0);

    private final CredentialedBacklog backlog;

    public AgentMetrics(MeterRegistry registry, AgentRepository agents, CredentialedBacklog backlog) {
        this.registry = registry;
        this.agents = agents;
        this.backlog = backlog;
    }

    @PostConstruct
    void register() {
        Gauge.builder("vectispire.agents.enabled", this, AgentMetrics::enabledAgents)
                .description("Remote agents an operator has enabled")
                .register(registry);

        // Beside the queue's gauge rather than inside it: a scan that waits for an executor able to
        // be handed its credential is queued like any other, and on a dashboard it looks like a busy
        // fleet. Zero is the healthy value; anything else waits until an operator acts.
        Gauge.builder("vectispire.scans.credential.unserved", this, AgentMetrics::unservedScans)
                .description("Waiting scans needing a credential that no executor able to be handed it can take")
                .register(registry);
    }

    /** An agent asked for work and was answered — with a job, or with nothing. */
    public void agentPolled(boolean gotWork) {
        Counter.builder("vectispire.agents.polls")
                .description("Long polls answered")
                .tag("outcome", gotWork ? "job" : "idle")
                .register(registry)
                .increment();
    }

    private double unservedScans() {
        try {
            double value = backlog.unserved().scans();
            lastUnserved.set(value);
            return value;
        } catch (RuntimeException unavailable) {
            log.debug("Metric read skipped, reporting the previous value: {}", unavailable.getMessage());
            return lastUnserved.get();
        }
    }

    private double enabledAgents() {
        try {
            double value = agents.findByEnabledTrue().size();
            lastEnabled.set(value);
            return value;
        } catch (RuntimeException unavailable) {
            log.debug("Metric read skipped, reporting the previous value: {}", unavailable.getMessage());
            return lastEnabled.get();
        }
    }
}
