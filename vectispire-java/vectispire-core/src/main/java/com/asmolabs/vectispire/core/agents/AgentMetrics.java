package com.asmolabs.vectispire.core.agents;

import com.asmolabs.vectispire.core.agents.persistence.Agents;
import io.micrometer.core.instrument.Counter;
import io.micrometer.core.instrument.Gauge;
import io.micrometer.core.instrument.MeterRegistry;
import jakarta.annotation.PostConstruct;
import java.util.concurrent.atomic.AtomicReference;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.stereotype.Service;

/**
 * The two meters about agents: how many are enabled, and how their long polls are answered.
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
    private final Agents agents;

    /**
     * The last count read, reported while the database is briefly unreachable — for the reason
     * {@code PlatformMetrics} gives: a gauge that throws stops being published, and a missing series
     * reads like a zero six hours later.
     */
    private final AtomicReference<Double> lastEnabled = new AtomicReference<>(0.0);

    public AgentMetrics(MeterRegistry registry, Agents agents) {
        this.registry = registry;
        this.agents = agents;
    }

    @PostConstruct
    void register() {
        Gauge.builder("vectispire.agents.enabled", this, AgentMetrics::enabledAgents)
                .description("Remote agents an operator has enabled")
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
