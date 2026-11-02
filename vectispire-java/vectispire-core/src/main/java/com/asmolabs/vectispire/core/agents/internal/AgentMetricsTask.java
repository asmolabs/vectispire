package com.asmolabs.vectispire.core.agents.internal;

import com.asmolabs.vectispire.core.agents.AgentMetrics;
import com.asmolabs.vectispire.core.maintenance.MaintenanceTask;
import org.springframework.core.annotation.Order;
import org.springframework.stereotype.Component;

/**
 * The agents' gauges, read on the scheduler's minute so that a scrape never queries — see {@link
 * AgentMetrics}. Every instance runs it, as every task: each instance's gauges are its own.
 */
@Component
@Order(MaintenanceTask.Sequence.AGENT_METRICS)
public class AgentMetricsTask implements MaintenanceTask {

    private final AgentMetrics metrics;

    public AgentMetricsTask(AgentMetrics metrics) {
        this.metrics = metrics;
    }

    @Override
    public Cadence cadence() {
        return Cadence.SCHEDULING;
    }

    @Override
    public void run() {
        metrics.refresh();
    }
}
