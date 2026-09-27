package com.asmolabs.vectispire.core.agents;

import com.asmolabs.vectispire.common.domain.agents.AgentLabels;
import com.asmolabs.vectispire.core.scanning.ScanDispatcher;
import com.asmolabs.vectispire.core.scanning.WorkerProperties;
import java.util.Set;
import org.springframework.stereotype.Component;

/**
 * The built-in worker as an executor the queue can count on: whether it takes anything, and under
 * which labels.
 *
 * <p><b>One definition, because two had drifted.</b> The figure of the credentialed scans nobody can
 * take counted the worker only when it is switched on <em>and</em> this control plane has a runner;
 * the list of labels nobody serves counted its labels whatever — so a worker switched off, or one
 * without a runner (which claims nothing, whatever its configuration says), still "served" its labels,
 * and the agents screen said nothing about scans that would wait for ever. Both now ask this.
 */
@Component
class BuiltInWorker {

    private final WorkerProperties worker;
    private final ScanDispatcher dispatcher;

    BuiltInWorker(WorkerProperties worker, ScanDispatcher dispatcher) {
        this.worker = worker;
        this.dispatcher = dispatcher;
    }

    /** Switched on, and able to run a scan here: the one case in which it claims anything. */
    boolean runs() {
        return worker.enabled() && dispatcher.runsScansHere();
    }

    /** The labels it serves — none when it does not run. */
    Set<String> labels() {
        return runs() ? Set.copyOf(AgentLabels.parse(worker.labels())) : Set.of();
    }
}
