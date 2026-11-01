package com.asmolabs.vectispire.core.agents;

import com.asmolabs.vectispire.common.domain.agents.AgentLabels;
import com.asmolabs.vectispire.common.domain.agents.WorkerExecutors;
import com.asmolabs.vectispire.core.scanning.ScanDispatcher;
import com.asmolabs.vectispire.core.scanning.WorkerProperties;
import java.util.Optional;
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

    /** Switched on by configuration, whether or not this control plane has a runner. */
    boolean enabled() {
        return worker.enabled();
    }

    /**
     * What its executor said at its last round — empty before the first, and when it has no runner. Read by the
     * agents screen; the round itself is what acts on it.
     */
    Optional<ScanDispatcher.ExecutorCheck> executors() {
        return dispatcher.builtInExecutors();
    }

    /**
     * The kinds of target it can be handed now: none when it does not run, every kind before its first round has
     * asked — as for an agent that never said — and otherwise what its executor answered.
     */
    Set<WorkerExecutors.Target> claimable() {
        if (!runs()) {
            return Set.of();
        }
        return WorkerExecutors.claimable(executors().map(ScanDispatcher.ExecutorCheck::executors).orElse(null));
    }
}
