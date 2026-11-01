package com.asmolabs.vectispire.agent;

import com.asmolabs.vectispire.common.domain.agents.WorkerExecutors;
import com.asmolabs.vectispire.common.scanning.ContainerExecutor;
import java.time.Clock;
import java.time.Duration;
import java.time.Instant;
import java.util.List;
import java.util.Objects;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * What this agent's executor can run, asked of it before a claim, and told to the control plane when the answer
 * changes.
 *
 * <p><b>The control plane decides, from what this says.</b> The agent keeps polling whatever the answer: a poll
 * is its sign of life, and an agent that went quiet because its daemon did would read as offline on the screen
 * that should say why. The claim hands it only what an available executor can run — nothing, when none is.
 *
 * <p><b>Reported on a change, not on every poll.</b> The hello carries the first answer; afterwards a ping or a
 * listing every {@link #INTERVAL} at most, and a call only when the answer moved. A report that did not arrive
 * is sent again at the next probe; a control plane that has no such route (404) is not asked again, since it
 * claims for this agent as it always did.
 */
final class ExecutorWatch {

    private static final Logger log = LoggerFactory.getLogger(ExecutorWatch.class);

    /** How stale the answer may be before a claim asks again: the claim's own wait is longer. */
    static final Duration INTERVAL = Duration.ofSeconds(15);

    private final String kind;
    private final ContainerExecutor executor;
    private final Clock clock;

    private Instant probedAt;
    private WorkerExecutors current;
    private WorkerExecutors reported;
    private boolean supported = true;

    /** @param kind the executor's name as configured: {@code docker} or {@code kubernetes} */
    ExecutorWatch(String kind, ContainerExecutor executor, Clock clock) {
        this.kind = kind;
        this.executor = executor;
        this.clock = clock;
    }

    /** Probes now and remembers the answer as the one the hello carries. */
    synchronized WorkerExecutors announced() {
        current = probe();
        reported = current;
        return current;
    }

    /**
     * Before a claim: probes again once {@link #INTERVAL} has passed, and reports the answer if it changed.
     *
     * @throws AgentProtocol.UnauthorizedException when the API key itself is refused
     */
    synchronized void beforeClaim(AgentProtocol protocol) {
        Instant now = clock.instant();
        if (probedAt != null && Duration.between(probedAt, now).compareTo(INTERVAL) < 0) {
            return;
        }
        current = probe();
        if (!supported || Objects.equals(current, reported)) {
            return;
        }
        AgentProtocol.ExecutorReport outcome;
        try {
            outcome = protocol.reportExecutors(current);
        } catch (AgentProtocol.UnauthorizedException refused) {
            throw refused;
        } catch (RuntimeException unreachable) {
            log.warn("This agent's executors could not be reported ({}); tried again at the next probe.",
                    unreachable.getMessage());
            return;
        }
        switch (outcome) {
            case ACCEPTED -> {
                reported = current;
                log.info("Executors reported: {}.", describe(current));
            }
            case NOT_SUPPORTED -> {
                supported = false;
                log.info("The control plane predates executor reports: it hands this agent work whatever its "
                        + "executor says. Executors: {}.", describe(current));
            }
            case FAILED -> log.warn("The control plane did not record this agent's executors; tried again at the "
                    + "next probe.");
        }
    }

    /** One executor, the one this agent was started with. */
    private WorkerExecutors probe() {
        probedAt = clock.instant();
        String why;
        try {
            why = executor.whyUnavailable().orElse(null);
        } catch (RuntimeException failed) {
            // An unknown is not "available": the claim it would allow fails on the scan, which is what this
            // exists to stop.
            why = failed.getMessage() == null ? failed.toString() : failed.getMessage();
        }
        List<String> targets = executor.exportsImages()
                ? List.of(WorkerExecutors.Target.REPOSITORY.wireName(), WorkerExecutors.Target.CONTAINER.wireName())
                : List.of(WorkerExecutors.Target.REPOSITORY.wireName());
        // Scrubbed by `bounded`, as a failure's reason is: it is the executor's own message, shown on a screen.
        WorkerExecutors.Executor state = new WorkerExecutors.Executor(kind, why == null, targets, why);
        WorkerExecutors probed = new WorkerExecutors(List.of(state)).bounded();
        if (why != null && (current == null || !Objects.equals(current, probed))) {
            log.warn("The {} executor cannot run scans: {}", kind, why);
        }
        return probed;
    }

    private static String describe(WorkerExecutors executors) {
        return executors.executors().stream()
                .map(e -> e.kind() + (e.available() ? " available for " + String.join(", ", e.targets()) : " unavailable"))
                .reduce((left, right) -> left + "; " + right)
                .orElse("none");
    }
}
