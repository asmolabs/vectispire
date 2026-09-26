package com.asmolabs.vectispire.core.agents.web;

import com.asmolabs.vectispire.common.domain.agents.AgentConcurrency;
import com.asmolabs.vectispire.core.access.AgentView;
import com.asmolabs.vectispire.core.agents.AgentMetrics;
import com.asmolabs.vectispire.core.scanning.ScanDispatcher;
import java.time.Duration;
import java.time.Instant;
import java.util.Optional;
import org.springframework.beans.factory.annotation.Qualifier;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.scheduling.TaskScheduler;
import org.springframework.stereotype.Component;
import org.springframework.web.context.request.async.DeferredResult;

/**
 * Long polling for the agent protocol, without holding a thread per idle agent.
 *
 * <p><b>This is the half the NestJS version did with {@code setTimeout} inside the service.</b>
 * Node can afford that; a servlet container cannot — a sleeping loop occupies a request thread
 * for the whole wait, and thirty idle agents polling for thirty seconds each is thirty threads
 * doing nothing while the interface waits for one.
 *
 * <p>Here the request is parked as a {@link DeferredResult} — the servlet thread goes back to
 * the pool immediately — and a scheduler re-checks the queue once a second until the deadline.
 * The cost is one scheduler task per waiting agent, which is a timer entry rather than a stack.
 *
 * <p>Decision 0003's reason for long polling is unchanged: an agent may sit behind a firewall
 * that allows no inbound connection, so the control plane cannot push. What changes is only who
 * pays for the wait.
 */
@Component
public class AgentJobPoller {

    /** The queue is asked again at this rate. Faster costs queries; slower makes work wait. */
    private static final Duration POLL_INTERVAL = Duration.ofSeconds(1);

    /** Unbounded waiting would hold a connection for ever, proxies included. */
    static final Duration MAX_WAIT = Duration.ofSeconds(30);

    private final ScanDispatcher dispatcher;
    private final AgentMetrics metrics;

    /**
     * <b>The agents' scheduler, not the jobs' one.</b> These two used to be the same bean, which
     * meant a long poll's re-check was queued behind whatever background job held the single
     * default thread — including a local scan, which is minutes. See {@code CoreConfiguration}.
     */
    private final TaskScheduler scheduler;

    public AgentJobPoller(
            ScanDispatcher dispatcher,
            AgentMetrics metrics,
            @Qualifier("agentPollScheduler") TaskScheduler scheduler) {
        this.dispatcher = dispatcher;
        this.metrics = metrics;
        this.scheduler = scheduler;
    }

    /**
     * A task, or <b>204</b> when the wait ran out.
     *
     * <p>204 rather than an empty object: "is there work?" has to be readable from the status
     * code, with no body to parse.
     */
    public DeferredResult<ResponseEntity<Object>> claim(AgentView agent, boolean secureTransport, Duration wait) {
        Duration bounded = wait.isNegative() ? Duration.ZERO : min(wait, MAX_WAIT);
        // The container's own timeout is set past ours, so the deadline that fires is the one
        // that knows what to answer. Letting the container win produces a 503 the agent reads as
        // an outage.
        String limit = String.valueOf(AgentConcurrency.effective(agent.maxConcurrent()));
        DeferredResult<ResponseEntity<Object>> result =
                new DeferredResult<>(bounded.plusSeconds(5).toMillis(), noJob(limit));

        Optional<ScanDispatcher.AgentTask> immediate = dispatcher.claimForAgent(agent, secureTransport);
        if (immediate.isPresent() || bounded.isZero()) {
            metrics.agentPolled(immediate.isPresent());
            result.setResult(immediate.map(task -> job(task, limit)).orElseGet(() -> noJob(limit)));
            return result;
        }

        schedule(result, agent, secureTransport, limit, Instant.now().plus(bounded));
        return result;
    }

    private void schedule(
            DeferredResult<ResponseEntity<Object>> result,
            AgentView agent,
            boolean secureTransport,
            String limit,
            Instant deadline) {

        scheduler.schedule(
                () -> {
                    if (result.isSetOrExpired()) {
                        return;
                    }
                    try {
                        Optional<ScanDispatcher.AgentTask> task = dispatcher.claimForAgent(agent, secureTransport);
                        if (task.isPresent()) {
                            metrics.agentPolled(true);
                            // **The return value is the delivery receipt.** Between the check above
                            // and this line the wait can run out or the agent hang up; the scan is
                            // then claimed by an agent that never received it, and sat there until
                            // the lease lapsed. False means nobody will read this answer — so the
                            // scan goes straight back to the queue.
                            if (!result.setResult(job(task.get(), limit))) {
                                dispatcher.returnUndelivered(task.get().scanId(), agent);
                            }
                        } else if (Instant.now().isAfter(deadline)) {
                            metrics.agentPolled(false);
                            result.setResult(noJob(limit));
                        } else {
                            schedule(result, agent, secureTransport, limit, deadline);
                        }
                    } catch (RuntimeException failed) {
                        // Handed to the error handler rather than swallowed: a refused
                        // credential transport is a 412 the agent can act on, and losing it here
                        // would turn it into a silent 204 that reads as "no work".
                        result.setErrorResult(failed);
                    }
                },
                Instant.now().plus(POLL_INTERVAL));
    }

    /**
     * Every answer names the limit this claim was held to, the 204 included — see {@link
     * AgentConcurrency#HEADER} for why the empty answer is the one that needs it most.
     */
    private static ResponseEntity<Object> job(ScanDispatcher.AgentTask task, String limit) {
        return ResponseEntity.ok().header(AgentConcurrency.HEADER, limit).body(task);
    }

    private static ResponseEntity<Object> noJob(String limit) {
        return ResponseEntity.status(HttpStatus.NO_CONTENT).header(AgentConcurrency.HEADER, limit).build();
    }

    private static Duration min(Duration left, Duration right) {
        return left.compareTo(right) <= 0 ? left : right;
    }
}
