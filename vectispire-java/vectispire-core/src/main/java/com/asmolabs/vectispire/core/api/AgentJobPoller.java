package com.asmolabs.vectispire.core.api;

import com.asmolabs.vectispire.core.persistence.AgentEntity;
import com.asmolabs.vectispire.core.services.ScanDispatcher;
import java.time.Duration;
import java.time.Instant;
import java.util.Optional;
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
    private final TaskScheduler scheduler;

    public AgentJobPoller(ScanDispatcher dispatcher, TaskScheduler scheduler) {
        this.dispatcher = dispatcher;
        this.scheduler = scheduler;
    }

    /**
     * A task, or <b>204</b> when the wait ran out.
     *
     * <p>204 rather than an empty object: "is there work?" has to be readable from the status
     * code, with no body to parse.
     */
    public DeferredResult<ResponseEntity<Object>> claim(AgentEntity agent, boolean secureTransport, Duration wait) {
        Duration bounded = wait.isNegative() ? Duration.ZERO : min(wait, MAX_WAIT);
        // The container's own timeout is set past ours, so the deadline that fires is the one
        // that knows what to answer. Letting the container win produces a 503 the agent reads as
        // an outage.
        DeferredResult<ResponseEntity<Object>> result =
                new DeferredResult<>(bounded.plusSeconds(5).toMillis(), noJob());

        Optional<ScanDispatcher.AgentTask> immediate = dispatcher.claimForAgent(agent, secureTransport);
        if (immediate.isPresent() || bounded.isZero()) {
            result.setResult(immediate.<ResponseEntity<Object>>map(ResponseEntity::ok).orElseGet(AgentJobPoller::noJob));
            return result;
        }

        schedule(result, agent, secureTransport, Instant.now().plus(bounded));
        return result;
    }

    private void schedule(
            DeferredResult<ResponseEntity<Object>> result,
            AgentEntity agent,
            boolean secureTransport,
            Instant deadline) {

        scheduler.schedule(
                () -> {
                    if (result.isSetOrExpired()) {
                        return;
                    }
                    try {
                        Optional<ScanDispatcher.AgentTask> task = dispatcher.claimForAgent(agent, secureTransport);
                        if (task.isPresent()) {
                            result.setResult(ResponseEntity.ok(task.get()));
                        } else if (Instant.now().isAfter(deadline)) {
                            result.setResult(noJob());
                        } else {
                            schedule(result, agent, secureTransport, deadline);
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

    private static ResponseEntity<Object> noJob() {
        return ResponseEntity.status(HttpStatus.NO_CONTENT).build();
    }

    private static Duration min(Duration left, Duration right) {
        return left.compareTo(right) <= 0 ? left : right;
    }
}
