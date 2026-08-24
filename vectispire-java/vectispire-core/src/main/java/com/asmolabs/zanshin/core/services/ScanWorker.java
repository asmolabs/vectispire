package com.asmolabs.zanshin.core.services;

import com.asmolabs.zanshin.common.domain.agents.AgentLabels;
import java.net.InetAddress;
import java.net.UnknownHostException;
import java.util.List;
import java.util.UUID;
import java.util.concurrent.atomic.AtomicBoolean;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.scheduling.annotation.Scheduled;
import org.springframework.stereotype.Component;

/**
 * The built-in worker: it runs inside Zanshin's process and drains the queue.
 *
 * <p><b>It has no privilege.</b> It claims exactly as a remote agent would, with the same lease
 * and the same ownership check. That is what makes adding an agent require no change here: the
 * queue does not know who serves it.
 *
 * <p><b>One turn at a time.</b> Without the guard, a slow scan would let turns stack up, all
 * claiming in parallel and overshooting the concurrency limit the previous turn had computed.
 */
@Component
public class ScanWorker {

    private static final Logger log = LoggerFactory.getLogger(ScanWorker.class);

    /**
     * This worker's identity: host name <b>and</b> a unique suffix.
     *
     * <p>The name alone would not tell two instances on the same host apart — the ordinary case
     * in a containerized deployment — and two workers sharing an identity would steal each
     * other's leases without the ownership check being able to notice.
     */
    private final String worker = hostName() + "/" + UUID.randomUUID().toString().substring(0, 8);

    private final AtomicBoolean busy = new AtomicBoolean();

    private final ScanDispatcher dispatcher;
    private final WorkerProperties properties;

    public ScanWorker(ScanDispatcher dispatcher, WorkerProperties properties) {
        this.dispatcher = dispatcher;
        this.properties = properties;
    }

    @Scheduled(
            fixedDelayString = "${zanshin.worker.interval:15s}",
            initialDelayString = "${zanshin.worker.initial-delay:15s}")
    public void tick() {
        if (!properties.enabled() || !busy.compareAndSet(false, true)) {
            return;
        }
        try {
            List<String> labels = AgentLabels.parse(properties.labels());
            ScanDispatcher.Dispatched result = dispatcher.dispatch(worker, properties.maxConcurrent(), labels);
            if (result.claimed() > 0) {
                log.info(
                        "{} scan(s) claimed — {} completed, {} failed.",
                        result.claimed(),
                        result.completed(),
                        result.failed());
            }
        } catch (RuntimeException failed) {
            // Logged and swallowed: an error here must not stop the schedule, or a passing
            // database outage would stop the queue until the next restart.
            log.error("The dispatch round failed: {}", failed.getMessage(), failed);
        } finally {
            busy.set(false);
        }
    }

    /** What this worker calls itself, for the agents screen and for {@code claimedBy}. */
    public String identity() {
        return worker;
    }

    private static String hostName() {
        try {
            return InetAddress.getLocalHost().getHostName();
        } catch (UnknownHostException unknown) {
            // A host that cannot name itself still has to produce a distinguishable identity;
            // the random suffix carries the whole burden in that case.
            return "unknown-host";
        }
    }
}
