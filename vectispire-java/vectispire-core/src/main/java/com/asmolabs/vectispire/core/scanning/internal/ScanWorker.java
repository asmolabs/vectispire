package com.asmolabs.vectispire.core.scanning.internal;

import com.asmolabs.vectispire.common.domain.agents.AgentLabels;
import com.asmolabs.vectispire.core.scanning.ScanDispatcher;
import com.asmolabs.vectispire.core.scanning.WorkerProperties;
import jakarta.annotation.PreDestroy;
import java.net.InetAddress;
import java.net.UnknownHostException;
import java.util.List;
import java.util.UUID;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.RejectedExecutionException;
import java.util.concurrent.atomic.AtomicBoolean;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.scheduling.annotation.Scheduled;
import org.springframework.stereotype.Component;

/**
 * The built-in worker: it runs inside Vectispire's process and drains the queue.
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

    /**
     * This worker's own thread, and not a bean.
     *
     * <p>Declaring an {@code Executor} bean would switch off Spring Boot's
     * {@code applicationTaskExecutor}, which the MVC layer uses for asynchronous requests — a
     * side effect nobody would connect to this class. One thread, because a round is already
     * sequential on purpose: {@code ScanDispatcher} decides how much fits before it starts, and
     * running five scans at once on a machine that supports one makes five time out instead of
     * one succeeding.
     */
    private final ExecutorService rounds = Executors.newSingleThreadExecutor(runnable -> {
        Thread thread = new Thread(runnable, "vectispire-scan-worker");
        thread.setDaemon(true);
        return thread;
    });

    private final ScanDispatcher dispatcher;
    private final WorkerProperties properties;

    public ScanWorker(ScanDispatcher dispatcher, WorkerProperties properties) {
        this.dispatcher = dispatcher;
        this.properties = properties;
    }

    /**
     * <b>Submits the round; it does not run it.</b>
     *
     * <p>A round executes the scans it claims, in this process, one after another — a clone and
     * four containers each, so minutes rather than milliseconds. It used to do that on the
     * thread that invoked it, which is the scheduler's: for the length of a scan the outbox
     * relayed nothing, the scan scheduler created nothing, and — through the same shared
     * scheduler — no remote agent's long poll was answered. A machine running its own worker
     * stopped serving its fleet.
     *
     * <p>So the tick hands the round to {@link #rounds} and returns immediately. What the
     * {@code busy} guard means is unchanged, only where it is released: one round at a time,
     * whatever the tick's period.
     */
    @Scheduled(
            fixedDelayString = "${vectispire.worker.interval:15s}",
            initialDelayString = "${vectispire.worker.initial-delay:15s}")
    public void tick() {
        if (!properties.enabled() || !busy.compareAndSet(false, true)) {
            return;
        }
        try {
            rounds.execute(this::round);
        } catch (RejectedExecutionException stopping) {
            // Shutting down. Releasing the guard here rather than in `round` — which will never
            // run — keeps the flag from being stuck true if the executor comes back.
            busy.set(false);
        }
    }

    /** One dispatch round, on this worker's own thread. */
    private void round() {
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

    /**
     * Stops accepting rounds when the application closes.
     *
     * <p>{@code shutdownNow} rather than a graceful wait: a round in flight is executing a scan
     * whose lease will expire and be reclaimed by whoever is still up, which is what
     * {@code reclaimLostLeases} exists for. Waiting minutes for it would delay every shutdown by
     * the length of a scan, and buy nothing the queue does not already handle.
     */
    @PreDestroy
    void stop() {
        rounds.shutdownNow();
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
