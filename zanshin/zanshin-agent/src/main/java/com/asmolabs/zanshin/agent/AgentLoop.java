package com.asmolabs.zanshin.agent;

import com.asmolabs.zanshin.common.scanning.ScanArtifacts;
import com.asmolabs.zanshin.common.scanning.ScanTask;
import java.time.Duration;
import java.util.Optional;
import java.util.concurrent.Executors;
import java.util.concurrent.ScheduledExecutorService;
import java.util.concurrent.ScheduledFuture;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicBoolean;
import java.util.function.Function;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * A remote agent's loop: claim, run, hand back.
 *
 * <p>Apart from the protocol and the runner for the same reason as everywhere else here: this
 * file carries <b>decisions</b> — when to give up, when to stay quiet, what to do with a lost
 * lease — and they are testable with no network and no Docker.
 */
public class AgentLoop {

    private static final Logger log = LoggerFactory.getLogger(AgentLoop.class);

    /** @param completed handed back; {@code failed} not run or not delivered; {@code abandoned} lease lost */
    public record Result(int completed, int failed, int abandoned) {

        static final Result NOTHING = new Result(0, 0, 0);
    }

    private final AgentProtocol protocol;
    private final Function<ScanTask, ScanArtifacts> execute;
    private final AgentProperties properties;
    private final ScheduledExecutorService heartbeats =
            Executors.newSingleThreadScheduledExecutor(Thread.ofVirtual().name("zanshin-heartbeat").factory());

    public AgentLoop(AgentProtocol protocol, Function<ScanTask, ScanArtifacts> execute, AgentProperties properties) {
        this.protocol = protocol;
        this.execute = execute;
        this.properties = properties;
    }

    /**
     * One turn: at most one scan.
     *
     * <p><b>One at a time, even when the control plane allows more.</b> Concurrency is decided by
     * how many agent processes an operator starts, not by this file: running three scans at once
     * on a machine that supports one would make all three time out rather than one succeed, and
     * that is the kind of setting that should be visible in a compose file rather than guessed at
     * in code.
     */
    public Result runOnce() {
        Optional<AgentProtocol.AssignedTask> claimed;
        try {
            claimed = protocol.claim(properties.claimWait());
        } catch (RuntimeException failed) {
            // A failed claim is not a lost scan: the control plane keeps the row queued, and
            // another agent — or this one next turn — will take it.
            log.warn("Could not claim: {}", failed.getMessage());
            sleep(properties.retryDelay());
            return Result.NOTHING;
        }

        if (claimed.isEmpty()) {
            return Result.NOTHING;
        }

        AgentProtocol.AssignedTask assigned = claimed.get();
        log.info("Scan {}: {}.", assigned.scanId(), describe(assigned.task()));

        AtomicBoolean lost = new AtomicBoolean();
        ScheduledFuture<?> beating = startHeartbeat(assigned.scanId(), lost);

        ScanArtifacts artifacts;
        try {
            artifacts = execute.apply(assigned.task());
        } catch (RuntimeException failed) {
            // **Nothing is handed back.** An agent posting an empty result after a failed run
            // would silently resolve the whole backlog of the types it did not look at — absent
            // versus empty, the distinction this entire system protects. The lease lapses, the
            // scan returns to the queue, and another agent takes it.
            log.warn("Scan {} abandoned: {}", assigned.scanId(), failed.getMessage());
            return new Result(0, 1, 0);
        } finally {
            beating.cancel(true);
        }

        if (lost.get()) {
            // The lease was taken over while we worked. Handing the result back would overwrite
            // the successor's, which is more recent than ours.
            log.warn("Scan {}: lease taken over during execution, result discarded.", assigned.scanId());
            return new Result(0, 0, 1);
        }

        try {
            if (protocol.submit(assigned.scanId(), artifacts)) {
                log.info("Scan {} submitted.", assigned.scanId());
                return new Result(1, 0, 0);
            }
            log.warn("Scan {}: result discarded, the lease was no longer ours.", assigned.scanId());
            return new Result(0, 0, 1);
        } catch (RuntimeException failed) {
            // The work is done but could not be handed back. The most frustrating case, and the
            // most honest way to treat it: retrying the upload would keep an agent busy on a
            // result whose lease is lapsing anyway.
            log.warn("Scan {}: result not delivered ({}).", assigned.scanId(), failed.getMessage());
            return new Result(0, 1, 0);
        }
    }

    /**
     * The sign of life, running alongside the execution.
     *
     * <p>It is what tells "slow" from "dead": without it a twenty-minute scan would see its lease
     * lapse and be taken over by another agent, which would redo the same work while the first
     * one finishes it.
     */
    private ScheduledFuture<?> startHeartbeat(long scanId, AtomicBoolean lost) {
        long period = properties.heartbeat().toMillis();
        return heartbeats.scheduleAtFixedRate(
                () -> {
                    try {
                        if (!protocol.heartbeat(scanId)) {
                            lost.set(true);
                        }
                    } catch (RuntimeException missed) {
                        // A missed beat is not a lost lease: the network hiccups, and the lease
                        // lasts several times the interval. Setting `lost` here would abandon a
                        // valid scan over a passing incident.
                        log.warn("Missed heartbeat for scan {}: {}", scanId, missed.getMessage());
                    }
                },
                period,
                period,
                TimeUnit.MILLISECONDS);
    }

    /** Releases the heartbeat thread. Called when the loop stops, not between turns. */
    public void close() {
        heartbeats.shutdownNow();
    }

    private static String describe(ScanTask task) {
        return switch (task.target()) {
            case ScanTask.Target.Repository repository -> repository.url() + " (" + repository.branch() + ")";
            case ScanTask.Target.Image image -> image.reference().format();
        };
    }

    private static void sleep(Duration duration) {
        try {
            Thread.sleep(duration.toMillis());
        } catch (InterruptedException interrupted) {
            Thread.currentThread().interrupt();
        }
    }
}
