package com.asmolabs.vectispire.agent;

import com.asmolabs.vectispire.common.domain.agents.AgentConcurrency;
import com.asmolabs.vectispire.common.domain.targets.RepositoryUrl;
import com.asmolabs.vectispire.common.scanning.ScanArtifacts;
import com.asmolabs.vectispire.common.scanning.ScanTask;
import java.time.Duration;
import java.util.Optional;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.ScheduledExecutorService;
import java.util.concurrent.ScheduledFuture;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicBoolean;
import java.util.function.Function;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * A remote agent's loop: claim, run, hand back — up to {@code max_concurrent} scans at once.
 *
 * <p>Apart from the protocol and the runner for the same reason as everywhere else here: this
 * file carries <b>decisions</b> — when to give up, when to stay quiet, what to do with a lost
 * lease, how many scans to hold — and they are testable with no network and no Docker.
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

    /**
     * One timer for every running scan's heartbeat, with as many virtual threads as scans may run.
     *
     * <p>A single thread used to do every beat in turn, which was right for one scan at a time.
     * With sixteen, one slow answer from the control plane — a beat has fifteen seconds — would
     * hold up the fifteen behind it.
     */
    private final ScheduledExecutorService heartbeats = Executors.newScheduledThreadPool(
            AgentConcurrency.MAX, Thread.ofVirtual().name("vectispire-heartbeat-", 1).factory());

    private final Slots slots;
    private final AtomicBoolean stopping = new AtomicBoolean();

    /** @param maxConcurrent the limit the hello announced; each claim's answer may change it */
    public AgentLoop(
            AgentProtocol protocol,
            Function<ScanTask, ScanArtifacts> execute,
            AgentProperties properties,
            int maxConcurrent) {
        this.protocol = protocol;
        this.execute = execute;
        this.properties = properties;
        this.slots = new Slots(maxConcurrent);
    }

    public AgentLoop(AgentProtocol protocol, Function<ScanTask, ScanArtifacts> execute, AgentProperties properties) {
        this(protocol, execute, properties, AgentConcurrency.DEFAULT);
    }

    /**
     * Claims and runs scans until {@link #stop} is called, at most {@link Slots#limit} at a time.
     *
     * <p><b>One claim in flight, never more.</b> A free slot is taken before the poll and given back
     * if the poll brings nothing, so the agent never asks for work it has no room for — and a full
     * agent does not poll at all, which keeps it off the control plane until a scan finishes. The
     * control plane enforces the same limit on its side; this half is what stops the agent from
     * holding a long poll open for an answer that can only be "no".
     *
     * <p><b>Returns once every scan it started has been handed back</b> — see {@link #stop} for why
     * shutting down waits rather than abandons. A claim answered after the stop was requested is
     * run too: the scan is this agent's from that moment, and dropping it would hold the row until
     * its lease lapsed.
     *
     * @throws AgentProtocol.UnauthorizedException when the key is refused — not a retry's to fix
     * @throws AgentProtocol.ContractMismatchException when the control plane speaks another contract
     */
    public void serve() {
        try (ExecutorService scans = Executors.newThreadPerTaskExecutor(
                Thread.ofVirtual().name("vectispire-scan-", 1).factory())) {
            while (!stopping.get()) {
                if (!acquireSlot()) {
                    break;
                }
                Optional<AgentProtocol.AssignedTask> claimed;
                try {
                    claimed = claim();
                } catch (RuntimeException fatal) {
                    slots.release();
                    throw fatal;
                }
                if (claimed.isEmpty()) {
                    slots.release();
                    continue;
                }
                AgentProtocol.AssignedTask assigned = claimed.get();
                scans.submit(() -> {
                    try {
                        run(assigned);
                    } finally {
                        slots.release();
                    }
                });
            }
            // Leaving the block waits for every scan submitted above. `close()` would interrupt
            // them if this thread were interrupted, so the flag is cleared first: an interrupt is
            // how a stop reaches a thread, and turning it into "kill the running scans" is the one
            // thing a graceful stop must not do.
            Thread.interrupted();
        }
    }

    /**
     * Asks {@link #serve} to stop claiming. Running scans are left to finish and hand back.
     *
     * <p><b>Waiting, not abandoning, and the reason is what abandoning costs.</b> The protocol has
     * no call to give a scan back, so an abandoned scan keeps its lease until it lapses — twenty
     * minutes by default — then goes back to the queue having used one of its attempts, and every
     * minute of work already done is thrown away. Waiting costs the orchestrator's grace period,
     * which is the operator's to set; if it runs out first, the process is killed and the leases
     * lapse, which is exactly what abandoning would have produced anyway.
     */
    public void stop() {
        stopping.set(true);
        slots.close();
    }

    /**
     * One turn: at most one scan, run on the calling thread.
     *
     * <p>{@link #serve} is what the agent runs; this is the same claim-run-hand-back without the
     * concurrency, for a caller that wants one answer.
     */
    public Result runOnce() {
        Optional<AgentProtocol.AssignedTask> claimed = claim();
        return claimed.map(this::run).orElse(Result.NOTHING);
    }

    private boolean acquireSlot() {
        try {
            return slots.acquire();
        } catch (InterruptedException interrupted) {
            Thread.currentThread().interrupt();
            stopping.set(true);
            return false;
        }
    }

    /**
     * Asks for a task, and takes the limit the answer carries.
     *
     * <p>A key refused or a contract mismatch is rethrown: neither is transitory, and a loop that
     * logged them as a failed claim would retry a revoked key every ten seconds for ever.
     */
    private Optional<AgentProtocol.AssignedTask> claim() {
        AgentProtocol.Claim claim;
        try {
            claim = protocol.claim(properties.claimWait());
        } catch (AgentProtocol.UnauthorizedException | AgentProtocol.ContractMismatchException fatal) {
            throw fatal;
        } catch (RuntimeException failed) {
            // A failed claim is not a lost scan: the control plane keeps the row queued, and
            // another agent — or this one next turn — will take it.
            log.warn("Could not claim: {}", failed.getMessage());
            sleep(properties.retryDelay());
            return Optional.empty();
        }
        claim.maxConcurrent().ifPresent(limit -> {
            if (limit != slots.limit()) {
                log.info("Concurrent scans: {} (was {}).", limit, slots.limit());
                slots.resize(limit);
            }
        });
        return claim.task();
    }

    /**
     * Runs one claimed scan and hands its result back.
     *
     * <p><b>Each scan reports on its own.</b> Several run at once and finish in any order; one
     * whose upload fails, or whose lease was taken over, says so for itself and costs the others
     * nothing.
     */
    private Result run(AgentProtocol.AssignedTask assigned) {
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

    /** Releases the heartbeat threads. Called when the loop stops, not between turns. */
    public void close() {
        heartbeats.shutdownNow();
    }

    private static String describe(ScanTask task) {
        return switch (task.target()) {
            case ScanTask.Target.Repository repository -> RepositoryUrl.redact(repository.url()) + " (" + repository.branch() + ")";
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
