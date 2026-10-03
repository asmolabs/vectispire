package com.asmolabs.vectispire.core.reportplugins.internal;

import com.asmolabs.vectispire.core.reportplugins.ReportExecutor;
import jakarta.annotation.PreDestroy;
import java.net.InetAddress;
import java.net.UnknownHostException;
import java.util.Optional;
import java.util.UUID;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.RejectedExecutionException;
import java.util.concurrent.ScheduledExecutorService;
import java.util.concurrent.ScheduledFuture;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicBoolean;
import java.util.concurrent.atomic.AtomicInteger;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.ObjectProvider;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.scheduling.annotation.Scheduled;
import org.springframework.stereotype.Component;

/**
 * The control plane's report executor at work (decision 0035 §2): a bounded pool claiming report runs from the
 * queue and carrying each out.
 *
 * <p><b>Nothing to do without an executor.</b> Where the built-in worker is switched off no {@link ReportExecutor}
 * exists, requests are refused, and this turns idle — it claims nothing it could not run, the rule the scan
 * dispatcher keeps: a claim the executor cannot honour is not made.
 *
 * <p><b>A bounded pool of its own</b> — {@code vectispire.reports.concurrency}, two by default — and not the
 * scheduler's thread: a run is a pull, a signature check and a container for up to five minutes, and the shared
 * scheduler also relays the outbox and answers the agents' polls. The tick only claims, at most what the pool has
 * room for, and hands each run over; a run still in flight keeps its slot. Not a Spring {@code Executor} bean, for
 * {@code ScanWorker}'s reason: declaring one switches off the application's own task executor.
 *
 * <p><b>Each turn first fails the runs a dead executor left</b> ({@link ReportQueue#failLapsed}) — this instance's
 * own after a restart, or a sibling's. <b>And a run carried out here is kept leased</b> while it is: renewed every
 * third of the lease, so two renewals can be lost before it lapses, on a thread of its own that the pool's long
 * runs cannot hold up — {@code ScanDispatcher}'s heartbeat for the built-in worker's scans, for the same defect: a
 * fixed lease failed as lost a run that was only slow.
 */
@Component
public class ReportWorker {

    private static final Logger log = LoggerFactory.getLogger(ReportWorker.class);

    /**
     * Host name and a unique suffix, for ScanWorker's reason: two instances on one host must not share a claim. The
     * name cut to what {@code claimed_by} holds with the suffix — a long host name must not fail every take.
     */
    private final String owner = abbreviated(hostName(), 80) + "/report-" + UUID.randomUUID().toString().substring(0, 8);

    private final Optional<ReportExecutor> executor;
    private final ReportQueue queue;
    private final ReportExecution execution;
    private final int concurrency;
    private final AtomicInteger inFlight = new AtomicInteger();
    private final AtomicBoolean ticking = new AtomicBoolean();
    private final ExecutorService pool;
    private final ScheduledExecutorService leaseKeeper = Executors.newSingleThreadScheduledExecutor(runnable -> {
        Thread thread = new Thread(runnable, "vectispire-report-lease");
        thread.setDaemon(true);
        return thread;
    });

    public ReportWorker(
            ObjectProvider<ReportExecutor> executor,
            ReportQueue queue,
            ReportExecution execution,
            @Value("${vectispire.reports.concurrency:2}") int concurrency) {
        this.executor = Optional.ofNullable(executor.getIfAvailable());
        this.queue = queue;
        this.execution = execution;
        this.concurrency = Math.max(1, concurrency);
        AtomicInteger threads = new AtomicInteger();
        this.pool = Executors.newFixedThreadPool(this.concurrency, runnable -> {
            Thread thread = new Thread(runnable, "vectispire-report-" + threads.incrementAndGet());
            thread.setDaemon(true);
            return thread;
        });
    }

    /** Claims what the pool has room for and hands each run to it; returns at once. */
    @Scheduled(
            fixedDelayString = "${vectispire.reports.interval:10s}",
            initialDelayString = "${vectispire.reports.initial-delay:15s}")
    public void tick() {
        if (executor.isEmpty() || !ticking.compareAndSet(false, true)) {
            return;
        }
        try {
            queue.failLapsed();
            while (inFlight.get() < concurrency) {
                Optional<Long> claimed = queue.claim(owner);
                if (claimed.isEmpty()) {
                    break;
                }
                inFlight.incrementAndGet();
                long runId = claimed.get();
                try {
                    pool.execute(() -> {
                        try {
                            carryOut(runId);
                        } finally {
                            inFlight.decrementAndGet();
                        }
                    });
                } catch (RejectedExecutionException stopping) {
                    // Shutting down with the run claimed: its lease lapses and the next turn, here or elsewhere,
                    // fails it as lost — which is what it is.
                    inFlight.decrementAndGet();
                    break;
                }
            }
        } catch (RuntimeException failed) {
            // Logged and swallowed: a passing database outage must not stop the schedule until the next restart.
            log.error("The report turn failed: {}", failed.getMessage(), failed);
        } finally {
            ticking.set(false);
        }
    }

    /**
     * The turn on the calling thread, run to the end of the queue: the lapsed runs failed, then every waiting run
     * claimed and carried out one after the other. What the tick does, without the pool — so that a test observes
     * the same claim and the same execution, deterministically. Returns how many runs it carried out.
     */
    public int drain() {
        if (executor.isEmpty()) {
            return 0;
        }
        queue.failLapsed();
        int carried = 0;
        for (Optional<Long> claimed = queue.claim(owner); claimed.isPresent(); claimed = queue.claim(owner)) {
            carryOut(claimed.get());
            carried++;
        }
        return carried;
    }

    /** Carries the run out, its lease renewed until it ends. */
    private void carryOut(long runId) {
        ScheduledFuture<?> heartbeat = keepLeased(runId);
        try {
            execution.execute(runId, owner);
        } finally {
            heartbeat.cancel(false);
        }
    }

    /**
     * Renews the run's lease every third of it. A renewal that fails is logged and the next one tried: the run is
     * not interrupted, and if it was failed as lost meanwhile its own write says so and records nothing.
     */
    private ScheduledFuture<?> keepLeased(long runId) {
        long period = Math.max(1_000L, queue.lease().toMillis() / 3);
        return leaseKeeper.scheduleAtFixedRate(() -> {
            try {
                if (!queue.renew(runId, owner)) {
                    log.warn("Report run {} is no longer this executor's: what it produces will not be recorded.", runId);
                }
            } catch (RuntimeException unavailable) {
                // Caught, or the scheduled executor would silently cancel every later renewal.
                log.warn("Lease renewal for report run {} failed: {}", runId, unavailable.getMessage());
            }
        }, period, period, TimeUnit.MILLISECONDS);
    }

    /** What this executor calls itself in {@code claimed_by}. */
    public String identity() {
        return owner;
    }

    /** {@code ScanWorker}'s reason: a run in flight is the lease's to recover, not the shutdown's to wait for. */
    @PreDestroy
    void stop() {
        pool.shutdownNow();
        leaseKeeper.shutdownNow();
    }

    private static String abbreviated(String name, int length) {
        return name.length() <= length ? name : name.substring(0, length);
    }

    private static String hostName() {
        try {
            return InetAddress.getLocalHost().getHostName();
        } catch (UnknownHostException unknown) {
            return "unknown-host";
        }
    }
}
