package com.asmolabs.vectispire.core.forges.internal;

import com.asmolabs.vectispire.common.domain.forges.ForgeKind;
import jakarta.annotation.PreDestroy;
import java.net.InetAddress;
import java.net.UnknownHostException;
import java.util.Optional;
import java.util.Set;
import java.util.UUID;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.RejectedExecutionException;
import java.util.concurrent.atomic.AtomicBoolean;
import java.util.concurrent.atomic.AtomicInteger;
import java.util.concurrent.atomic.AtomicReference;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.scheduling.annotation.Scheduled;
import org.springframework.stereotype.Component;

/**
 * The control plane's discoveries at work (decision 0037 §3): a bounded pool claiming waiting discoveries from the
 * table and carrying each out.
 *
 * <p><b>On every control-plane instance, whatever the built-in worker's switch.</b> A discovery is an outbound
 * listing from the control plane — never from an agent, which would need the connection's token (§6, follow-up
 * 7) — so an installation whose scans all run on agents discovers all the same. Two instances share the table: the
 * conditional take gives each run to one of them, and a run whose instance died is resumed by the next turn of
 * either ({@link DiscoveryQueue#recoverLapsed}).
 *
 * <p><b>A bounded pool of its own</b> — {@code vectispire.forges.discovery.concurrency}, two by default — and not the
 * scheduler's thread: a discovery lists for up to thirty minutes, sleeping on rate limits, and the shared scheduler
 * also relays the outbox and answers the agents' polls. Not a Spring {@code Executor} bean, for {@code ScanWorker}'s
 * reason: declaring one switches off the application's own task executor.
 *
 * <p><b>What waits on a disabled forge is said once, not every five seconds.</b> The claim passes over the runs of
 * suspended connections (decision 0040 §2); the turn logs how many wait, and on which integrations, when that changes
 * — the turn runs every few seconds, and a line per turn would bury the log for as long as a forge stays off.
 */
@Component
public class DiscoveryWorker {

    private static final Logger log = LoggerFactory.getLogger(DiscoveryWorker.class);

    /**
     * Host name and a unique suffix, for ScanWorker's reason: two instances on one host must not share a claim. The
     * name cut to what {@code claimed_by} holds with the suffix.
     */
    private final String owner = abbreviated(hostName(), 80) + "/discovery-" + UUID.randomUUID().toString().substring(0, 8);

    private final DiscoveryQueue queue;
    private final DiscoveryExecution execution;
    private final int concurrency;
    private final AtomicInteger inFlight = new AtomicInteger();
    private final AtomicBoolean ticking = new AtomicBoolean();
    private final ForgeIntegrations integrations;
    /** What the last turn found waiting on disabled forges, so that only a change is logged. */
    private final AtomicReference<String> held = new AtomicReference<>("");
    private final ExecutorService pool;

    public DiscoveryWorker(
            DiscoveryQueue queue,
            DiscoveryExecution execution,
            ForgeIntegrations integrations,
            @Value("${vectispire.forges.discovery.concurrency:2}") int concurrency) {
        this.queue = queue;
        this.execution = execution;
        this.integrations = integrations;
        this.concurrency = Math.max(1, concurrency);
        AtomicInteger threads = new AtomicInteger();
        this.pool = Executors.newFixedThreadPool(this.concurrency, runnable -> {
            Thread thread = new Thread(runnable, "vectispire-discovery-" + threads.incrementAndGet());
            thread.setDaemon(true);
            return thread;
        });
    }

    /** Recovers the lapsed runs, then claims what the pool has room for and hands each over; returns at once. */
    @Scheduled(
            fixedDelayString = "${vectispire.forges.discovery.interval:5s}",
            initialDelayString = "${vectispire.forges.discovery.initial-delay:20s}")
    public void tick() {
        if (!ticking.compareAndSet(false, true)) {
            return;
        }
        try {
            queue.recoverLapsed();
            reportHeld();
            while (inFlight.get() < concurrency) {
                Optional<Long> claimed = queue.claim(owner);
                if (claimed.isEmpty()) {
                    break;
                }
                inFlight.incrementAndGet();
                long id = claimed.get();
                try {
                    pool.execute(() -> {
                        try {
                            execution.execute(id, owner);
                        } finally {
                            inFlight.decrementAndGet();
                        }
                    });
                } catch (RejectedExecutionException stopping) {
                    // Shutting down with the run claimed: its lease lapses and the next turn, here or on another
                    // instance, resumes it.
                    inFlight.decrementAndGet();
                    break;
                }
            }
        } catch (RuntimeException failed) {
            // Logged and swallowed: a passing database outage must not stop the schedule until the next restart.
            log.error("The discovery turn failed: {}", failed.getMessage(), failed);
        } finally {
            ticking.set(false);
        }
    }

    /**
     * The turn on the calling thread, run to the end of the queue: what the tick does, without the pool — so that a
     * test observes the same claim and the same execution, deterministically. How many runs it carried out.
     */
    public int drain() {
        queue.recoverLapsed();
        reportHeld();
        int carried = 0;
        for (Optional<Long> claimed = queue.claim(owner); claimed.isPresent(); claimed = queue.claim(owner)) {
            execution.execute(claimed.get(), owner);
            carried++;
        }
        return carried;
    }

    /** Logs the runs left waiting on disabled forges, when what waits has changed since the last turn. */
    private void reportHeld() {
        Set<ForgeKind> disabled = integrations.disabled();
        long waiting = queue.waitingOn(disabled);
        String now = waiting == 0 ? "" : waiting + " on " + ForgeIntegrations.keys(disabled);
        if (!now.equals(held.getAndSet(now)) && waiting > 0) {
            log.info("Forge discoveries: {} waiting run(s) left waiting, the {} integration(s) disabled; their "
                    + "connections are suspended, and the runs resume when a governor re-enables them.", waiting,
                    ForgeIntegrations.keys(disabled));
        }
    }

    /** What this instance calls itself in {@code claimed_by}. */
    public String identity() {
        return owner;
    }

    /** A run in flight is the lease's to recover, not the shutdown's to wait for. */
    @PreDestroy
    void stop() {
        pool.shutdownNow();
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
