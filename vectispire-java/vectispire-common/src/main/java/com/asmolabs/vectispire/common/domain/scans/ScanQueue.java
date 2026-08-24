package com.asmolabs.vectispire.common.domain.scans;

import java.time.Duration;
import java.time.Instant;

/**
 * The scan queue's rules — pure, no queries.
 *
 * <p>The queue lives in the database and not in a thread pool. Three reasons, each observed: a
 * pool makes the queue <b>invisible</b> (twelve scans triggered, no way to know which will run
 * when); <b>a restart loses it</b> (the rows survive, the futures do not, and those scans stay
 * pending forever); and the concurrency limit becomes a property of the process instead of a
 * setting.
 *
 * <p>The order is creation order, with no priority. A priority column would be easy to add and
 * is deliberately missing: "in the order they were asked for" is a rule an operator can
 * predict, and the first thing a priority scheme costs is that predictability.
 */
public final class ScanQueue {

    private ScanQueue() {}

    public static final String LEASE_EXHAUSTED_MESSAGE =
            "The scan was taken over too many times without completing: its worker stops responding before the "
                    + "end. Check the agent's logs, then run the scan again.";

    /**
     * The queue's tunables, passed in rather than read from the environment at class load.
     *
     * <p>Constants initialized from the environment cannot be varied by a test, and a lease
     * duration nobody can vary in a test is a lease duration nobody checks. The application
     * binds these from configuration; the rules below never look at where they came from.
     *
     * @param lease past this, a scan is considered abandoned and becomes claimable again
     * @param maxAttempts how many takeovers before definitive failure. With no cap, a target
     *     that jams its worker every time circulates from agent to agent indefinitely,
     *     consuming the whole fleet's capacity — and the operator sees a scan forever "about to
     *     start"
     * @param claimAttempts claim attempts before giving up on a round. <b>Exists for MySQL</b>,
     *     which counts skipped rows against its {@code LIMIT}: with {@code LIMIT 1}, ten
     *     concurrent claimants against a queue of twenty scans left six empty-handed. Nothing
     *     was ever claimed twice — it was a throughput problem, whose production shape is an
     *     agent polling for thirty seconds while work waits. PostgreSQL keeps scanning until it
     *     has {@code LIMIT} unlocked rows, so the loop costs nothing where it is not needed
     */
    public record Policy(Duration lease, int maxAttempts, int claimAttempts) {

        public static final Policy DEFAULT = new Policy(Duration.ofMinutes(20), 3, 12);
    }

    /** What becomes of a scan whose lease has lapsed. */
    public enum Lapsed {
        REQUEUE,
        FAIL
    }

    /**
     * How many scans can still start.
     *
     * <p>Computed on every dispatch rather than fixed at startup: that is what makes the limit
     * changeable without restarting the application.
     */
    public static int capacity(int maxConcurrent, int running) {
        return Math.max(0, maxConcurrent - running);
    }

    /** A lease that never expires is not a lease: an absent date counts as expired. */
    public static boolean leaseHasLapsed(Instant leaseExpiresAt, Instant asOf) {
        return leaseExpiresAt == null || leaseExpiresAt.isBefore(asOf);
    }

    /**
     * What to do with a scan whose lease has lapsed.
     *
     * <p>Nothing is <em>stopped</em> here: the work may still be running elsewhere, and nothing
     * in this process can kill a thread on another machine. The row becomes claimable again,
     * and it is the ownership check that will later refuse the deposed worker's results.
     */
    public static Lapsed afterLapse(int attempts, Policy policy) {
        return attempts >= policy.maxAttempts() ? Lapsed.FAIL : Lapsed.REQUEUE;
    }

    /** The lease to set at the moment of a claim. */
    public static Instant leaseUntil(Instant claimedAt, Policy policy) {
        return claimedAt.plus(policy.lease());
    }
}
