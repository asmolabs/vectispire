package com.asmolabs.vectispire.common.domain.scans;

import java.time.Duration;
import java.time.Instant;
import java.util.List;

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
     * @param retryDelays how long a scan whose attempt failed transiently waits before it can be
     *     claimed again: the first entry after the first attempt, the second after the second, the
     *     last for every attempt past the list. See {@link #retryDelay}
     */
    public record Policy(Duration lease, int maxAttempts, int claimAttempts, List<Duration> retryDelays) {

        /** One minute, then five, then fifteen: what the owner decided on 2026-09-28. */
        public static final List<Duration> DEFAULT_RETRY_DELAYS =
                List.of(Duration.ofMinutes(1), Duration.ofMinutes(5), Duration.ofMinutes(15));

        public static final Policy DEFAULT = new Policy(Duration.ofMinutes(20), 3, 12, DEFAULT_RETRY_DELAYS);

        /**
         * Refused at start rather than read as "no wait": a negative delay is a typing mistake in the
         * configuration, and taken literally it puts a failed scan back as due at once — the very
         * retake-in-seconds the delays exist to end.
         */
        public Policy {
            retryDelays = List.copyOf(retryDelays == null ? List.of() : retryDelays);
            for (Duration delay : retryDelays) {
                if (delay.isNegative()) {
                    throw new IllegalArgumentException("A scan retry delay cannot be negative: " + delay + ".");
                }
            }
        }

        public Policy(Duration lease, int maxAttempts, int claimAttempts) {
            this(lease, maxAttempts, claimAttempts, DEFAULT_RETRY_DELAYS);
        }
    }

    /**
     * What becomes of a scan whose attempt could not run: another attempt, not before an instant, or
     * failed for good.
     */
    public sealed interface Next {

        /** Back in the queue, claimable from {@code notBefore} on. */
        record Retry(Instant notBefore) implements Next {}

        /**
         * Failed for good.
         *
         * @param permanent failed because another attempt would meet the same refusal, not because
         *     the attempts ran out — what the sentence on the scan says
         */
        record Fail(boolean permanent) implements Next {}
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

    /**
     * What to do with a scan whose attempt {@code attempt} could not run, as its executor classified
     * the failure.
     *
     * <p><b>A permanent failure fails at once, whatever the attempt.</b> Retrying a changed host key
     * or a repository that is not there spends the scan's attempts on the same refusal, and with a
     * single agent it spent all three in as many polls — seconds — while the reason waited behind
     * them. A transient one follows the lapse's rule, the attempt counted, and waits {@link
     * #retryDelay} before it can be claimed again: without the wait, a lone agent took back at its
     * next poll the scan it had just reported, and three attempts meant to outlast a passing
     * incident were over before it passed.
     *
     * @param attempt the attempt that failed, counted from one
     * @param failedAt when it failed — the wait counts from there
     */
    public static Next afterFailure(int attempt, FailureKind kind, Instant failedAt, Policy policy) {
        if (kind == FailureKind.PERMANENT) {
            return new Next.Fail(true);
        }
        return afterLapse(attempt, policy) == Lapsed.FAIL
                ? new Next.Fail(false)
                : new Next.Retry(failedAt.plus(retryDelay(attempt, policy)));
    }

    /**
     * How long a scan waits after its attempt {@code attempt} failed: the policy's delay for that
     * attempt, the last one past the end of the list, none when the list is empty.
     *
     * <p>An attempt below one is a scan whose count was given back — a refunded claim, the repair of
     * withheld claims — and waits the first delay, as its first failure would.
     */
    public static Duration retryDelay(int attempt, Policy policy) {
        List<Duration> delays = policy.retryDelays();
        if (delays.isEmpty()) {
            return Duration.ZERO;
        }
        return delays.get(Math.min(Math.max(attempt, 1), delays.size()) - 1);
    }

    /** The lease to set at the moment of a claim. */
    public static Instant leaseUntil(Instant claimedAt, Policy policy) {
        return claimedAt.plus(policy.lease());
    }
}
