package com.asmolabs.zanshin.common.domain.notifications;

import java.time.Duration;
import java.time.Instant;
import java.util.Optional;

/**
 * The outbox's retry policy.
 *
 * <p>Exponential backoff, capped, then abandonment. Every term in that sentence is a decision:
 *
 * <ul>
 *   <li><b>Backoff</b>, because the two realistic failures are a briefly unreachable webhook
 *       and a misconfigured one. Retrying the first quickly is right; retrying the second every
 *       sixty seconds indefinitely turns a typo into permanent load.
 *   <li><b>Capped attempts</b>, because an endpoint that has refused eight times over several
 *       hours will not accept the ninth, and a queue that never drains hides — behind those
 *       messages — the ones that could still go out.
 *   <li><b>Abandoned, not deleted.</b> A message nobody will ever receive is exactly what an
 *       operator has to be able to find: it stays, with its last error.
 * </ul>
 */
public final class OutboxRetry {

    private OutboxRetry() {}

    /** Eight attempts over a widening window: about four hours in total. */
    public static final int MAX_ATTEMPTS = 8;

    public static final Duration BASE_BACKOFF = Duration.ofSeconds(60);
    public static final Duration MAX_BACKOFF = Duration.ofHours(1);

    /**
     * How many messages one pass sends.
     *
     * <p>Maintenance does other work too; a burst of two hundred webhooks would starve all of
     * it.
     */
    public static final int MAX_PER_PASS = 20;

    /** Delivered messages are kept for a few days, so "did it go out?" has an answer. */
    public static final Duration SENT_RETENTION = Duration.ofDays(7);

    /** How long an error is kept. A proxy's HTML page is not worth a kilobyte per attempt. */
    private static final int MAX_ERROR_LENGTH = 500;

    /**
     * {@code 60s, 120s, 240s…} capped at one hour.
     *
     * <p>Computed from the attempt count rather than stored, so the policy can change with no
     * migration and without rows carrying an older version's schedule.
     */
    public static Duration backoff(int attempts) {
        if (attempts <= 0) {
            return BASE_BACKOFF;
        }
        // Shifting rather than `Math.pow`: at eight attempts the exponent is small, but an
        // unbounded shift on a corrupted counter would wrap to a negative delay and retry at
        // once, forever.
        int exponent = Math.min(attempts - 1, 20);
        Duration computed = BASE_BACKOFF.multipliedBy(1L << exponent);
        return computed.compareTo(MAX_BACKOFF) > 0 ? MAX_BACKOFF : computed;
    }

    /** The outcome of a failed attempt: abandonment, or another chance at such an instant. */
    public static Optional<Instant> nextAttemptAt(int attempts, Instant now) {
        return attempts >= MAX_ATTEMPTS ? Optional.empty() : Optional.of(now.plus(backoff(attempts)));
    }

    public static boolean isAbandoned(int attempts) {
        return attempts >= MAX_ATTEMPTS;
    }

    /** The error as it will be kept: truncated. */
    public static String recordableError(Throwable error) {
        String value = error == null
                ? "unknown error"
                : error.getClass().getSimpleName() + ": " + error.getMessage();
        return value.length() <= MAX_ERROR_LENGTH ? value : value.substring(0, MAX_ERROR_LENGTH);
    }
}
