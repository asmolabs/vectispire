package com.asmolabs.vectispire.common.domain.aireview;

import java.time.Instant;
import java.util.Locale;

/**
 * Where a model review is: asked and waiting for the model, or settled one way or the other.
 *
 * <p><b>Three states since the call left the transaction.</b> The row used to be written once, after
 * the model answered, inside a transaction held open for as long as the model took — five minutes by
 * default. It is written when the review is asked for now, {@link #RUNNING}, and settled in a second
 * transaction once the model has answered or failed. A process that dies in between leaves a row
 * that says {@code running}, which is why a running row carries a deadline: past it, nothing is
 * waiting for the answer any more.
 */
public enum AiReviewStatus {
    RUNNING,
    COMPLETED,
    FAILED;

    /** What the error says of a review whose deadline passed with nobody left to settle it. */
    public static final String ABANDONED =
            "The control plane stopped before the model answered, and nothing is waiting for this report any more. "
                    + "Ask for it again.";

    private final String wireName = name().toLowerCase(Locale.ROOT);

    public String wireName() {
        return wireName;
    }

    /**
     * The state a stored row is in at {@code now}: a running review past its deadline is failed,
     * whether or not the hourly sweep has written it yet — the screen must not go on announcing a
     * report in progress for an hour over a request whose process is gone.
     */
    public static String effective(String stored, Instant deadline, Instant now) {
        return isAbandoned(stored, deadline, now) ? FAILED.wireName : stored;
    }

    /** Running, and past the deadline by which whoever asked would have settled it. */
    public static boolean isAbandoned(String stored, Instant deadline, Instant now) {
        return RUNNING.wireName.equals(stored) && deadline != null && deadline.isBefore(now);
    }
}
