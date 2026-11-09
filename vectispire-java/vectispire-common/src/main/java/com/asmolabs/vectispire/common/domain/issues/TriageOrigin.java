package com.asmolabs.vectispire.common.domain.issues;

import java.util.Optional;
import java.util.stream.Stream;

/**
 * What wrote an entry of an issue's triage history ({@code t_issue_triage_event.origin}).
 *
 * <p>A type rather than the private constants each writer and reader kept: the exceptions register
 * spelled {@code "review"} again beside the triage service that wrote it, and a reader that does not
 * know an origin cannot tell a decision from a fact about the issue. The origin is what separates a
 * person's decision from a deadline that passed and from a scan that saw the issue again.
 */
public enum TriageOrigin {
    /** Somebody decided. */
    MANUAL("manual"),
    /** A second person approved a decision that waited for it (four-eyes). */
    APPROVAL("approval"),
    /** A deadline passed: nobody decided, and the actor is null. */
    EXPIRY("expiry"),
    /** A periodic review of an exception, which may change nothing. */
    REVIEW("review"),
    /**
     * A resolved issue was found again and reopened — by a scan, or by an import. <b>Not a decision</b>:
     * the actor is null, the entry carries the resolution it ended ({@code previous_resolved_at}), and
     * a {@code fixed} triage the return contradicted is what it left. Without it the history showed a
     * {@code fixed} that had silently become {@code under_review}, and a reading of the past could not
     * see that the issue had been resolved in between.
     */
    REOPENING("reopen");

    private final String wireName;

    TriageOrigin(String wireName) {
        this.wireName = wireName;
    }

    /** The value stored in the column and served by the API. */
    public String wireName() {
        return wireName;
    }

    public static Optional<TriageOrigin> byWireName(String value) {
        return Stream.of(values()).filter(origin -> origin.wireName.equals(value)).findFirst();
    }
}
