package com.asmolabs.vectispire.common.domain.issues;

import java.util.Optional;
import java.util.stream.Stream;

/**
 * Whether an issue is still being found.
 *
 * <p>An enum rather than a string constant per caller. The NestJS tree declared {@code
 * STATE_OPEN} in the gate and {@code STATE_RESOLVED} in the exports, in two files that never
 * meet, and every service that needed either wrote its own copy — a private {@code
 * STATE_OPEN} in one place, a literal in a query in another. The values agreed by luck.
 *
 * <p><b>Not the same axis as {@link TriageStatus}.</b> This one is the scanner's answer — is
 * it still there — and it is written by reconciliation only. Triage is the human's answer,
 * and nothing automatic may overwrite it.
 */
public enum IssueState {
    /** Found by the last scan that looked for its type. */
    OPEN("open"),

    /**
     * Not found by a scan that did look for its type.
     *
     * <p>"Looked and did not find", never "did not look" — the whole reason the set of
     * scanned types is carried explicitly through reconciliation.
     */
    RESOLVED("resolved");

    private final String wireName;

    IssueState(String wireName) {
        this.wireName = wireName;
    }

    /** The value stored in the column and served by the API. */
    public String wireName() {
        return wireName;
    }

    public static Optional<IssueState> byWireName(String value) {
        return Stream.of(values()).filter(state -> state.wireName.equals(value)).findFirst();
    }
}
