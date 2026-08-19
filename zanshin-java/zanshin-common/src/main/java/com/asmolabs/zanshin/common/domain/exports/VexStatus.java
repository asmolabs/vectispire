package com.asmolabs.zanshin.common.domain.exports;

import com.asmolabs.zanshin.common.domain.issues.TriageStatus;

/**
 * The OpenVEX status vocabulary.
 *
 * <p>Zanshin's triage vocabulary is already OpenVEX's, with one exception:
 * {@link TriageStatus#UNDER_REVIEW} is spelled {@code under_investigation} in the
 * specification. That single divergence is the entire reason this mapping exists, and it is
 * written here rather than inside the serializer so that it cannot be half-applied.
 */
public enum VexStatus {
    NOT_AFFECTED("not_affected"),
    AFFECTED("affected"),
    FIXED("fixed"),
    UNDER_INVESTIGATION("under_investigation");

    private final String wireName;

    VexStatus(String wireName) {
        this.wireName = wireName;
    }

    public String wireName() {
        return wireName;
    }

    public static VexStatus of(TriageStatus triage) {
        if (triage == null) {
            return UNDER_INVESTIGATION;
        }
        return switch (triage) {
            case NOT_AFFECTED -> NOT_AFFECTED;
            case AFFECTED -> AFFECTED;
            case FIXED -> FIXED;
            case UNDER_REVIEW -> UNDER_INVESTIGATION;
        };
    }
}
