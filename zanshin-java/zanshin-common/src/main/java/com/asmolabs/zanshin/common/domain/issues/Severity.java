package com.asmolabs.zanshin.common.domain.issues;

import java.util.Arrays;
import java.util.Locale;

/**
 * Severity, declared worst first, so that {@linkplain Enum#compareTo natural order} is the
 * comparison rank.
 *
 * <p>The NestJS version kept a string array and looked up indices, which meant every
 * comparison read as {@code severityRank(a) <= severityRank(b)} — a form that hides its own
 * inversion. Ordering the enum instead makes {@link #isAtLeast} the only place the direction
 * is written down, and {@code harden} the only other place it matters.
 *
 * <p><b>{@link #UNKNOWN} ranks below {@link #LOW}, deliberately.</b> The OSV backend returns
 * it whenever an advisory carries no normalized severity; treating it as the worst case would
 * fail every build on that backend.
 */
public enum Severity {
    CRITICAL,
    HIGH,
    MEDIUM,
    LOW,
    NEGLIGIBLE,
    UNKNOWN;

    /** The lowercase form used by the API and stored in the database. */
    public String wireName() {
        return name().toLowerCase(Locale.ROOT);
    }

    /**
     * Parses a stored or submitted severity, falling back to {@link #UNKNOWN}.
     *
     * <p>Lenient because scanners invent labels: a value nobody anticipated must rank last and
     * be evaluated, not throw and abandon the whole verdict.
     */
    public static Severity of(String value) {
        if (value == null) {
            return UNKNOWN;
        }
        String normalized = value.trim().toLowerCase(Locale.ROOT);
        return Arrays.stream(values())
                .filter(severity -> severity.wireName().equals(normalized))
                .findFirst()
                .orElse(UNKNOWN);
    }

    /** Whether this severity is at least as severe as {@code threshold}. */
    public boolean isAtLeast(Severity threshold) {
        // Declared worst first, so "at least as severe" is "at most as far down the list".
        return compareTo(threshold) <= 0;
    }

    /** Whether this severity is strictly stricter as a *threshold* than {@code other}. */
    public boolean isStricterThresholdThan(Severity other) {
        // A *lower* threshold fails on more issues, so it is the stricter one. Getting this
        // backwards delivers the exact opposite of the gate-hardening feature: a pipeline free
        // to raise its own threshold to `critical` and turn everything green.
        return compareTo(other) > 0;
    }
}
