package com.asmolabs.vectispire.core.compliance.persistence;

import java.time.Instant;

/**
 * The weekly OWASP record summed over a reader's targets: per week, category and recorded state, how
 * many targets read that state and what they counted.
 *
 * @param capturedAt the newest capture among these rows — a week is captured whole, so this is the
 *     week's capture as far as these targets go
 */
public record OwaspWeeklyStateCount(
        Instant weekStart, String category, String state, long targets, long open, long settled, Instant capturedAt) {}
