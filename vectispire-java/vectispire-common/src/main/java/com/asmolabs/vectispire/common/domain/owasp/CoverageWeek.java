package com.asmolabs.vectispire.common.domain.owasp;

import java.time.DayOfWeek;
import java.time.Instant;
import java.time.LocalDate;
import java.time.ZoneOffset;
import java.time.temporal.TemporalAdjusters;

/**
 * The week an OWASP coverage record belongs to: the ISO week, named by its Monday at 00:00 UTC.
 *
 * <p><b>UTC and not the reader's zone.</b> The record is shared by every reader of a deployment, and
 * a week cut at each reader's midnight would put Sunday night's capture in a different week for each of
 * them. One cut, stated, is what lets two people compare the same column of a heatmap.
 */
public final class CoverageWeek {

    private CoverageWeek() {}

    /** The Monday at 00:00 UTC of the week {@code at} falls in; a Monday at midnight is its own week. */
    public static Instant startOf(Instant at) {
        return LocalDate.ofInstant(at, ZoneOffset.UTC)
                .with(TemporalAdjusters.previousOrSame(DayOfWeek.MONDAY))
                .atStartOfDay(ZoneOffset.UTC)
                .toInstant();
    }
}
