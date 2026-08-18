package com.asmolabs.zanshin.common.domain.scheduling;

import static org.assertj.core.api.Assertions.assertThat;

import java.time.Duration;
import java.time.Instant;
import java.util.Optional;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Nested;
import org.junit.jupiter.api.Test;

@DisplayName("scan scheduling")
class SchedulesTest {

    private static final Instant NOW = Instant.parse("2026-08-13T10:00:00Z");

    /** Every night at 02:00 UTC, written as a schedule rather than as cron syntax. */
    private static final CronSchedule NIGHTLY_AT_TWO = from -> {
        Instant candidate = from.truncatedTo(java.time.temporal.ChronoUnit.DAYS).plus(Duration.ofHours(2));
        while (!candidate.isAfter(from)) {
            candidate = candidate.plus(Duration.ofDays(1));
        }
        return Optional.of(candidate);
    };

    private static Instant minutesAgo(long minutes) {
        return NOW.minus(Duration.ofMinutes(minutes));
    }

    @Nested
    @DisplayName("by interval")
    class ByInterval {

        @Test
        @DisplayName("a target with no interval is manual only")
        void noIntervalNeverFires() {
            assertThat(Schedules.intervalDue(null, null, NOW)).isFalse();
            assertThat(Schedules.intervalDue(Duration.ZERO, null, NOW)).isFalse();
        }

        @Test
        @DisplayName("a target never scanned is due immediately")
        void neverScannedIsDue() {
            // Otherwise switching the scheduler on leaves the target waiting a whole interval
            // — a day of silence with a daily one, which reads as a broken scheduler.
            assertThat(Schedules.intervalDue(Duration.ofDays(1), null, NOW)).isTrue();
        }

        @Test
        @DisplayName("waits for the interval to elapse")
        void waitsForTheInterval() {
            assertThat(Schedules.intervalDue(Duration.ofHours(1), minutesAgo(59), NOW)).isFalse();
            assertThat(Schedules.intervalDue(Duration.ofHours(1), minutesAgo(60), NOW)).isTrue();
        }
    }

    @Nested
    @DisplayName("by cron expression")
    class ByCron {

        @Test
        @DisplayName("a target never scanned is due")
        void neverScannedIsDue() {
            assertThat(Schedules.cronDue(NIGHTLY_AT_TWO, null, NOW)).isTrue();
        }

        @Test
        @DisplayName("catches up an occurrence a late round missed")
        void catchesUp() {
            // Computed from the last round, not from now: a restart must not skip the night.
            assertThat(Schedules.cronDue(NIGHTLY_AT_TWO, Instant.parse("2026-08-11T02:00:00Z"), NOW)).isTrue();
        }

        @Test
        @DisplayName("is not due before the next occurrence")
        void notDueYet() {
            assertThat(Schedules.cronDue(NIGHTLY_AT_TWO, Instant.parse("2026-08-13T02:00:00Z"), NOW)).isFalse();
        }

        @Test
        @DisplayName("an unusable expression fires nothing, even on a target never scanned")
        void unusableExpressionNeverFires() {
            // The order of the two checks is the whole point. Taking the "never scanned"
            // shortcut first would make the one target whose configuration is broken the only
            // one to fire unasked.
            assertThat(Schedules.cronDue(CronSchedule.NEVER, null, NOW)).isFalse();
            assertThat(Schedules.cronDue(CronSchedule.NEVER, minutesAgo(10_000), NOW)).isFalse();
        }
    }

    @Nested
    @DisplayName("choosing between the two")
    class Precedence {

        @Test
        @DisplayName("the cron expression wins over the interval")
        void cronWins() {
            // An interval cannot say "every night at two": it drifts, and a scan set for the
            // quiet hours ends up in the middle of the day.
            Schedules.Schedulable target = new Schedules.Schedulable(
                    Optional.of(NIGHTLY_AT_TWO), Duration.ofMinutes(1), Instant.parse("2026-08-13T02:00:00Z"));

            assertThat(Schedules.isDue(target, NOW)).isFalse();
        }

        @Test
        @DisplayName("falls back to the interval when the expression is cleared")
        void fallsBackToInterval() {
            Schedules.Schedulable target =
                    new Schedules.Schedulable(Optional.empty(), Duration.ofHours(1), minutesAgo(90));

            assertThat(Schedules.isDue(target, NOW)).isTrue();
        }

        @Test
        @DisplayName("a broken expression does not fall back to the interval")
        void brokenCronDoesNotFallBack() {
            // "No cron" and "a cron that cannot be read" are different states, and only the
            // first one means "run on the interval". A target asking for 2 am must not quietly
            // start running every minute instead.
            Schedules.Schedulable target = new Schedules.Schedulable(
                    Optional.of(CronSchedule.NEVER), Duration.ofMinutes(1), minutesAgo(90));

            assertThat(Schedules.isDue(target, NOW)).isFalse();
        }
    }
}
