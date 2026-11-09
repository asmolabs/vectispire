package com.asmolabs.vectispire.common.domain.scheduling;

import static org.assertj.core.api.Assertions.assertThat;

import com.asmolabs.vectispire.common.domain.targets.ScanTarget;
import java.time.Duration;
import java.time.Instant;
import java.util.ArrayList;
import java.util.List;
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

    private static final ScanTarget REPO = new ScanTarget.Repository(1);
    private static final Duration WEEK = Duration.ofDays(7);

    private static Schedules.Schedulable target(boolean manualOnly, Optional<CronSchedule> cron, Duration interval, Instant last) {
        return new Schedules.Schedulable(REPO, manualOnly, cron, interval, last);
    }

    @Nested
    @DisplayName("choosing what is in force")
    class Precedence {

        @Test
        @DisplayName("the cron expression wins over the interval")
        void cronWins() {
            // An interval cannot say "every night at two": it drifts, and a scan set for the
            // quiet hours ends up in the middle of the day.
            Schedules.Schedulable target = target(
                    false, Optional.of(NIGHTLY_AT_TWO), Duration.ofMinutes(1), Instant.parse("2026-08-13T02:00:00Z"));

            assertThat(target.mode()).isEqualTo(Schedules.Mode.CRON);
            assertThat(Schedules.isDue(target, WEEK, NOW)).isFalse();
        }

        @Test
        @DisplayName("falls back to the interval when the expression is cleared")
        void fallsBackToInterval() {
            Schedules.Schedulable target = target(false, Optional.empty(), Duration.ofHours(1), minutesAgo(90));

            assertThat(target.mode()).isEqualTo(Schedules.Mode.INTERVAL);
            assertThat(Schedules.isDue(target, WEEK, NOW)).isTrue();
        }

        @Test
        @DisplayName("a target's own interval wins over the default, counted from its last round as before")
        void ownIntervalWinsOverTheDefault() {
            // Due by the default's slot (never picked up) would say yes; a day counted from an hour ago says no.
            Schedules.Schedulable target = target(false, Optional.empty(), Duration.ofDays(1), minutesAgo(60));

            assertThat(Schedules.isDue(target, Duration.ofMinutes(1), NOW)).isFalse();
            assertThat(Schedules.isDue(target(false, Optional.empty(), Duration.ofDays(1), minutesAgo(1440)),
                    Duration.ofDays(30), NOW)).isTrue();
        }

        @Test
        @DisplayName("a broken expression does not fall back to the interval, nor to the default")
        void brokenCronDoesNotFallBack() {
            // "No cron" and "a cron that cannot be read" are different states, and only the
            // first one means "run on the interval". A target asking for 2 am must not quietly
            // start running every minute instead.
            assertThat(Schedules.isDue(target(false, Optional.of(CronSchedule.NEVER), Duration.ofMinutes(1), minutesAgo(90)),
                    WEEK, NOW)).isFalse();
            assertThat(Schedules.isDue(target(false, Optional.of(CronSchedule.NEVER), Duration.ZERO, null), WEEK, NOW))
                    .isFalse();
        }

        @Test
        @DisplayName("neither an interval nor an expression is the default, and a zero interval is no interval")
        void nothingIsTheDefault() {
            Schedules.Schedulable unset = target(false, Optional.empty(), Duration.ZERO, null);

            assertThat(unset.mode()).isEqualTo(Schedules.Mode.DEFAULT);
            assertThat(target(false, Optional.empty(), null, null).mode()).isEqualTo(Schedules.Mode.DEFAULT);
            assertThat(target(false, Optional.empty(), Duration.ofMinutes(-5), null).mode()).isEqualTo(Schedules.Mode.DEFAULT);
            // Never picked up and under a default: due now, like a new target on an interval.
            assertThat(Schedules.isDue(unset, WEEK, NOW)).isTrue();
        }

        @Test
        @DisplayName("a default of zero leaves a target with no schedule unscheduled, as before 0.11.0")
        void noDefault() {
            assertThat(Schedules.isDue(target(false, Optional.empty(), Duration.ZERO, null), Duration.ZERO, NOW)).isFalse();
            assertThat(Schedules.isDue(target(false, Optional.empty(), Duration.ZERO, minutesAgo(100_000)), Duration.ZERO, NOW))
                    .isFalse();
        }

        @Test
        @DisplayName("manual only wins over everything the row carries, the default included")
        void manualOnlyWins() {
            assertThat(target(true, Optional.of(NIGHTLY_AT_TWO), Duration.ofMinutes(1), null).mode())
                    .isEqualTo(Schedules.Mode.MANUAL);
            assertThat(Schedules.isDue(target(true, Optional.empty(), Duration.ZERO, null), WEEK, NOW)).isFalse();
            assertThat(Schedules.isDue(target(true, Optional.empty(), Duration.ofMinutes(1), minutesAgo(90)), WEEK, NOW))
                    .isFalse();
            assertThat(Schedules.isDue(target(true, Optional.of(NIGHTLY_AT_TWO), Duration.ZERO, null), WEEK, NOW)).isFalse();
        }

        @Test
        @DisplayName("what is in force says the interval a list shows")
        void inForce() {
            assertThat(Schedules.inForce(target(false, Optional.empty(), Duration.ZERO, null), WEEK))
                    .isEqualTo(new Schedules.InForce(Schedules.Mode.DEFAULT, Optional.of(WEEK)));
            assertThat(Schedules.inForce(target(false, Optional.empty(), Duration.ZERO, null), Duration.ZERO))
                    .isEqualTo(new Schedules.InForce(Schedules.Mode.DEFAULT, Optional.empty()));
            assertThat(Schedules.inForce(target(false, Optional.empty(), Duration.ofHours(6), null), WEEK))
                    .isEqualTo(new Schedules.InForce(Schedules.Mode.INTERVAL, Optional.of(Duration.ofHours(6))));
            assertThat(Schedules.inForce(target(false, Optional.of(NIGHTLY_AT_TWO), Duration.ofHours(6), null), WEEK))
                    .isEqualTo(new Schedules.InForce(Schedules.Mode.CRON, Optional.empty()));
            assertThat(Schedules.inForce(target(true, Optional.empty(), Duration.ZERO, null), WEEK))
                    .isEqualTo(new Schedules.InForce(Schedules.Mode.MANUAL, Optional.empty()));
        }
    }

    @Nested
    @DisplayName("the default interval, spread")
    class DefaultSpread {

        /** The instant of the upgrade, as V70 stamps it on every target with no schedule. */
        private final Instant upgrade = Instant.parse("2026-10-05T09:17:23Z");

        @Test
        @DisplayName("each target's moment is its own, the same at every call, inside the interval")
        void offsetIsStableAndBounded() {
            Duration offset = Schedules.offset(new ScanTarget.Repository(42), WEEK);
            assertThat(Schedules.offset(new ScanTarget.Repository(42), WEEK)).isEqualTo(offset);
            assertThat(offset).isGreaterThanOrEqualTo(Duration.ZERO).isLessThan(WEEK);
            // The kind enters: repository 42 and image 42 do not share a moment.
            assertThat(Schedules.offset(new ScanTarget.Container(42), WEEK)).isNotEqualTo(offset);
        }

        @Test
        @DisplayName("1,000 targets stamped at the upgrade are spread over the following week, none due at the upgrade")
        void theUpgradeCrowdIsSpread() {
            int[] perHour = new int[168];
            for (int id = 1; id <= 1_000; id++) {
                ScanTarget target = id % 2 == 0 ? new ScanTarget.Repository(id / 2) : new ScanTarget.Container(id / 2 + 1);
                assertThat(Schedules.defaultDue(target, WEEK, upgrade, upgrade)).as("not due at the upgrade itself").isFalse();
                Instant first = firstDue(target, upgrade);
                assertThat(first).isAfter(upgrade).isBeforeOrEqualTo(upgrade.plus(WEEK));
                perHour[(int) Duration.between(upgrade, first).toHours()]++;
            }
            // Six per hour on average; the bound leaves room for chance and none for a crowd.
            int busiest = java.util.Arrays.stream(perHour).max().orElseThrow();
            assertThat(busiest).as("the busiest hour of the first week").isLessThanOrEqualTo(20);
            assertThat(java.util.Arrays.stream(perHour).filter(count -> count == 0).count())
                    .as("hours with no round at all").isLessThanOrEqualTo(5);
        }

        @Test
        @DisplayName("consecutive ids, an estate registered in one sitting, land apart")
        void consecutiveIdsLandApart() {
            int[] perHour = new int[168];
            for (long id = 1; id <= 1_000; id++) {
                perHour[(int) Schedules.offset(new ScanTarget.Repository(id), WEEK).toHours()]++;
            }
            assertThat(java.util.Arrays.stream(perHour).max().orElseThrow()).isLessThanOrEqualTo(20);
        }

        @Test
        @DisplayName("ticking every minute for five weeks, each target runs exactly once a week, a week apart")
        void oncePerInterval() {
            for (long id = 1; id <= 50; id++) {
                ScanTarget target = new ScanTarget.Repository(id);
                Instant last = upgrade;
                List<Instant> rounds = new ArrayList<>();
                for (Instant now = upgrade; now.isBefore(upgrade.plus(Duration.ofDays(35))); now = now.plusSeconds(60)) {
                    if (Schedules.defaultDue(target, WEEK, last, now)) {
                        rounds.add(now);
                        last = now;
                    }
                }
                assertThat(rounds).as("rounds of %s", target).hasSize(5);
                for (int round = 1; round < rounds.size(); round++) {
                    assertThat(Duration.between(rounds.get(round - 1), rounds.get(round))).isEqualTo(WEEK);
                }
            }
        }

        @Test
        @DisplayName("a late round does not shift the next one, and a missed one is caught up once")
        void lateRoundsKeepTheSlot() {
            ScanTarget target = new ScanTarget.Repository(7);
            // The exact moment, not the first minute of the walk that reached it.
            Instant slot = Schedules.latestSlot(target, WEEK, firstDue(target, upgrade));
            // The process was down at the slot and came back three hours later: due, once.
            Instant late = slot.plus(Duration.ofHours(3));
            assertThat(Schedules.defaultDue(target, WEEK, upgrade, late)).isTrue();
            assertThat(Schedules.defaultDue(target, WEEK, late, late.plusSeconds(60))).isFalse();
            // The next round is at the slot a week on, not three hours after it.
            assertThat(Schedules.defaultDue(target, WEEK, late, slot.plus(WEEK).minusSeconds(1))).isFalse();
            assertThat(Schedules.defaultDue(target, WEEK, late, slot.plus(WEEK))).isTrue();
        }

        private Instant firstDue(ScanTarget target, Instant last) {
            // The slot, read off the rule itself and not off the formula: the first minute it says "due".
            Instant now = last;
            while (!Schedules.defaultDue(target, WEEK, last, now)) {
                now = now.plusSeconds(60);
            }
            return now;
        }
    }

    @Nested
    @DisplayName("running at least once a period")
    class Cadence {

        /** Every day at 02:00, UTC, written by hand so that no parser is under test here. */
        private final CronSchedule daily = from -> {
            Instant today = from.truncatedTo(java.time.temporal.ChronoUnit.DAYS).plus(Duration.ofHours(2));
            return Optional.of(today.isAfter(from) ? today : today.plus(Duration.ofDays(1)));
        };

        /** Every hour of the first five days of each thirty-day block: often, then a long silence. */
        private final CronSchedule burst = from -> {
            Instant next = from.truncatedTo(java.time.temporal.ChronoUnit.HOURS).plus(Duration.ofHours(1));
            long day = Math.floorMod(next.getEpochSecond() / 86_400, 30);
            return Optional.of(day < 5 ? next : next.plus(Duration.ofDays(30 - day)).truncatedTo(java.time.temporal.ChronoUnit.DAYS));
        };

        @Test
        @DisplayName("a daily expression runs at least weekly, and not at least twice a day")
        void daily() {
            assertThat(Schedules.runsAtLeastEvery(Optional.of(daily), Duration.ZERO, Duration.ofDays(7), NOW)).isTrue();
            assertThat(Schedules.runsAtLeastEvery(Optional.of(daily), Duration.ZERO, Duration.ofHours(12), NOW)).isFalse();
        }

        @Test
        @DisplayName("every gap is compared, not only the next occurrence")
        void everyGap() {
            // From the start of a burst: the next occurrence is an hour away, the silence twenty-five days on.
            Instant burstStart = Instant.ofEpochSecond(86_400L * 30 * 684);
            assertThat(Schedules.runsAtLeastEvery(Optional.of(burst), Duration.ZERO, Duration.ofDays(7), burstStart))
                    .isFalse();
        }

        @Test
        @DisplayName("an interval runs as often as it says, and no schedule or a broken one never does")
        void intervalsAndNone() {
            assertThat(Schedules.runsAtLeastEvery(Optional.empty(), Duration.ofDays(1), Duration.ofDays(7), NOW)).isTrue();
            assertThat(Schedules.runsAtLeastEvery(Optional.empty(), Duration.ofDays(8), Duration.ofDays(7), NOW)).isFalse();
            assertThat(Schedules.runsAtLeastEvery(Optional.empty(), Duration.ZERO, Duration.ofDays(7), NOW)).isFalse();
            assertThat(Schedules.runsAtLeastEvery(Optional.of(CronSchedule.NEVER), Duration.ofDays(1), Duration.ofDays(7),
                    NOW)).as("a broken expression does not fall back to the interval").isFalse();
        }

        @Test
        @DisplayName("the schedule in force: the default counts, manual only and a default of zero do not")
        void inForce() {
            Schedules.Schedulable unset = target(false, Optional.empty(), Duration.ZERO, null);
            assertThat(Schedules.runsAtLeastEvery(unset, WEEK, Duration.ofDays(7), NOW)).isTrue();
            assertThat(Schedules.runsAtLeastEvery(unset, Duration.ofDays(14), Duration.ofDays(7), NOW)).isFalse();
            assertThat(Schedules.runsAtLeastEvery(unset, Duration.ZERO, Duration.ofDays(7), NOW)).isFalse();
            assertThat(Schedules.runsAtLeastEvery(target(true, Optional.empty(), Duration.ofDays(1), null), WEEK,
                    Duration.ofDays(7), NOW)).as("manual only, whatever its stale interval").isFalse();
            assertThat(Schedules.runsAtLeastEvery(target(false, Optional.empty(), Duration.ofDays(1), null), Duration.ZERO,
                    Duration.ofDays(7), NOW)).isTrue();
            assertThat(Schedules.runsAtLeastEvery(target(false, Optional.of(daily), Duration.ZERO, null), Duration.ZERO,
                    Duration.ofDays(7), NOW)).isTrue();
        }
    }
}
