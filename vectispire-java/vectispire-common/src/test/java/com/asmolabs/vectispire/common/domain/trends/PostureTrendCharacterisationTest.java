package com.asmolabs.vectispire.common.domain.trends;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.within;

import com.asmolabs.vectispire.common.domain.trends.PostureTrendAnalytics.DailyPosturePoint;
import com.asmolabs.vectispire.common.domain.trends.PostureTrendAnalytics.IssueObservation;
import com.asmolabs.vectispire.common.domain.trends.PostureTrendAnalytics.TargetMaturityScore;
import java.time.Instant;
import java.time.LocalDate;
import java.util.List;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Nested;
import org.junit.jupiter.api.Test;

/**
 * Every number this engine produces, pinned before it is rewritten.
 *
 * <h2>What this is for</h2>
 *
 * <p>The dashboard loads <em>every</em> issue in the estate to draw a trend, and then walks the
 * whole list again for each day in the window. That is being replaced by a window-bounded read
 * plus SQL aggregates. The replacement has to produce identical numbers, and "identical" is not
 * something a reviewer can check by reading two implementations — the arithmetic is spread over
 * a hundred lines with four different date predicates that nearly agree.
 *
 * <p>So this fixture is deliberately hostile: the same twelve observations exercise every branch
 * that the two implementations could disagree about. It is written against the behaviour as it
 * <em>is</em>, not as it arguably should be, which is the point of a characterisation test.
 *
 * <h2>Three behaviours pinned here that look like defects</h2>
 *
 * <p>They are pinned rather than fixed, because a rewrite that changes numbers on a customer's
 * dashboard while claiming to be a refactoring is the failure this test exists to prevent. Each
 * is worth deciding on separately, afterwards.
 *
 * <ol>
 *   <li><b>An issue resolved in the same instant it was first seen counts as resolved for its
 *       target, but never for the window.</b> {@code incrementResolved} runs for it;
 *       {@code totalResolvedInWindow} requires {@code resolvedAt} to be strictly after
 *       {@code firstSeen}, so it is excluded there and contributes no MTTR. A scan that finds
 *       and closes an issue in one pass is therefore invisible to the velocity figure.
 *   <li><b>A null severity is scored as LOW.</b> {@code incrementOpen} falls through to
 *       {@code low++}, so an unknown severity is penalised one point rather than being reported
 *       as unknown.
 *   <li><b>The comment on {@code netResolutionRatePercentage} does not describe the code.</b> It
 *       says {@code (resolved / (opened + 1)) * 100}; the code divides by {@code opened} and
 *       special-cases zero. The code is what is pinned.
 * </ol>
 *
 * <h2>What is deliberately not asserted</h2>
 *
 * <p>The order of two targets with the <em>same</em> security score. The scoreboard is sorted on
 * the score alone, out of a {@link java.util.HashMap}'s values, so ties resolve in whatever order
 * the map iterates — not stable across JVMs, and not something a test may pretend is defined.
 * The fixture gives every target a distinct score so the ordering assertions mean something.
 */
@DisplayName("the posture trend engine, as it behaves today")
class PostureTrendCharacterisationTest {

    /** Fixed, because a window boundary computed from a moving clock is a flaky test. */
    private static final Instant NOW = Instant.parse("2026-03-01T00:00:00Z");

    private static final int WINDOW_DAYS = 10;

    /** {@code NOW - 10 days}. Several observations sit exactly on it, on purpose. */
    private static final Instant WINDOW_START = Instant.parse("2026-02-19T00:00:00Z");

    private static PostureTrendAnalytics analytics() {
        return PostureTrendAnalytics.calculate(WINDOW_DAYS, NOW, fixture());
    }

    /**
     * Twelve observations across three targets, chosen so that every predicate in the engine
     * separates at least one of them from the rest.
     */
    private static List<IssueObservation> fixture() {
        return List.of(
                // repo-alpha: one resolved inside the window, one resolved long before it, one open.
                obs(1L, "REPOSITORY", "repo-alpha", "CRITICAL", "2026-02-20T00:00:00Z", "2026-02-22T00:00:00Z"),
                obs(1L, "REPOSITORY", "repo-alpha", "HIGH", "2026-01-05T00:00:00Z", "2026-01-10T00:00:00Z"),
                obs(1L, "REPOSITORY", "repo-alpha", "MEDIUM", "2026-02-25T00:00:00Z", null),

                // target 2 has no name, an unknown severity, an issue with no first sighting, and
                // one closed in the instant it was opened.
                obs(2L, "CONTAINER", null, null, "2026-02-10T00:00:00Z", null),
                obs(2L, "CONTAINER", null, "CRITICAL", null, "2026-02-24T00:00:00Z"),
                obs(2L, "CONTAINER", null, "LOW", "2026-02-21T00:00:00Z", "2026-02-21T00:00:00Z"),

                // repo-gamma carries the open criticals that sink its grade.
                obs(3L, "REPOSITORY", "repo-gamma", "CRITICAL", "2026-02-01T00:00:00Z", null),
                obs(3L, "REPOSITORY", "repo-gamma", "CRITICAL", "2026-02-02T00:00:00Z", null),
                obs(3L, "REPOSITORY", "repo-gamma", "HIGH", "2026-02-26T00:00:00Z", "2026-02-28T00:00:00Z"));
    }

    private static IssueObservation obs(
            Long id, String kind, String name, String severity, String firstSeen, String resolvedAt) {
        return new IssueObservation(
                id,
                kind,
                name,
                severity,
                firstSeen == null ? null : Instant.parse(firstSeen),
                resolvedAt == null ? null : Instant.parse(resolvedAt));
    }

    @Nested
    @DisplayName("the window aggregates")
    class WindowAggregates {

        @Test
        @DisplayName("echo the window they were asked for")
        void echo_the_window() {
            assertThat(analytics().windowDays()).isEqualTo(WINDOW_DAYS);
        }

        @Test
        @DisplayName("count an issue as opened when its first sighting is not before the window start")
        void count_opened_in_window() {
            // 02-20, 02-25, 02-21 and 02-26. Not 01-05 or 02-10 (before), not the one with no
            // first sighting at all.
            assertThat(analytics().totalOpenedInWindow()).isEqualTo(4);
        }

        @Test
        @DisplayName("count an issue as resolved only when it was resolved in the window and lived a while")
        void count_resolved_in_window() {
            // 02-22 and 02-28 qualify. 01-10 is before the window. The one with no first sighting
            // has no duration, and the one closed in its own instant is not *after* its sighting.
            assertThat(analytics().totalResolvedInWindow()).isEqualTo(2);
        }

        @Test
        @DisplayName("average only the durations that counted as resolved in the window")
        void average_the_window_durations() {
            // Two days each. The five-day resolution of 01-05 → 01-10 is outside and must not
            // move this number — the very thing a window filter could break.
            assertThat(analytics().overallMttrDays()).isEqualTo(2.0);
        }

        @Test
        @DisplayName("break the average down by severity, uppercased")
        void break_the_average_down_by_severity() {
            assertThat(analytics().mttrBySeverity())
                    .containsOnlyKeys("CRITICAL", "HIGH")
                    .containsEntry("CRITICAL", 2.0)
                    .containsEntry("HIGH", 2.0);
        }

        @Test
        @DisplayName("express velocity as resolved over opened, to one decimal")
        void express_velocity() {
            // 2 / 4. Note the record's own comment claims (resolved / (opened + 1)); it does not.
            assertThat(analytics().netResolutionRatePercentage()).isEqualTo(50.0, within(0.001));
        }
    }

    @Nested
    @DisplayName("the daily series")
    class DailySeries {

        @Test
        @DisplayName("carries one point per day, both ends included")
        void one_point_per_day() {
            assertThat(analytics().dailySeries())
                    .hasSize(11)
                    .first()
                    .extracting(DailyPosturePoint::date)
                    .isEqualTo(LocalDate.of(2026, 2, 19));

            assertThat(analytics().dailySeries().get(10).date()).isEqualTo(LocalDate.of(2026, 3, 1));
        }

        @Test
        @DisplayName("counts a backlog that includes issues opened long before the window")
        void backlog_includes_issues_older_than_the_window() {
            // The three still-open issues first seen on 02-10, 02-01 and 02-02. All three predate
            // the window, and dropping them is exactly how a naive window filter would go wrong.
            assertThat(dayOf(LocalDate.of(2026, 2, 19)).openBacklog()).isEqualTo(3);
        }

        @Test
        @DisplayName("excludes an issue on the day it is resolved, counting the day exclusively")
        void backlog_excludes_the_day_of_resolution() {
            // 02-22 is the day the critical was resolved: it leaves the backlog that same day.
            assertThat(dayOf(LocalDate.of(2026, 2, 22)).openBacklog()).isEqualTo(3);
            assertThat(dayOf(LocalDate.of(2026, 2, 22)).newlyResolved()).isEqualTo(1);
            assertThat(dayOf(LocalDate.of(2026, 2, 22)).rollingMttrDays()).isEqualTo(2.0);
        }

        @Test
        @DisplayName("counts a sighting on the day it happens and not the day before")
        void discovery_lands_on_its_own_day() {
            assertThat(dayOf(LocalDate.of(2026, 2, 25)).newlyDiscovered()).isEqualTo(1);
            assertThat(dayOf(LocalDate.of(2026, 2, 24)).newlyDiscovered()).isZero();
        }

        @Test
        @DisplayName("counts a resolution with no first sighting, but gives it no duration")
        void resolution_without_a_sighting_has_no_duration() {
            assertThat(dayOf(LocalDate.of(2026, 2, 24)).newlyResolved()).isEqualTo(1);
            assertThat(dayOf(LocalDate.of(2026, 2, 24)).rollingMttrDays())
                    .as("nothing to average, so no value rather than zero")
                    .isNull();
        }

        @Test
        @DisplayName("shows a same-instant open-and-close as both discovered and resolved")
        void same_instant_issue_appears_on_both_counters() {
            DailyPosturePoint day = dayOf(LocalDate.of(2026, 2, 21));
            assertThat(day.newlyDiscovered()).isEqualTo(1);
            assertThat(day.newlyResolved()).isEqualTo(1);
            assertThat(day.rollingMttrDays())
                    .as("a zero-length life is still averaged into the day, unlike into the window")
                    .isEqualTo(0.0);
        }

        @Test
        @DisplayName("ends on the backlog the estate actually carries")
        void ends_on_the_current_backlog() {
            assertThat(dayOf(LocalDate.of(2026, 3, 1)).openBacklog()).isEqualTo(4);
        }

        private DailyPosturePoint dayOf(LocalDate date) {
            return analytics().dailySeries().stream()
                    .filter(point -> point.date().equals(date))
                    .findFirst()
                    .orElseThrow(() -> new AssertionError("no point for " + date));
        }
    }

    @Nested
    @DisplayName("the target scoreboard")
    class Scoreboard {

        @Test
        @DisplayName("holds one row per target, best score first")
        void one_row_per_target_best_first() {
            assertThat(analytics().targetScoreboard())
                    .hasSize(3)
                    .extracting(TargetMaturityScore::securityScore)
                    .containsExactly(99, 97, 50);
        }

        @Test
        @DisplayName("names a target that has no name after its id")
        void unnamed_target_falls_back_to_its_id() {
            assertThat(scoreOf(2L).targetName()).isEqualTo("target-2");
        }

        @Test
        @DisplayName("scores an unknown severity as if it were low")
        void unknown_severity_is_scored_low() {
            assertThat(scoreOf(2L).openLow()).isEqualTo(1);
            assertThat(scoreOf(2L).openCritical()).isZero();
            assertThat(scoreOf(2L).securityScore()).isEqualTo(99);
            assertThat(scoreOf(2L).maturityGrade()).isEqualTo("A");
        }

        @Test
        @DisplayName("counts resolutions over all time, not over the window")
        void resolutions_are_counted_over_all_time() {
            // **The reason the window filter is not free.** repo-alpha's second issue was resolved
            // in January, seven weeks before the window opens, and it still counts here.
            assertThat(scoreOf(1L).totalResolved()).isEqualTo(2);
        }

        @Test
        @DisplayName("averages target MTTR over all time too, window or not")
        void target_mttr_is_all_time() {
            // (2 days + 5 days) / 2. The five-day one is outside the window; the window MTTR above
            // is 2.0 and this is 3.5, and both are correct for what they measure.
            assertThat(scoreOf(1L).targetMttrDays()).isEqualTo(3.5);
        }

        @Test
        @DisplayName("counts a same-instant resolution for the target, though the window ignored it")
        void same_instant_resolution_counts_for_the_target() {
            assertThat(scoreOf(2L).totalResolved()).isEqualTo(2);
            assertThat(scoreOf(2L).targetMttrDays())
                    .as("neither of the two produced a duration, so there is nothing to average")
                    .isNull();
        }

        @Test
        @DisplayName("penalises open criticals hardest, and grades on the result")
        void grades_on_the_penalty() {
            assertThat(scoreOf(3L).openCritical()).isEqualTo(2);
            assertThat(scoreOf(3L).securityScore()).isEqualTo(50);
            assertThat(scoreOf(3L).maturityGrade()).isEqualTo("C");
        }

        @Test
        @DisplayName("keeps a target's kind, because two targets may share an id")
        void keeps_the_kind() {
            assertThat(scoreOf(1L).targetKind()).isEqualTo("REPOSITORY");
            assertThat(scoreOf(2L).targetKind()).isEqualTo("CONTAINER");
        }

        private TargetMaturityScore scoreOf(long id) {
            return analytics().targetScoreboard().stream()
                    .filter(score -> score.targetId().equals(id))
                    .findFirst()
                    .orElseThrow(() -> new AssertionError("no score for target " + id));
        }
    }
}
