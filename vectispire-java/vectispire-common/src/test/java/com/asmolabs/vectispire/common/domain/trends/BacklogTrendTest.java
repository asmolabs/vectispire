package com.asmolabs.vectispire.common.domain.trends;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

import com.asmolabs.vectispire.common.domain.trends.BacklogTrend.Lifespan;
import com.asmolabs.vectispire.common.domain.trends.BacklogTrend.Point;
import com.asmolabs.vectispire.common.domain.trends.BacklogTrend.Series;
import java.time.Instant;
import java.time.LocalDate;
import java.util.List;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

/**
 * The backlog over time.
 *
 * <p>Every assertion here is a day boundary, because that is the only thing this calculation can
 * get wrong in a way nobody notices: a chart whose steps land a day away from the events that
 * caused them still looks like a chart.
 */
@DisplayName("the backlog over time")
class BacklogTrendTest {

    private static final LocalDate DAY_ONE = LocalDate.of(2026, 8, 1);

    @Test
    @DisplayName("an issue counts from the day it appeared until the day it was resolved")
    void countsOpenPerDay() {
        // Seen late on the 1st, resolved early on the 3rd.
        Lifespan issue = new Lifespan(at("2026-08-01T23:00:00Z"), at("2026-08-03T01:00:00Z"));

        Series series = BacklogTrend.over(List.of(issue), DAY_ONE, DAY_ONE.plusDays(3));

        assertThat(series.points()).extracting(Point::open).containsExactly(1L, 1L, 0L, 0L);
        // Open at the *end* of the day: 23:00 on the 1st counts that day, and 01:00 on the 3rd
        // means it was already gone by the time the 3rd closed.
        assertThat(series.points()).extracting(Point::opened).containsExactly(1L, 0L, 0L, 0L);
        assertThat(series.points()).extracting(Point::resolved).containsExactly(0L, 0L, 1L, 0L);
    }

    @Test
    @DisplayName("an issue still open has no resolution day and keeps counting")
    void anOpenIssueNeverLeaves() {
        Lifespan open = new Lifespan(at("2026-08-02T12:00:00Z"), null);

        Series series = BacklogTrend.over(List.of(open), DAY_ONE, DAY_ONE.plusDays(2));

        assertThat(series.points()).extracting(Point::open).containsExactly(0L, 1L, 1L);
        assertThat(series.points()).extracting(Point::resolved).containsExactly(0L, 0L, 0L);
    }

    @Test
    @DisplayName("midnight belongs to the day that starts, not the one that ends")
    void midnightIsNotAmbiguous() {
        // The boundary case, and the one a reader would notice: an event at exactly 00:00:00Z.
        Lifespan issue = new Lifespan(at("2026-08-02T00:00:00Z"), null);

        Series series = BacklogTrend.over(List.of(issue), DAY_ONE, DAY_ONE.plusDays(2));

        assertThat(series.points()).extracting(Point::opened).containsExactly(0L, 1L, 0L);
    }

    @Test
    @DisplayName("an issue older than the window is already in the backlog on the first day")
    void historyBeforeTheWindowStillCounts() {
        Lifespan old = new Lifespan(at("2020-01-01T00:00:00Z"), null);

        Series series = BacklogTrend.over(List.of(old), DAY_ONE, DAY_ONE.plusDays(1));

        // It was not *opened* in the window, and it is very much open during it. A chart that
        // started every series at zero would show a backlog appearing out of nothing.
        assertThat(series.points()).extracting(Point::open).containsExactly(1L, 1L);
        assertThat(series.points()).extracting(Point::opened).containsExactly(0L, 0L);
    }

    @Test
    @DisplayName("the mean time to resolve is absent when nothing was resolved, not zero")
    void noResolutionMeansNoMeasurement() {
        Series series = BacklogTrend.over(
                List.of(new Lifespan(at("2026-08-01T00:00:00Z"), null)), DAY_ONE, DAY_ONE.plusDays(2));

        // Zero would read as "everything is fixed the day it appears" — the opposite of "we have
        // no measurement", and precisely the confusion `None is not an empty list` exists to stop.
        assertThat(series.meanDaysToResolve()).isEmpty();
        assertThat(series.resolvedInWindow()).isZero();
    }

    @Test
    @DisplayName("the mean covers what was resolved in the window, not everything ever resolved")
    void theMeanIsWindowed() {
        List<Lifespan> issues = List.of(
                // Resolved long before the window: 100 days to fix, and irrelevant to whether the
                // team is getting faster now.
                new Lifespan(at("2025-01-01T00:00:00Z"), at("2025-04-11T00:00:00Z")),
                // Resolved inside it, in exactly two days.
                new Lifespan(at("2026-08-01T00:00:00Z"), at("2026-08-03T00:00:00Z")));

        Series series = BacklogTrend.over(issues, DAY_ONE, DAY_ONE.plusDays(5));

        assertThat(series.resolvedInWindow()).isEqualTo(1);
        assertThat(series.meanDaysToResolve()).get().satisfies(mean -> assertThat(mean).isEqualTo(2.0));
    }

    @Test
    @DisplayName("a resolution before the first sighting does not drag the mean below zero")
    void badDataIsClamped() {
        // A clock stepping back, or a row written by hand. Left negative, one such issue would pull
        // the mean under anything real and be read as an improvement.
        Series series = BacklogTrend.over(
                List.of(new Lifespan(at("2026-08-03T00:00:00Z"), at("2026-08-02T00:00:00Z"))),
                DAY_ONE,
                DAY_ONE.plusDays(5));

        assertThat(series.meanDaysToResolve()).get().satisfies(mean -> assertThat(mean).isZero());
    }

    @Test
    @DisplayName("a row with no first sighting is skipped, not dated today")
    void anUndatedRowDrawsNoSpike() {
        Series series = BacklogTrend.over(
                List.of(new Lifespan(null, null)), DAY_ONE, DAY_ONE.plusDays(1));

        assertThat(series.points()).extracting(Point::open).containsExactly(0L, 0L);
        assertThat(series.points()).extracting(Point::opened).containsExactly(0L, 0L);
    }

    @Test
    @DisplayName("the window is inclusive at both ends")
    void theWindowIsInclusive() {
        assertThat(BacklogTrend.over(List.of(), DAY_ONE, DAY_ONE).points()).hasSize(1);
        assertThat(BacklogTrend.over(List.of(), DAY_ONE, DAY_ONE.plusDays(6)).points()).hasSize(7);
    }

    @Test
    @DisplayName("a window that ends before it starts is refused rather than drawn empty")
    void aBackwardsWindowIsRefused() {
        // An empty chart is what a caller would see for an off-by-one in the request, and it reads
        // as "nothing happened".
        assertThatThrownBy(() -> BacklogTrend.over(List.of(), DAY_ONE, DAY_ONE.minusDays(1)))
                .isInstanceOf(IllegalArgumentException.class);
    }

    private static Instant at(String moment) {
        return Instant.parse(moment);
    }
}
