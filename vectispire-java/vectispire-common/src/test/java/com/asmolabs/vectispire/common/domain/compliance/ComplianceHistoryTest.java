package com.asmolabs.vectispire.common.domain.compliance;

import static org.assertj.core.api.Assertions.assertThat;

import com.asmolabs.vectispire.common.domain.compliance.ComplianceHistory.Movement;
import com.asmolabs.vectispire.common.domain.compliance.ComplianceHistory.Series;
import java.time.Instant;
import java.util.List;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

/**
 * Reading a compliance score across months.
 *
 * <h2>Every case here is about a fall that is not a regression</h2>
 *
 * <p><b>The score drops for reasons that are progress.</b> Registering a repository lowers it —
 * the new target arrives with a backlog and no history. Switching a detector on lowers it —
 * findings appear that were always there. A chart drawn without that distinction reports "we got
 * worse" over the month somebody started watching more, and a team reading it learns to watch
 * less.
 *
 * <p>So the assertions below are almost all on the attribution rather than on the arithmetic. The
 * delta is trivial to compute and impossible to get wrong; deciding what it <em>means</em> is the
 * part a chart gets wrong while looking right.
 */
@DisplayName("a compliance series")
class ComplianceHistoryTest {

    private static final ComplianceFramework ISO = ComplianceFramework.ISO_27001;

    @Test
    @DisplayName("does not read a fall as regression when the estate grew")
    void growthIsNotRegression() {
        Series series = ComplianceHistory.of(ISO, List.of(
                snapshot("2026-07", 90, 10),
                snapshot("2026-08", 71, 14)));

        ComplianceHistory.Step last = series.steps().getLast();
        assertThat(last.delta()).isEqualTo(-19);
        assertThat(last.movement())
                .as("nineteen points lost by watching four more repositories is not a regression")
                .isEqualTo(Movement.ESTATE_GREW);
        assertThat(last.because()).contains("4 target(s) more");
    }

    @Test
    @DisplayName("does not read a rise as progress when the estate shrank")
    void shrinkingIsNotProgress() {
        Series series = ComplianceHistory.of(ISO, List.of(
                snapshot("2026-07", 60, 14),
                snapshot("2026-08", 88, 9)));

        assertThat(series.steps().getLast().movement())
                .as("a score that rises by removing targets was bought, not earned")
                .isEqualTo(Movement.ESTATE_SHRANK);
    }

    @Test
    @DisplayName("names a rule change rather than attributing it to the estate")
    void settingsChangeIsNamed() {
        ComplianceSnapshot before = snapshot("2026-07", 90, 10);
        ComplianceSnapshot after = new ComplianceSnapshot(
                "2026-08", ISO, 64, ComplianceControl.Status.PARTIAL, 10, 10, 4,
                7, true, true, 4, 4, 0, Instant.EPOCH);

        ComplianceHistory.Step last = ComplianceHistory.of(ISO, List.of(before, after)).steps().getLast();

        assertThat(last.movement()).isEqualTo(Movement.RULES_CHANGED);
        assertThat(last.because())
                .as("the estate has not moved: what changed is the rule judging it")
                .contains("freshness window moved from 30 to 7");
    }

    @Test
    @DisplayName("calls the work the work, and only when nothing else moved")
    void improvementIsOnlyWhenNothingElseMoved() {
        Series series = ComplianceHistory.of(ISO, List.of(
                snapshot("2026-07", 60, 10),
                snapshot("2026-08", 78, 10)));

        ComplianceHistory.Step last = series.steps().getLast();
        assertThat(last.movement()).isEqualTo(Movement.IMPROVED);
        assertThat(last.because()).contains("This one is the work");
    }

    @Test
    @DisplayName("treats a one-point move as noise rather than a story")
    void smallMovesAreNoise() {
        Series series = ComplianceHistory.of(ISO, List.of(
                snapshot("2026-07", 74, 10),
                snapshot("2026-08", 75, 10)));

        // A single issue opened or closed moves a percentage by about as much. Annotating every
        // one of them is annotating nothing.
        assertThat(series.steps().getLast().movement()).isEqualTo(Movement.STEADY);
    }

    @Test
    @DisplayName("says the first capture has nothing to compare against")
    void firstCaptureIsNamed() {
        Series series = ComplianceHistory.of(ISO, List.of(snapshot("2026-07", 74, 10)));

        assertThat(series.steps()).singleElement().satisfies(step -> {
            assertThat(step.movement()).isEqualTo(Movement.FIRST);
            assertThat(step.delta()).isZero();
        });
        assertThat(series.comparable())
                .as("un seul point n'est pas une tendance")
                .isFalse();
    }

    @Test
    @DisplayName("refuses to call a series comparable when its shape kept moving")
    void aMovingShapeIsNotATrend() {
        assertThat(ComplianceHistory.of(ISO, List.of(
                        snapshot("2026-06", 90, 8),
                        snapshot("2026-07", 80, 10),
                        snapshot("2026-08", 75, 12))).comparable())
                .as("three months, three different estates: that is a shape, not a trend")
                .isFalse();

        assertThat(ComplianceHistory.of(ISO, List.of(
                        snapshot("2026-06", 70, 10),
                        snapshot("2026-07", 80, 10),
                        snapshot("2026-08", 88, 10))).comparable())
                .isTrue();
    }

    @Test
    @DisplayName("keeps months in order, whatever order they arrive in")
    void ordersByPeriod() {
        Series series = ComplianceHistory.of(ISO, List.of(
                snapshot("2026-08", 80, 10), snapshot("2026-06", 60, 10), snapshot("2026-07", 70, 10)));

        assertThat(series.steps()).extracting(step -> step.snapshot().period())
                .containsExactly("2026-06", "2026-07", "2026-08");
    }

    @Test
    @DisplayName("ignores another framework's months")
    void otherFrameworksAreDropped() {
        ComplianceSnapshot other = new ComplianceSnapshot(
                "2026-08", ComplianceFramework.SOC_2, 10, ComplianceControl.Status.NON_COMPLIANT,
                10, 10, 10, 30, true, true, 4, 0, 4, Instant.EPOCH);

        assertThat(ComplianceHistory.of(ISO, List.of(snapshot("2026-08", 80, 10), other)).steps())
                .singleElement()
                .satisfies(step -> assertThat(step.snapshot().framework()).isEqualTo(ISO));
    }

    private static ComplianceSnapshot snapshot(String period, int score, int targets) {
        return new ComplianceSnapshot(
                period, ISO, score, ComplianceControl.Status.PARTIAL, targets, targets, targets,
                30, true, true, 4, 4, 0, Instant.EPOCH);
    }
}
