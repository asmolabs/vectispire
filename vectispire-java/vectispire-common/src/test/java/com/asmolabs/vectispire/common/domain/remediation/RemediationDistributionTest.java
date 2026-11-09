package com.asmolabs.vectispire.common.domain.remediation;

import static org.assertj.core.api.Assertions.assertThat;

import com.asmolabs.vectispire.common.domain.issues.RemediationSla;
import com.asmolabs.vectispire.common.domain.issues.Severity;
import java.time.Duration;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

/**
 * The figures a mean cannot produce.
 *
 * <p><b>The case this exists for, in one fixture.</b> Two hundred low findings closed in a day and
 * one critical open since March: the mean says a day and a half and the estate is not remediating.
 * The tests below are written against that shape, because it is the shape a security backlog
 * actually has and the one every average flatters.
 */
@DisplayName("the remediation distribution")
class RemediationDistributionTest {

    private static final long DAY = 86_400L;

    private static final RemediationSla SLA = new RemediationSla(Map.of(
            Severity.CRITICAL, Duration.ofDays(7),
            Severity.HIGH, Duration.ofDays(30),
            Severity.MEDIUM, Duration.ofDays(90)));

    @Test
    @DisplayName("reports the share that met its deadline, and the count behind it")
    void reports_the_share_within_sla() {
        List<RemediationDistribution.Resolved> resolved = List.of(
                new RemediationDistribution.Resolved(Severity.CRITICAL, 2 * DAY),
                new RemediationDistribution.Resolved(Severity.CRITICAL, 5 * DAY),
                new RemediationDistribution.Resolved(Severity.CRITICAL, 9 * DAY),
                new RemediationDistribution.Resolved(Severity.CRITICAL, 40 * DAY));

        RemediationDistribution.BySeverity critical =
                severity(RemediationDistribution.calculate(90, SLA, resolved, List.of()), Severity.CRITICAL);

        assertThat(critical.withinSla()).isEqualTo(2);
        assertThat(critical.late())
                .as("kept beside the share: two of four and two hundred of four hundred are the "
                        + "same ratio and not the same fact")
                .isEqualTo(2);
        assertThat(critical.percentageWithinSla()).isEqualTo(50.0);
    }

    @Test
    @DisplayName("reports the tail, which is what moves when a process is failing")
    void reports_the_tail() {
        // Eight quick fixes and two that took a year. The mean is about seventy-five days and
        // describes neither; the median says the typical fix is fast, which is true and
        // reassuring, and the ninetieth says a tenth of the work is catastrophic, which is the
        // fact somebody has to act on.
        List<RemediationDistribution.Resolved> resolved = new ArrayList<>();
        for (int i = 0; i < 8; i++) {
            resolved.add(new RemediationDistribution.Resolved(Severity.HIGH, 2 * DAY));
        }
        resolved.add(new RemediationDistribution.Resolved(Severity.HIGH, 365 * DAY));
        resolved.add(new RemediationDistribution.Resolved(Severity.HIGH, 365 * DAY));

        RemediationDistribution.BySeverity high =
                severity(RemediationDistribution.calculate(90, SLA, resolved, List.of()), Severity.HIGH);

        assertThat(high.medianDays())
                .as("the typical fix, and it is genuinely fast")
                .isEqualTo(2.0);
        assertThat(high.ninetiethDays())
                .as("and the tail, which a mean of seventy-five days would have blurred into "
                        + "something that looks like a slow team rather than a broken case")
                .isEqualTo(365.0);
        assertThat(high.late()).isEqualTo(2);
    }

    @Test
    @DisplayName("names the oldest open item, which no average can show")
    void names_the_oldest_open_item() {
        RemediationDistribution distribution = RemediationDistribution.calculate(
                90,
                SLA,
                List.of(new RemediationDistribution.Resolved(Severity.LOW, DAY)),
                List.of(
                        new RemediationDistribution.Open(Severity.LOW, 200, 0, 3L),
                        new RemediationDistribution.Open(Severity.CRITICAL, 1, 1, 240L)));

        assertThat(distribution.oldestOpenDays()).isEqualTo(240L);
        assertThat(distribution.oldestOpenSeverity())
                .as("and which severity it is, because two hundred days of low is not two hundred "
                        + "days of critical")
                .isEqualTo(Severity.CRITICAL);
        assertThat(severity(distribution, Severity.CRITICAL).openOverdue()).isEqualTo(1);
    }

    @Test
    @DisplayName("refuses to report a percentage against a deadline nobody set")
    void refuses_a_percentage_without_a_deadline() {
        RemediationDistribution.BySeverity low = severity(
                RemediationDistribution.calculate(
                        90,
                        SLA,
                        List.of(new RemediationDistribution.Resolved(Severity.LOW, 500 * DAY)),
                        List.of()),
                Severity.LOW);

        assertThat(low.windowDays()).isZero();
        assertThat(low.percentageWithinSla())
                .as("a hundred per cent against no rule is a claim earned by an absent rule")
                .isNull();
        assertThat(low.medianDays())
                .as("the duration is still reported — it is the judgement that is withheld")
                .isEqualTo(500.0);
    }

    @Test
    @DisplayName("reports nothing rather than zero for a severity with no resolutions")
    void reports_nothing_for_an_empty_severity() {
        RemediationDistribution.BySeverity medium = severity(
                RemediationDistribution.calculate(90, SLA, List.of(), List.of()), Severity.MEDIUM);

        assertThat(medium.medianDays())
                .as("zero days to remediate would be the most flattering possible lie")
                .isNull();
        assertThat(medium.withinSla()).isZero();
    }

    private static RemediationDistribution.BySeverity severity(
            RemediationDistribution distribution, Severity severity) {
        return distribution.bySeverity().stream()
                .filter(row -> row.severity() == severity)
                .findFirst()
                .orElseThrow(() -> new AssertionError("no row for " + severity));
    }
}
