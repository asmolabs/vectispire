package com.asmolabs.zanshin.common.domain.issues;

import static org.assertj.core.api.Assertions.assertThat;

import java.time.Duration;
import java.time.Instant;
import java.util.Map;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

@DisplayName("the remediation window")
class RemediationSlaTest {

    private static final Instant NOW = Instant.parse("2026-08-21T12:00:00Z");
    private static final RemediationSla POLICY = RemediationSla.DEFAULT;

    @Test
    @DisplayName("a fresh critical is on time")
    void insideTheWindow() {
        var assessment = POLICY.assess(Severity.CRITICAL, NOW.minus(Duration.ofDays(2)), true, false, NOW);

        assertThat(assessment).get().satisfies(sla -> {
            assertThat(sla.state()).isEqualTo(RemediationSla.SlaState.ON_TIME);
            assertThat(sla.days()).isEqualTo(13);
            assertThat(sla.isOverdue()).isFalse();
        });
    }

    @Test
    @DisplayName("past its window, it is late — and the day count goes negative")
    void pastTheWindow() {
        var assessment = POLICY.assess(Severity.CRITICAL, NOW.minus(Duration.ofDays(20)), true, false, NOW);

        assertThat(assessment).get().satisfies(sla -> {
            assertThat(sla.state()).isEqualTo(RemediationSla.SlaState.OVERDUE);
            // One signed field: "5 days late" and "due in 13 days" are one measurement read from
            // opposite sides, and two fields would allow a row that is both.
            assertThat(sla.days()).isEqualTo(-5);
        });
    }

    @Test
    @DisplayName("the last week before the deadline is due-soon")
    void theWarningWindow() {
        assertThat(POLICY.assess(Severity.HIGH, NOW.minus(Duration.ofDays(24)), true, false, NOW))
                .get()
                .returns(RemediationSla.SlaState.DUE_SOON, RemediationSla.Assessment::state);

        // And a day earlier it is not: the boundary is checked from both sides, because an
        // off-by-one here shows up as a badge that appears a day late and nobody notices.
        assertThat(POLICY.assess(Severity.HIGH, NOW.minus(Duration.ofDays(22)), true, false, NOW))
                .get()
                .returns(RemediationSla.SlaState.ON_TIME, RemediationSla.Assessment::state);
    }

    @Test
    @DisplayName("lateness is decided by the instant, not by the day count")
    void almostDueIsNotLate() {
        // Due in twenty-three hours: the day count floors to 0, which read as "late" would make
        // every issue late for its last day. The comparison is on the instants.
        var assessment = POLICY.assess(
                Severity.CRITICAL, NOW.minus(Duration.ofDays(15)).plus(Duration.ofHours(23)), true, false, NOW);

        assertThat(assessment).get().satisfies(sla -> {
            assertThat(sla.days()).isZero();
            assertThat(sla.state()).isEqualTo(RemediationSla.SlaState.DUE_SOON);
            assertThat(sla.isOverdue()).isFalse();
        });
    }

    @Test
    @DisplayName("the clock starts at the first sighting, so a rescan cannot reset it")
    void rediscoveryDoesNotReset() {
        // The defect this guards against would make the whole feature decorative: a target
        // scanned nightly would restart every window every night, and nothing would ever be late.
        Instant firstSeen = NOW.minus(Duration.ofDays(40));

        assertThat(POLICY.assess(Severity.HIGH, firstSeen, true, false, NOW))
                .get()
                .returns(RemediationSla.SlaState.OVERDUE, RemediationSla.Assessment::state)
                .returns(firstSeen.plus(Duration.ofDays(30)), RemediationSla.Assessment::dueAt);
    }

    @Test
    @DisplayName("a settled issue has no deadline")
    void settledIssuesAreNotLate() {
        Instant ancient = NOW.minus(Duration.ofDays(400));

        // Fixed, or argued not to apply: a human decision took it out of the way, and counting it
        // as late would punish the triage this system exists to encourage.
        assertThat(POLICY.assess(Severity.CRITICAL, ancient, true, true, NOW)).isEmpty();
        // Nor a closed one: it is done, and reporting it late would describe work already
        // finished.
        assertThat(POLICY.assess(Severity.CRITICAL, ancient, false, false, NOW)).isEmpty();
    }

    @Test
    @DisplayName("a severity with no window has no deadline, and zero means no window")
    void severitiesWithoutAWindow() {
        Instant ancient = NOW.minus(Duration.ofDays(400));

        // Negligible and unknown carry none by default: neither describes work anybody schedules.
        assertThat(POLICY.assess(Severity.NEGLIGIBLE, ancient, true, false, NOW)).isEmpty();
        assertThat(POLICY.assess(Severity.UNKNOWN, ancient, true, false, NOW)).isEmpty();

        // **Zero is "no deadline", not "due immediately".** Read the other way, an operator
        // clearing the field would put every low-severity issue into breach at once.
        RemediationSla cleared = new RemediationSla(Map.of(Severity.LOW, Duration.ZERO));
        assertThat(cleared.windowFor(Severity.LOW)).isEmpty();
        assertThat(cleared.assess(Severity.LOW, ancient, true, false, NOW)).isEmpty();

        // And a negative value, which only a hand-edited row produces, reads the same way rather
        // than raising an alarm nobody can act on.
        RemediationSla negative = new RemediationSla(Map.of(Severity.LOW, Duration.ofDays(-5)));
        assertThat(negative.windowFor(Severity.LOW)).isEmpty();
    }

    @Test
    @DisplayName("a missing first sighting is not a breach")
    void unknownFirstSightingIsNotLate() {
        // The column is nullable, and "we do not know when this appeared" must not read as "it
        // has been open since the epoch".
        assertThat(POLICY.assess(Severity.CRITICAL, null, true, false, NOW)).isEmpty();
    }

    @Test
    @DisplayName("the overdue threshold is what a database can compare against")
    void theThresholdForCounting() {
        // Counting in SQL rather than assessing every row in memory: one indexed comparison per
        // severity instead of reading the whole backlog to produce one number.
        assertThat(POLICY.overdueBefore(Severity.CRITICAL, NOW)).contains(NOW.minus(Duration.ofDays(15)));
        assertThat(POLICY.overdueBefore(Severity.UNKNOWN, NOW)).isEmpty();
    }

    @Test
    @DisplayName("the default policy is not empty, because a feature that ships off is not found")
    void theDefaultGrantsWindows() {
        assertThat(POLICY.windowFor(Severity.CRITICAL)).contains(Duration.ofDays(15));
        assertThat(POLICY.windowFor(Severity.HIGH)).contains(Duration.ofDays(30));
        assertThat(POLICY.windowFor(Severity.MEDIUM)).contains(Duration.ofDays(90));
        assertThat(POLICY.windowFor(Severity.LOW)).contains(Duration.ofDays(180));
    }
}
