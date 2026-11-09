package com.asmolabs.vectispire.common.domain.owasp;

import static org.assertj.core.api.Assertions.assertThat;

import com.asmolabs.vectispire.common.domain.issues.FindingType;
import com.asmolabs.vectispire.common.domain.owasp.OwaspCoverage.Measurement;
import com.asmolabs.vectispire.common.domain.owasp.OwaspCoverage.Split;
import com.asmolabs.vectispire.common.domain.owasp.OwaspCoverage.State;
import java.time.Instant;
import java.util.List;
import java.util.Map;
import java.util.Set;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

/**
 * The grid with accepted risks counted apart, as the weekly record stores it.
 *
 * <p>The owner's rule: an accepted risk is shown, in its own colour, and is neither dropped from the
 * record nor counted as work to do. The state stays the one the live grid reports.
 */
@DisplayName("the OWASP grid, settled findings counted apart")
class OwaspCoverageSplitTest {

    @Test
    @DisplayName("counts the settled findings apart, and keeps the state the grid shows")
    void settledApart() {
        List<Split> split = OwaspCoverage.split(
                OwaspCoverage.assess(measured(Map.of(FindingType.VULNERABILITY, 2L, FindingType.SECRET, 0L))),
                OwaspCoverage.assess(measured(Map.of(FindingType.VULNERABILITY, 5L, FindingType.SECRET, 1L))));

        assertThat(of(split, "A06")).isEqualTo(new Split("A06", State.FINDINGS, 2, 3));
        // Every open secret is accepted: the grid says nothing open, and the record says what that cost.
        assertThat(of(split, "A07")).isEqualTo(new Split("A07", State.NO_FINDING, 0, 1));
    }

    @Test
    @DisplayName("counts nothing, settled or not, in a category nothing measures or nothing covers")
    void unmeasuredCountsNothing() {
        // Code analysis switched off: settled code findings exist in the counts, and a category with no
        // measurement has no figure of either kind — the grid's own rule, applied to both readings alike.
        List<Split> split = OwaspCoverage.split(
                OwaspCoverage.assess(new Measurement(true, false, Map.of(), Set.of("A03"), Map.of("A03", 0L),
                        List.of(OwaspEvidence.examinedRepository(1, "A03")))),
                OwaspCoverage.assess(new Measurement(true, false, Map.of(), Set.of("A03"), Map.of("A03", 4L),
                        List.of(OwaspEvidence.examinedRepository(1, "A03")))));

        assertThat(of(split, "A03")).isEqualTo(new Split("A03", State.NOT_MEASURED, 0, 0));
        assertThat(of(split, "A01")).isEqualTo(new Split("A01", State.NOT_COVERED, 0, 0));
        assertThat(split).map(Split::id).containsExactlyElementsOf(OwaspCoverage.CATEGORIES.keySet());
    }

    @Test
    @DisplayName("keeps the settled findings of a scope nothing examined: an accepted risk is a fact too")
    void settledOverAnUnexaminedScope() {
        List<Split> split = OwaspCoverage.split(
                OwaspCoverage.assess(new Measurement(true, true, Map.of(FindingType.VULNERABILITY, 0L), Set.of(), Map.of(),
                        List.of())),
                OwaspCoverage.assess(new Measurement(true, true, Map.of(FindingType.VULNERABILITY, 4L), Set.of(), Map.of(),
                        List.of())));

        assertThat(of(split, "A06")).isEqualTo(new Split("A06", State.NOT_MEASURED, 0, 4));
    }

    @Test
    @DisplayName("never counts a settled finding below zero")
    void neverNegative() {
        // Two statements, and a finding settled between them: the second reading holds fewer.
        List<Split> split = OwaspCoverage.split(
                OwaspCoverage.assess(measured(Map.of(FindingType.VULNERABILITY, 3L))),
                OwaspCoverage.assess(measured(Map.of(FindingType.VULNERABILITY, 2L))));

        assertThat(of(split, "A06").settled()).isZero();
    }

    @Test
    @DisplayName("names a week by its Monday at midnight UTC, whatever the day and the hour")
    void weeksStartOnMonday() {
        Instant monday = Instant.parse("2026-09-28T00:00:00Z");

        assertThat(CoverageWeek.startOf(monday)).isEqualTo(monday);
        assertThat(CoverageWeek.startOf(Instant.parse("2026-10-04T23:59:59Z"))).isEqualTo(monday);
        assertThat(CoverageWeek.startOf(Instant.parse("2026-09-27T23:59:59Z")))
                .isEqualTo(Instant.parse("2026-09-21T00:00:00Z"));
    }

    private static Measurement measured(Map<FindingType, Long> open) {
        return OwaspEvidence.measured(open);
    }

    private static Split of(List<Split> split, String id) {
        return split.stream().filter(line -> line.id().equals(id)).findFirst().orElseThrow();
    }
}
