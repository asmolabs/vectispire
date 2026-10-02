package com.asmolabs.vectispire.common.domain.owasp;

import static org.assertj.core.api.Assertions.assertThat;

import com.asmolabs.vectispire.common.domain.issues.FindingType;
import com.asmolabs.vectispire.common.domain.owasp.OwaspCoverage.Measurement;
import com.asmolabs.vectispire.common.domain.owasp.OwaspCoverage.Split;
import com.asmolabs.vectispire.common.domain.owasp.OwaspCoverage.State;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.Set;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

/**
 * Where one issue lands, and what a category reads over several targets — the two rules the weekly
 * view and its drill-down read from the grid rather than restate.
 */
@DisplayName("the OWASP placement of one issue, and a category's state over several targets")
class OwaspPlacementTest {

    @Test
    @DisplayName("a type placed by rule keeps its category, whatever the column says")
    void byType() {
        assertThat(OwaspCoverage.placementOf(FindingType.VULNERABILITY, null)).contains("A06");
        assertThat(OwaspCoverage.placementOf(FindingType.EOL, "A03")).contains("A06");
        assertThat(OwaspCoverage.placementOf(FindingType.IAC, null)).contains("A05");
        assertThat(OwaspCoverage.placementOf(FindingType.SECRET, null)).contains("A07");
        assertThat(OwaspCoverage.typesPlacedIn("A06")).containsExactlyInAnyOrder(FindingType.VULNERABILITY, FindingType.EOL);
        assertThat(OwaspCoverage.typesPlacedIn("A03")).isEmpty();
    }

    @Test
    @DisplayName("code analysis is placed by its rule's declaration, and nothing else is")
    void byDeclaration() {
        assertThat(OwaspCoverage.placementOf(FindingType.SAST, "A03")).contains("A03");
        assertThat(OwaspCoverage.placementOf(FindingType.SAST, null)).isEmpty();
        assertThat(OwaspCoverage.placementOf(FindingType.SAST, "A11")).as("no such category").isEmpty();
        // The grid counts code analysis by the column and no other type: a plugin's finding carrying a
        // category is not in it, so it is in no week's flow either.
        assertThat(OwaspCoverage.placementOf(FindingType.PLUGIN, "A03")).isEmpty();
    }

    @Test
    @DisplayName("the types placed anywhere are those placed in some category, and the only ones placed with no declaration")
    void anywhere() {
        for (FindingType type : FindingType.values()) {
            boolean inSome = OwaspCoverage.CATEGORIES.keySet().stream()
                    .anyMatch(category -> OwaspCoverage.typesPlacedIn(category).contains(type));
            assertThat(OwaspCoverage.typesPlacedAnywhere().contains(type)).as(type.wireName()).isEqualTo(inSome);
            assertThat(OwaspCoverage.placementOf(type, null).isPresent()).as(type.wireName()).isEqualTo(inSome);
        }
    }

    @Test
    @DisplayName("agrees with the grid: every type the grid counts in a category is placed there")
    void agreesWithTheGrid() {
        for (FindingType type : FindingType.values()) {
            Map<FindingType, Long> one = Map.of(type, 1L);
            OwaspCoverage.Grid grid = OwaspCoverage.assess(new Measurement(true, true, true, one, Set.of(), Map.of()));
            Optional<String> counted = grid.lines().stream()
                    .filter(line -> line.findings() > 0)
                    .map(OwaspCoverage.CoverageLine::id)
                    .findFirst();
            assertThat(OwaspCoverage.placementOf(type, null)).as(type.wireName()).isEqualTo(counted);
        }
    }

    @Test
    @DisplayName("over several targets: counted where any target measured, else not covered only when all are, else not measured")
    void acrossTargets() {
        assertThat(across(line(State.NOT_MEASURED, 0, 0), line(State.NO_FINDING, 0, 1), line(State.FINDINGS, 2, 0)))
                .contains(new Split("A06", State.FINDINGS, 2, 1));
        assertThat(across(line(State.NOT_MEASURED, 0, 0), line(State.NO_FINDING, 0, 0)))
                .as("one target scanned and clean measures the category, as one scanned target does in the grid")
                .contains(new Split("A06", State.NO_FINDING, 0, 0));
        assertThat(across(line(State.NOT_MEASURED, 3, 1), line(State.NO_FINDING, 0, 0)))
                .as("a never-scanned target's findings, beside a measured target: the grid counts them")
                .contains(new Split("A06", State.FINDINGS, 3, 1));
        assertThat(across(line(State.NOT_MEASURED, 3, 1), line(State.NOT_MEASURED, 0, 0)))
                .as("nothing scanned: the grid counts nothing, a never-scanned target's findings included")
                .contains(new Split("A06", State.NOT_MEASURED, 0, 0));
        assertThat(across(line(State.NOT_COVERED, 0, 0), line(State.NOT_COVERED, 0, 0)))
                .contains(new Split("A06", State.NOT_COVERED, 0, 0));
        assertThat(across(line(State.NOT_COVERED, 0, 0), line(State.NOT_MEASURED, 0, 0)))
                .contains(new Split("A06", State.NOT_MEASURED, 0, 0));
        assertThat(OwaspCoverage.acrossTargets("A06", List.of())).as("nothing recorded is not a state").isEmpty();
    }

    @Test
    @DisplayName("a never-scanned target is not measured, and keeps the findings the grid would count")
    void unscanned() {
        assertThat(OwaspCoverage.unscanned(List.of(
                        new Split("A05", State.FINDINGS, 2, 1),
                        new Split("A06", State.NO_FINDING, 0, 3),
                        new Split("A01", State.NOT_COVERED, 0, 0),
                        new Split("A03", State.NOT_MEASURED, 0, 0))))
                .containsExactly(
                        new Split("A05", State.NOT_MEASURED, 2, 1),
                        new Split("A06", State.NOT_MEASURED, 0, 3),
                        new Split("A01", State.NOT_COVERED, 0, 0),
                        new Split("A03", State.NOT_MEASURED, 0, 0));
    }

    private static Optional<Split> across(Split... lines) {
        return OwaspCoverage.acrossTargets("A06", List.of(lines));
    }

    private static Split line(State state, long open, long settled) {
        return new Split("A06", state, open, settled);
    }
}
