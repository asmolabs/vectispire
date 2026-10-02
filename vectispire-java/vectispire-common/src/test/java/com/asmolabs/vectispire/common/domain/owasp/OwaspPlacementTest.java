package com.asmolabs.vectispire.common.domain.owasp;

import static org.assertj.core.api.Assertions.assertThat;

import com.asmolabs.vectispire.common.domain.issues.FindingType;
import com.asmolabs.vectispire.common.domain.owasp.OwaspCoverage.Measurement;
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
    @DisplayName("over several targets: findings anywhere, else measured anywhere, else not covered only when all are")
    void acrossTargets() {
        assertThat(OwaspCoverage.acrossTargets(List.of(State.NOT_MEASURED, State.NO_FINDING, State.FINDINGS)))
                .contains(State.FINDINGS);
        assertThat(OwaspCoverage.acrossTargets(List.of(State.NOT_MEASURED, State.NO_FINDING)))
                .as("one target scanned and clean measures the category, as one scanned target does in the grid")
                .contains(State.NO_FINDING);
        assertThat(OwaspCoverage.acrossTargets(List.of(State.NOT_MEASURED, State.NOT_MEASURED)))
                .contains(State.NOT_MEASURED);
        assertThat(OwaspCoverage.acrossTargets(List.of(State.NOT_COVERED, State.NOT_COVERED)))
                .contains(State.NOT_COVERED);
        assertThat(OwaspCoverage.acrossTargets(List.of(State.NOT_COVERED, State.NOT_MEASURED)))
                .contains(State.NOT_MEASURED);
        assertThat(OwaspCoverage.acrossTargets(List.of())).as("nothing recorded is not a state").isEmpty();
    }
}
