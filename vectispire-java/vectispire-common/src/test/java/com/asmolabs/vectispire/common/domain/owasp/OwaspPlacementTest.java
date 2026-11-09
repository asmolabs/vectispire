package com.asmolabs.vectispire.common.domain.owasp;

import static org.assertj.core.api.Assertions.assertThat;

import com.asmolabs.vectispire.common.domain.issues.FindingType;
import com.asmolabs.vectispire.common.domain.owasp.OwaspCoverage.Split;
import com.asmolabs.vectispire.common.domain.owasp.OwaspCoverage.State;
import java.util.List;
import java.util.Map;
import java.util.Optional;
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
            OwaspCoverage.Grid grid = OwaspCoverage.assess(OwaspEvidence.measured(one));
            Optional<String> counted = grid.lines().stream()
                    .filter(line -> line.findings() > 0)
                    .map(OwaspCoverage.CoverageLine::id)
                    .findFirst();
            assertThat(OwaspCoverage.placementOf(type, null)).as(type.wireName()).isEqualTo(counted);
        }
    }

    @Test
    @DisplayName("over several targets: findings anywhere count, a target nothing can examine is left aside, one unexamined holds the scope unmeasured")
    void acrossTargets() {
        assertThat(across(line(State.NOT_MEASURED, 0, 0), line(State.NO_FINDING, 0, 1), line(State.FINDINGS, 2, 0)))
                .contains(new Split("A06", State.FINDINGS, 2, 1));
        assertThat(across(line(State.NOT_MEASURED, 0, 0), line(State.NO_FINDING, 0, 0)))
                .as("one target examined and clean, one not: a scope examined in part is not measured")
                .contains(new Split("A06", State.NOT_MEASURED, 0, 0));
        assertThat(across(line(State.NOT_COVERED, 0, 0), line(State.NO_FINDING, 0, 2)))
                .as("an image beside an examined repository, for a category no image is examined for")
                .contains(new Split("A06", State.NO_FINDING, 0, 2));
        assertThat(across(line(State.NOT_MEASURED, 3, 1), line(State.NO_FINDING, 0, 0)))
                .as("a line written before 0.11.0 for a never-scanned target: its findings are facts")
                .contains(new Split("A06", State.FINDINGS, 3, 1));
        assertThat(across(line(State.NOT_MEASURED, 3, 1), line(State.NOT_MEASURED, 0, 0)))
                .as("findings count whatever examined the targets since")
                .contains(new Split("A06", State.FINDINGS, 3, 1));
        assertThat(across(line(State.NOT_COVERED, 0, 0), line(State.NOT_COVERED, 0, 0)))
                .as("a category a type places, over targets none of which it applies to: not measured, never not covered")
                .contains(new Split("A06", State.NOT_MEASURED, 0, 0));
        assertThat(OwaspCoverage.acrossTargets("A03", List.of(new Split("A03", State.NOT_COVERED, 0, 0))))
                .as("only code analysis reaches it: the lines cannot say whether a rule declared it")
                .contains(new Split("A03", State.NOT_COVERED, 0, 0));
        assertThat(across(line(State.NOT_COVERED, 0, 0), line(State.NOT_MEASURED, 0, 0)))
                .contains(new Split("A06", State.NOT_MEASURED, 0, 0));
        assertThat(OwaspCoverage.acrossTargets("A06", List.of())).as("nothing recorded is not a state").isEmpty();
    }

    private static Optional<Split> across(Split... lines) {
        return OwaspCoverage.acrossTargets("A06", List.of(lines));
    }

    private static Split line(State state, long open, long settled) {
        return new Split("A06", state, open, settled);
    }
}
