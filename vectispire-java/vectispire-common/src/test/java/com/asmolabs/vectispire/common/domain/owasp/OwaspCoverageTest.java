package com.asmolabs.vectispire.common.domain.owasp;

import static org.assertj.core.api.Assertions.assertThat;

import com.asmolabs.vectispire.common.domain.issues.FindingType;
import com.asmolabs.vectispire.common.domain.owasp.OwaspCoverage.Grid;
import com.asmolabs.vectispire.common.domain.owasp.OwaspCoverage.CoverageLine;
import com.asmolabs.vectispire.common.domain.owasp.OwaspCoverage.Measurement;
import com.asmolabs.vectispire.common.domain.owasp.OwaspCoverage.State;
import java.util.Map;
import java.util.Set;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

/**
 * What this deployment may honestly say about each of the ten.
 *
 * <h2>The distinction every case here turns on</h2>
 *
 * <p><b>A category with nothing found and a category nothing looks at produce the same green.</b>
 * Two states cannot tell them apart, which is why there are four; and the assertions below are
 * almost all about the three that are not "found nothing", because those are the ones a two-state
 * grid gets wrong while looking right.
 *
 * <p>The uncomfortable one is the first: <b>seven of the ten are not covered by any scanner
 * here</b>. Saying so is the most useful thing this grid does, and the easiest thing for a later
 * change to quietly undo by inventing a mapping.
 */
@DisplayName("the OWASP coverage grid")
class OwaspCoverageTest {

    private static final Measurement FULL = new Measurement(
            true, true, true,
            Map.of(FindingType.IAC, 0L, FindingType.VULNERABILITY, 0L, FindingType.EOL, 0L, FindingType.SECRET, 0L));

    @Test
    @DisplayName("says outright which categories nothing here looks at")
    void namesWhatItCannotSee() {
        Grid grid = OwaspCoverage.assess(FULL);

        assertThat(grid.covered())
                .as("three of the ten, and a grid claiming more would be claiming an examination "
                        + "that never happened")
                .isEqualTo(3);
        assertThat(states(grid, State.NOT_COVERED))
                .containsExactly("A01", "A02", "A03", "A04", "A08", "A09", "A10");
    }

    @Test
    @DisplayName("places a finding by its type, and says which rule placed it")
    void placesFindingsByType() {
        Grid grid = OwaspCoverage.assess(new Measurement(
                true, true, true,
                Map.of(FindingType.IAC, 3L, FindingType.VULNERABILITY, 12L, FindingType.SECRET, 1L)));

        assertThat(line(grid, "A05").state()).isEqualTo(State.FINDINGS);
        assertThat(line(grid, "A05").findings()).isEqualTo(3);
        assertThat(line(grid, "A07").findings()).isEqualTo(1);
        assertThat(grid.withFindings()).isEqualTo(3);
    }

    @Test
    @DisplayName("adds the two types that share a category, and only those")
    void sumsTheTypesOfOneCategory() {
        Grid grid = OwaspCoverage.assess(new Measurement(
                true, true, true, Map.of(FindingType.VULNERABILITY, 12L, FindingType.EOL, 4L)));

        assertThat(line(grid, "A06").findings())
                .as("\"vulnerable *and outdated*\" names both halves")
                .isEqualTo(16);
    }

    @Test
    @DisplayName("reports a switched-off detector as unmeasured, never as clean")
    void switchedOffIsNotClean() {
        Grid grid = OwaspCoverage.assess(new Measurement(
                true, false, true, Map.of(FindingType.VULNERABILITY, 0L)));

        // A06 stays measured by grype even without end-of-life: it is the sum that loses a half,
        // not the category that disappears.
        assertThat(line(grid, "A06").state()).isEqualTo(State.NO_FINDING);
        assertThat(line(grid, "A06").because()).doesNotContain("eol");
    }

    @Test
    @DisplayName("counts nothing for a detector that is off, even when its backlog is not empty")
    void aSwitchedOffDetectorContributesNothing() {
        // Switching detection off leaves the findings open rather than resolving them — that is a
        // deliberate product choice. Counting them here would make the grid say we are still
        // measuring.
        Grid grid = OwaspCoverage.assess(new Measurement(
                true, false, true, Map.of(FindingType.VULNERABILITY, 0L, FindingType.EOL, 9L)));

        assertThat(line(grid, "A06").findings()).isZero();
        assertThat(line(grid, "A06").state()).isEqualTo(State.NO_FINDING);
    }

    @Test
    @DisplayName("reports an estate nobody has scanned as unmeasured across the board")
    void neverScannedIsUnmeasured() {
        Grid grid = OwaspCoverage.assess(new Measurement(false, true, true, Map.of()));

        assertThat(states(grid, State.NOT_MEASURED)).containsExactly("A05", "A06", "A07");
        assertThat(grid.unmeasured()).isEqualTo(3);
        assertThat(states(grid, State.NO_FINDING))
                .as("an estate never scanned has no clean category")
                .isEmpty();
    }

    @Test
    @DisplayName("places no code finding on its type alone, the category not being a property of it")
    void codeAnalysisIsNotPlacedByItsType() {
        // One Semgrep rule finds injections, another SSRF: the type says nothing about the
        // category, which is why the declaration travels with the finding.
        assertThat(OwaspCoverage.categoryOf(FindingType.SAST))
                .as("placing a code finding by reading pieces of its rule identifier would be "
                        + "reproducible and would still be a guess")
                .isEmpty();
        assertThat(OwaspCoverage.categoryOf(FindingType.LICENSE)).isEmpty();
        assertThat(OwaspCoverage.categoryOf(FindingType.QUALITY)).isEmpty();
    }


    @Test
    @DisplayName("opens a category no type covers, as soon as an installed rule declares it")
    void aDeclaredCategoryBecomesCovered() {
        // A03 — Injection — is covered by no finding type. It is covered as soon as a code-analysis
        // rule declares so in its own metadata, and that is what moves it out of "nothing here looks
        // at that".
        Grid grid = OwaspCoverage.assess(new Measurement(
                true, true, true, Map.of(), Set.of("A03"), Map.of("A03", 4L)));

        assertThat(line(grid, "A03").state()).isEqualTo(State.FINDINGS);
        assertThat(line(grid, "A03").findings()).isEqualTo(4);
        assertThat(grid.covered())
                .as("the original three, plus the one the installed rules declare")
                .isEqualTo(4);
        assertThat(states(grid, State.NOT_COVERED)).containsExactly("A01", "A02", "A04", "A08", "A09", "A10");
    }

    @Test
    @DisplayName("says \"looked at, nothing to report\" for a declared category with no finding")
    void aDeclaredCategoryWithoutFindingsIsClean() {
        // **The case that justifies reading the rules rather than the findings.** Deriving coverage
        // from the findings would drop A03 out of the grid the day its last finding is fixed — that
        // is, at the moment it most deserves to say it was looked at.
        Grid grid = OwaspCoverage.assess(new Measurement(
                true, true, true, Map.of(), Set.of("A03"), Map.of()));

        assertThat(line(grid, "A03").state()).isEqualTo(State.NO_FINDING);
        assertThat(line(grid, "A03").because()).contains("code analysis");
    }

    @Test
    @DisplayName("a declared category stays unmeasured when code analysis reaches nothing")
    void aDeclaredCategoryUnreached() {
        Grid grid = OwaspCoverage.assess(new Measurement(
                true, true, false, Map.of(), Set.of("A03"), Map.of("A03", 4L)));

        assertThat(line(grid, "A03").state()).isEqualTo(State.NOT_MEASURED);
        assertThat(line(grid, "A03").findings())
                .as("yesterday's findings do not measure today: the count would be read as a result")
                .isZero();
        assertThat(line(grid, "A03").because()).contains("Code analysis is off");
    }

    @Test
    @DisplayName("adds a type and code analysis together when both cover the same category")
    void aCategoryCoveredTwice() {
        // A05 is covered by the infrastructure checks, and a code rule can declare it too. The two
        // counts add up — they are distinct findings.
        Grid grid = OwaspCoverage.assess(new Measurement(
                true, true, true, Map.of(FindingType.IAC, 3L), Set.of("A05"), Map.of("A05", 2L)));

        assertThat(line(grid, "A05").findings()).isEqualTo(5);
        assertThat(line(grid, "A05").state()).isEqualTo(State.FINDINGS);
    }

    @Test
    @DisplayName("does not add code findings to a category the analysis no longer measures")
    void unreachedCodeFindingsAreNotAdded() {
        // A05 is measured by the infrastructure checks; code analysis, for its part, reaches
        // nothing. Its findings from yesterday still exist — switching a detector off does not
        // resolve them — and adding them here would pass them off as a measurement of today, under
        // a category that is itself properly measured. That is the worst form of the defect: a
        // correct number in the wrong place, in an otherwise green row.
        Grid grid = OwaspCoverage.assess(new Measurement(
                true, true, false, Map.of(FindingType.IAC, 3L), Set.of("A05"), Map.of("A05", 7L)));

        assertThat(line(grid, "A05").state()).isEqualTo(State.FINDINGS);
        assertThat(line(grid, "A05").findings())
                .as("les trois de l'infrastructure, et rien de l'analyse de code qui ne mesure pas")
                .isEqualTo(3);
        assertThat(line(grid, "A05").because()).doesNotContain("code analysis");
    }

    @Test
    @DisplayName("names both switched-off halves rather than one")
    void bothHalvesOff() {
        // A06 is covered by grype and by end-of-life; if a code rule declares it too and the
        // analysis reaches nothing, naming only one of the two causes would send somebody to switch
        // back on a detector that was already running.
        Grid grid = OwaspCoverage.assess(new Measurement(
                true, false, false, Map.of(), Set.of("A06"), Map.of()));

        assertThat(line(grid, "A06").state())
                .as("grype still measures A06: the category stays measured")
                .isEqualTo(State.NO_FINDING);
    }

    @Test
    @DisplayName("a code finding enters no category when its rule declares none")
    void anUndeclaredCodeFindingIsPlacedNowhere() {
        // Most rules declare nothing. Finding them a default category would put findings into a
        // category nobody claimed.
        Grid grid = OwaspCoverage.assess(new Measurement(
                true, true, true, Map.of(), Set.of(), Map.of("A03", 12L)));

        assertThat(line(grid, "A03").state()).isEqualTo(State.NOT_COVERED);
        assertThat(line(grid, "A03").findings()).isZero();
    }

    @Test
    @DisplayName("carries a sentence an assessor can quote, on every line")
    void everyLineSaysWhy() {
        assertThat(OwaspCoverage.assess(FULL).lines())
                .allSatisfy(line -> assertThat(line.because()).isNotBlank());
    }

    @Test
    @DisplayName("keeps the standard's own order, which is the order the questions come in")
    void keepsTheStandardOrder() {
        assertThat(OwaspCoverage.assess(FULL).lines())
                .extracting(CoverageLine::id)
                .containsExactly("A01", "A02", "A03", "A04", "A05", "A06", "A07", "A08", "A09", "A10");
    }

    private static CoverageLine line(Grid grid, String id) {
        return grid.lines().stream().filter(line -> line.id().equals(id)).findFirst().orElseThrow();
    }

    private static java.util.List<String> states(Grid grid, State state) {
        return grid.lines().stream().filter(line -> line.state() == state).map(CoverageLine::id).toList();
    }
}
