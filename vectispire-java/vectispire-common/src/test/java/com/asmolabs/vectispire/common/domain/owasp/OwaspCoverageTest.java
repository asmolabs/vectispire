package com.asmolabs.vectispire.common.domain.owasp;

import static org.assertj.core.api.Assertions.assertThat;

import com.asmolabs.vectispire.common.domain.issues.FindingType;
import com.asmolabs.vectispire.common.domain.owasp.OwaspCoverage.Grid;
import com.asmolabs.vectispire.common.domain.owasp.OwaspCoverage.CoverageLine;
import com.asmolabs.vectispire.common.domain.owasp.OwaspCoverage.Measurement;
import com.asmolabs.vectispire.common.domain.owasp.OwaspCoverage.State;
import java.util.Map;
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
                .as("« vulnérable *et obsolète* » nomme les deux moitiés")
                .isEqualTo(16);
    }

    @Test
    @DisplayName("reports a switched-off detector as unmeasured, never as clean")
    void switchedOffIsNotClean() {
        Grid grid = OwaspCoverage.assess(new Measurement(
                true, false, true, Map.of(FindingType.VULNERABILITY, 0L)));

        // A06 reste mesuré par grype même sans fin de vie : c'est l'addition qui perd une moitié,
        // pas la catégorie qui disparaît.
        assertThat(line(grid, "A06").state()).isEqualTo(State.NO_FINDING);
        assertThat(line(grid, "A06").because()).doesNotContain("eol");
    }

    @Test
    @DisplayName("counts nothing for a detector that is off, even when its backlog is not empty")
    void aSwitchedOffDetectorContributesNothing() {
        // Éteindre la détection laisse les constats ouverts plutôt que de les résoudre — c'est
        // délibéré côté produit. Les compter ici ferait dire à la grille qu'on mesure encore.
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
                .as("un parc jamais scanné n'a aucune catégorie propre")
                .isEmpty();
    }

    @Test
    @DisplayName("places no code finding, because no rule in this product declares where it goes")
    void codeAnalysisPlacesNothing() {
        assertThat(OwaspCoverage.categoryOf(FindingType.SAST))
                .as("placer un constat de code en lisant des morceaux de son identifiant de règle "
                        + "serait reproductible et resterait une supposition")
                .isEmpty();
        assertThat(OwaspCoverage.categoryOf(FindingType.LICENSE)).isEmpty();
        assertThat(OwaspCoverage.categoryOf(FindingType.QUALITY)).isEmpty();
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
