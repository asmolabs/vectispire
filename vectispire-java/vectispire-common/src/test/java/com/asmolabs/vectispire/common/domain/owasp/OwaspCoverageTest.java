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
    @DisplayName("ne place aucun constat de code sur son seul type, la catégorie n'en étant pas une propriété")
    void codeAnalysisIsNotPlacedByItsType() {
        // Une règle Semgrep trouve des injections, une autre des SSRF : le type ne dit rien de la
        // catégorie, et c'est pour cela que la déclaration voyage avec le constat.
        assertThat(OwaspCoverage.categoryOf(FindingType.SAST))
                .as("placer un constat de code en lisant des morceaux de son identifiant de règle "
                        + "serait reproductible et resterait une supposition")
                .isEmpty();
        assertThat(OwaspCoverage.categoryOf(FindingType.LICENSE)).isEmpty();
        assertThat(OwaspCoverage.categoryOf(FindingType.QUALITY)).isEmpty();
    }


    @Test
    @DisplayName("ouvre une catégorie qu'aucun type ne couvre, dès qu'une règle installée la déclare")
    void aDeclaredCategoryBecomesCovered() {
        // A03 — Injection — n'est couverte par aucun type de constat. Elle l'est dès qu'une règle
        // d'analyse de code le déclare dans ses propres métadonnées, et c'est ce qui la fait
        // sortir de « rien ici ne regarde ça ».
        Grid grid = OwaspCoverage.assess(new Measurement(
                true, true, true, Map.of(), Set.of("A03"), Map.of("A03", 4L)));

        assertThat(line(grid, "A03").state()).isEqualTo(State.FINDINGS);
        assertThat(line(grid, "A03").findings()).isEqualTo(4);
        assertThat(grid.covered())
                .as("les trois d'origine, plus celle que les règles installées déclarent")
                .isEqualTo(4);
        assertThat(states(grid, State.NOT_COVERED)).containsExactly("A01", "A02", "A04", "A08", "A09", "A10");
    }

    @Test
    @DisplayName("dit « regardée, rien à signaler » pour une catégorie déclarée sans constat")
    void aDeclaredCategoryWithoutFindingsIsClean() {
        // **Le cas qui justifie de lire les règles plutôt que les constats.** Dériver la
        // couverture des constats ferait sortir A03 de la grille le jour où son dernier constat
        // est corrigé — c'est-à-dire au moment où elle mérite le plus de dire qu'elle a été
        // regardée.
        Grid grid = OwaspCoverage.assess(new Measurement(
                true, true, true, Map.of(), Set.of("A03"), Map.of()));

        assertThat(line(grid, "A03").state()).isEqualTo(State.NO_FINDING);
        assertThat(line(grid, "A03").because()).contains("code analysis");
    }

    @Test
    @DisplayName("une catégorie déclarée reste non mesurée quand l'analyse de code n'atteint rien")
    void aDeclaredCategoryUnreached() {
        Grid grid = OwaspCoverage.assess(new Measurement(
                true, true, false, Map.of(), Set.of("A03"), Map.of("A03", 4L)));

        assertThat(line(grid, "A03").state()).isEqualTo(State.NOT_MEASURED);
        assertThat(line(grid, "A03").findings())
                .as("des constats d'hier ne mesurent pas aujourd'hui : le compte serait lu comme un résultat")
                .isZero();
        assertThat(line(grid, "A03").because()).contains("Code analysis is off");
    }

    @Test
    @DisplayName("additionne un type et l'analyse de code quand les deux couvrent la même catégorie")
    void aCategoryCoveredTwice() {
        // A05 est couverte par les contrôles d'infrastructure, et une règle de code peut la
        // déclarer aussi. Les deux comptes s'ajoutent — ce sont des constats distincts.
        Grid grid = OwaspCoverage.assess(new Measurement(
                true, true, true, Map.of(FindingType.IAC, 3L), Set.of("A05"), Map.of("A05", 2L)));

        assertThat(line(grid, "A05").findings()).isEqualTo(5);
        assertThat(line(grid, "A05").state()).isEqualTo(State.FINDINGS);
    }

    @Test
    @DisplayName("n'ajoute pas les constats de code à une catégorie que l'analyse ne mesure plus")
    void unreachedCodeFindingsAreNotAdded() {
        // A05 est mesurée par les contrôles d'infrastructure ; l'analyse de code, elle, n'atteint
        // rien. Ses constats d'hier existent toujours — éteindre un détecteur ne les résout pas —
        // et les additionner ici les ferait passer pour une mesure d'aujourd'hui, sous une
        // catégorie qui, elle, est bien mesurée. C'est la pire forme du défaut : un chiffre juste
        // au mauvais endroit, dans une ligne verte par ailleurs.
        Grid grid = OwaspCoverage.assess(new Measurement(
                true, true, false, Map.of(FindingType.IAC, 3L), Set.of("A05"), Map.of("A05", 7L)));

        assertThat(line(grid, "A05").state()).isEqualTo(State.FINDINGS);
        assertThat(line(grid, "A05").findings())
                .as("les trois de l'infrastructure, et rien de l'analyse de code qui ne mesure pas")
                .isEqualTo(3);
        assertThat(line(grid, "A05").because()).doesNotContain("code analysis");
    }

    @Test
    @DisplayName("nomme les deux moitiés éteintes plutôt qu'une seule")
    void bothHalvesOff() {
        // A06 est couverte par grype et par la fin de vie ; si une règle de code la déclare aussi
        // et que l'analyse n'atteint rien, dire une seule des deux causes enverrait quelqu'un
        // rallumer un détecteur qui tournait déjà.
        Grid grid = OwaspCoverage.assess(new Measurement(
                true, false, false, Map.of(), Set.of("A06"), Map.of()));

        assertThat(line(grid, "A06").state())
                .as("grype mesure toujours A06 : la catégorie reste mesurée")
                .isEqualTo(State.NO_FINDING);
    }

    @Test
    @DisplayName("un constat de code n'entre dans aucune catégorie quand sa règle n'en déclare pas")
    void anUndeclaredCodeFindingIsPlacedNowhere() {
        // La plupart des règles ne déclarent rien. Leur trouver une catégorie par défaut ferait
        // entrer des constats dans une catégorie que personne n'a revendiquée.
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
