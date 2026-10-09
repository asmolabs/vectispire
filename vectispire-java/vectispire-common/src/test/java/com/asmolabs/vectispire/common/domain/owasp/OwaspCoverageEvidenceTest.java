package com.asmolabs.vectispire.common.domain.owasp;

import static com.asmolabs.vectispire.common.domain.owasp.OwaspEvidence.EVERY_STEP;
import static com.asmolabs.vectispire.common.domain.owasp.OwaspEvidence.examinedImage;
import static com.asmolabs.vectispire.common.domain.owasp.OwaspEvidence.examinedRepository;
import static com.asmolabs.vectispire.common.domain.owasp.OwaspEvidence.failedRepository;
import static com.asmolabs.vectispire.common.domain.owasp.OwaspEvidence.over;
import static com.asmolabs.vectispire.common.domain.owasp.OwaspEvidence.repository;
import static org.assertj.core.api.Assertions.assertThat;

import com.asmolabs.vectispire.common.domain.gate.Observation;
import com.asmolabs.vectispire.common.domain.issues.FindingType;
import com.asmolabs.vectispire.common.domain.owasp.OwaspCoverage.CoverageLine;
import com.asmolabs.vectispire.common.domain.owasp.OwaspCoverage.Evidence;
import com.asmolabs.vectispire.common.domain.owasp.OwaspCoverage.Grid;
import com.asmolabs.vectispire.common.domain.owasp.OwaspCoverage.Measurement;
import com.asmolabs.vectispire.common.domain.owasp.OwaspCoverage.Split;
import com.asmolabs.vectispire.common.domain.owasp.OwaspCoverage.State;
import com.asmolabs.vectispire.common.domain.plugins.Language;
import com.asmolabs.vectispire.common.domain.targets.ScanTarget;
import java.util.ArrayList;
import java.util.EnumMap;
import java.util.EnumSet;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.Set;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

/**
 * What a category's "nothing found" rests on: the latest scan of every target it applies to having
 * examined it (decision 0007 — absent is not empty).
 *
 * <p><b>The defect these cases pin.</b> The grid read a category measured as soon as anything in scope had
 * a scan. An image's scan reads its dependencies only, so an image-only project showed A05 and A07 — IaC,
 * secrets — as clean; a repository whose secret step failed showed A07 clean on the strength of the
 * steps that did not; and one Python rule declaring A03 made Injection clean for every Java project.
 */
@DisplayName("the OWASP grid, read over what each target's latest scan examined")
class OwaspCoverageEvidenceTest {

    private static final Map<FindingType, Long> NOTHING_OPEN = Map.of(
            FindingType.IAC, 0L, FindingType.VULNERABILITY, 0L, FindingType.EOL, 0L, FindingType.SECRET, 0L);

    @Test
    @DisplayName("an image-only scope is examined for its dependencies, and for neither secrets nor misconfiguration")
    void anImageOnlyScope() {
        Grid grid = OwaspCoverage.assess(over(List.of(examinedImage(1), examinedImage(2)), NOTHING_OPEN, Set.of(), Map.of()));

        assertThat(line(grid, "A06").state()).isEqualTo(State.NO_FINDING);
        assertThat(line(grid, "A05").state()).isEqualTo(State.NOT_MEASURED);
        assertThat(line(grid, "A07").state()).isEqualTo(State.NOT_MEASURED);
        assertThat(line(grid, "A07").because()).startsWith("No target in this scope can be examined for secret");
        assertThat(line(grid, "A05").because()).contains("iac");
    }

    @Test
    @DisplayName("a repository whose latest scan did not produce its secret step leaves A07 unmeasured, and only A07")
    void aStepThatDidNotRun() {
        Set<FindingType> noSecrets = EnumSet.copyOf(EVERY_STEP);
        noSecrets.remove(FindingType.SECRET);
        Grid grid = OwaspCoverage.assess(over(List.of(repository(1, noSecrets)), NOTHING_OPEN, Set.of(), Map.of()));

        assertThat(line(grid, "A07").state()).isEqualTo(State.NOT_MEASURED);
        assertThat(line(grid, "A07").because())
                .isEqualTo("1 of 1 target this category applies to was not examined for it by secret (1 whose latest "
                        + "scan did not complete that step), so a zero here would not be a result.");
        assertThat(line(grid, "A05").state()).isEqualTo(State.NO_FINDING);
        assertThat(line(grid, "A06").state()).isEqualTo(State.NO_FINDING);
    }

    @Test
    @DisplayName("a scope examined in part is not measured, and says how many were not and why")
    void aMixedScope() {
        Grid grid = OwaspCoverage.assess(over(
                List.of(examinedRepository(1), failedRepository(2), Evidence.neverScanned(new ScanTarget.Repository(3)),
                        unrecorded(4)),
                NOTHING_OPEN, Set.of(), Map.of()));

        assertThat(line(grid, "A07").state())
                .as("nothing found over a quarter of the scope is the false green this removes")
                .isEqualTo(State.NOT_MEASURED);
        assertThat(line(grid, "A07").because()).startsWith("3 of 4 targets this category applies to were not examined")
                .contains("1 never finished a scan", "1 whose latest scan failed",
                        "1 whose latest scan predates the record of what it examined");
    }

    @Test
    @DisplayName("a target nothing can examine for a category is left aside, not counted against the scope")
    void anImageBesideARepository() {
        Grid grid = OwaspCoverage.assess(over(List.of(examinedRepository(1), examinedImage(2)), NOTHING_OPEN, Set.of(), Map.of()));

        assertThat(line(grid, "A07").state()).isEqualTo(State.NO_FINDING);
        assertThat(line(grid, "A05").state()).isEqualTo(State.NO_FINDING);
        assertThat(line(grid, "A06").state()).isEqualTo(State.NO_FINDING);
    }

    @Test
    @DisplayName("open findings read as findings whatever examined the target since")
    void findingsStayFindings() {
        Grid grid = OwaspCoverage.assess(over(List.of(failedRepository(1), examinedImage(2)),
                Map.of(FindingType.SECRET, 2L, FindingType.IAC, 0L, FindingType.VULNERABILITY, 1L), Set.of(), Map.of()));

        assertThat(line(grid, "A07").state()).as("a secret found before the scan that failed is still open").isEqualTo(State.FINDINGS);
        assertThat(line(grid, "A07").findings()).isEqualTo(2);
        assertThat(line(grid, "A06").state()).isEqualTo(State.FINDINGS);
        assertThat(line(grid, "A05").state()).isEqualTo(State.NOT_MEASURED);
    }

    @Test
    @DisplayName("A06 asks for both halves the settings measure: an end-of-life lookup that failed leaves it unmeasured")
    void bothHalvesOfA06() {
        Set<FindingType> noEndOfLife = EnumSet.copyOf(EVERY_STEP);
        noEndOfLife.remove(FindingType.EOL);
        List<Evidence> one = List.of(repository(1, noEndOfLife));

        assertThat(line(OwaspCoverage.assess(over(one, NOTHING_OPEN, Set.of(), Map.of())), "A06").state())
                .isEqualTo(State.NOT_MEASURED);
        assertThat(line(OwaspCoverage.assess(new Measurement(false, true, NOTHING_OPEN, Set.of(), Map.of(), one)), "A06").state())
                .as("end of life switched off: the vulnerabilities alone measure it")
                .isEqualTo(State.NO_FINDING);
    }

    @Test
    @DisplayName("a declared category is measured on a repository only when a rule for one of its languages declares it")
    void codeAnalysisPerLanguage() {
        Set<String> declared = Set.of("A02", "A03");

        Grid javaOnlyA02 = OwaspCoverage.assess(over(List.of(examinedRepository(1, "A02")), Map.of(), declared, Map.of()));
        assertThat(line(javaOnlyA02, "A03").state())
                .as("an A03 rule for Python says nothing of a Java repository")
                .isEqualTo(State.NOT_MEASURED);
        assertThat(line(javaOnlyA02, "A03").because())
                .contains("1 in whose languages no installed rule declares this category");
        assertThat(line(javaOnlyA02, "A02").state()).isEqualTo(State.NO_FINDING);

        assertThat(line(OwaspCoverage.assess(over(List.of(examinedRepository(1, "A03")), Map.of(), declared, Map.of())), "A03")
                        .state())
                .isEqualTo(State.NO_FINDING);

        Set<FindingType> noSast = EnumSet.copyOf(EVERY_STEP);
        noSast.remove(FindingType.SAST);
        assertThat(line(OwaspCoverage.assess(over(List.of(repository(1, noSast, "A03")), Map.of(), declared, Map.of())), "A03")
                        .because())
                .contains("1 whose latest scan did not complete that step");

        Evidence uncounted = new Evidence(new ScanTarget.Repository(1), Observation.OK, Optional.of(EVERY_STEP),
                Optional.empty(), Optional.empty());
        assertThat(line(OwaspCoverage.assess(over(List.of(uncounted), Map.of(), declared, Map.of())), "A03").because())
                .contains("1 whose latest scan did not record its languages, or its rules'");

        assertThat(line(OwaspCoverage.assess(over(List.of(examinedRepository(1, "A02"), examinedRepository(2, "A03")),
                                Map.of(), declared, Map.of())), "A03")
                        .state())
                .as("one repository of two reached is not the scope reached")
                .isEqualTo(State.NOT_MEASURED);
    }

    @Test
    @DisplayName("code findings count whatever the rules reach, and a scope holding no repository has no code to read")
    void codeAnalysisFindingsAndImages() {
        Grid reached = OwaspCoverage.assess(over(List.of(examinedRepository(1, "A02")), Map.of(), Set.of("A03"),
                Map.of("A03", 2L)));
        assertThat(line(reached, "A03").state()).isEqualTo(State.FINDINGS);
        assertThat(line(reached, "A03").findings()).isEqualTo(2);

        Grid images = OwaspCoverage.assess(over(List.of(examinedImage(1)), Map.of(), Set.of("A03"), Map.of()));
        assertThat(line(images, "A03").state())
                .as("not covered, for the fold's reason: a recorded week cannot say whether a rule declared it")
                .isEqualTo(State.NOT_COVERED);
    }

    @Test
    @DisplayName("a target's own line reads not covered where nothing can examine that kind of target")
    void aTargetsOwnLine() {
        Grid image = OwaspCoverage.assessTarget(over(List.of(examinedImage(1)), NOTHING_OPEN, Set.of("A03"), Map.of()));

        assertThat(line(image, "A07").state()).isEqualTo(State.NOT_COVERED);
        assertThat(line(image, "A05").state()).isEqualTo(State.NOT_COVERED);
        assertThat(line(image, "A03").state()).isEqualTo(State.NOT_COVERED);
        assertThat(line(image, "A06").state()).isEqualTo(State.NO_FINDING);

        Measurement repository = over(List.of(failedRepository(1)), NOTHING_OPEN, Set.of("A03"), Map.of());
        assertThat(OwaspCoverage.assessTarget(repository))
                .as("for a repository, its own line and the scope of it alone are the same grid")
                .isEqualTo(OwaspCoverage.assess(repository));
    }

    @Test
    @DisplayName("evidence: the tree's languages its rules read, the categories their rules declare, nothing from a failed scan")
    void evidenceOfAScan() {
        Map<Language, Set<String>> declared = Map.of(Language.PYTHON, Set.of("A03"), Language.JAVA, Set.of("A02"));
        ScanTarget target = new ScanTarget.Repository(1);

        Evidence java = Evidence.of(target, Observation.OK, Optional.of(EVERY_STEP),
                Optional.of(Set.of(Language.JAVA, Language.YAML)), Optional.of(Set.of(Language.JAVA, Language.PYTHON)), declared);
        assertThat(java.analysed()).contains(Set.of(Language.JAVA));
        assertThat(java.codeReaches()).as("the Python rule's A03 is not this tree's").contains(Set.of("A02"));

        Evidence unread = Evidence.of(target, Observation.OK, Optional.of(EVERY_STEP),
                Optional.of(Set.of(Language.GO)), Optional.of(Set.of(Language.JAVA)), declared);
        assertThat(unread.analysed()).contains(Set.of());
        assertThat(unread.codeReaches()).as("counted, and no rule reads it: the empty set").contains(Set.of());

        assertThat(Evidence.of(target, Observation.OK, Optional.of(EVERY_STEP), Optional.empty(),
                        Optional.of(Set.of(Language.JAVA)), declared).codeReaches())
                .as("nobody counted the tree: unknown, not the empty set")
                .isEmpty();

        assertThat(Evidence.of(target, Observation.LAST_SCAN_FAILED, Optional.of(EVERY_STEP), Optional.empty(),
                        Optional.empty(), declared).examined())
                .as("a failed scan's record is no examination")
                .isEmpty();
    }

    /**
     * <b>A scope's grid is the fold of its targets' lines</b> — what lets the weekly record, kept per
     * target, show for a project the grid the screen shows beside it. Every scope of up to three targets
     * drawn from the kinds of evidence there are, with findings or none, settled or not, read under both
     * settings of code analysis and end of life: the scope's line and the fold of the targets' agree on
     * the state and on both counts, for every category.
     */
    @Test
    @DisplayName("a scope's grid is the fold of its targets' own lines, for every scope of up to three targets")
    void theScopeIsTheFoldOfItsTargets() {
        Set<FindingType> noSecrets = EnumSet.copyOf(EVERY_STEP);
        noSecrets.remove(FindingType.SECRET);
        List<Evidence> kinds = List.of(
                examinedRepository(1, "A03"),
                examinedRepository(2, "A02"),
                repository(3, noSecrets, "A03"),
                failedRepository(4),
                Evidence.neverScanned(new ScanTarget.Repository(5)),
                unrecorded(6),
                examinedImage(7),
                Evidence.neverScanned(new ScanTarget.Container(8)));
        List<Map<FindingType, Long>> backlogs = List.of(
                Map.of(),
                Map.of(FindingType.SECRET, 1L),
                Map.of(FindingType.VULNERABILITY, 2L, FindingType.EOL, 1L));

        int compared = 0;
        for (List<Evidence> scope : scopes(kinds)) {
            for (int variant = 0; variant < backlogs.size(); variant++) {
                for (boolean code : List.of(true, false)) {
                    for (boolean endOfLife : List.of(true, false)) {
                        compared += compare(scope, variant, backlogs, code, endOfLife);
                    }
                }
            }
        }
        assertThat(compared).as("the scopes were all compared").isGreaterThan(1_000);
    }

    private static int compare(List<Evidence> scope, int variant, List<Map<FindingType, Long>> backlogs,
            boolean code, boolean endOfLife) {
        Set<String> declared = Set.of("A02", "A03");
        // Each target holds the variant's backlog, unsettled, plus one settled secret on the first one —
        // so the counts are a sum over targets the fold has to reproduce.
        Map<FindingType, Long> unsettledSum = new EnumMap<>(FindingType.class);
        Map<FindingType, Long> allSum = new EnumMap<>(FindingType.class);
        Map<String, Long> codeUnsettledSum = new HashMap<>();
        Map<String, Long> codeAllSum = new HashMap<>();
        List<List<Split>> perTarget = new ArrayList<>();
        for (int index = 0; index < scope.size(); index++) {
            Evidence evidence = scope.get(index);
            boolean repository = evidence.target() instanceof ScanTarget.Repository;
            Map<FindingType, Long> unsettled = new EnumMap<>(FindingType.class);
            backlogs.get(variant).forEach((type, count) -> {
                if (repository || OwaspCoverage.examinable(type, evidence.target())) {
                    unsettled.put(type, count);
                }
            });
            Map<FindingType, Long> all = new EnumMap<>(unsettled);
            if (index == 0 && repository) {
                all.merge(FindingType.SECRET, 1L, Long::sum);
            }
            Map<String, Long> codeUnsettled = repository && variant == 1 ? Map.of("A03", 1L) : Map.of();
            Map<String, Long> codeAll = codeUnsettled;
            unsettled.forEach((type, count) -> unsettledSum.merge(type, count, Long::sum));
            all.forEach((type, count) -> allSum.merge(type, count, Long::sum));
            codeUnsettled.forEach((category, count) -> codeUnsettledSum.merge(category, count, Long::sum));
            codeAll.forEach((category, count) -> codeAllSum.merge(category, count, Long::sum));
            perTarget.add(OwaspCoverage.split(
                    OwaspCoverage.assessTarget(new Measurement(endOfLife, code, unsettled, declared, codeUnsettled, List.of(evidence))),
                    OwaspCoverage.assessTarget(new Measurement(endOfLife, code, all, declared, codeAll, List.of(evidence)))));
        }
        List<Split> scoped = OwaspCoverage.split(
                OwaspCoverage.assess(new Measurement(endOfLife, code, unsettledSum, declared, codeUnsettledSum, scope)),
                OwaspCoverage.assess(new Measurement(endOfLife, code, allSum, declared, codeAllSum, scope)));
        for (Split line : scoped) {
            List<Split> lines = perTarget.stream()
                    .map(target -> target.stream().filter(one -> one.id().equals(line.id())).findFirst().orElseThrow())
                    .toList();
            assertThat(OwaspCoverage.acrossTargets(line.id(), lines))
                    .as("%s over %s, backlog %d, code %s, end of life %s", line.id(), scope, variant, code, endOfLife)
                    .contains(line);
        }
        return scoped.size();
    }

    /** Every non-empty scope of up to three distinct kinds of evidence. */
    private static List<List<Evidence>> scopes(List<Evidence> kinds) {
        List<List<Evidence>> scopes = new ArrayList<>();
        for (int a = 0; a < kinds.size(); a++) {
            scopes.add(List.of(kinds.get(a)));
            for (int b = a + 1; b < kinds.size(); b++) {
                scopes.add(List.of(kinds.get(a), kinds.get(b)));
                for (int c = b + 1; c < kinds.size(); c++) {
                    scopes.add(List.of(kinds.get(a), kinds.get(b), kinds.get(c)));
                }
            }
        }
        return scopes;
    }

    /** A completed scan from before {@code examined_types}: it ran, and nothing says what it examined. */
    private static Evidence unrecorded(long id) {
        return new Evidence(new ScanTarget.Repository(id), Observation.OK, Optional.empty(), Optional.empty(), Optional.empty());
    }

    private static CoverageLine line(Grid grid, String id) {
        return grid.lines().stream().filter(line -> line.id().equals(id)).findFirst().orElseThrow();
    }
}
