package com.asmolabs.vectispire.common.domain.owasp;

import static com.asmolabs.vectispire.common.domain.owasp.OwaspEvidence.examinedImage;
import static com.asmolabs.vectispire.common.domain.owasp.OwaspEvidence.examinedRepository;
import static com.asmolabs.vectispire.common.domain.owasp.OwaspEvidence.failedRepository;
import static com.asmolabs.vectispire.common.domain.owasp.OwaspEvidence.over;
import static org.assertj.core.api.Assertions.assertThat;

import com.asmolabs.vectispire.common.domain.issues.FindingType;
import com.asmolabs.vectispire.common.domain.owasp.OwaspCoverage.CoverageLine;
import com.asmolabs.vectispire.common.domain.owasp.OwaspCoverage.CoverageReason;
import com.asmolabs.vectispire.common.domain.owasp.OwaspCoverage.Evidence;
import com.asmolabs.vectispire.common.domain.owasp.OwaspCoverage.Gap;
import com.asmolabs.vectispire.common.domain.owasp.OwaspCoverage.GapCount;
import com.asmolabs.vectispire.common.domain.owasp.OwaspCoverage.Grid;
import com.asmolabs.vectispire.common.domain.owasp.OwaspCoverage.Measurement;
import com.asmolabs.vectispire.common.domain.owasp.OwaspCoverage.ReasonCode;
import com.asmolabs.vectispire.common.domain.owasp.OwaspCoverage.State;
import com.asmolabs.vectispire.common.domain.targets.ScanTarget;
import java.util.ArrayList;
import java.util.EnumSet;
import java.util.List;
import java.util.Map;
import java.util.Set;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

/**
 * Each line's reason as a code and its values, beside the English sentence (decision 0019).
 *
 * <p><b>What these cases pin.</b> The grid's {@code because} was the only explanation, built in English on
 * the server and printed as it stood by a French screen. The code is what the screen now translates, so it
 * must say what the sentence says — the sentence is written from it — and its values must be the ones the
 * sentence quotes, never a second count that could drift from the first.
 */
@DisplayName("the OWASP grid's reasons, as codes")
class OwaspCoverageReasonTest {

    private static final Map<FindingType, Long> NOTHING_OPEN = Map.of(
            FindingType.IAC, 0L, FindingType.VULNERABILITY, 0L, FindingType.EOL, 0L, FindingType.SECRET, 0L);

    /** Grids that between them produce every code the rules can reach today. */
    private static List<Grid> everyReachableReason() {
        List<Evidence> scanned = List.of(examinedRepository(1, "A03"));
        List<Grid> grids = new ArrayList<>();
        grids.add(OwaspCoverage.assess(over(scanned, Map.of(FindingType.SECRET, 2L), Set.of("A03"), Map.of())));
        grids.add(OwaspCoverage.assess(over(scanned, NOTHING_OPEN, Set.of("A03"), Map.of())));
        grids.add(OwaspCoverage.assess(new Measurement(true, false, NOTHING_OPEN, Set.of("A03"), Map.of(), scanned)));
        grids.add(OwaspCoverage.assess(over(List.of(), NOTHING_OPEN, Set.of("A03"), Map.of())));
        grids.add(OwaspCoverage.assess(over(List.of(examinedImage(2)), NOTHING_OPEN, Set.of("A03"), Map.of())));
        grids.add(OwaspCoverage.assessTarget(over(List.of(examinedImage(2)), NOTHING_OPEN, Set.of("A03"), Map.of())));
        grids.add(OwaspCoverage.assess(over(
                List.of(examinedRepository(1, "A03"), failedRepository(3), Evidence.neverScanned(new ScanTarget.Repository(4))),
                NOTHING_OPEN, Set.of("A03"), Map.of())));
        return grids;
    }

    @Test
    @DisplayName("every line's sentence is its reason written in English, and every code but the unreachable two is produced")
    void theSentenceIsTheReasonInEnglish() {
        Set<ReasonCode> produced = EnumSet.noneOf(ReasonCode.class);
        for (Grid grid : everyReachableReason()) {
            for (CoverageLine line : grid.lines()) {
                assertThat(line.because()).as(line.id()).isEqualTo(line.reason().sentence());
                produced.add(line.reason().code());
            }
        }
        // No category is placed by switchable types alone — end of life shares A06 with the
        // vulnerabilities — so the two "detection is off" codes answer a switch that does not exist yet.
        assertThat(produced).isEqualTo(EnumSet.complementOf(
                EnumSet.of(ReasonCode.DETECTION_OFF, ReasonCode.DETECTION_AND_CODE_ANALYSIS_OFF)));
    }

    @Test
    @DisplayName("each state is explained by a code of its own state, and a scope's grid never by a target's own")
    void codesBelongToTheirStates() {
        Grid scope = OwaspCoverage.assess(over(List.of(examinedImage(2)), NOTHING_OPEN, Set.of("A03"), Map.of()));
        Grid target = OwaspCoverage.assessTarget(over(List.of(examinedImage(2)), NOTHING_OPEN, Set.of("A03"), Map.of()));

        assertThat(line(scope, "A07").reason().code()).isEqualTo(ReasonCode.NO_EXAMINABLE_TARGET_IN_SCOPE);
        assertThat(line(scope, "A07").state()).isEqualTo(State.NOT_MEASURED);
        assertThat(line(scope, "A03").reason().code()).isEqualTo(ReasonCode.NO_REPOSITORY_IN_SCOPE);
        assertThat(line(target, "A07").reason().code()).isEqualTo(ReasonCode.TARGET_KIND_NOT_EXAMINED);
        assertThat(line(target, "A07").state()).isEqualTo(State.NOT_COVERED);
        assertThat(line(target, "A03").reason().code()).isEqualTo(ReasonCode.CODE_ANALYSIS_READS_REPOSITORIES_ONLY);
    }

    @Test
    @DisplayName("names the types it speaks of by their wire names, as the sentence does")
    void typesAreWireNames() {
        Grid grid = OwaspCoverage.assess(over(List.of(examinedRepository(1)), NOTHING_OPEN, Set.of(), Map.of()));

        CoverageReason a06 = line(grid, "A06").reason();
        assertThat(a06.code()).isEqualTo(ReasonCode.EXAMINED_NOTHING_OPEN);
        assertThat(a06.types()).containsExactly("vulnerability", "eol");
        assertThat(a06.missing()).isNull();
        assertThat(a06.gaps()).isEmpty();

        Grid noEndOfLife = OwaspCoverage.assess(
                new Measurement(false, true, NOTHING_OPEN, Set.of(), Map.of(), List.of(examinedRepository(1))));
        assertThat(line(noEndOfLife, "A06").reason().types())
                .as("a type switched off examined nothing, and is not named as having done so")
                .containsExactly("vulnerability");
        assertThat(line(grid, "A01").reason().types()).isEmpty();
    }

    @Test
    @DisplayName("an unexamined scope carries how many, out of how many, and why — the sentence's own figures")
    void unexaminedCarriesItsCounts() {
        Grid grid = OwaspCoverage.assess(over(
                List.of(examinedRepository(1, "A03"), failedRepository(2), failedRepository(3),
                        Evidence.neverScanned(new ScanTarget.Repository(4)), examinedImage(5)),
                NOTHING_OPEN, Set.of("A03"), Map.of()));

        CoverageReason secrets = line(grid, "A07").reason();
        assertThat(secrets.code()).isEqualTo(ReasonCode.TARGETS_NOT_EXAMINED);
        assertThat(secrets.types()).containsExactly("secret");
        assertThat(secrets.missing()).isEqualTo(3L);
        assertThat(secrets.applicable()).as("the image is not a target secrets apply to").isEqualTo(4L);
        assertThat(secrets.gaps()).containsExactly(new GapCount(Gap.NEVER_SCANNED, 1), new GapCount(Gap.LAST_SCAN_FAILED, 2));
        assertThat(line(grid, "A07").because()).startsWith("3 of 4 targets this category applies to were not examined");

        CoverageReason injection = line(grid, "A03").reason();
        assertThat(injection.code()).isEqualTo(ReasonCode.REPOSITORIES_NOT_EXAMINED);
        assertThat(injection.types()).isEmpty();
        assertThat(injection.missing()).isEqualTo(3L);
        assertThat(injection.applicable()).isEqualTo(4L);
    }

    @Test
    @DisplayName("the two codes no rule reaches today still name their types in the sentence")
    void theUnreachableCodesStillSaySomething() {
        CoverageReason off = new CoverageReason(ReasonCode.DETECTION_OFF, List.of("eol"), null, null, List.of());
        CoverageReason both = new CoverageReason(ReasonCode.DETECTION_AND_CODE_ANALYSIS_OFF, List.of("eol"), null, null, null);

        assertThat(off.sentence()).isEqualTo("Detection is switched off for eol, so this category is not measured.");
        assertThat(both.sentence()).contains("eol", "code analysis is off");
        assertThat(both.gaps()).isEmpty();
    }

    private static CoverageLine line(Grid grid, String id) {
        return grid.lines().stream().filter(line -> line.id().equals(id)).findFirst().orElseThrow();
    }
}
