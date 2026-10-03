package com.asmolabs.vectispire.common.domain.scorecard;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

import com.asmolabs.vectispire.common.domain.errors.InvalidInputException;
import com.asmolabs.vectispire.common.domain.scorecard.CandidateScore.Counts;
import com.asmolabs.vectispire.common.domain.scorecard.CandidateScore.Weights;
import java.util.List;
import java.util.function.UnaryOperator;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.CsvSource;

@DisplayName("the candidate score (experimental, wired to no grade)")
class CandidateScoreTest {

    private static final Weights PROPOSED = Weights.PROPOSED;

    /** One more issue of each class, in turn. */
    private static final List<UnaryOperator<Counts>> ONE_MORE = List.of(
            c -> new Counts(c.exploited() + 1, c.critical(), c.high(), c.medium(), c.low()),
            c -> new Counts(c.exploited(), c.critical() + 1, c.high(), c.medium(), c.low()),
            c -> new Counts(c.exploited(), c.critical(), c.high() + 1, c.medium(), c.low()),
            c -> new Counts(c.exploited(), c.critical(), c.high(), c.medium() + 1, c.low()),
            c -> new Counts(c.exploited(), c.critical(), c.high(), c.medium(), c.low() + 1));

    private static final List<Counts> BACKLOGS = List.of(
            Counts.NONE,
            new Counts(0, 1, 0, 0, 0),
            new Counts(0, 0, 0, 50, 0),
            new Counts(0, 0, 27, 0, 0),
            new Counts(4, 0, 0, 0, 0),
            new Counts(1, 3, 12, 80, 200));

    @Test
    @DisplayName("an empty backlog scores 100, A+")
    void emptyBacklog() {
        assertThat(CandidateScore.of(Counts.NONE, PROPOSED))
                .isEqualTo(new CandidateScore.Result(100, SecurityGrade.A_PLUS));
    }

    @Test
    @DisplayName("any issue of any class lowers the exact score, and more issues never raise the shown one")
    void monotonic() {
        for (Counts backlog : BACKLOGS) {
            for (UnaryOperator<Counts> more : ONE_MORE) {
                Counts larger = more.apply(backlog);
                assertThat(CandidateScore.exact(larger, PROPOSED))
                        .as("%s then %s", backlog, larger)
                        .isLessThan(CandidateScore.exact(backlog, PROPOSED));
                assertThat(CandidateScore.of(larger, PROPOSED).score())
                        .as("%s then %s", backlog, larger)
                        .isLessThanOrEqualTo(CandidateScore.of(backlog, PROPOSED).score());
            }
        }
    }

    /**
     * The saturation the candidate exists to remove: in production fifty and five hundred mediums
     * both read A+ (mediums weigh nothing), and twenty-seven highs read 0 like two hundred do.
     */
    @Test
    @DisplayName("fifty and five hundred mediums no longer read the same grade, nor do 27 highs and 4 exploited criticals")
    void noSaturationAtTheSizesThatMatter() {
        assertThat(CandidateScore.of(new Counts(0, 0, 0, 50, 0), PROPOSED).grade())
                .isNotEqualTo(CandidateScore.of(new Counts(0, 0, 0, 500, 0), PROPOSED).grade());
        assertThat(CandidateScore.exact(new Counts(0, 0, 0, 500, 0), PROPOSED))
                .isLessThan(CandidateScore.exact(new Counts(0, 0, 0, 50, 0), PROPOSED));
        assertThat(CandidateScore.exact(new Counts(0, 0, 270, 0, 0), PROPOSED))
                .isGreaterThan(0)
                .isLessThan(CandidateScore.exact(new Counts(0, 0, 27, 0, 0), PROPOSED));
    }

    @Test
    @DisplayName("never reaches zero for a finite backlog, however large")
    void neverZero() {
        Counts enormous = new Counts(1_000_000, 1_000_000, 1_000_000, 1_000_000, 1_000_000);
        assertThat(CandidateScore.of(enormous, PROPOSED).score()).isEqualTo(1);
        assertThat(CandidateScore.of(new Counts(0, 0, 0, 500, 0), PROPOSED).score()).isPositive();
    }

    @Test
    @DisplayName("an exploited issue caps the grade at D, however light its weight")
    void exploitedCap() {
        Weights featherweight = new Weights(0.001, 10, 4, 1, 0.25, 55);
        CandidateScore.Result one = CandidateScore.of(new Counts(1, 0, 0, 0, 0), featherweight);
        assertThat(one.score()).isEqualTo(CandidateScore.EXPLOITED_CAP);
        assertThat(one.grade()).isEqualTo(SecurityGrade.D);

        // Below the cap the formula decides: the cap never raises a score.
        CandidateScore.Result many = CandidateScore.of(new Counts(4, 0, 0, 0, 0), PROPOSED);
        assertThat(many.score()).isLessThan(CandidateScore.EXPLOITED_CAP);
        assertThat(many.grade()).isEqualTo(SecurityGrade.F);
    }

    /** The calibration targets the javadoc of {@link Weights#PROPOSED} states, read at those weights. */
    @ParameterizedTest(name = "{0} exploited, {1} critical, {2} high, {3} medium, {4} low: {5}, {6}")
    @CsvSource({
            "0, 1,  0,   0, 0, 83, B",
            "1, 0,  0,   0, 0, 54, D",
            "0, 0,  0,  50, 0, 40, D",
            "0, 0,  0, 500, 0,  1, F",
            "0, 0, 27,   0, 0,  14, F",
            "4, 0,  0,   0, 0,  16, F",
            "0, 0,  0,  10, 0, 83, B",
            "0, 0,  0,   0, 4, 98, A_PLUS",
    })
    void calibration(long exploited, long critical, long high, long medium, long low, int score, SecurityGrade grade) {
        assertThat(CandidateScore.of(new Counts(exploited, critical, high, medium, low), PROPOSED))
                .isEqualTo(new CandidateScore.Result(score, grade));
    }

    @Test
    @DisplayName("a medium at half weight meets the third target too: fifty mediums read C")
    void halfWeightMediums() {
        Weights halfMedium = new Weights(25, 10, 4, 0.5, 0.25, 55);
        assertThat(CandidateScore.of(new Counts(0, 0, 0, 50, 0), halfMedium).grade()).isEqualTo(SecurityGrade.C);
        assertThat(CandidateScore.of(new Counts(0, 1, 0, 0, 0), halfMedium).grade()).isEqualTo(SecurityGrade.B);
    }

    @ParameterizedTest
    @CsvSource({"-1, 55", "NaN, 55", "Infinity, 55", "1, 0", "1, -3", "2000000, 55"})
    @DisplayName("refuses a weight or a k it cannot use, in words")
    void refusesParameters(double medium, double k) {
        assertThatThrownBy(() -> new Weights(25, 10, 4, medium, 0.25, k))
                .isInstanceOf(InvalidInputException.class);
    }
}
