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
            c -> new Counts(c.exploited() + 1, c.critical(), c.high(), c.medium(), c.low(), c.licences()),
            c -> new Counts(c.exploited(), c.critical() + 1, c.high(), c.medium(), c.low(), c.licences()),
            c -> new Counts(c.exploited(), c.critical(), c.high() + 1, c.medium(), c.low(), c.licences()),
            c -> new Counts(c.exploited(), c.critical(), c.high(), c.medium() + 1, c.low(), c.licences()),
            c -> new Counts(c.exploited(), c.critical(), c.high(), c.medium(), c.low() + 1, c.licences()),
            c -> new Counts(c.exploited(), c.critical(), c.high(), c.medium(), c.low(), c.licences() + 1));

    private static final List<Counts> BACKLOGS = List.of(
            Counts.NONE,
            new Counts(0, 1, 0, 0, 0, 0),
            new Counts(0, 0, 0, 50, 0, 0),
            new Counts(0, 0, 27, 0, 0, 0),
            new Counts(4, 0, 0, 0, 0, 0),
            new Counts(1, 3, 12, 80, 200, 2));

    @Test
    @DisplayName("an empty backlog scores 100, A+")
    void emptyBacklog() {
        assertThat(CandidateScore.of(Counts.NONE, PROPOSED))
                .isEqualTo(new CandidateScore.Result(100, SecurityGrade.A_PLUS, 0));
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
        assertThat(CandidateScore.of(new Counts(0, 0, 0, 50, 0, 0), PROPOSED).grade())
                .isNotEqualTo(CandidateScore.of(new Counts(0, 0, 0, 500, 0, 0), PROPOSED).grade());
        assertThat(CandidateScore.exact(new Counts(0, 0, 0, 500, 0, 0), PROPOSED))
                .isLessThan(CandidateScore.exact(new Counts(0, 0, 0, 50, 0, 0), PROPOSED));
        assertThat(CandidateScore.exact(new Counts(0, 0, 270, 0, 0, 0), PROPOSED))
                .isGreaterThan(0)
                .isLessThan(CandidateScore.exact(new Counts(0, 0, 27, 0, 0, 0), PROPOSED));
    }

    @Test
    @DisplayName("never reaches zero for a finite backlog, however large")
    void neverZero() {
        Counts enormous = new Counts(1_000_000, 1_000_000, 1_000_000, 1_000_000, 1_000_000, 1_000_000);
        assertThat(CandidateScore.of(enormous, PROPOSED).score()).isEqualTo(1);
        assertThat(CandidateScore.of(new Counts(0, 0, 0, 500, 0, 0), PROPOSED).score()).isPositive();
    }

    @Test
    @DisplayName("an exploited issue caps the grade at D, however light its weight")
    void exploitedCap() {
        Weights featherweight = new Weights(0.001, 10, 4, 0.5, 0.125, 4, 55);
        CandidateScore.Result one = CandidateScore.of(new Counts(1, 0, 0, 0, 0, 0), featherweight);
        assertThat(one.score()).isEqualTo(CandidateScore.EXPLOITED_CAP);
        assertThat(one.grade()).isEqualTo(SecurityGrade.D);

        // Below the cap the formula decides: the cap never raises a score.
        CandidateScore.Result many = CandidateScore.of(new Counts(4, 0, 0, 0, 0, 0), PROPOSED);
        assertThat(many.score()).isLessThan(CandidateScore.EXPLOITED_CAP);
        assertThat(many.grade()).isEqualTo(SecurityGrade.F);
    }

    /**
     * The calibration targets {@link Weights#PROPOSED} states, read at those weights: one critical B,
     * one exploited critical D (the cap), fifty mediums C, one disallowed licence A — and the risk
     * points each was computed from.
     */
    @ParameterizedTest(name = "{0} exploited, {1} critical, {2} high, {3} medium, {4} low, {5} licences: {6}, {7}, {8} points")
    @CsvSource({
            "0, 1,  0,   0, 0,  0, 83, B,      10",
            "1, 0,  0,   0, 0,  0, 54, D,      25",
            "0, 0,  0,  50, 0,  0, 63, C,      25",
            "0, 0,  0,   0, 0,  1, 93, A,       4",
            "0, 1,  0,   0, 0,  1, 78, B,      14",
            "0, 0,  0,   0, 0, 10, 48, D,      40",
            "0, 0,  0, 500, 0,  0,  1, F,     250",
            "0, 0, 27,   0, 0,  0, 14, F,     108",
            "4, 0,  0,   0, 0,  0, 16, F,     100",
            "0, 0,  0,  10, 0,  0, 91, A,       5",
            "0, 0,  0,   0, 4,  0, 99, A_PLUS, 0.5",
    })
    void calibration(long exploited, long critical, long high, long medium, long low, long licences,
            int score, SecurityGrade grade, double riskPoints) {
        assertThat(CandidateScore.of(new Counts(exploited, critical, high, medium, low, licences), PROPOSED))
                .isEqualTo(new CandidateScore.Result(score, grade, riskPoints));
    }

    @Test
    @DisplayName("a disallowed licence weighs exactly what a high does")
    void licenceWeighsAHigh() {
        assertThat(CandidateScore.of(new Counts(0, 0, 0, 0, 0, 3), PROPOSED))
                .isEqualTo(CandidateScore.of(new Counts(0, 0, 3, 0, 0, 0), PROPOSED));
    }

    /**
     * The saturation the risk points exist to show past: two backlogs both held at a score of one
     * still differ by what separates them, so fixing a thousand mediums inside F is visible.
     */
    @Test
    @DisplayName("below a score of one, the risk points still tell two backlogs apart")
    void riskPointsMovePastTheFloor() {
        CandidateScore.Result worse = CandidateScore.of(new Counts(0, 0, 0, 2000, 0, 0), PROPOSED);
        CandidateScore.Result better = CandidateScore.of(new Counts(0, 0, 0, 1000, 0, 0), PROPOSED);
        assertThat(worse.score()).isEqualTo(better.score()).isEqualTo(1);
        assertThat(worse.riskPoints()).isEqualTo(1000);
        assertThat(better.riskPoints()).isEqualTo(500);
    }

    @Test
    @DisplayName("a medium at full weight misses the third target: fifty mediums read D")
    void fullWeightMediums() {
        Weights fullMedium = new Weights(25, 10, 4, 1, 0.25, 4, 55);
        assertThat(CandidateScore.of(new Counts(0, 0, 0, 50, 0, 0), fullMedium).grade()).isEqualTo(SecurityGrade.D);
        assertThat(CandidateScore.of(new Counts(0, 1, 0, 0, 0, 0), fullMedium).grade()).isEqualTo(SecurityGrade.B);
    }

    @ParameterizedTest
    @CsvSource({"-1, 55", "NaN, 55", "Infinity, 55", "1, 0", "1, -3", "2000000, 55"})
    @DisplayName("refuses a weight or a k it cannot use, in words")
    void refusesParameters(double medium, double k) {
        assertThatThrownBy(() -> new Weights(25, 10, 4, medium, 0.125, 4, k))
                .isInstanceOf(InvalidInputException.class);
    }

    @ParameterizedTest
    @CsvSource({"-1", "NaN", "Infinity", "2000000"})
    @DisplayName("refuses a licence weight it cannot use, by its name")
    void refusesLicenceWeight(double licence) {
        assertThatThrownBy(() -> new Weights(25, 10, 4, 0.5, 0.125, licence, 55))
                .isInstanceOf(InvalidInputException.class)
                .hasMessageStartingWith("licence ");
    }
}
