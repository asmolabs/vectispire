package com.asmolabs.vectispire.common.domain.scorecard;

import com.asmolabs.vectispire.common.domain.errors.InvalidInputException;

/**
 * <b>The scorecard's formula since 0.11.0</b> (decision 0036, accepted 2026-10-03): every card, the
 * ranking and the public badge read it through {@code SecurityScorecardService}, with {@link
 * Weights#PROPOSED}. The name is the one it was simulated under; it moves into the scorecard's own
 * vocabulary when the simulation route that still compares other weights is retired, the release
 * after.
 *
 * <p><b>What it replaced.</b> The score was a hundred less a fixed charge per issue (KEV 25,
 * critical 8, high 4, a disallowed licence 5), plus five for a completed scan, clamped at zero:
 * twenty-seven highs or four exploited criticals already read 0, F, and since mediums and lows
 * weighed nothing, fifty and five hundred open issues read the same grade. The scale saturated where
 * the estates that most need telling apart sit.
 *
 * <p><b>The formula</b>: {@code 100 × exp(−Σ wₛ·nₛ / k)}. Each issue removes the same <em>share</em>
 * of what is left rather than the same number of points, so the score falls quickly for the first
 * issues and keeps falling, ever more slowly, without reaching the floor: a backlog twice as large
 * always scores lower, which is what the saturated formula could not say. {@code k} sets the slope —
 * the weighted backlog that takes the score from 100 to about 37.
 *
 * <p><b>The risk points.</b> {@code Σ wₛ·nₛ} itself, returned beside the score ({@link
 * Result#riskPoints}). Below a score of one every target reads 1, F, however much it fixes; the risk
 * points keep moving, so a team deep in F still sees its progress.
 *
 * <p><b>The cap.</b> An actively exploited issue (CISA KEV) caps the grade at D whatever else the
 * backlog holds: under the formula alone one exploited issue in an otherwise clean target reads C,
 * and the grade's own description of D is "unresolved critical vulnerabilities or KEV
 * threats". The score is capped with it (at 54, D's top) so that the number and the letter agree.
 *
 * <p><b>Exploited is a class of its own, whatever the severity.</b> The old score charged KEV on top
 * of the severity, for any severity; reading only exploited <em>criticals</em> as exploited
 * would make an exploited high weigh less than an unexploited critical. An exploited issue is
 * counted in {@link Counts#exploited} and in no severity.
 *
 * <p><b>Licences weigh like a high, and observing earns nothing.</b> A disallowed licence is a term
 * of the backlog — the old formula charged it too — counted exactly as the card counts it (the
 * caller passes that count, never one of its own). The old bonus of five points for a completed scan
 * was not carried over: it is the condition for being graded at all (a target never
 * scanned is {@code NO_DATA}, decided before any score), so as a term it only lifted every graded
 * target by the same five points and let a clean target's hundred absorb one high.
 *
 * @see SecurityGrade#fromScore the bands, unchanged
 */
public final class CandidateScore {

    /** The highest score of grade D: an exploited issue caps the score here. */
    public static final int EXPLOITED_CAP = 54;

    /**
     * A ceiling on every parameter, so that a typing slip in the simulator is refused in words rather
     * than producing a table of zeros nobody can read.
     */
    private static final double MAX_PARAMETER = 1_000_000;

    private CandidateScore() {}

    /**
     * The parameters of the formula.
     *
     * @param licence the weight of one disallowed licence entry, as the card counts them
     * @param k the weighted backlog that brings the score to 100/e ≈ 37; strictly positive
     */
    public record Weights(
            double exploited, double critical, double high, double medium, double low, double licence, double k) {

        /**
         * The production weights — the calibration the product owner validated on 2026-10-03, and a
         * contract since: any change moves every badge overnight, and is a decision recorded in 0036.
         * Exploited 25, critical 10, high 4, medium 0.5, low 0.125, a disallowed licence 4 (a high's),
         * {@code k = 55}. One critical
         * reads B (83), one exploited critical D (63 by the formula, capped at 54), fifty mediums C
         * (63), one disallowed licence A (93). With a medium weighing 1 no {@code k} gives both one
         * critical a B and fifty mediums a C — B needs {@code k < 61.5}, C needs {@code k ≥ 83.6} —
         * which is why the medium is halved, and the low with it to keep their ratio.
         */
        public static final Weights PROPOSED = new Weights(25, 10, 4, 0.5, 0.125, 4, 55);

        /** Refuses a weight that is negative, infinite or NaN, and a {@code k} that is not positive. */
        public Weights {
            requireWeight("exploited", exploited);
            requireWeight("critical", critical);
            requireWeight("high", high);
            requireWeight("medium", medium);
            requireWeight("low", low);
            requireWeight("licence", licence);
            requireWeight("k", k);
            if (k <= 0) {
                throw new InvalidInputException("k must be greater than zero.");
            }
        }

        private static void requireWeight(String name, double value) {
            if (!Double.isFinite(value) || value < 0 || value > MAX_PARAMETER) {
                throw new InvalidInputException(
                        name + " must be a number between 0 and " + (long) MAX_PARAMETER + ".");
            }
        }
    }

    /**
     * One target's open, unsettled backlog by class, and its disallowed licences. Each issue is in
     * exactly one class: an exploited one is not also counted under its severity.
     *
     * @param licences the target's licence entries its policy refuses — the card's count, passed in
     */
    public record Counts(long exploited, long critical, long high, long medium, long low, long licences) {

        public Counts {
            if (exploited < 0 || critical < 0 || high < 0 || medium < 0 || low < 0 || licences < 0) {
                throw new IllegalArgumentException("A count is never negative.");
            }
        }

        public static final Counts NONE = new Counts(0, 0, 0, 0, 0, 0);
    }

    /**
     * A score, the grade it reads, and the weighted total it was computed from.
     *
     * @param riskPoints {@code Σ wₛ·nₛ}, unrounded and uncapped: what still moves when the score is
     *     held at one
     */
    public record Result(int score, SecurityGrade grade, double riskPoints) {}

    /** The weighted backlog {@code Σ wₛ·nₛ} — the risk points. Zero exactly for an empty backlog. */
    public static double riskPoints(Counts counts, Weights weights) {
        return counts.exploited() * weights.exploited()
                + counts.critical() * weights.critical()
                + counts.high() * weights.high()
                + counts.medium() * weights.medium()
                + counts.low() * weights.low()
                + counts.licences() * weights.licence();
    }

    /**
     * The unrounded, uncapped score: {@code 100 × exp(−Σ wₛ·nₛ / k)}, in (0, 100] until the exponent
     * underflows a double — beyond a weighted backlog of about 745·k.
     */
    public static double exact(Counts counts, Weights weights) {
        return 100 * Math.exp(-riskPoints(counts, weights) / weights.k());
    }

    /**
     * The score a card would show, its grade under the bands, and its risk points.
     *
     * <p><b>Never zero.</b> Rounded, then held at one at least: zero reads as "nothing left to lose",
     * which is the saturation this formula exists to remove. A backlog large enough to round to one
     * is an F however it is counted; the exact value ({@link #exact}) and the risk points still order
     * such targets.
     */
    public static Result of(Counts counts, Weights weights) {
        int score = (int) Math.max(1, Math.round(exact(counts, weights)));
        if (counts.exploited() > 0) {
            score = Math.min(score, EXPLOITED_CAP);
        }
        return new Result(score, SecurityGrade.fromScore(score), riskPoints(counts, weights));
    }
}
