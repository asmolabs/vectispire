package com.asmolabs.vectispire.common.domain.scorecard;

import com.asmolabs.vectispire.common.domain.errors.InvalidInputException;

/**
 * <b>Experimental, and wired to nothing that grades.</b> A candidate replacement for the scorecard's
 * score, kept beside the one in production so that the product owner can compare the two on a real
 * estate before deciding (the score simulation route) — no card, badge or ranking reads it.
 *
 * <p><b>Why a candidate at all.</b> The production score is a hundred less a fixed charge per issue
 * (KEV 25, critical 8, high 4), clamped at zero: twenty-seven highs or four exploited criticals
 * already read 0, F, and since mediums and lows weigh nothing, fifty and five hundred open issues
 * read the same grade. The scale saturates where the estates that most need telling apart sit.
 *
 * <p><b>The formula</b>: {@code 100 × exp(−Σ wₛ·nₛ / k)}. Each issue removes the same <em>share</em>
 * of what is left rather than the same number of points, so the score falls quickly for the first
 * issues and keeps falling, ever more slowly, without reaching the floor: a backlog twice as large
 * always scores lower, which is what the saturated formula could not say. {@code k} sets the slope —
 * the weighted backlog that takes the score from 100 to about 37.
 *
 * <p><b>The cap.</b> An actively exploited issue (CISA KEV) caps the grade at D whatever else the
 * backlog holds: under the formula alone one exploited issue in an otherwise clean target reads C,
 * and the production grade's own description of D is "unresolved critical vulnerabilities or KEV
 * threats". The score is capped with it (at 54, D's top) so that the number and the letter agree.
 *
 * <p><b>Exploited is a class of its own, whatever the severity.</b> The production score charges KEV
 * on top of the severity, for any severity; reading only exploited <em>criticals</em> as exploited
 * would make an exploited high weigh less than an unexploited critical. An exploited issue is
 * counted in {@link Counts#exploited} and in no severity.
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
     * @param k the weighted backlog that brings the score to 100/e ≈ 37; strictly positive
     */
    public record Weights(double exploited, double critical, double high, double medium, double low, double k) {

        /**
         * The weights the backlog item proposed and {@code k = 55}, calibrated so that one critical
         * reads B (83) and one exploited critical D (63 by the formula, capped). Fifty mediums read D
         * (40) at these weights: with a medium weighing 1, no {@code k} gives both one critical a B
         * and fifty mediums a C — B needs {@code k < 61.5}, C needs {@code k ≥ 83.6}. A medium
         * weighing 0.5 at the same {@code k} meets all three (fifty mediums: 63, C).
         */
        public static final Weights PROPOSED = new Weights(25, 10, 4, 1, 0.25, 55);

        /** Refuses a weight that is negative, infinite or NaN, and a {@code k} that is not positive. */
        public Weights {
            requireWeight("exploited", exploited);
            requireWeight("critical", critical);
            requireWeight("high", high);
            requireWeight("medium", medium);
            requireWeight("low", low);
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
     * One target's open, unsettled backlog by class. Each issue is in exactly one class: an exploited
     * one is not also counted under its severity.
     */
    public record Counts(long exploited, long critical, long high, long medium, long low) {

        public Counts {
            if (exploited < 0 || critical < 0 || high < 0 || medium < 0 || low < 0) {
                throw new IllegalArgumentException("A count is never negative.");
            }
        }

        public static final Counts NONE = new Counts(0, 0, 0, 0, 0);
    }

    /** A score and the grade it reads. */
    public record Result(int score, SecurityGrade grade) {}

    /**
     * The unrounded, uncapped score: {@code 100 × exp(−Σ wₛ·nₛ / k)}, in (0, 100] until the exponent
     * underflows a double — beyond a weighted backlog of about 745·k.
     */
    public static double exact(Counts counts, Weights weights) {
        double weighted = counts.exploited() * weights.exploited()
                + counts.critical() * weights.critical()
                + counts.high() * weights.high()
                + counts.medium() * weights.medium()
                + counts.low() * weights.low();
        return 100 * Math.exp(-weighted / weights.k());
    }

    /**
     * The score a card would show, and its grade under the production bands.
     *
     * <p><b>Never zero.</b> Rounded, then held at one at least: zero reads as "nothing left to lose",
     * which is the saturation this formula exists to remove. A backlog large enough to round to one
     * is an F however it is counted; the exact value ({@link #exact}) still orders such targets.
     */
    public static Result of(Counts counts, Weights weights) {
        int score = (int) Math.max(1, Math.round(exact(counts, weights)));
        if (counts.exploited() > 0) {
            score = Math.min(score, EXPLOITED_CAP);
        }
        return new Result(score, SecurityGrade.fromScore(score));
    }
}
