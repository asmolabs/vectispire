package com.asmolabs.vectispire.common.domain.checklists;

import com.asmolabs.vectispire.common.domain.errors.InvalidInputException;
import java.math.BigDecimal;

/**
 * A ratio a rule states — a share resolved, a share of lines covered — and how one is compared.
 *
 * <p><b>Decimal, never a double.</b> The ratio enters the item's content digest through the rule's
 * canonical form, so {@code 0.6} must be written the same way every time; and a comparison of 3 of 5
 * lines with 0.6 must say "met", which binary floating point does not promise. Four decimals are
 * enough for a KPI and keep the canonical form out of scientific notation.
 */
final class Ratios {

    static final int SCALE = 4;

    private Ratios() {}

    /**
     * The ratio in its one written form, refused outside [0, 1] or past four decimals.
     *
     * @param zeroAllowed whether 0 is a threshold: "at least none resolved" is one a KPI may state,
     *     "at least nothing covered" is not a coverage rule
     */
    static BigDecimal require(BigDecimal ratio, String what, boolean zeroAllowed) {
        if (ratio.signum() < 0 || ratio.compareTo(BigDecimal.ONE) > 0 || (!zeroAllowed && ratio.signum() == 0)) {
            throw new InvalidInputException(what + " is a ratio " + (zeroAllowed ? "from 0" : "above 0") + " to 1 — 0.6 "
                    + "for 60 %; " + ratio.toPlainString() + " is not.");
        }
        BigDecimal normalized = ratio.stripTrailingZeros();
        if (normalized.scale() > SCALE) {
            throw new InvalidInputException(what + " has at most " + SCALE + " decimals; " + ratio.toPlainString()
                    + " has more.");
        }
        return normalized.scale() < 0 ? normalized.setScale(0) : normalized;
    }

    /** Whether {@code part} of {@code whole} is at least {@code ratio}, exactly: part ≥ ratio × whole. */
    static boolean atLeast(long part, long whole, BigDecimal ratio) {
        return BigDecimal.valueOf(part).compareTo(ratio.multiply(BigDecimal.valueOf(whole))) >= 0;
    }
}
