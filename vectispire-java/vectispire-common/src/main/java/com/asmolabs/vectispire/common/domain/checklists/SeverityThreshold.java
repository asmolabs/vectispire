package com.asmolabs.vectispire.common.domain.checklists;

import com.asmolabs.vectispire.common.domain.errors.InvalidInputException;
import java.math.BigDecimal;
import java.util.Objects;
import java.util.Optional;

/**
 * What one severity may still hold for a findings rule to pass: at most so many open issues, at least
 * such a share of them resolved — the organisation's KPI, written by the person binding the rule and
 * never read out of the KPI's sentence (decision 0032 §3, step 4).
 *
 * <p>At least one of the two: a severity named with neither would read as a threshold and check
 * nothing.
 *
 * @param maxOpen the most open issues the severity may hold over the project, settled triage left out
 * @param minResolvedRatio the least resolved ÷ (resolved + open), in [0, 1], four decimals at most
 */
public record SeverityThreshold(Optional<Integer> maxOpen, Optional<BigDecimal> minResolvedRatio) {

    /** A million: a KPI allowing more open issues than that is not a threshold. */
    public static final int MAX_OPEN = 1_000_000;

    public SeverityThreshold {
        Objects.requireNonNull(maxOpen, "maxOpen");
        Objects.requireNonNull(minResolvedRatio, "minResolvedRatio");
        if (maxOpen.isEmpty() && minResolvedRatio.isEmpty()) {
            throw new InvalidInputException("A severity's threshold states maxOpen, minResolvedRatio or both.");
        }
        maxOpen.filter(max -> max < 0 || max > MAX_OPEN).ifPresent(max -> {
            throw new InvalidInputException("maxOpen is between 0 and " + MAX_OPEN + "; " + max + " is not.");
        });
        minResolvedRatio = minResolvedRatio.map(ratio -> Ratios.require(ratio, "minResolvedRatio", true));
    }
}
