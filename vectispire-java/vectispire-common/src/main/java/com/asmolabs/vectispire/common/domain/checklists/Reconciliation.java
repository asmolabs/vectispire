package com.asmolabs.vectispire.common.domain.checklists;

import java.util.Locale;
import java.util.Optional;

/**
 * An answer beside its line's measurement, in the statement of applicability's vocabulary (decision
 * 0032 §6): the disagreement between what is declared and what is measured is what an assessor opens
 * with, so it is named on the screen and in the document rather than resolved by either side.
 */
public enum Reconciliation {
    /** {@code YES} and {@code PASS}, or {@code NO} and {@code FAIL}. */
    CONSISTENT,
    /** {@code YES} against {@code FAIL}: refused at submission (question 3). */
    CONTRADICTED,
    /**
     * An answer where the measurement has no data: allowed, and for a {@code YES} only with a comment and
     * a proof (question 4).
     */
    DECLARED_NOT_MEASURED,
    /** {@code NO} against {@code PASS}: allowed, the comment says why. */
    UNDERSTATED,
    /** {@code NOT_APPLICABLE}: the line is argued out of scope, whatever the rule measured. */
    EXCLUDED,
    /** The line has no rule bound: not measured here. */
    NOT_MEASURED_HERE,
    /** A rule is bound and nobody has answered yet. */
    UNANSWERED;

    public String wireName() {
        return name().toLowerCase(Locale.ROOT);
    }

    /** The line's reconciliation; no measurement means no rule is bound. */
    public static Reconciliation of(Optional<ChecklistAnswer> answer, Optional<MeasurementOutcome> measured) {
        if (measured.isEmpty()) {
            return NOT_MEASURED_HERE;
        }
        if (answer.isEmpty()) {
            return UNANSWERED;
        }
        return switch (answer.get()) {
            case NOT_APPLICABLE -> EXCLUDED;
            case YES -> switch (measured.get()) {
                case PASS -> CONSISTENT;
                case FAIL -> CONTRADICTED;
                case NO_DATA -> DECLARED_NOT_MEASURED;
            };
            case NO -> switch (measured.get()) {
                case PASS -> UNDERSTATED;
                case FAIL -> CONSISTENT;
                case NO_DATA -> DECLARED_NOT_MEASURED;
            };
        };
    }
}
