package com.asmolabs.vectispire.core.checklists;

import java.util.Locale;

/**
 * Why answering every measured line as measured left a line alone (decision 0032 §6) — the tokens of
 * {@link ChecklistAsMeasuredView.AsMeasuredSkip#reason()}, enumerated in the OpenAPI document from here.
 */
enum AsMeasuredSkipReason {
    /**
     * The line has a current answer — any, a carried one awaiting confirmation and one equal to what
     * the measurement would give included. A person's answer is never replaced by a gesture that did
     * not look at it; one equal to the measurement would be a second row saying the same thing.
     */
    ALREADY_ANSWERED,
    /** The measurement has no data: there is nothing to answer as measured, and a "yes" on it is declared. */
    NO_DATA,
    /**
     * The measurement fails, so the answer would be "no", and a "no" needs its comment saying why
     * (§5). The single one-click opens the form for the person to write it; one gesture over every
     * line has nobody writing, and a comment the product wrote would be a claim the person never made.
     */
    NEEDS_COMMENT;

    String wireName() {
        return name().toLowerCase(Locale.ROOT);
    }
}
