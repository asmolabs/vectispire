package com.asmolabs.vectispire.core.checklists;

import java.util.Locale;

/**
 * What a measurement was computed for (decision 0032 §6). Only the last three are stored: a
 * measurement read on screen is recomputed at every read, one relied on is kept with what relied on it.
 */
enum MeasurementPurpose {
    /** Computed for a reader, not stored. */
    READ,
    /** An answer rests on it — the one-click answer the measurement prefilled. */
    ANSWER,
    /** Recomputed at the submission, reconciled with each answer. */
    SUBMISSION,
    /** Recomputed inside the sign-off, and frozen with the revision. */
    SIGN_OFF;

    String wireName() {
        return name().toLowerCase(Locale.ROOT);
    }
}
