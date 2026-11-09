package com.asmolabs.vectispire.common.domain.checklists;

import java.util.Arrays;
import java.util.Locale;
import java.util.Optional;

/**
 * What a measurement says of its line (decision 0032 §6). {@link #NO_DATA} is never {@link #PASS}: it
 * is "did not look", with its reason — decision 0007 applied to a checklist line.
 */
public enum MeasurementOutcome {
    PASS,
    FAIL,
    NO_DATA;

    public String wireName() {
        return name().toLowerCase(Locale.ROOT);
    }

    /** A stored outcome read back; one this version does not know is none of these. */
    public static Optional<MeasurementOutcome> ofStored(String value) {
        return Arrays.stream(values()).filter(outcome -> outcome.wireName().equals(value)).findFirst();
    }
}
