package com.asmolabs.vectispire.common.domain.vex;

import com.fasterxml.jackson.annotation.JsonValue;
import java.util.Locale;

/**
 * Standardized OpenVEX status values.
 */
public enum VexStatus {
    NOT_AFFECTED,
    AFFECTED,
    FIXED,
    UNDER_INVESTIGATION;

    @JsonValue
    public String serialized() {
        return name().toLowerCase(Locale.ROOT);
    }
}
