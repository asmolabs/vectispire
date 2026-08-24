package com.asmolabs.vectispire.common.domain.vex;

import com.fasterxml.jackson.annotation.JsonValue;
import java.util.Locale;

/**
 * Official OpenVEX justifications for not_affected statements.
 */
public enum VexJustification {
    COMPONENT_NOT_PRESENT,
    VULNERABLE_CODE_NOT_PRESENT,
    VULNERABLE_CODE_NOT_IN_EXECUTE_PATH,
    VULNERABLE_CODE_CANNOT_BE_CONTROLLED_BY_ADVERSARY,
    INLINE_MITIGATIONS_EXIST;

    @JsonValue
    public String serialized() {
        return name().toLowerCase(Locale.ROOT);
    }
}
