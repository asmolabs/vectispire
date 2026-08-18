package com.asmolabs.zanshin.common.domain.issues;

import java.util.Arrays;
import java.util.Locale;
import java.util.Optional;

/**
 * The justifications a {@code not_affected} statement may carry, per the OpenVEX / CSAF
 * vocabulary.
 *
 * <p>Kept as the canonical list so a VEX document can be produced from stored rows without
 * re-translating free text. That is the whole reason triage is recorded in the standard's
 * vocabulary rather than as prose: the export is a serialization, not a translation.
 *
 * <p>An enum rather than a string list, because these values leave the building. A typo in a
 * free-text field is a typo; a typo here is an invalid VEX document handed to a customer.
 */
public enum VexJustification {
    COMPONENT_NOT_PRESENT,
    VULNERABLE_CODE_NOT_PRESENT,
    VULNERABLE_CODE_NOT_IN_EXECUTE_PATH,
    VULNERABLE_CODE_CANNOT_BE_CONTROLLED_BY_ADVERSARY,
    INLINE_MITIGATIONS_ALREADY_EXIST;

    public String wireName() {
        return name().toLowerCase(Locale.ROOT);
    }

    public static Optional<VexJustification> fromWireName(String value) {
        if (value == null || value.isBlank()) {
            return Optional.empty();
        }
        String normalized = value.trim().toLowerCase(Locale.ROOT);
        return Arrays.stream(values()).filter(j -> j.wireName().equals(normalized)).findFirst();
    }
}
