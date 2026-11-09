package com.asmolabs.vectispire.common.domain.issues;

import com.fasterxml.jackson.annotation.JsonCreator;
import com.fasterxml.jackson.annotation.JsonValue;
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
 *
 * <p><b>It is also the only one, now.</b> A second copy lived in {@code domain.vex} and serialized
 * {@code inline_mitigations_already_exist} as {@code inline_mitigations_exist} — a value the
 * specification does not define. It went out on every signed advisory, and the only reader who
 * would have objected is a downstream consumer nobody hears from. Two enumerations of one
 * controlled vocabulary is how one of them comes to be wrong quietly.
 */
public enum VexJustification {
    COMPONENT_NOT_PRESENT,
    VULNERABLE_CODE_NOT_PRESENT,
    VULNERABLE_CODE_NOT_IN_EXECUTE_PATH,
    VULNERABLE_CODE_CANNOT_BE_CONTROLLED_BY_ADVERSARY,
    INLINE_MITIGATIONS_ALREADY_EXIST;

    /**
     * The wire form, which is the specification's label and not the Java constant.
     *
     * <p>{@code @JsonValue} rather than a conversion at each boundary: this value is the contract
     * with every VEX consumer, and a serialization decided by the enum's spelling is a contract
     * decided by a rename.
     */
    @JsonValue
    public String wireName() {
        return name().toLowerCase(Locale.ROOT);
    }

    /**
     * Reads a justification, or nothing.
     *
     * <p>Lenient on the Java constant form as well as the wire form: documents exist carrying
     * either, including ones this product emitted. Unknown values read as absent rather than
     * throwing — an upstream vendor's unrecognised justification must not cost the reader the
     * other two hundred statements in the same document.
     */
    @JsonCreator
    public static VexJustification fromJson(String value) {
        return fromWireName(value).orElse(null);
    }

    public static Optional<VexJustification> fromWireName(String value) {
        if (value == null || value.isBlank()) {
            return Optional.empty();
        }
        String normalized = value.trim().toLowerCase(Locale.ROOT);
        return Arrays.stream(values()).filter(j -> j.wireName().equals(normalized)).findFirst();
    }
}
