package com.asmolabs.vectispire.common.domain.text;

/**
 * A blank value read as absent.
 *
 * <p>Seven classes carried a private copy, three of them trimming on the way and two different
 * trims among those. Each spelling is kept here, under its own name, because which whitespace a
 * value loses is part of what was stored — a subject compared with a certificate's is stripped as
 * Unicode reads blanks, a forge path as {@link String#trim} does.
 */
public final class Texts {

    private Texts() {}

    /** {@code null} for a null or blank value, the value unchanged otherwise. */
    public static String blankToNull(String value) {
        return value == null || value.isBlank() ? null : value;
    }

    /** {@code null} for a null or blank value, the value {@link String#strip stripped} otherwise. */
    public static String strippedOrNull(String value) {
        return value == null || value.isBlank() ? null : value.strip();
    }

    /** {@code null} for a null or blank value, the value {@link String#trim trimmed} otherwise. */
    public static String trimmedOrNull(String value) {
        return value == null || value.isBlank() ? null : value.trim();
    }
}
