package com.asmolabs.vectispire.common.domain.threatintel;

/**
 * What the stored CISA KEV catalogue says about one identifier.
 *
 * <p><b>Three answers, not a boolean.</b> An issue's {@code isKev} reads false before the catalogue
 * was ever read, and for an identifier the catalogue cannot list — a GHSA, a rule id — so a false
 * there says "nobody looked" as often as "not listed". The advisor printed that false as a fact to
 * the reader and to the model; and where it had no issue to read, it made the answer up by matching
 * two CVE ids typed into the code. {@link #UNKNOWN} is what a screen says when nothing answered.
 */
public enum KevListing {
    /** Listed in the catalogue in use: exploitation in the wild has been reported to CISA. */
    LISTED,
    /** A CVE the catalogue in use does not list — which says nothing about tomorrow's. */
    NOT_LISTED,
    /** The catalogue was never synchronised, or the identifier is not a CVE it could list. */
    UNKNOWN
}
