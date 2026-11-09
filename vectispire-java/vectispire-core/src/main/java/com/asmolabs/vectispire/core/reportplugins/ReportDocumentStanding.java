package com.asmolabs.vectispire.core.reportplugins;

import com.fasterxml.jackson.annotation.JsonValue;

/**
 * Whether this installation stands by a document a holder names by its SHA-256 (decision 0035 §4, lot R7).
 *
 * <ul>
 *   <li>{@link #UPHELD} — it produced and signed it, and the manifest that produced it was not withdrawn;
 *   <li>{@link #WITHDRAWN} — it produced and signed it, and the platform governor has since withdrawn the manifest:
 *       the signature still verifies — a detached signature cannot be un-made — but the installation no longer
 *       stands by what it says;
 *   <li>{@link #UNKNOWN} — no document this caller may see has that digest: never produced here, produced for a
 *       project since deleted, or produced for one the caller does not see whole. One word for the three, so that
 *       the answer says nothing of a project its asker may not read.
 * </ul>
 */
public enum ReportDocumentStanding {
    UPHELD("upheld"),
    WITHDRAWN("withdrawn"),
    UNKNOWN("unknown");

    private final String wireName;

    ReportDocumentStanding(String wireName) {
        this.wireName = wireName;
    }

    /** The value the API carries, and the download's {@code Vectispire-Document-Status} header. */
    @JsonValue
    public String wireName() {
        return wireName;
    }
}
