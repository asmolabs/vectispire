package com.asmolabs.vectispire.common.domain.reportplugins;

import com.fasterxml.jackson.annotation.JsonValue;
import java.util.Arrays;

/**
 * Where one manifest digest of a report plugin stands (decision 0035 §4).
 *
 * <ul>
 *   <li>{@link #PENDING_APPROVAL} — registered or updated while four-eyes was on: no run uses it until a
 *       second person holding {@code canWriteGovernance} approves that digest, and the plugin's previous
 *       approved digest keeps serving meanwhile;
 *   <li>{@link #APPROVED} — approved, or registered while four-eyes was off: a run may use it while it is
 *       the plugin's current one. An approved digest the plugin has since moved past stays approved — the
 *       documents it produced still stand, and setting the plugin back to it needs no second approval;
 *   <li>{@link #SUPERSEDED} — pending, and replaced by a later registration before anybody approved it: it
 *       never ran, and cannot be approved any more;
 *   <li>{@link #WITHDRAWN} — the governor withdrew it, in writing: it never runs again, cannot be
 *       registered again, and every document it produced is marked withdrawn (lot R7). Final.
 * </ul>
 */
public enum ReportPluginManifestStatus {
    PENDING_APPROVAL("pending_approval"),
    APPROVED("approved"),
    SUPERSEDED("superseded"),
    WITHDRAWN("withdrawn");

    private final String wireName;

    ReportPluginManifestStatus(String wireName) {
        this.wireName = wireName;
    }

    /** The value the column stores and the API carries. */
    @JsonValue
    public String wireName() {
        return wireName;
    }

    /** A stored value read back; a value this version does not know is a fault of the row, not a state. */
    public static ReportPluginManifestStatus ofStored(String stored) {
        return Arrays.stream(values()).filter(status -> status.wireName.equals(stored)).findFirst()
                .orElseThrow(() -> new IllegalStateException("Unknown report plugin manifest status \"" + stored + "\"."));
    }
}
