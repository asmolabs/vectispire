package com.asmolabs.vectispire.common.domain.reportplugins;

import com.fasterxml.jackson.annotation.JsonValue;
import java.util.Arrays;

/**
 * Where one report run stands (decision 0035 §2). Exactly one at a time.
 *
 * <ul>
 *   <li>{@link #PENDING} — requested, waiting for the control plane's executor to claim it;
 *   <li>{@link #RUNNING} — claimed: the export is being built, the image verified, or the plugin running. A
 *       claim whose lease lapsed — the executor died with it — is failed {@code executor_lost};
 *   <li>{@link #PRODUCED} — the plugin exited {@code 0} and wrote its file within its bounds;
 *   <li>{@link #FAILED} — the plugin, or what it was given, went wrong: an exit code, a timeout, a full or
 *       missing output, an export over its bounds, a requester who no longer sees the whole project. The fix
 *       is the plugin's code or the project, so the reason says which;
 *   <li>{@link #REFUSED} — never started, for want of a verified signer or of the export major the manifest
 *       reads. Told apart from {@link #FAILED} because the fix is provenance or version, not the plugin's code.
 * </ul>
 */
public enum ReportRunState {
    PENDING("pending"),
    RUNNING("running"),
    PRODUCED("produced"),
    FAILED("failed"),
    REFUSED("refused");

    private final String wireName;

    ReportRunState(String wireName) {
        this.wireName = wireName;
    }

    /** The value the column stores and the API carries. */
    @JsonValue
    public String wireName() {
        return wireName;
    }

    /** Ended: nothing moves it any more. */
    public boolean ended() {
        return this == PRODUCED || this == FAILED || this == REFUSED;
    }

    /** A stored value read back; a value this version does not know is a fault of the row, not a state. */
    public static ReportRunState ofStored(String stored) {
        return Arrays.stream(values()).filter(state -> state.wireName.equals(stored)).findFirst()
                .orElseThrow(() -> new IllegalStateException("Unknown report run state \"" + stored + "\"."));
    }
}
