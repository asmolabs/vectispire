package com.asmolabs.vectispire.common.domain.reportplugins;

import com.fasterxml.jackson.annotation.JsonValue;
import java.util.Arrays;
import java.util.Optional;

/**
 * Why a report run ended without producing (decision 0035 §2): a closed word a screen and a SIEM rule read
 * without parsing a sentence, and the state it belongs to — a reason is never paired with the other state.
 *
 * <p>The refusals are the image's provenance or the export's version: nothing was started, and nothing of the
 * project left the control plane. The failures are everything else.
 */
public enum ReportRunReason {
    /** The manifest declares no signer. A report plugin always needs one, and there is no waiver. */
    UNSIGNED("unsigned", ReportRunState.REFUSED),
    /** cosign did not verify the image against the declared signer — another signer, none, or no answer. */
    SIGNATURE_UNVERIFIED("signature_unverified", ReportRunState.REFUSED),
    /** The registry would not be read with the control plane's Docker configuration, so nothing was verified. */
    REGISTRY_AUTHENTICATION_REQUIRED("registry_authentication_required", ReportRunState.REFUSED),
    /** The manifest reads an export major this installation no longer produces; never another one instead. */
    EXPORT_SCHEMA_UNAVAILABLE("export_schema_unavailable", ReportRunState.REFUSED),

    /** The plugin exited with a code other than {@code 0}: a renderer has no "found something" code. */
    EXIT_CODE("exit_code", ReportRunState.FAILED),
    /** The plugin ran past its manifest's timeout and was stopped. */
    TIMEOUT("timeout", ReportRunState.FAILED),
    /** Its output directory filled, or a file outgrew the ceiling: what could not be written is not in it. */
    OUTPUT_FULL("output_full", ReportRunState.FAILED),
    /** It exited without writing the file its manifest names. */
    OUTPUT_MISSING("output_missing", ReportRunState.FAILED),
    /** The file it names is a link, a directory or a device: never read. */
    OUTPUT_NOT_REGULAR("output_not_regular", ReportRunState.FAILED),
    /** The project's export is over its bounds: refused, never cut short (0035 §1). */
    EXPORT_TOO_LARGE("export_too_large", ReportRunState.FAILED),
    /**
     * The requester no longer sees the whole project, no longer holds a role that may request a report, or is
     * gone: the export is built for the requester at the claim, and nobody else's visibility stands in.
     */
    REQUESTER_NOT_ALLOWED("requester_not_allowed", ReportRunState.FAILED),
    /** Between the request and the claim the plugin was switched off for the project, disabled, or lost its approved manifest. */
    PLUGIN_UNAVAILABLE("plugin_unavailable", ReportRunState.FAILED),
    /** The executor holding the run stopped answering: its lease lapsed. */
    EXECUTOR_LOST("executor_lost", ReportRunState.FAILED),
    /** The executor could not do its part — the daemon, the pull, the verifier, the host — whatever the plugin did. */
    EXECUTOR_ERROR("executor_error", ReportRunState.FAILED);

    private final String wireName;
    private final ReportRunState state;

    ReportRunReason(String wireName, ReportRunState state) {
        this.wireName = wireName;
        this.state = state;
    }

    @JsonValue
    public String wireName() {
        return wireName;
    }

    /** {@link ReportRunState#FAILED} or {@link ReportRunState#REFUSED}. */
    public ReportRunState state() {
        return state;
    }

    /** A stored value read back; absent for a run that has none. */
    public static Optional<ReportRunReason> ofStored(String stored) {
        if (stored == null) {
            return Optional.empty();
        }
        return Optional.of(Arrays.stream(values()).filter(reason -> reason.wireName.equals(stored)).findFirst()
                .orElseThrow(() -> new IllegalStateException("Unknown report run reason \"" + stored + "\".")));
    }
}
