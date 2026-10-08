package com.asmolabs.vectispire.common.domain.gate;

import com.asmolabs.vectispire.common.domain.scans.ScanStatus;
import java.util.Optional;

/**
 * What a target's scans say about how much a verdict on its backlog can be trusted.
 *
 * <p><b>One reading, for the screen and for the gate.</b> It lived inside {@link SecurityOverview},
 * which named "never scanned" and "last scan failed" on the security screen, while {@code POST
 * /api/v1/gate} read only the backlog — so a pipeline asking about a target nobody had examined got
 * {@code passed: true} from the same application whose screen said the target had never been looked
 * at. Two definitions of "examined" would drift the way two verdicts would; there is one, here.
 *
 * <p><b>Which scan it is asked about is the caller's to say, and the two callers differ on
 * purpose.</b> The screen shows the newest scan, running or not, because "a scan is in progress" is
 * worth showing. A verdict reads the backlog the newest <em>finished</em> scan left — a running scan
 * has changed nothing yet — so the gate and the screen's verdict ask about that one: a target whose
 * only scans are still running was never examined, and a target re-scanned on a schedule does not
 * turn red for the minutes its next scan runs.
 */
public enum Observation {
    OK,
    NEVER_SCANNED,
    LAST_SCAN_FAILED,
    IN_PROGRESS;

    /**
     * The observation a scan's status stands for.
     *
     * @param scan the status of the scan the caller asks about; empty when there is none — or when
     *     its stored status is one this version does not know, which is read as no observation
     *     rather than guessed into one
     */
    public static Observation of(Optional<ScanStatus> scan) {
        if (scan.isEmpty()) {
            return NEVER_SCANNED;
        }
        if (scan.get().isInFlight()) {
            return IN_PROGRESS;
        }
        return scan.get() == ScanStatus.FAILED ? LAST_SCAN_FAILED : OK;
    }

    /** Whether the backlog rests on a scan that ran to its end. */
    public boolean examined() {
        return this == OK;
    }

    /**
     * Why a verdict cannot rest on this observation, in the words a pipeline's log shows. Empty when
     * it can.
     */
    Optional<String> refusal() {
        return switch (this) {
            case OK -> Optional.empty();
            case NEVER_SCANNED -> Optional.of("no scan of this target has completed — it was never examined,"
                    + " and an empty backlog is not a clean one");
            case LAST_SCAN_FAILED -> Optional.of("the last scan of this target failed — its backlog is not"
                    + " an observation of the code as it is");
            case IN_PROGRESS -> Optional.of("no scan of this target has finished yet");
        };
    }
}
