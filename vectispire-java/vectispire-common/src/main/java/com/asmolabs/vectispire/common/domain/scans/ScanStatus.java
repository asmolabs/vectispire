package com.asmolabs.vectispire.common.domain.scans;

import java.util.Arrays;
import java.util.Locale;
import java.util.Optional;

/** Where a scan is in its life. */
public enum ScanStatus {
    PENDING(true),
    SCANNING(true),
    COMPLETED(false),
    FAILED(false);

    private final String wireName;
    private final boolean inFlight;

    ScanStatus(boolean inFlight) {
        this.wireName = name().toLowerCase(Locale.ROOT);
        this.inFlight = inFlight;
    }

    public String wireName() {
        return wireName;
    }

    /** Whether the scan is still expected to produce a result. */
    public boolean isInFlight() {
        return inFlight;
    }

    public static Optional<ScanStatus> fromWireName(String value) {
        return value == null
                ? Optional.empty()
                : Arrays.stream(values())
                        .filter(status -> status.wireName.equals(value.trim().toLowerCase(Locale.ROOT)))
                        .findFirst();
    }
}
