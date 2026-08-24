package com.asmolabs.vectispire.common.domain.reachability;

import java.util.Locale;

/**
 * Reachability status indicating whether vulnerable dependency code is actively invoked
 * by the host application source code.
 */
public enum ReachabilityStatus {

    /**
     * Vulnerable library symbols/methods are directly imported and invoked in the codebase.
     * High exploitation risk — requires immediate remediation.
     */
    REACHABLE,

    /**
     * Library is present in the dependency tree, but no direct invocation of vulnerable symbols
     * is detected in the application call graph. Lower immediate exploitation risk.
     */
    UNREACHABLE,

    /**
     * Reachability analysis is not applicable or could not be determined (e.g. pure container image without source).
     */
    UNKNOWN;

    public String wireName() {
        return name().toLowerCase(Locale.ROOT);
    }

    public static ReachabilityStatus fromWire(String wire) {
        if (wire == null || wire.isBlank()) {
            return UNKNOWN;
        }
        return switch (wire.trim().toUpperCase(Locale.ROOT)) {
            case "REACHABLE" -> REACHABLE;
            case "UNREACHABLE" -> UNREACHABLE;
            default -> UNKNOWN;
        };
    }
}
