package com.asmolabs.vectispire.common.domain.apis;

import java.util.Locale;
/**
 * An API endpoint discovered in source code, contract, or infrastructure definition.
 */
public record ApiEndpoint(
        String method,
        String path,
        boolean authRequired,
        String authType,
        ApiVisibility visibility,
        String filePath,
        Integer lineNumber,
        String framework,
        String operationId,
        String summary,
        String tags) {

    /**
     * The most endpoints one repository's discovery may report, its contracts' declared paths included.
     *
     * <p>Fifty thousand is far beyond an application's surface — a large public API declares a few thousand
     * operations — and within what the inventory writes and the synthesized document numbers in well under a
     * second. Past it, the discovery is <b>failed, not cut</b>: a partial list retires every endpoint it left
     * out (decision 0007), so the step reports why, and the inventory keeps what it had.
     */
    public static final int MAX_PER_REPOSITORY = 50_000;

    public ApiEndpoint {
        if (method != null) {
            method = method.toUpperCase(Locale.ROOT);
        }
        if (path == null || path.isBlank()) {
            path = "/";
        }
        if (!path.startsWith("/")) {
            path = "/" + path;
        }
        if (visibility == null) {
            visibility = ApiVisibility.UNKNOWN;
        }
    }

    /**
     * Whether this endpoint exposes sensitive management or administrative capabilities.
     */
    public boolean isSensitivePath() {
        String lower = path.toLowerCase(Locale.ROOT);
        return lower.contains("/admin")
                || lower.contains("/actuator")
                || lower.contains("/debug")
                || lower.contains("/internal")
                || lower.contains("/metrics")
                || lower.contains("/env")
                || lower.contains("/health");
    }
}
