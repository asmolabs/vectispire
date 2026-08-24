package com.asmolabs.vectispire.common.domain.apis;

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

    public ApiEndpoint {
        if (method != null) {
            method = method.toUpperCase();
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
        String lower = path.toLowerCase();
        return lower.contains("/admin")
                || lower.contains("/actuator")
                || lower.contains("/debug")
                || lower.contains("/internal")
                || lower.contains("/metrics")
                || lower.contains("/env")
                || lower.contains("/health");
    }
}
