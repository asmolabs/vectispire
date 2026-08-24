package com.asmolabs.vectispire.common.domain.sbom;

/**
 * Delta of a vulnerability between two SBOM / scan versions.
 */
public record CveDelta(
        String cveId,
        String severity,
        String packageName,
        String version,
        Status status) {

    public enum Status {
        INTRODUCED,
        RESOLVED,
        PERSISTENT
    }
}
