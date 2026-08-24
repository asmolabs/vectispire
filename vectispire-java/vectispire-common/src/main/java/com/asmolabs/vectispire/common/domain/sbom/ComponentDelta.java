package com.asmolabs.vectispire.common.domain.sbom;

/**
 * Delta of a single component between two SBOM versions.
 */
public record ComponentDelta(
        String name,
        String purl,
        String type,
        Boolean isDirect,
        String oldVersion,
        String newVersion,
        String oldLicense,
        String newLicense,
        ChangeType changeType) {

    public enum ChangeType {
        ADDED,
        REMOVED,
        VERSION_CHANGED,
        LICENSE_CHANGED,
        UNCHANGED
    }
}
