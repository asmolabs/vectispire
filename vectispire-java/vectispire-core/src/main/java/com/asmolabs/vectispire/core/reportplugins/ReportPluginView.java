package com.asmolabs.vectispire.core.reportplugins;

import java.time.Instant;
import java.util.List;

/**
 * A registered report plugin, under the entity's property names, with every manifest it ever had.
 *
 * @param approvedDigest the manifest a run uses; null until one is approved, and after it is withdrawn
 * @param pendingDigest the manifest awaiting a second person's approval, if any
 * @param manifests its history, newest first — each with its status, its approval and its withdrawal
 */
public record ReportPluginView(
        String id,
        String name,
        String approvedDigest,
        String pendingDigest,
        boolean enabled,
        Instant createdAt,
        String createdBy,
        Instant updatedAt,
        String updatedBy,
        List<ReportPluginManifestView> manifests) {

    public ReportPluginView {
        manifests = List.copyOf(manifests);
    }
}
