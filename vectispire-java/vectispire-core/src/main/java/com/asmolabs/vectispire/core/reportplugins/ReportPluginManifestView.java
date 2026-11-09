package com.asmolabs.vectispire.core.reportplugins;

import com.asmolabs.vectispire.common.domain.reportplugins.ReportPluginManifest;
import com.asmolabs.vectispire.common.domain.reportplugins.ReportPluginManifestStatus;
import java.time.Instant;

/**
 * One manifest of a report plugin, by digest: what it declares, where it stands, who registered, approved and
 * withdrew it.
 *
 * <p>No account id: the four-eyes comparison is the service's, and the names are what the audit log shows.
 *
 * @param approvalFourEyes whether four-eyes applied to its approval — {@code false} when it took effect at its
 *     registration because the rule was off; null until approved
 */
public record ReportPluginManifestView(
        String digest,
        ReportPluginManifestStatus status,
        ReportPluginManifest manifest,
        Instant registeredAt,
        String registeredBy,
        Instant approvedAt,
        String approvedBy,
        Boolean approvalFourEyes,
        Instant withdrawnAt,
        String withdrawnBy,
        String withdrawalJustification) {}
