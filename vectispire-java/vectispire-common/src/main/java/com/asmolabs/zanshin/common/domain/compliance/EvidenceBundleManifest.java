package com.asmolabs.zanshin.common.domain.compliance;

import java.time.Instant;
import java.util.List;

/**
 * Manifest document sealing an audit evidence package.
 *
 * <p>Carries individual SHA-256 digests of all bundled artifacts and audit chain verification status.
 */
public record EvidenceBundleManifest(
        String version,
        Instant generatedAt,
        String generatedBy,
        String auditChainStatus,
        long totalAuditLogEntries,
        List<EvidenceFileEntry> files) {

    public record EvidenceFileEntry(
            String path,
            String description,
            long sizeBytes,
            String sha256) {}
}
