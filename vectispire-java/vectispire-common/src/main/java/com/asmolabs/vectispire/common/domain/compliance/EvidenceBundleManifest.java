package com.asmolabs.vectispire.common.domain.compliance;

import java.time.Instant;
import java.util.List;

/**
 * Manifest document sealing an audit evidence package.
 *
 * <p>Carries individual SHA-256 digests of all bundled artifacts and audit chain verification status.
 *
 * @param totalAuditLogEntries how many entries section 02 carries; {@code null} when the section was
 *     withheld, because a count of an estate's audit trail is not zero merely because this archive
 *     does not include it
 * @param withheld the sections this archive leaves out and why — empty for a whole bundle. An
 *     archive built for a credential restricted to some targets cannot carry what describes the
 *     whole estate, and it says so here rather than looking incomplete
 */
public record EvidenceBundleManifest(
        String version,
        Instant generatedAt,
        String generatedBy,
        String auditChainStatus,
        Long totalAuditLogEntries,
        List<EvidenceFileEntry> files,
        List<WithheldSection> withheld) {

    public EvidenceBundleManifest {
        files = List.copyOf(files);
        withheld = List.copyOf(withheld);
    }

    /** A section left out of the archive, and the reason a reader of the manifest is given. */
    public record WithheldSection(String path, String reason) {}

    public record EvidenceFileEntry(
            String path,
            String description,
            long sizeBytes,
            String sha256) {}
}
