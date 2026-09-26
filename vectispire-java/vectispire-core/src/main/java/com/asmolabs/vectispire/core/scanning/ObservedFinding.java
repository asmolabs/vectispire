package com.asmolabs.vectispire.core.scanning;

import com.asmolabs.vectispire.core.scanning.persistence.FindingEntity;

/**
 * What one scan observed about one thing — the finding as it crosses a port, before any column has
 * clipped it.
 *
 * <p><b>Whole values, always.</b> The identifier, the purl, the package name and the path are the
 * inputs of an issue's fingerprint, a data contract (AGENTS.md): the fingerprint is computed from
 * these, and only the stored copies are clipped to their columns, each by the module that owns the
 * column. A clipped value here would give two findings sharing their first 255 characters one
 * identity.
 *
 * <p><b>Why a record, not the row.</b> The ingest pipeline hands findings to three other modules —
 * {@code threatintel} contributes end-of-life findings, {@code issues} folds them into the backlog —
 * and it used to hand them the scan's {@code FindingEntity}, mutable, to fill in place. The row is
 * {@code scanning}'s (decision 0029); what crosses is this.
 *
 * @param kev whether the vulnerability is exploited in the wild; {@code false} until enrichment says
 *     otherwise
 * @param directDependency {@code null} when the scanner cannot tell, which is not {@code false}
 */
public record ObservedFinding(
        String type,
        String source,
        String identifier,
        String severity,
        String packageName,
        String packageVersion,
        String purl,
        String filePath,
        Integer line,
        Boolean directDependency,
        String owaspCategory,
        Double epssScore,
        Double cvssScore,
        String cvssVector,
        String fixState,
        String fixVersions,
        String link,
        boolean kev,
        String description) {

    /** What the row holds, before its columns clip it — ingestion builds rows and hands these over. */
    static ObservedFinding of(FindingEntity finding) {
        return new ObservedFinding(
                finding.getType(),
                finding.getSource(),
                finding.getIdentifier(),
                finding.getSeverity(),
                finding.getPackageName(),
                finding.getPackageVersion(),
                finding.getPurl(),
                finding.getFilePath(),
                finding.getLine(),
                finding.getIsDirectDependency(),
                finding.getOwaspCategory(),
                finding.getEpssScore(),
                finding.getCvssScore(),
                finding.getCvssVector(),
                finding.getFixState(),
                finding.getFixVersions(),
                finding.getLink(),
                Boolean.TRUE.equals(finding.getIsKev()),
                finding.getDescription());
    }
}
