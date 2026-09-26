package com.asmolabs.vectispire.core.scanning;

import com.asmolabs.vectispire.core.scanning.persistence.FindingEntity;
import java.time.Instant;

/**
 * A finding of one scan as the layers above the services hold it: the row's properties under their
 * own names, not the row.
 *
 * <p>Not {@code FindingView}: that is the name of the scan route's response record, and the
 * published schema is named after it.
 */
public record ScanFindingView(
        Long id,
        Long scanId,
        String type,
        String severity,
        String identifier,
        String packageName,
        String packageVersion,
        String purl,
        String filePath,
        String owaspCategory,
        String source,
        Double epssScore,
        boolean isKev,
        Instant createdAt,
        Double cvssScore,
        String cvssVector,
        String fixState,
        String fixVersions,
        String link,
        Long issueId,
        Boolean isDirectDependency,
        Integer line,
        String description,
        String reachability,
        String reachableSymbols) {

    public static ScanFindingView of(FindingEntity finding) {
        return new ScanFindingView(
                finding.getId(),
                finding.getScanId(),
                finding.getType(),
                finding.getSeverity(),
                finding.getIdentifier(),
                finding.getPackageName(),
                finding.getPackageVersion(),
                finding.getPurl(),
                finding.getFilePath(),
                finding.getOwaspCategory(),
                finding.getSource(),
                finding.getEpssScore(),
                finding.getIsKev(),
                finding.getCreatedAt(),
                finding.getCvssScore(),
                finding.getCvssVector(),
                finding.getFixState(),
                finding.getFixVersions(),
                finding.getLink(),
                finding.getIssueId(),
                finding.getIsDirectDependency(),
                finding.getLine(),
                finding.getDescription(),
                finding.getReachability(),
                finding.getReachableSymbols());
    }
}
