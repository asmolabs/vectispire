package com.asmolabs.vectispire.core.plugins;

import com.asmolabs.vectispire.core.plugins.persistence.CoverageImportEntity;
import java.time.Instant;
import java.util.UUID;

/**
 * An accepted coverage import, under the entity's property names.
 *
 * @param format {@code jacoco}, {@code cobertura} or {@code lcov}, as the pipeline declared it
 * @param toolVersion the producer's version when the report states it
 * @param branchesCovered and {@code branchesTotal}: null when the report counted no branch
 * @param commit and {@code branch}: what the pipeline stated, verified against nothing
 * @param documentSha256 of the bytes uploaded — what lets a pipeline prove which report it sent
 */
public record CoverageImportView(
        Long id,
        Long sourceId,
        String sourceSlug,
        Long repoId,
        String format,
        String toolVersion,
        long linesCovered,
        long linesTotal,
        Long branchesCovered,
        Long branchesTotal,
        String commit,
        String branch,
        String documentSha256,
        Instant importedAt,
        String importedBy,
        UUID apiKeyId) {

    static CoverageImportView of(CoverageImportEntity row) {
        return new CoverageImportView(row.getId(), row.getSourceId(), row.getSourceSlug(), row.getRepoId(), row.getFormat(),
                row.getToolVersion(), row.getLinesCovered(), row.getLinesTotal(), row.getBranchesCovered(),
                row.getBranchesTotal(), row.getCommit(), row.getBranch(), row.getDocumentSha256(), row.getImportedAt(),
                row.getImportedBy(), row.getApiKeyId());
    }
}
