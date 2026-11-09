package com.asmolabs.vectispire.core.inventory;

import com.asmolabs.vectispire.core.inventory.persistence.BuildSbomEntity;
import java.time.Instant;
import java.util.UUID;

/**
 * An accepted build SBOM, under the entity's property names.
 *
 * @param specVersion the CycloneDX version the document declared
 * @param tool the tool that wrote it, as its metadata names it, or null
 * @param componentsCount the components it listed, nested ones included, each package once
 * @param commit and {@code branch}: what the pipeline stated; a stated branch limits the scans it completes
 * @param documentSha256 of the bytes uploaded — what lets a pipeline prove which document it sent
 * @param completedScanId the newest scan whose inventory it completed, or null: no completed scan holding
 *     an SBOM yet, a branch no scan of the repository is of, or a newer SBOM that took its place
 */
public record BuildSbomView(
        Long id,
        Long sourceId,
        String sourceSlug,
        Long repoId,
        String specVersion,
        String tool,
        Integer componentsCount,
        String commit,
        String branch,
        String documentSha256,
        Instant importedAt,
        String importedBy,
        UUID apiKeyId,
        Long completedScanId) {

    static BuildSbomView of(BuildSbomEntity row, Long completedScanId) {
        return new BuildSbomView(row.getId(), row.getSourceId(), row.getSourceSlug(), row.getRepoId(), row.getSpecVersion(),
                row.getTool(), row.getComponentsCount(), row.getCommit(), row.getBranch(), row.getDocumentSha256(),
                row.getImportedAt(), row.getImportedBy(), row.getApiKeyId(), completedScanId);
    }
}
