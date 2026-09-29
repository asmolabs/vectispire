package com.asmolabs.vectispire.core.plugins;

import com.asmolabs.vectispire.core.plugins.persistence.SarifImportEntity;
import java.time.Instant;
import java.util.UUID;

/**
 * An accepted import, under the entity's property names: what was declared, by which source and
 * key, and what it did to the repository's backlog.
 *
 * @param tools the tools the report declared, {@code name version}, comma-separated
 * @param toolKeys the tool keys whose runs were accepted, sorted, comma-separated; null for an import
 *     accepted before they were recorded
 * @param documentSha256 of the bytes uploaded — what lets a pipeline prove which report it sent
 */
public record SarifImportView(
        Long id,
        Long sourceId,
        String sourceSlug,
        Long repoId,
        String tools,
        String toolKeys,
        String documentSha256,
        int resultsCount,
        int createdCount,
        int resolvedCount,
        int reopenedCount,
        Instant importedAt,
        String importedBy,
        UUID apiKeyId) {

    static SarifImportView of(SarifImportEntity row) {
        return new SarifImportView(row.getId(), row.getSourceId(), row.getSourceSlug(), row.getRepoId(), row.getTools(),
                row.getToolKeys(), row.getDocumentSha256(), row.getResultsCount(), row.getCreatedCount(), row.getResolvedCount(),
                row.getReopenedCount(), row.getImportedAt(), row.getImportedBy(), row.getApiKeyId());
    }
}
