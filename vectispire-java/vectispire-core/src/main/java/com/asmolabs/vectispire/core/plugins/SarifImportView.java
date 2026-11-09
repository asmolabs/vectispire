package com.asmolabs.vectispire.core.plugins;

import com.asmolabs.vectispire.core.plugins.persistence.SarifImportEntity;
import java.time.Instant;
import java.util.Arrays;
import java.util.List;
import java.util.UUID;

/**
 * An accepted import, under the entity's property names: what was declared, by which source and
 * key, and what it did to the repository's backlog.
 *
 * @param tools the tools the report declared, one {@code name version} each, in the report's order.
 *     Split from the stored text, which the import clips at 1,000 characters — the last entry of a
 *     report naming that much ends where the clip did. The document's digest names the exact words.
 * @param toolKeys the tool keys whose runs were accepted, sorted, one per entry; null — never an empty
 *     list — for an import accepted before they were recorded, which is not an import that accepted none
 * @param documentSha256 of the bytes uploaded — what lets a pipeline prove which report it sent
 */
public record SarifImportView(
        Long id,
        Long sourceId,
        String sourceSlug,
        Long repoId,
        List<String> tools,
        List<String> toolKeys,
        String documentSha256,
        int resultsCount,
        int createdCount,
        int resolvedCount,
        int reopenedCount,
        Instant importedAt,
        String importedBy,
        UUID apiKeyId) {

    static SarifImportView of(SarifImportEntity row) {
        return new SarifImportView(row.getId(), row.getSourceId(), row.getSourceSlug(), row.getRepoId(),
                tools(row.getTools()), toolKeys(row.getToolKeys()), row.getDocumentSha256(), row.getResultsCount(),
                row.getCreatedCount(), row.getResolvedCount(), row.getReopenedCount(), row.getImportedAt(), row.getImportedBy(), row.getApiKeyId());
    }

    /**
     * The stored keys as the list they were joined from. A key holds no comma — {@code import:<source>/<tool>},
     * a slug and a declared tool name, both refused with one — which is what the repository's own match
     * ({@code concat(',', toolKeys, ',')}) already relies on. Null stays null: a row from before V53
     * recorded no keys, and an empty list would say it accepted none.
     */
    static List<String> toolKeys(String stored) {
        if (stored == null) {
            return null;
        }
        return Arrays.stream(stored.split(",")).map(String::strip).filter(key -> !key.isEmpty()).toList();
    }

    /**
     * The stored text as the list it was joined from. A tool name holds no comma — the import accepts
     * only names a source declared, and a declared one is refused with a comma — and {@link
     * SarifImportService} writes a version's commas as semicolons, so a comma always separates. Rows
     * written before that keep a version's comma, and read as one entry more; the text is display, and
     * nothing decides on it.
     */
    static List<String> tools(String stored) {
        if (stored == null || stored.isBlank()) {
            return List.of();
        }
        return Arrays.stream(stored.split(",")).map(String::strip).filter(tool -> !tool.isEmpty()).toList();
    }
}
