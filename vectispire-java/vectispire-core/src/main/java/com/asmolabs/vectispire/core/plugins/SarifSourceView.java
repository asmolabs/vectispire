package com.asmolabs.vectispire.core.plugins;

import com.asmolabs.vectispire.core.plugins.persistence.SarifSourceEntity;
import java.time.Instant;
import java.util.Arrays;
import java.util.List;
import java.util.UUID;

/**
 * A declared SARIF source, under the entity's property names.
 *
 * @param projectId and {@code repositoryId}: exactly one is set — the one scope it may deliver for
 * @param tools the tool names it may deliver, lowercased, as {@code tool.driver.name} is compared
 */
public record SarifSourceView(
        Long id,
        String slug,
        String name,
        UUID apiKeyId,
        Long projectId,
        Long repositoryId,
        List<String> tools,
        boolean enabled,
        Instant createdAt,
        String createdBy) {

    static SarifSourceView of(SarifSourceEntity source) {
        return new SarifSourceView(source.getId(), source.getSlug(), source.getName(), source.getApiKeyId(),
                source.getProjectId(), source.getRepositoryId(), tools(source.getTools()), source.getEnabled(),
                source.getCreatedAt(), source.getCreatedBy());
    }

    static List<String> tools(String stored) {
        return stored == null || stored.isBlank() ? List.of() : Arrays.stream(stored.split(",")).toList();
    }
}
