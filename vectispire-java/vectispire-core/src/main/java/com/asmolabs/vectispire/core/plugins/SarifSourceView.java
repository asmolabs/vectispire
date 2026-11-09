package com.asmolabs.vectispire.core.plugins;

import com.asmolabs.vectispire.core.plugins.persistence.SarifSourceEntity;
import java.time.Instant;
import java.util.Arrays;
import java.util.List;
import java.util.UUID;

/**
 * A declared source, under the entity's property names.
 *
 * @param apiKeyName the bound key's name, as the key list shows it — what lets a governance reader who
 *     may not open that list (an auditor, a CISO) tell which pipeline delivers; null once the key is
 *     revoked, which leaves the source importing nothing
 * @param projectId and {@code repositoryId}: exactly one is set — the one scope it may deliver for
 * @param tools the SARIF tool names it may deliver, lowercased, as {@code tool.driver.name} is
 *     compared; empty for a source that delivers no SARIF
 * @param kinds what it may deliver: {@code sarif}, {@code coverage}, {@code test_report}
 */
public record SarifSourceView(
        Long id,
        String slug,
        String name,
        UUID apiKeyId,
        String apiKeyName,
        Long projectId,
        Long repositoryId,
        List<String> tools,
        List<String> kinds,
        boolean enabled,
        Instant createdAt,
        String createdBy) {

    static SarifSourceView of(SarifSourceEntity source, String apiKeyName) {
        return new SarifSourceView(source.getId(), source.getSlug(), source.getName(), source.getApiKeyId(), apiKeyName,
                source.getProjectId(), source.getRepositoryId(), tools(source.getTools()),
                SourceKind.fromStored(source.getKinds()).stream().map(SourceKind::wireName).toList(), source.getEnabled(),
                source.getCreatedAt(), source.getCreatedBy());
    }

    static List<String> tools(String stored) {
        return stored == null || stored.isBlank() ? List.of() : Arrays.stream(stored.split(",")).toList();
    }
}
