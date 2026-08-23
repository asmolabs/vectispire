package com.asmolabs.zanshin.core.services;

import com.asmolabs.zanshin.common.domain.dependencies.DependencyGraph;
import com.asmolabs.zanshin.core.persistence.ComponentEntity;
import com.asmolabs.zanshin.core.repositories.Components;
import com.fasterxml.jackson.databind.JsonNode;
import java.util.ArrayList;
import java.util.List;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Propagation;
import org.springframework.transaction.annotation.Transactional;

/**
 * Turning a stored SBOM into rows a search can reach.
 *
 * <p>A service of its own because two callers need exactly the same rule: ingestion writes the
 * inventory of a scan that just ran, and the backfill writes the inventory of scans that ran
 * before this existed. Two copies would be two answers to "what counts as a component", and they
 * would drift on the first ecosystem that reports something unusual.
 */
@Service
public class ComponentInventory {

    private final Components components;

    public ComponentInventory(Components components) {
        this.components = components;
    }

    /**
     * Replaces this scan's inventory with what the SBOM says.
     *
     * <p><b>Replaced, never merged.</b> A scan re-run after a failure must not leave the
     * components of its first attempt beside the second's: the inventory of a scan is what that
     * scan saw, and two overlapping answers to that are worse than none.
     */
    @Transactional(propagation = Propagation.REQUIRED)
    public int record(long scanId, JsonNode sbom, DependencyGraph graph) {
        JsonNode artifacts = sbom == null ? null : sbom.path("artifacts");
        if (artifacts == null || !artifacts.isArray()) {
            return 0;
        }

        components.deleteByScanId(scanId);

        List<ComponentEntity> rows = new ArrayList<>();
        for (JsonNode artifact : artifacts) {
            String name = artifact.path("name").asText(null);
            if (name == null || name.isBlank()) {
                continue;
            }
            String version = text(artifact.path("version"));
            String purl = text(artifact.path("purl"));

            ComponentEntity row = new ComponentEntity();
            row.setScanId(scanId);
            row.setName(trim(name, 255));
            row.setVersion(trim(version, 255));
            row.setPurl(trim(purl, 500));
            row.setType(trim(text(artifact.path("type")), 50));
            row.setIsDirect(switch (graph.of(purl, name, version)) {
                case DIRECT -> Boolean.TRUE;
                case TRANSITIVE -> Boolean.FALSE;
                // Not `false`. Several ecosystems produce an SBOM with no dependency graph, and
                // recording "transitive" there would state something nothing established.
                case UNKNOWN -> null;
            });
            rows.add(row);
        }

        components.saveAll(rows);
        return rows.size();
    }

    private static String text(JsonNode node) {
        return node.isTextual() && !node.asText().isBlank() ? node.asText() : null;
    }

    /** The column's width, applied here rather than discovered as a write failure mid-scan. */
    private static String trim(String value, int max) {
        return value == null || value.length() <= max ? value : value.substring(0, max);
    }
}
