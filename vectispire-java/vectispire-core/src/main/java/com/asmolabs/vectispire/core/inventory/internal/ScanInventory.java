package com.asmolabs.vectispire.core.inventory.internal;

import com.asmolabs.vectispire.common.domain.apis.ApiContract;
import com.asmolabs.vectispire.common.domain.apis.ApiEndpoint;
import com.asmolabs.vectispire.common.domain.dependencies.DependencyGraph;
import com.asmolabs.vectispire.core.inventory.ApiInventoryService;
import com.asmolabs.vectispire.core.inventory.BuildSbomInventory;
import com.asmolabs.vectispire.core.inventory.ComponentInventory;
import com.asmolabs.vectispire.core.scanning.ScanIngestor;
import com.asmolabs.vectispire.core.scanning.ScanOrigin;
import com.fasterxml.jackson.databind.JsonNode;
import java.util.List;
import java.util.Optional;
import org.springframework.stereotype.Component;

/**
 * {@code scanning}'s {@link ScanIngestor.InventorySink}: the components and the API surface a scan
 * found, handed to the two services that kept them before the ingestor stopped calling them itself.
 *
 * <p>The scanner's components are then completed by the repository's newest build SBOM that may speak
 * for the scan ({@link BuildSbomInventory#complete}), in the same transaction: a scan of an unchanged
 * tree keeps what the last build stated, and nothing reads the inventory in between.
 */
@Component
public class ScanInventory implements ScanIngestor.InventorySink {

    private final ComponentInventory components;
    private final ApiInventoryService apis;
    private final BuildSbomInventory builds;

    public ScanInventory(ComponentInventory components, ApiInventoryService apis, BuildSbomInventory builds) {
        this.components = components;
        this.apis = apis;
        this.builds = builds;
    }

    @Override
    public void components(ScanOrigin scan, JsonNode sbom, DependencyGraph graph) {
        components.record(scan, sbom, graph);
        builds.complete(scan);
    }

    @Override
    public void apis(long scanId, Long repositoryId, Optional<List<ApiEndpoint>> endpoints,
            Optional<List<ApiContract>> contracts) {
        apis.record(scanId, repositoryId, endpoints, contracts);
    }
}
