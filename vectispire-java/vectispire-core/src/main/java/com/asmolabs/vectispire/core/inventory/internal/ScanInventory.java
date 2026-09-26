package com.asmolabs.vectispire.core.inventory.internal;

import com.asmolabs.vectispire.common.domain.apis.ApiContract;
import com.asmolabs.vectispire.common.domain.apis.ApiEndpoint;
import com.asmolabs.vectispire.common.domain.dependencies.DependencyGraph;
import com.asmolabs.vectispire.core.inventory.ApiInventoryService;
import com.asmolabs.vectispire.core.inventory.ComponentInventory;
import com.asmolabs.vectispire.core.services.scanning.ScanIngestor;
import com.fasterxml.jackson.databind.JsonNode;
import java.util.List;
import java.util.Optional;
import org.springframework.stereotype.Component;

/**
 * {@code scanning}'s {@link ScanIngestor.InventorySink}: the components and the API surface a scan
 * found, handed to the two services that kept them before the ingestor stopped calling them itself.
 */
@Component
public class ScanInventory implements ScanIngestor.InventorySink {

    private final ComponentInventory components;
    private final ApiInventoryService apis;

    public ScanInventory(ComponentInventory components, ApiInventoryService apis) {
        this.components = components;
        this.apis = apis;
    }

    @Override
    public void components(long scanId, JsonNode sbom, DependencyGraph graph) {
        components.record(scanId, sbom, graph);
    }

    @Override
    public void apis(long scanId, Long repositoryId, Optional<List<ApiEndpoint>> endpoints,
            Optional<List<ApiContract>> contracts) {
        apis.record(scanId, repositoryId, endpoints, contracts);
    }
}
