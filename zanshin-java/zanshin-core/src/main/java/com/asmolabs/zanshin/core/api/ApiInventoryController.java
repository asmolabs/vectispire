package com.asmolabs.zanshin.core.api;

import com.asmolabs.zanshin.core.api.security.RequiresAccount;
import com.asmolabs.zanshin.core.services.ApiInventoryService;
import com.asmolabs.zanshin.core.services.ApiInventoryService.GlobalAttackSurface;
import com.asmolabs.zanshin.core.services.ApiInventoryService.RepositoryApisOverview;
import org.springframework.http.HttpHeaders;
import org.springframework.http.MediaType;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

/**
 * REST API for Attack Surface Discovery & Exposed API Inventory.
 */
@RestController
@RequestMapping("/api/v1")
@RequiresAccount
public class ApiInventoryController {

    private final ApiInventoryService apiInventoryService;

    public ApiInventoryController(ApiInventoryService apiInventoryService) {
        this.apiInventoryService = apiInventoryService;
    }

    /**
     * Cross-repository global attack surface summary and high risk exposed endpoints.
     */
    @GetMapping("/attack-surface")
    public GlobalAttackSurface globalAttackSurface() {
        return apiInventoryService.globalAttackSurface();
    }

    /**
     * Discovered endpoints, contracts, and shadow API drift for a specific repository.
     */
    @GetMapping("/repositories/{id}/apis")
    public RepositoryApisOverview repositoryApis(@PathVariable long id) {
        return apiInventoryService.forRepository(id);
    }

    /**
     * Export synthesized OpenAPI 3.0 specification for a repository.
     */
    @GetMapping(value = "/repositories/{id}/apis/export/openapi", produces = MediaType.APPLICATION_JSON_VALUE)
    public ResponseEntity<String> exportOpenApi(@PathVariable long id) {
        String json = apiInventoryService.exportSynthesizedOpenApiJson(id);
        return ResponseEntity.ok()
                .header(HttpHeaders.CONTENT_DISPOSITION, "attachment; filename=\"openapi-repository-" + id + ".json\"")
                .body(json);
    }
}
