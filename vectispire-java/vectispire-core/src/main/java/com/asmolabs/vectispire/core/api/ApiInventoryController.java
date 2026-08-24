package com.asmolabs.vectispire.core.api;

import com.asmolabs.vectispire.core.api.security.RequiresAccount;
import com.asmolabs.vectispire.core.services.ApiInventoryService;
import com.asmolabs.vectispire.core.services.ApiInventoryService.GlobalAttackSurface;
import com.asmolabs.vectispire.core.services.ApiInventoryService.RepositoryApisOverview;
import io.swagger.v3.oas.annotations.Operation;
import io.swagger.v3.oas.annotations.Parameter;
import io.swagger.v3.oas.annotations.responses.ApiResponse;
import io.swagger.v3.oas.annotations.tags.Tag;
import org.springframework.http.HttpHeaders;
import org.springframework.http.MediaType;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.DeleteMapping;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

/**
 * REST API for Attack Surface Discovery & Exposed API Inventory.
 */
@Tag(name = "Attack Surface", description = "Discovered API endpoints, declared contracts (OpenAPI/Swagger) and shadow APIs")
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
    @Operation(summary = "Get global attack surface", description = "Returns cross-repository aggregated statistics, frameworks detected, and unauthenticated endpoints.")
    @ApiResponse(responseCode = "200", description = "Global attack surface summary retrieved successfully")
    @GetMapping("/attack-surface")
    public GlobalAttackSurface globalAttackSurface() {
        return apiInventoryService.globalAttackSurface();
    }

    /**
     * Discovered endpoints, contracts, and shadow API drift for a specific repository.
     */
    @Operation(summary = "Get repository APIs overview", description = "Returns all discovered endpoints, declared OpenAPI contracts, and shadow API differences for a repository.")
    @ApiResponse(responseCode = "200", description = "Repository API inventory retrieved successfully")
    @GetMapping("/repositories/{id}/apis")
    public RepositoryApisOverview repositoryApis(
            @Parameter(description = "Repository identifier", required = true) @PathVariable long id) {
        return apiInventoryService.forRepository(id);
    }

    /**
     * Purges all discovered endpoints and contracts across all repositories.
     */
    @Operation(summary = "Purge all attack surface data", description = "Atomically deletes all endpoints and contracts across the entire platform.")
    @ApiResponse(responseCode = "204", description = "Global attack surface purged successfully")
    @DeleteMapping("/attack-surface")
    public ResponseEntity<Void> clearAllAttackSurfaces() {
        apiInventoryService.clearAll();
        return ResponseEntity.noContent().build();
    }

    /**
     * Purges discovered endpoints and contracts for a specific repository.
     */
    @Operation(summary = "Purge repository attack surface data", description = "Deletes all endpoints and contracts belonging to a specific repository.")
    @ApiResponse(responseCode = "204", description = "Repository attack surface purged successfully")
    @DeleteMapping("/repositories/{id}/apis")
    public ResponseEntity<Void> clearRepositoryAttackSurface(
            @Parameter(description = "Repository identifier", required = true) @PathVariable long id) {
        apiInventoryService.clearForRepository(id);
        return ResponseEntity.noContent().build();
    }

    /**
     * Export synthesized OpenAPI 3.0 specification for a repository.
     */
    @Operation(summary = "Export synthesized OpenAPI specification", description = "Synthesizes an OpenAPI 3.0 document from static endpoint discovery.")
    @ApiResponse(responseCode = "200", description = "Synthesized OpenAPI 3.0 JSON document")
    @GetMapping(value = "/repositories/{id}/apis/export/openapi", produces = MediaType.APPLICATION_JSON_VALUE)
    public ResponseEntity<String> exportOpenApi(
            @Parameter(description = "Repository identifier", required = true) @PathVariable long id) {
        String json = apiInventoryService.exportSynthesizedOpenApiJson(id);
        return ResponseEntity.ok()
                .header(HttpHeaders.CONTENT_DISPOSITION, "attachment; filename=\"openapi-repository-" + id + ".json\"")
                .body(json);
    }
}
