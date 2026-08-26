package com.asmolabs.vectispire.core.api;

import com.asmolabs.vectispire.common.domain.attackpath.AttackPathGraph;
import com.asmolabs.vectispire.core.api.security.RequiresAccount;
import com.asmolabs.vectispire.core.services.AttackPathService;
import io.swagger.v3.oas.annotations.Operation;
import io.swagger.v3.oas.annotations.Parameter;
import io.swagger.v3.oas.annotations.responses.ApiResponse;
import io.swagger.v3.oas.annotations.tags.Tag;
import java.util.List;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

/**
 * Controller exposing Attack Path Analysis graphs and scenario correlations.
 */
@Tag(name = "Attack Paths", description = "Attack Path Visualization and Exploit Scenario Correlation")
@RestController
@RequestMapping("/api/v1/attack-paths")
public class AttackPathController {

    private final AttackPathService attackPathService;

    public AttackPathController(AttackPathService attackPathService) {
        this.attackPathService = attackPathService;
    }

    @Operation(
            summary = "Get repository attack path graph",
            description = "Returns the correlated attack path graph (Ingress -> API Endpoint -> Vulnerability -> Secret/DB) for a repository.")
    @ApiResponse(responseCode = "200", description = "Attack path graph generated successfully")
    @ApiResponse(responseCode = "404", description = "Repository not found")
    @RequiresAccount
    @GetMapping("/repositories/{repoId}")
    public ResponseEntity<AttackPathGraph> getRepositoryAttackPath(
            @Parameter(description = "Repository unique ID", required = true)
            @PathVariable("repoId") Long repoId) {
        return attackPathService.getAttackPathGraph(repoId)
                .map(ResponseEntity::ok)
                .orElseGet(() -> ResponseEntity.notFound().build());
    }

    @Operation(
            summary = "Get global attack paths overview",
            description = "Returns multi-target attack path summaries and critical exploit chain counts across all repositories.")
    @ApiResponse(responseCode = "200", description = "Attack path overview retrieved successfully")
    @RequiresAccount
    @GetMapping("/overview")
    public List<AttackPathGraph> getOverview() {
        return attackPathService.getOverview();
    }
}
