package com.asmolabs.vectispire.core.posture.web;

import com.asmolabs.vectispire.common.domain.access.Visibility;
import com.asmolabs.vectispire.common.domain.attackpath.AttackPathGraph;
import com.asmolabs.vectispire.common.domain.paging.ListWindow;
import com.asmolabs.vectispire.core.access.VisibilityService;
import com.asmolabs.vectispire.core.access.web.security.RequiresAccount;
import com.asmolabs.vectispire.core.access.web.security.VectispirePrincipal;
import com.asmolabs.vectispire.core.posture.AttackPathService;
import io.swagger.v3.oas.annotations.Operation;
import io.swagger.v3.oas.annotations.Parameter;
import io.swagger.v3.oas.annotations.media.Schema;
import io.swagger.v3.oas.annotations.responses.ApiResponse;
import io.swagger.v3.oas.annotations.tags.Tag;
import java.util.List;
import org.springframework.http.ResponseEntity;
import org.springframework.security.core.annotation.AuthenticationPrincipal;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;

/**
 * Controller exposing Attack Path Analysis graphs and scenario correlations.
 */
@Tag(name = "Attack Paths", description = "Attack Path Visualization and Exploit Scenario Correlation")
@RestController
@RequestMapping("/api/v1/attack-paths")
public class AttackPathController {

    private final AttackPathService attackPathService;
    private final VisibilityService visibility;

    public AttackPathController(
            AttackPathService attackPathService, VisibilityService visibility) {
        this.attackPathService = attackPathService;
        this.visibility = visibility;
    }

    @Operation(
            summary = "Get repository attack path graph",
            description = "Returns the correlated attack path graph (Ingress -> API Endpoint -> Vulnerability -> Secret/DB) for a repository.")
    @ApiResponse(responseCode = "200", description = "Attack path graph generated successfully")
    @ApiResponse(responseCode = "404", description = "Repository not found")
    @RequiresAccount
    @GetMapping("/repositories/{repoId}")
    public ResponseEntity<AttackPathGraph> getRepositoryAttackPath(
            @AuthenticationPrincipal VectispirePrincipal principal,
            @Parameter(description = "Repository unique ID", required = true)
            @PathVariable("repoId") Long repoId) {
        // A hidden repository is refused by the service, as an absent target.
        return attackPathService.getAttackPathGraph(repoId, allowanceOf(principal))
                .map(ResponseEntity::ok)
                .orElseGet(() -> ResponseEntity.notFound().build());
    }

    @Operation(
            summary = "Get global attack paths overview",
            description = "Returns multi-target attack path summaries and critical exploit chain counts across the "
                    + "repositories visible to the caller, by repository id. With limit, one page of them: the same "
                    + "array, cut from what the caller sees; a page shorter than limit is the last.")
    @ApiResponse(responseCode = "200", description = "Attack path overview retrieved successfully")
    @RequiresAccount
    @GetMapping("/overview")
    public List<AttackPathGraph> getOverview(
            @AuthenticationPrincipal VectispirePrincipal principal,
            @Parameter(description = ListWindow.LIMIT_ON_REQUEST,
                    schema = @Schema(type = "integer", format = "int32", minimum = "1", maximum = "" + ListWindow.MAX_LIMIT))
            @RequestParam(required = false) Integer limit,
            @Parameter(description = ListWindow.OFFSET_ON_REQUEST, schema = @Schema(type = "integer", format = "int32", minimum = "0"))
            @RequestParam(required = false) Integer offset) {
        return attackPathService.getOverview(allowanceOf(principal), limit, offset);
    }

    private Visibility allowanceOf(VectispirePrincipal principal) {
        return visibility.of(principal.user().orElse(null), principal.credentialRestriction());
    }
}
