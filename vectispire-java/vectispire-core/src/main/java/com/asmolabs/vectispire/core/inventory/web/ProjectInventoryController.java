package com.asmolabs.vectispire.core.inventory.web;

import com.asmolabs.vectispire.common.domain.apikeys.ApiKeyScope;
import com.asmolabs.vectispire.core.access.VisibilityService;
import com.asmolabs.vectispire.core.access.web.security.AcceptsApiKey;
import com.asmolabs.vectispire.core.access.web.security.RequiresAccount;
import com.asmolabs.vectispire.core.access.web.security.VectispirePrincipal;
import com.asmolabs.vectispire.core.inventory.ConsolidatedInventoryService;
import com.asmolabs.vectispire.core.inventory.ConsolidatedInventoryService.ConsolidatedInventory;
import com.asmolabs.vectispire.core.targets.SolutionQueryService;
import io.swagger.v3.oas.annotations.Operation;
import io.swagger.v3.oas.annotations.tags.Tag;
import org.springframework.security.core.annotation.AuthenticationPrincipal;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.RestController;

/**
 * A project's consolidated SBOM, as JSON (decision 0023). Its CycloneDX document is {@code exports}'.
 *
 * <p><b>The refusal is {@code targets}' guard, here</b>, because this module's services do not use
 * {@code access}: the route resolves the project as far as the caller sees it — 404 for an absent
 * project and for one the caller sees nothing of, in one sentence — and hands the service that proof.
 */
@Tag(name = "Solutions", description = "Solutions, their projects and the repositories and images filed in them")
@RestController
@RequiresAccount
public class ProjectInventoryController {

    private final ConsolidatedInventoryService inventory;
    private final SolutionQueryService projects;
    private final VisibilityService visibility;

    public ProjectInventoryController(
            ConsolidatedInventoryService inventory, SolutionQueryService projects, VisibilityService visibility) {
        this.inventory = inventory;
        this.projects = projects;
        this.visibility = visibility;
    }

    @Operation(summary = "Project components", description = "The components of the newest completed scan of each of "
            + "the project's repositories and images the caller may see, merged by package URL and version, each naming "
            + "the targets that carry it. Every visible target is listed with what was read of it: listed, empty, absent "
            + "(its newest completed scan holds no SBOM) or never_scanned; complete is false while one is absent or never "
            + "scanned. partial says the project holds targets the caller does not see. A project that does not exist and "
            + "one the caller sees nothing of both answer 404, \"Project not found.\".")
    @AcceptsApiKey(ApiKeyScope.READ)
    @GetMapping("/api/v1/projects/{id}/components")
    public ConsolidatedInventory components(
            @PathVariable long id, @AuthenticationPrincipal VectispirePrincipal principal) {
        return inventory.of(projects.visibleProject(id, allowanceOf(principal)));
    }

    /** The caller's visibility with the projects it holds as such, which the tree's rule reads. */
    private VisibilityService.Allowance allowanceOf(VectispirePrincipal principal) {
        return visibility.allowance(principal.user().orElse(null), principal.credentialRestriction());
    }
}
