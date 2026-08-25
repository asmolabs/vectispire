package com.asmolabs.vectispire.core.api;

import com.asmolabs.vectispire.common.domain.graph.BlastRadiusReport;
import com.asmolabs.vectispire.common.domain.graph.BlastRadiusReport.TopImpactPackage;
import com.asmolabs.vectispire.common.domain.access.Visibility;
import com.asmolabs.vectispire.core.api.security.RequiresAccount;
import com.asmolabs.vectispire.core.api.security.VectispirePrincipal;
import com.asmolabs.vectispire.core.services.BlastRadiusService;
import com.asmolabs.vectispire.core.services.VisibilityService;
import java.util.List;
import org.springframework.security.core.annotation.AuthenticationPrincipal;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;

/**
 * REST controller for interactive dependency graph and blast radius impact analysis.
 *
 * <p><b>Both routes are target-scoped and neither used to say so.</b> A blast-radius answer names
 * repositories, packages, versions and CVE identifiers — an inventory. Served without a
 * {@link Visibility}, it handed a reader assigned one repository the contents of every other.
 */
@RestController
@RequestMapping("/api/v1/blast-radius")
@RequiresAccount
public class BlastRadiusController {

    private final BlastRadiusService blastRadiusService;
    private final VisibilityService visibilityService;

    public BlastRadiusController(
            BlastRadiusService blastRadiusService, VisibilityService visibilityService) {
        this.blastRadiusService = blastRadiusService;
        this.visibilityService = visibilityService;
    }

    @GetMapping("/explore")
    public BlastRadiusReport explore(
            @AuthenticationPrincipal VectispirePrincipal principal,
            @RequestParam(value = "q", required = false) String query) {
        return blastRadiusService.explore(query, allowanceOf(principal));
    }

    @GetMapping("/top-impact")
    public List<TopImpactPackage> getTopImpact(
            @AuthenticationPrincipal VectispirePrincipal principal,
            @RequestParam(value = "limit", defaultValue = "10") int limit) {
        return blastRadiusService.getTopImpactPackages(limit, allowanceOf(principal));
    }

    private Visibility allowanceOf(VectispirePrincipal principal) {
        return visibilityService.of(principal.user().orElse(null), principal.credentialRestriction());
    }
}
