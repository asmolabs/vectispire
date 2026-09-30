package com.asmolabs.vectispire.core.compliance.web;

import com.asmolabs.vectispire.common.domain.apikeys.ApiKeyScope;
import com.asmolabs.vectispire.core.access.VisibilityService;
import com.asmolabs.vectispire.core.access.web.security.AcceptsApiKey;
import com.asmolabs.vectispire.core.access.web.security.RequiresAccount;
import com.asmolabs.vectispire.core.access.web.security.VectispirePrincipal;
import com.asmolabs.vectispire.core.compliance.ScopeComplianceService;
import com.asmolabs.vectispire.core.compliance.ScopeComplianceService.ScopeCompliance;
import io.swagger.v3.oas.annotations.Operation;
import io.swagger.v3.oas.annotations.tags.Tag;
import org.springframework.security.core.annotation.AuthenticationPrincipal;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.RestController;

/**
 * A project's and a solution's compliance and score. The rules, the refusal included, are {@link
 * ScopeComplianceService}'s; the route maps the path and the caller.
 */
@Tag(name = "Compliance", description = "Regulatory conformity frameworks (NIS2, ISO 27001, CRA, SOC2, PCI-DSS)")
@RestController
@RequiresAccount
public class ScopeComplianceController {

    private static final String SHAPE = " The estate summary's evaluations, MTTR, counts and per-target matrix, and the "
            + "portfolio scorecard, each computed over the targets the caller sees and nothing else — the same controls, "
            + "coverage and freshness caps, and NO_DATA when none of them was scanned. partial says targets are hidden "
            + "from the caller; targetCount says how many were counted.";

    private final ScopeComplianceService compliance;
    private final VisibilityService visibility;

    public ScopeComplianceController(ScopeComplianceService compliance, VisibilityService visibility) {
        this.compliance = compliance;
        this.visibility = visibility;
    }

    @Operation(summary = "Project compliance", description = "The project's compliance and score." + SHAPE
            + " A project that does not exist and one the caller sees nothing of both answer 404, \"Project not found.\".")
    @AcceptsApiKey(ApiKeyScope.READ)
    @GetMapping("/api/v1/projects/{id}/compliance")
    public ScopeCompliance project(@PathVariable long id, @AuthenticationPrincipal VectispirePrincipal principal) {
        return compliance.ofProject(id, allowanceOf(principal));
    }

    @Operation(summary = "Solution compliance", description = "The solution's compliance and score, over the targets "
            + "filed in its projects." + SHAPE + " A solution that does not exist and one the caller sees nothing of both "
            + "answer 404, \"Solution not found.\".")
    @AcceptsApiKey(ApiKeyScope.READ)
    @GetMapping("/api/v1/solutions/{id}/compliance")
    public ScopeCompliance solution(@PathVariable long id, @AuthenticationPrincipal VectispirePrincipal principal) {
        return compliance.ofSolution(id, allowanceOf(principal));
    }

    /** The caller's visibility with the projects it holds as such, which the tree's rule reads. */
    private VisibilityService.Allowance allowanceOf(VectispirePrincipal principal) {
        return visibility.allowance(principal.user().orElse(null), principal.credentialRestriction());
    }
}
