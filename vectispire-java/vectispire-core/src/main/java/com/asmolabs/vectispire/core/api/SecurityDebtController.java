package com.asmolabs.vectispire.core.api;

import com.asmolabs.vectispire.common.domain.access.Visibility;
import com.asmolabs.vectispire.common.domain.remediation.HighImpactFix;
import com.asmolabs.vectispire.common.domain.remediation.RemediationCoverage;
import com.asmolabs.vectispire.common.domain.remediation.RemediationDistribution;
import com.asmolabs.vectispire.common.domain.remediation.SecurityDebtReport;
import com.asmolabs.vectispire.core.api.security.RequiresAccount;
import com.asmolabs.vectispire.core.api.security.VectispirePrincipal;
import com.asmolabs.vectispire.core.services.RemediationDistributionService;
import com.asmolabs.vectispire.core.services.SecurityDebtService;
import com.asmolabs.vectispire.core.services.access.VisibilityService;
import java.util.List;
import org.springframework.security.core.annotation.AuthenticationPrincipal;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;
import io.swagger.v3.oas.annotations.responses.ApiResponse;
import io.swagger.v3.oas.annotations.Operation;

/**
 * Endpoints for security debt analytics and prioritized high-impact remediation fixes.
 */
@RestController
@RequestMapping("/api/v1/remediation")
@RequiresAccount
public class SecurityDebtController {

    private final SecurityDebtService securityDebtService;
    private final VisibilityService visibilityService;
    private final RemediationDistributionService distribution;

    public SecurityDebtController(
            SecurityDebtService securityDebtService,
            VisibilityService visibilityService,
            RemediationDistributionService distribution) {
        this.securityDebtService = securityDebtService;
        this.visibilityService = visibilityService;
        this.distribution = distribution;
    }

    /**
     * How long remediation takes, as a shape.
     *
     * <p><b>Beside the mean rather than instead of it.</b> The summary's mean answers "what does a
     * fix usually cost"; this answers "what fraction met its deadline, and how bad is the worst
     * thing still open". A process is proven by the second question — an estate with a mean of two
     * days and a critical open since March is not remediating, and only the tail says so.
     */
    @Operation(summary = "Remediation time distribution", description = "Share within SLA, median, ninetieth percentile and oldest open item, per severity.")
    @ApiResponse(responseCode = "200", description = "Distribution returned")
    @GetMapping("/distribution")
    public RemediationDistributionView distribution(
            @AuthenticationPrincipal VectispirePrincipal principal,
            @RequestParam(required = false, defaultValue = "90") int days) {

        Visibility allowed = visibilityService.of(principal.user().orElse(null), principal.credentialRestriction());
        return RemediationDistributionView.of(distribution.distribution(days, allowed));
    }

    @GetMapping("/debt")
    public SecurityDebtReport debt(
            @AuthenticationPrincipal VectispirePrincipal principal,
            @RequestParam(value = "repoId", required = false) Long repoId,
            @RequestParam(value = "containerId", required = false) Long containerId) {
        Visibility allowed = visibilityService.of(principal.user().orElse(null), principal.credentialRestriction());
        return securityDebtService.calculateDebt(repoId, containerId, allowed);
    }

    /**
     * What the plan cannot close, and why.
     *
     * <p>A separate resource rather than one more field on the plan: a screen that could not
     * obtain the admission must still show the work order, which is its subject.
     */
    @Operation(summary = "Remediation plan coverage", description = "How many open findings an upgrade can close, and which families it cannot.")
    @ApiResponse(responseCode = "200", description = "Coverage returned")
    @GetMapping("/coverage")
    public RemediationCoverage coverage(
            @AuthenticationPrincipal VectispirePrincipal principal,
            @RequestParam(value = "repoId", required = false) Long repoId,
            @RequestParam(value = "containerId", required = false) Long containerId) {
        Visibility allowed = visibilityService.of(principal.user().orElse(null), principal.credentialRestriction());
        return securityDebtService.coverage(repoId, containerId, allowed);
    }

    @GetMapping("/high-impact-fixes")
    public List<HighImpactFix> highImpactFixes(
            @AuthenticationPrincipal VectispirePrincipal principal,
            @RequestParam(value = "repoId", required = false) Long repoId,
            @RequestParam(value = "containerId", required = false) Long containerId,
            // Ten by default, because a short work order is the point; the service clamps any
            // value into its bounds rather than refusing, a plan being no place to answer 400.
            @RequestParam(value = "limit", defaultValue = "10") int limit) {
        Visibility allowed = visibilityService.of(principal.user().orElse(null), principal.credentialRestriction());
        return securityDebtService.highImpactFixes(repoId, containerId, limit, allowed);
    }
}
