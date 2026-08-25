package com.asmolabs.vectispire.core.api;

import com.asmolabs.vectispire.common.domain.access.Visibility;
import com.asmolabs.vectispire.common.domain.remediation.HighImpactFix;
import com.asmolabs.vectispire.common.domain.remediation.SecurityDebtReport;
import com.asmolabs.vectispire.core.api.security.RequiresAccount;
import com.asmolabs.vectispire.core.api.security.VectispirePrincipal;
import com.asmolabs.vectispire.core.services.SecurityDebtService;
import com.asmolabs.vectispire.core.services.VisibilityService;
import java.util.List;
import org.springframework.security.core.annotation.AuthenticationPrincipal;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;

/**
 * Endpoints for security debt analytics and prioritized high-impact remediation fixes.
 */
@RestController
@RequestMapping("/api/v1/remediation")
@RequiresAccount
public class SecurityDebtController {

    private final SecurityDebtService securityDebtService;
    private final VisibilityService visibilityService;

    public SecurityDebtController(
            SecurityDebtService securityDebtService,
            VisibilityService visibilityService) {
        this.securityDebtService = securityDebtService;
        this.visibilityService = visibilityService;
    }

    @GetMapping("/debt")
    public SecurityDebtReport debt(
            @AuthenticationPrincipal VectispirePrincipal principal,
            @RequestParam(value = "repoId", required = false) Long repoId,
            @RequestParam(value = "containerId", required = false) Long containerId) {
        Visibility allowed = visibilityService.of(principal.user().orElse(null), principal.credentialRestriction());
        return securityDebtService.calculateDebt(repoId, containerId, allowed);
    }

    @GetMapping("/high-impact-fixes")
    public List<HighImpactFix> highImpactFixes(
            @AuthenticationPrincipal VectispirePrincipal principal,
            @RequestParam(value = "repoId", required = false) Long repoId,
            @RequestParam(value = "containerId", required = false) Long containerId) {
        Visibility allowed = visibilityService.of(principal.user().orElse(null), principal.credentialRestriction());
        return securityDebtService.highImpactFixes(repoId, containerId, allowed);
    }
}
