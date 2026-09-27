package com.asmolabs.vectispire.core.inventory.web;

import com.asmolabs.vectispire.common.domain.access.Visibility;
import com.asmolabs.vectispire.common.domain.licenses.LicenseConflictMatrix;
import com.asmolabs.vectispire.common.domain.licenses.LicenseEntry;
import com.asmolabs.vectispire.common.domain.licenses.LicensePolicy;
import com.asmolabs.vectispire.common.domain.licenses.LicenseSummary;
import com.asmolabs.vectispire.common.domain.targets.ScanTarget;
import com.asmolabs.vectispire.core.access.VisibilityService;
import com.asmolabs.vectispire.core.access.web.security.RequestActors;
import com.asmolabs.vectispire.core.access.web.security.RequiresAccount;
import com.asmolabs.vectispire.core.access.web.security.RequiresSecurityLead;
import com.asmolabs.vectispire.core.access.web.security.VectispirePrincipal;
import com.asmolabs.vectispire.core.access.web.security.Visibilities;
import com.asmolabs.vectispire.core.inventory.LicenseGovernanceService;
import jakarta.servlet.http.HttpServletRequest;
import java.util.List;
import org.springframework.security.core.annotation.AuthenticationPrincipal;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PutMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;

/**
 * Controller exposing open source software license inventory and compliance policies.
 */
@RestController
@RequestMapping("/api/v1/licenses")
@RequiresAccount
public class LicenseController {

    private final LicenseGovernanceService licenseService;
    private final VisibilityService visibility;

    public LicenseController(LicenseGovernanceService licenseService, VisibilityService visibility) {
        this.licenseService = licenseService;
        this.visibility = visibility;
    }

    @GetMapping("/inventory")
    public List<LicenseEntry> getInventory(
            @AuthenticationPrincipal VectispirePrincipal principal,
            @RequestParam(name = "repo_id", required = false) Long repoId,
            @RequestParam(name = "container_id", required = false) Long containerId) {
        // A named target must be one the caller may see; an unfiltered call is narrowed to their
        // allowance by the service.
        return licenseService.getInventory(requireTargetVisible(principal, repoId, containerId), repoId, containerId);
    }

    @GetMapping("/summary")
    public LicenseSummary getSummary(
            @AuthenticationPrincipal VectispirePrincipal principal,
            @RequestParam(name = "repo_id", required = false) Long repoId,
            @RequestParam(name = "container_id", required = false) Long containerId) {
        // A restricted reader is given their own target's figures or none — never the estate's,
        // which the service refuses them.
        return licenseService.getSummary(requireTargetVisible(principal, repoId, containerId), repoId, containerId);
    }

    @GetMapping("/policy")
    public LicensePolicy getPolicy() {
        return licenseService.getPolicy();
    }

    @PutMapping("/policy")
    @RequiresSecurityLead
    public LicensePolicy updatePolicy(
            @RequestBody LicensePolicy policy,
            @AuthenticationPrincipal VectispirePrincipal principal,
            HttpServletRequest request) {

        return licenseService.updatePolicy(policy, RequestActors.of(principal, request, "system"));
    }

    @GetMapping("/conflicts")
    public List<LicenseConflictMatrix.LicenseConflict> getConflicts(
            @AuthenticationPrincipal VectispirePrincipal principal,
            @RequestParam(name = "repo_id", required = false) Long repoId,
            @RequestParam(name = "container_id", required = false) Long containerId,
            @RequestParam(name = "proprietary", defaultValue = "true") boolean proprietary) {
        // On the summary's terms: a named target the caller may see, or — for a restricted reader —
        // refused by the service rather than answered with the estate's.
        return licenseService.evaluateConflicts(
                requireTargetVisible(principal, repoId, containerId), repoId, containerId, proprietary);
    }

    @GetMapping("/matrix")
    public List<LicenseConflictMatrix.CompatibilityCell> getCompatibilityMatrix() {
        return licenseService.getCompatibilityRules();
    }

    /**
     * The allowance in force, having refused a named target the caller cannot see.
     *
     * <p>Here rather than in the service because the refusal's one sentence is {@code access}'s,
     * and this module uses {@code access} from its routes only. 404 rather than 403, as everywhere
     * else: a refusal distinguishable from an absence answers the enumeration it was meant to
     * prevent.
     */
    private Visibility requireTargetVisible(VectispirePrincipal principal, Long repoId, Long containerId) {
        Visibility allowed = visibility.of(principal.user().orElse(null), principal.credentialRestriction());
        if (repoId != null) {
            Visibilities.requireVisible(new ScanTarget.Repository(repoId), allowed);
        }
        if (containerId != null) {
            Visibilities.requireVisible(new ScanTarget.Container(containerId), allowed);
        }
        return allowed;
    }
}
