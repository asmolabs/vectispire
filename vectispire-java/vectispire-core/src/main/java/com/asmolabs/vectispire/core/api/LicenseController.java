package com.asmolabs.vectispire.core.api;

import com.asmolabs.vectispire.common.domain.audit.AuditOperation;
import com.asmolabs.vectispire.common.domain.licenses.LicenseConflictMatrix;
import com.asmolabs.vectispire.common.domain.licenses.LicenseEntry;
import com.asmolabs.vectispire.common.domain.licenses.LicensePolicy;
import com.asmolabs.vectispire.common.domain.licenses.LicenseSummary;
import com.asmolabs.vectispire.core.api.security.RequiresAccount;
import com.asmolabs.vectispire.common.domain.access.Visibility;
import com.asmolabs.vectispire.common.domain.targets.ScanTarget;
import com.asmolabs.vectispire.core.api.security.VectispirePrincipal;
import com.asmolabs.vectispire.core.services.VisibilityService;
import com.asmolabs.vectispire.core.api.security.RequiresSecurityLead;
import com.asmolabs.vectispire.core.api.security.VectispirePrincipal;
import com.asmolabs.vectispire.core.services.AuditLogService;
import com.asmolabs.vectispire.core.services.LicenseGovernanceService;
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
    private final AuditLogService audit;

    public LicenseController(LicenseGovernanceService licenseService, AuditLogService audit,
            VisibilityService visibility) {
        this.licenseService = licenseService;
        this.audit = audit;
        this.visibility = visibility;
    }

    @GetMapping("/inventory")
    public List<LicenseEntry> getInventory(
            @AuthenticationPrincipal VectispirePrincipal principal,
            @RequestParam(name = "repo_id", required = false) Long repoId,
            @RequestParam(name = "container_id", required = false) Long containerId) {
        // A component inventory is a map of someone's dependencies and their licences. A named
        // target must be one the caller may see; an unfiltered call is narrowed to their allowance
        // because the service takes a target, not an allowance.
        Visibility allowed = requireTargetVisible(principal, repoId, containerId);
        return licenseService.getInventory(repoId, containerId).stream()
                .filter(e -> permits(allowed, e.targetKind(), e.targetId()))
                .toList();
    }

    @GetMapping("/summary")
    public LicenseSummary getSummary(
            @AuthenticationPrincipal VectispirePrincipal principal,
            @RequestParam(name = "repo_id", required = false) Long repoId,
            @RequestParam(name = "container_id", required = false) Long containerId) {
        // The summary aggregates the inventory into counts. It takes a target, not an allowance,
        // so a restricted reader is given their own target's figures or none — never the estate's.
        requireEstateOrVisibleTarget(principal, repoId, containerId);
        return licenseService.getSummary(repoId, containerId);
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

        String username = principal != null && principal.user().isPresent()
                ? principal.user().get().getUsername()
                : "system";

        LicensePolicy updated = licenseService.updatePolicy(policy);

        audit.record(new AuditLogService.Record(
                AuditOperation.SETTING_UPDATED,
                "license_policy",
                "Updated open source license compliance policy (disallowed=" + policy.disallowedCategories() + ")",
                username,
                request != null ? request.getRemoteAddr() : null,
                request != null ? request.getHeader("User-Agent") : null));

        return updated;
    }

    @GetMapping("/conflicts")
    public List<LicenseConflictMatrix.LicenseConflict> getConflicts(
            @AuthenticationPrincipal VectispirePrincipal principal,
            @RequestParam(name = "repo_id", required = false) Long repoId,
            @RequestParam(name = "container_id", required = false) Long containerId,
            @RequestParam(name = "proprietary", defaultValue = "true") boolean proprietary) {
        // A conflict carries a target name but no id, so it cannot be filtered per row the way the
        // inventory is. Handled on the same terms as the summary: a named target the caller may
        // see, or — for a restricted reader — refused rather than answered with the estate's.
        requireEstateOrVisibleTarget(principal, repoId, containerId);
        return licenseService.evaluateConflicts(repoId, containerId, proprietary);
    }

    @GetMapping("/matrix")
    public List<LicenseConflictMatrix.CompatibilityCell> getCompatibilityMatrix() {
        return licenseService.getCompatibilityRules();
    }

    /**
     * The allowance in force, having refused a named target the caller cannot see.
     *
     * <p>404 rather than 403, as everywhere else: a refusal distinguishable from an absence
     * answers the enumeration it was meant to prevent.
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

    /**
     * Refuses an aggregate a restricted reader must not receive whole.
     *
     * <p>A named target is checked normally. A call with no target is fine for a reader who sees
     * everything and refused for one who does not, because these two routes aggregate an inventory
     * they cannot narrow themselves.
     */
    private void requireEstateOrVisibleTarget(VectispirePrincipal principal, Long repoId, Long containerId) {
        Visibility allowed = requireTargetVisible(principal, repoId, containerId);
        if (repoId == null && containerId == null && !(allowed instanceof Visibility.Everything)) {
            throw new java.util.NoSuchElementException("Not found.");
        }
    }

    private static boolean permits(Visibility allowed, String targetKind, Long targetId) {
        if (targetId == null) {
            return allowed.permits(null);
        }
        return allowed.permits("container".equalsIgnoreCase(targetKind)
                ? new ScanTarget.Container(targetId)
                : new ScanTarget.Repository(targetId));
    }

}
