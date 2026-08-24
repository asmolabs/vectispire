package com.asmolabs.vectispire.core.api;

import com.asmolabs.vectispire.common.domain.audit.AuditOperation;
import com.asmolabs.vectispire.common.domain.licenses.LicenseConflictMatrix;
import com.asmolabs.vectispire.common.domain.licenses.LicenseEntry;
import com.asmolabs.vectispire.common.domain.licenses.LicensePolicy;
import com.asmolabs.vectispire.common.domain.licenses.LicenseSummary;
import com.asmolabs.vectispire.core.api.security.RequiresAccount;
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
    private final AuditLogService audit;

    public LicenseController(LicenseGovernanceService licenseService, AuditLogService audit) {
        this.licenseService = licenseService;
        this.audit = audit;
    }

    @GetMapping("/inventory")
    public List<LicenseEntry> getInventory(
            @RequestParam(name = "repo_id", required = false) Long repoId,
            @RequestParam(name = "container_id", required = false) Long containerId) {
        return licenseService.getInventory(repoId, containerId);
    }

    @GetMapping("/summary")
    public LicenseSummary getSummary(
            @RequestParam(name = "repo_id", required = false) Long repoId,
            @RequestParam(name = "container_id", required = false) Long containerId) {
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
            @RequestParam(name = "repo_id", required = false) Long repoId,
            @RequestParam(name = "container_id", required = false) Long containerId,
            @RequestParam(name = "proprietary", defaultValue = "true") boolean proprietary) {
        return licenseService.evaluateConflicts(repoId, containerId, proprietary);
    }

    @GetMapping("/matrix")
    public List<LicenseConflictMatrix.CompatibilityCell> getCompatibilityMatrix() {
        return licenseService.getCompatibilityRules();
    }
}
