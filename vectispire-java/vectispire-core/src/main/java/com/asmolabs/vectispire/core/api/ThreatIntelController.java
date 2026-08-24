package com.asmolabs.vectispire.core.api;

import com.asmolabs.vectispire.common.domain.audit.AuditOperation;
import com.asmolabs.vectispire.common.domain.threatintel.ThreatIntelSyncStatus;
import com.asmolabs.vectispire.core.api.security.RequiresSecurityLead;
import com.asmolabs.vectispire.core.api.security.VectispirePrincipal;
import com.asmolabs.vectispire.core.services.AuditLogService;
import com.asmolabs.vectispire.core.services.ThreatIntelFeedService;
import jakarta.servlet.http.HttpServletRequest;
import org.springframework.security.core.annotation.AuthenticationPrincipal;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

/**
 * Controller exposing live Threat Intelligence feed synchronization and status.
 */
@RestController
@RequestMapping("/api/v1/threat-intel")
@RequiresSecurityLead
public class ThreatIntelController {

    private final ThreatIntelFeedService threatIntelService;
    private final AuditLogService audit;

    public ThreatIntelController(ThreatIntelFeedService threatIntelService, AuditLogService audit) {
        this.threatIntelService = threatIntelService;
        this.audit = audit;
    }

    @GetMapping("/status")
    public ThreatIntelSyncStatus getStatus() {
        return threatIntelService.getStatus();
    }

    @PostMapping("/sync")
    public ThreatIntelSyncStatus sync(
            @AuthenticationPrincipal VectispirePrincipal principal,
            HttpServletRequest request) {

        String username = principal != null && principal.user().isPresent()
                ? principal.user().get().getUsername()
                : "system";

        ThreatIntelSyncStatus result = threatIntelService.syncThreatIntel();

        audit.record(new AuditLogService.Record(
                AuditOperation.SETTING_UPDATED,
                "threat_intel",
                "Live Threat Intel feed synchronized (KEV=" + result.totalKev() + ", updated=" + result.backlogUpdatedCount() + ")",
                username,
                request != null ? request.getRemoteAddr() : null,
                request != null ? request.getHeader("User-Agent") : null));

        return result;
    }
}
