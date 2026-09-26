package com.asmolabs.vectispire.core.api;

import com.asmolabs.vectispire.common.domain.threatintel.ThreatIntelSyncStatus;
import com.asmolabs.vectispire.core.api.security.RequiresGovernanceRead;
import com.asmolabs.vectispire.core.api.security.RequiresSecurityLead;
import com.asmolabs.vectispire.core.api.security.VectispirePrincipal;
import com.asmolabs.vectispire.core.services.threatintel.ThreatIntelFeedService;
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
@RequiresGovernanceRead
public class ThreatIntelController {

    private final ThreatIntelFeedService threatIntelService;

    public ThreatIntelController(ThreatIntelFeedService threatIntelService) {
        this.threatIntelService = threatIntelService;
    }

    @GetMapping("/status")
    public ThreatIntelSyncStatus getStatus() {
        return threatIntelService.getStatus();
    }

    @RequiresSecurityLead
    @PostMapping("/sync")
    public ThreatIntelSyncStatus sync(
            @AuthenticationPrincipal VectispirePrincipal principal,
            HttpServletRequest request) {

        return threatIntelService.syncThreatIntel(RequestActors.of(principal, request, "system"));
    }
}
