package com.asmolabs.vectispire.core.api;

import com.asmolabs.vectispire.common.domain.threatintel.EpssRiskMatrix.EpssFleetSummary;
import com.asmolabs.vectispire.common.domain.threatintel.ThreatIntelRecord;
import com.asmolabs.vectispire.common.domain.threatintel.ThreatIntelSyncStatus;
import com.asmolabs.vectispire.core.api.security.RequiresAccount;
import com.asmolabs.vectispire.core.api.security.VectispirePrincipal;
import com.asmolabs.vectispire.core.services.VisibilityService;
import org.springframework.security.core.annotation.AuthenticationPrincipal;
import com.asmolabs.vectispire.core.api.security.RequiresSecurityLead;
import com.asmolabs.vectispire.core.services.EpssPrioritizationService;
import com.asmolabs.vectispire.core.services.ThreatIntelFeedService;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

/**
 * REST controller for EPSS (Exploit Prediction Scoring System) prioritization,
 * vulnerability quadrant mapping, and real-time CVE lookup.
 */
@RestController
@RequestMapping("/api/v1/epss")
@RequiresAccount
public class EpssController {

    private final EpssPrioritizationService epssService;
    private final ThreatIntelFeedService threatIntelFeedService;
    private final VisibilityService visibility;

    public EpssController(
            EpssPrioritizationService epssService,
            ThreatIntelFeedService threatIntelFeedService,
            VisibilityService visibility) {
        this.epssService = epssService;
        this.threatIntelFeedService = threatIntelFeedService;
        this.visibility = visibility;
    }

    @GetMapping("/priorities")
    public EpssFleetSummary getPriorities(@AuthenticationPrincipal VectispirePrincipal principal) {
        return epssService.getFleetSummary(
                visibility.of(principal.user().orElse(null), principal.credentialRestriction()));
    }

    @GetMapping("/cve/{cveId}")
    public ResponseEntity<ThreatIntelRecord> lookupCve(@PathVariable String cveId) {
        return epssService.lookupCve(cveId)
                .map(ResponseEntity::ok)
                .orElseGet(() -> ResponseEntity.notFound().build());
    }

    // Outbound, repeatable at will, and rate-limited by whoever serves it. Not destructive,
    // which is why it is a lead's rather than an administrator's, but not a reader's.
    @RequiresSecurityLead
    @PostMapping("/sync")
    public ThreatIntelSyncStatus sync() {
        return threatIntelFeedService.syncThreatIntel();
    }
}
