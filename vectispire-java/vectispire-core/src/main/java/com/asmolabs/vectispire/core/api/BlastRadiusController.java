package com.asmolabs.zanshin.core.api;

import com.asmolabs.zanshin.common.domain.graph.BlastRadiusReport;
import com.asmolabs.zanshin.common.domain.graph.BlastRadiusReport.TopImpactPackage;
import com.asmolabs.zanshin.core.api.security.RequiresAccount;
import com.asmolabs.zanshin.core.services.BlastRadiusService;
import java.util.List;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;

/**
 * REST controller for interactive dependency graph and blast radius impact analysis.
 */
@RestController
@RequestMapping("/api/v1/blast-radius")
@RequiresAccount
public class BlastRadiusController {

    private final BlastRadiusService blastRadiusService;

    public BlastRadiusController(BlastRadiusService blastRadiusService) {
        this.blastRadiusService = blastRadiusService;
    }

    @GetMapping("/explore")
    public BlastRadiusReport explore(@RequestParam(value = "q", required = false) String query) {
        return blastRadiusService.explore(query);
    }

    @GetMapping("/top-impact")
    public List<TopImpactPackage> getTopImpact(@RequestParam(value = "limit", defaultValue = "10") int limit) {
        return blastRadiusService.getTopImpactPackages(limit);
    }
}
