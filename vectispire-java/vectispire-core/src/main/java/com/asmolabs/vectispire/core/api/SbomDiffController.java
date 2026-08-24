package com.asmolabs.vectispire.core.api;

import com.asmolabs.vectispire.common.domain.sbom.SbomDiffReport;
import com.asmolabs.vectispire.core.api.security.RequiresAccount;
import com.asmolabs.vectispire.core.services.SbomDiffService;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;

/**
 * Endpoints for comparing SBOM inventories and vulnerability deltas across scan runs.
 */
@RestController
@RequestMapping("/api/v1/sbom")
@RequiresAccount
public class SbomDiffController {

    private final SbomDiffService sbomDiffService;

    public SbomDiffController(SbomDiffService sbomDiffService) {
        this.sbomDiffService = sbomDiffService;
    }

    @GetMapping("/diff")
    public ResponseEntity<SbomDiffReport> diff(
            @RequestParam("fromScanId") long fromScanId,
            @RequestParam("toScanId") long toScanId) {
        return sbomDiffService.diff(fromScanId, toScanId)
                .map(ResponseEntity::ok)
                .orElseGet(() -> ResponseEntity.notFound().build());
    }

    @GetMapping("/diff/latest")
    public ResponseEntity<SbomDiffReport> diffLatest(
            @RequestParam(value = "repoId", required = false) Long repoId,
            @RequestParam(value = "containerId", required = false) Long containerId) {
        return sbomDiffService.diffLatest(repoId, containerId)
                .map(ResponseEntity::ok)
                .orElseGet(() -> ResponseEntity.notFound().build());
    }
}
