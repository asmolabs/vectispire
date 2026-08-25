package com.asmolabs.vectispire.core.api;

import com.asmolabs.vectispire.common.domain.sbom.SbomDiffReport;
import com.asmolabs.vectispire.common.domain.access.Visibility;
import com.asmolabs.vectispire.common.domain.targets.ScanTarget;
import com.asmolabs.vectispire.core.api.security.RequiresAccount;
import com.asmolabs.vectispire.core.api.security.VectispirePrincipal;
import com.asmolabs.vectispire.core.repositories.Scans;
import com.asmolabs.vectispire.core.services.VisibilityService;
import java.util.NoSuchElementException;
import org.springframework.security.core.annotation.AuthenticationPrincipal;
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
    private final Scans scans;
    private final VisibilityService visibility;

    public SbomDiffController(
            SbomDiffService sbomDiffService, Scans scans, VisibilityService visibility) {
        this.sbomDiffService = sbomDiffService;
        this.scans = scans;
        this.visibility = visibility;
    }

    @GetMapping("/diff")
    public ResponseEntity<SbomDiffReport> diff(
            @AuthenticationPrincipal VectispirePrincipal principal,
            @RequestParam("fromScanId") long fromScanId,
            @RequestParam("toScanId") long toScanId) {
        // **Both ends, not one.** A diff names the components that appeared and disappeared
        // between two scans; checking only the first would let a caller pair a scan they may see
        // with one they may not and read the second through the difference.
        Visibility allowed = allowanceOf(principal);
        requireVisibleScan(fromScanId, allowed);
        requireVisibleScan(toScanId, allowed);
        return sbomDiffService.diff(fromScanId, toScanId)
                .map(ResponseEntity::ok)
                .orElseGet(() -> ResponseEntity.notFound().build());
    }

    @GetMapping("/diff/latest")
    public ResponseEntity<SbomDiffReport> diffLatest(
            @AuthenticationPrincipal VectispirePrincipal principal,
            @RequestParam(value = "repoId", required = false) Long repoId,
            @RequestParam(value = "containerId", required = false) Long containerId) {
        Visibility allowed = allowanceOf(principal);
        if (repoId != null) {
            Visibilities.requireVisible(new ScanTarget.Repository(repoId), allowed);
        }
        if (containerId != null) {
            Visibilities.requireVisible(new ScanTarget.Container(containerId), allowed);
        }
        return sbomDiffService.diffLatest(repoId, containerId)
                .map(ResponseEntity::ok)
                .orElseGet(() -> ResponseEntity.notFound().build());
    }

    private Visibility allowanceOf(VectispirePrincipal principal) {
        return visibility.of(principal.user().orElse(null), principal.credentialRestriction());
    }

    private void requireVisibleScan(long scanId, Visibility allowed) {
        Visibilities.requireVisible(
                scans.findById(scanId).orElseThrow(() -> new NoSuchElementException("Scan not found.")),
                allowed);
    }

}
