package com.asmolabs.vectispire.core.inventory.web;

import com.asmolabs.vectispire.common.domain.access.Visibility;
import com.asmolabs.vectispire.common.domain.access.VisibleTarget;
import com.asmolabs.vectispire.common.domain.sbom.SbomDiffReport;
import com.asmolabs.vectispire.common.domain.targets.ScanTarget;
import com.asmolabs.vectispire.core.access.VisibilityService;
import com.asmolabs.vectispire.core.access.web.security.RequiresAccount;
import com.asmolabs.vectispire.core.access.web.security.VectispirePrincipal;
import com.asmolabs.vectispire.core.access.web.security.Visibilities;
import com.asmolabs.vectispire.core.inventory.SbomDiffService;
import org.springframework.http.ResponseEntity;
import org.springframework.security.core.annotation.AuthenticationPrincipal;
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
    private final VisibilityService visibility;

    public SbomDiffController(SbomDiffService sbomDiffService, VisibilityService visibility) {
        this.sbomDiffService = sbomDiffService;
        this.visibility = visibility;
    }

    @GetMapping("/diff")
    public ResponseEntity<SbomDiffReport> diff(
            @AuthenticationPrincipal VectispirePrincipal principal,
            @RequestParam("fromScanId") long fromScanId,
            @RequestParam("toScanId") long toScanId) {
        // Both ends are refused by the service, where the next caller of the diff meets the rule too.
        return sbomDiffService.diff(fromScanId, toScanId, allowanceOf(principal))
                .map(ResponseEntity::ok)
                .orElseGet(() -> ResponseEntity.notFound().build());
    }

    @GetMapping("/diff/latest")
    public ResponseEntity<SbomDiffReport> diffLatest(
            @AuthenticationPrincipal VectispirePrincipal principal,
            @RequestParam(value = "repoId", required = false) Long repoId,
            @RequestParam(value = "containerId", required = false) Long containerId) {
        // Both refused when both are named, as they always were, and the repository compared. The
        // service takes the proof of the check (`VisibleTarget`) because this module's services do
        // not use `access`. Naming neither compares nothing, which has always answered 404.
        Visibility allowed = allowanceOf(principal);
        VisibleTarget<?> repository = repoId == null
                ? null
                : Visibilities.requireVisible(new ScanTarget.Repository(repoId), allowed);
        VisibleTarget<?> container = containerId == null
                ? null
                : Visibilities.requireVisible(new ScanTarget.Container(containerId), allowed);
        VisibleTarget<?> target = repository != null ? repository : container;
        if (target == null) {
            return ResponseEntity.notFound().build();
        }
        return sbomDiffService.diffLatest(target)
                .map(ResponseEntity::ok)
                .orElseGet(() -> ResponseEntity.notFound().build());
    }

    private Visibility allowanceOf(VectispirePrincipal principal) {
        return visibility.of(principal.user().orElse(null), principal.credentialRestriction());
    }
}
