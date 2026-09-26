package com.asmolabs.vectispire.core.exports.web;

import com.asmolabs.vectispire.common.domain.access.Visibility;
import com.asmolabs.vectispire.common.domain.apikeys.ApiKeyScope;
import com.asmolabs.vectispire.common.domain.cyclonedx.CycloneDxDocument;
import com.asmolabs.vectispire.core.access.VisibilityService;
import com.asmolabs.vectispire.core.access.web.security.AcceptsApiKey;
import com.asmolabs.vectispire.core.access.web.security.RequiresAccount;
import com.asmolabs.vectispire.core.access.web.security.VectispirePrincipal;
import com.asmolabs.vectispire.core.exports.CycloneDxGeneratorService;
import com.asmolabs.vectispire.core.scanning.ScanDocumentService;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpStatus;
import org.springframework.http.MediaType;
import org.springframework.http.ResponseEntity;
import org.springframework.security.core.annotation.AuthenticationPrincipal;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;
import org.springframework.web.server.ResponseStatusException;

/**
 * REST controller exposing CycloneDX 1.5/1.6 SBOM with BOM-linked VEX advisories.
 */
@RestController
@RequestMapping("/api/v1/cyclonedx")
@RequiresAccount
public class CycloneDxController {

    private final CycloneDxGeneratorService cycloneDxService;
    private final ScanDocumentService scans;
    private final VisibilityService visibility;

    public CycloneDxController(
            CycloneDxGeneratorService cycloneDxService, ScanDocumentService scans, VisibilityService visibility) {
        this.cycloneDxService = cycloneDxService;
        this.scans = scans;
        this.visibility = visibility;
    }

    @AcceptsApiKey(ApiKeyScope.EXPORT)
    @GetMapping(value = "/scans/{scanId}/cyclonedx-vex.json", produces = MediaType.APPLICATION_JSON_VALUE)
    public ResponseEntity<CycloneDxDocument> getScanCycloneDx(
            @AuthenticationPrincipal VectispirePrincipal principal,
            @PathVariable("scanId") Long scanId) {
        requireVisibleScan(principal, scanId);
        CycloneDxDocument doc = cycloneDxService.generateForScan(scanId)
                .orElseThrow(() -> new ResponseStatusException(HttpStatus.NOT_FOUND, "Scan not found: " + scanId));

        return ResponseEntity.ok()
                .header(HttpHeaders.CONTENT_DISPOSITION, "attachment; filename=\"scan-" + scanId + "-cyclonedx-vex.json\"")
                .body(doc);
    }

    @AcceptsApiKey(ApiKeyScope.EXPORT)
    @GetMapping(value = "/aggregate.json", produces = MediaType.APPLICATION_JSON_VALUE)
    public ResponseEntity<CycloneDxDocument> getAggregateCycloneDx(
            @AuthenticationPrincipal VectispirePrincipal principal) {
        CycloneDxDocument doc = cycloneDxService.generateAggregate(allowanceOf(principal));
        return ResponseEntity.ok()
                .header(HttpHeaders.CONTENT_DISPOSITION, "attachment; filename=\"vectispire-aggregate-cyclonedx-vex.json\"")
                .body(doc);
    }

    /**
     * The same scan under a different format is the same authorization question.
     *
     * <p>{@code ScansController} has always asked it for the SBOM; this route did not ask it at
     * all, so which document a caller requested decided whether the check happened.
     */
    private void requireVisibleScan(VectispirePrincipal principal, Long scanId) {
        scans.requireVisible(
                scanId,
                visibility.of(principal.user().orElse(null), principal.credentialRestriction()));
    }


    private Visibility allowanceOf(VectispirePrincipal principal) {
        return visibility.of(principal.user().orElse(null), principal.credentialRestriction());
    }

}
