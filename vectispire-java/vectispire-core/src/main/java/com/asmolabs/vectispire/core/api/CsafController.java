package com.asmolabs.vectispire.core.api;

import com.asmolabs.vectispire.common.domain.csaf.CsafDocument;
import com.asmolabs.vectispire.common.domain.access.Visibility;
import com.asmolabs.vectispire.core.api.security.RequiresAccount;
import com.asmolabs.vectispire.core.api.security.VectispirePrincipal;
import com.asmolabs.vectispire.core.repositories.Scans;
import com.asmolabs.vectispire.core.services.VisibilityService;
import java.util.NoSuchElementException;
import org.springframework.security.core.annotation.AuthenticationPrincipal;
import com.asmolabs.vectispire.core.services.CsafGeneratorService;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpStatus;
import org.springframework.http.MediaType;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;
import org.springframework.web.server.ResponseStatusException;

/**
 * REST controller exposing standardized OASIS CSAF 2.0 VEX security advisory documents.
 */
@RestController
@RequestMapping("/api/v1/csaf")
@RequiresAccount
public class CsafController {

    private final CsafGeneratorService csafService;
    private final Scans scans;
    private final VisibilityService visibility;

    public CsafController(CsafGeneratorService csafService, Scans scans, VisibilityService visibility) {
        this.csafService = csafService;
        this.scans = scans;
        this.visibility = visibility;
    }

    @GetMapping(value = "/scans/{scanId}/csaf.json", produces = MediaType.APPLICATION_JSON_VALUE)
    public ResponseEntity<CsafDocument> getScanCsaf(
            @AuthenticationPrincipal VectispirePrincipal principal,
            @PathVariable("scanId") Long scanId) {
        requireVisibleScan(principal, scanId);
        CsafDocument doc = csafService.generateForScan(scanId)
                .orElseThrow(() -> new ResponseStatusException(HttpStatus.NOT_FOUND, "Scan not found: " + scanId));

        return ResponseEntity.ok()
                .header(HttpHeaders.CONTENT_DISPOSITION, "attachment; filename=\"scan-" + scanId + "-csaf.json\"")
                .body(doc);
    }

    @GetMapping(value = "/aggregate.json", produces = MediaType.APPLICATION_JSON_VALUE)
    public ResponseEntity<CsafDocument> getAggregateCsaf(
            @AuthenticationPrincipal VectispirePrincipal principal) {
        CsafDocument doc = csafService.generateAggregate(allowanceOf(principal));
        return ResponseEntity.ok()
                .header(HttpHeaders.CONTENT_DISPOSITION, "attachment; filename=\"vectispire-aggregate-csaf.json\"")
                .body(doc);
    }

    /**
     * The same scan under a different format is the same authorization question.
     *
     * <p>{@code ScansController} has always asked it for the SBOM; this route did not ask it at
     * all, so which document a caller requested decided whether the check happened.
     */
    private void requireVisibleScan(VectispirePrincipal principal, Long scanId) {
        Visibilities.requireVisible(
                scans.findById(scanId).orElseThrow(() -> new NoSuchElementException("Scan not found.")),
                visibility.of(principal.user().orElse(null), principal.credentialRestriction()));
    }


    private Visibility allowanceOf(VectispirePrincipal principal) {
        return visibility.of(principal.user().orElse(null), principal.credentialRestriction());
    }

}
