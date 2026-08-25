package com.asmolabs.vectispire.core.api;

import com.asmolabs.vectispire.common.domain.vex.OpenVexDocument;
import com.asmolabs.vectispire.common.domain.access.Visibility;
import com.asmolabs.vectispire.core.api.security.RequiresAccount;
import com.asmolabs.vectispire.core.api.security.VectispirePrincipal;
import com.asmolabs.vectispire.core.repositories.Scans;
import com.asmolabs.vectispire.core.services.VisibilityService;
import java.util.NoSuchElementException;
import org.springframework.security.core.annotation.AuthenticationPrincipal;
import com.asmolabs.vectispire.core.api.security.RequiresSecurityLead;
import com.asmolabs.vectispire.core.services.VexGeneratorService;
import com.asmolabs.vectispire.core.services.VexIngestorService;
import com.fasterxml.jackson.databind.JsonNode;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpStatus;
import org.springframework.http.MediaType;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;
import org.springframework.web.server.ResponseStatusException;

/**
 * REST controller exposing standardized OpenVEX v0.2.0 documents and handling multi-format VEX ingestion.
 */
@RestController
@RequestMapping("/api/v1/vex")
@RequiresAccount
public class VexController {

    private final VexGeneratorService vexService;
    private final VexIngestorService vexIngestor;
    private final Scans scans;
    private final VisibilityService visibility;

    public VexController(
            VexGeneratorService vexService,
            VexIngestorService vexIngestor,
            Scans scans,
            VisibilityService visibility) {
        this.vexService = vexService;
        this.vexIngestor = vexIngestor;
        this.scans = scans;
        this.visibility = visibility;
    }

    @GetMapping(value = "/scans/{scanId}/openvex.json", produces = MediaType.APPLICATION_JSON_VALUE)
    public ResponseEntity<OpenVexDocument> getScanVex(
            @AuthenticationPrincipal VectispirePrincipal principal,
            @PathVariable("scanId") Long scanId) {
        requireVisibleScan(principal, scanId);
        OpenVexDocument doc = vexService.generateForScan(scanId)
                .orElseThrow(() -> new ResponseStatusException(HttpStatus.NOT_FOUND, "Scan not found: " + scanId));

        return ResponseEntity.ok()
                .header(HttpHeaders.CONTENT_DISPOSITION, "attachment; filename=\"scan-" + scanId + "-openvex.json\"")
                .body(doc);
    }

    @GetMapping(value = "/aggregate.json", produces = MediaType.APPLICATION_JSON_VALUE)
    public ResponseEntity<OpenVexDocument> getAggregateVex(
            @AuthenticationPrincipal VectispirePrincipal principal) {
        OpenVexDocument doc = vexService.generateAggregate(allowanceOf(principal));
        return ResponseEntity.ok()
                .header(HttpHeaders.CONTENT_DISPOSITION, "attachment; filename=\"vectispire-aggregate-openvex.json\"")
                .body(doc);
    }

    // **A VEX document says "not affected".** Accepting one from any account means any
    // account can silence findings across the estate — the same decision the four-eyes workflow
    // makes deliberately expensive when a human takes it through the interface.
    @RequiresSecurityLead
    @PostMapping(value = "/ingest", consumes = MediaType.APPLICATION_JSON_VALUE)
    public VexIngestorService.IngestionResult ingestVex(@RequestBody String payload) {
        return vexIngestor.ingestPayload(payload);
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
