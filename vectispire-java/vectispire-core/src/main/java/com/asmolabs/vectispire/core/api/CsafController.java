package com.asmolabs.vectispire.core.api;

import com.asmolabs.vectispire.common.domain.csaf.CsafDocument;
import com.asmolabs.vectispire.core.api.security.RequiresAccount;
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

    public CsafController(CsafGeneratorService csafService) {
        this.csafService = csafService;
    }

    @GetMapping(value = "/scans/{scanId}/csaf.json", produces = MediaType.APPLICATION_JSON_VALUE)
    public ResponseEntity<CsafDocument> getScanCsaf(@PathVariable("scanId") Long scanId) {
        CsafDocument doc = csafService.generateForScan(scanId)
                .orElseThrow(() -> new ResponseStatusException(HttpStatus.NOT_FOUND, "Scan not found: " + scanId));

        return ResponseEntity.ok()
                .header(HttpHeaders.CONTENT_DISPOSITION, "attachment; filename=\"scan-" + scanId + "-csaf.json\"")
                .body(doc);
    }

    @GetMapping(value = "/aggregate.json", produces = MediaType.APPLICATION_JSON_VALUE)
    public ResponseEntity<CsafDocument> getAggregateCsaf() {
        CsafDocument doc = csafService.generateAggregate();
        return ResponseEntity.ok()
                .header(HttpHeaders.CONTENT_DISPOSITION, "attachment; filename=\"vectispire-aggregate-csaf.json\"")
                .body(doc);
    }
}
