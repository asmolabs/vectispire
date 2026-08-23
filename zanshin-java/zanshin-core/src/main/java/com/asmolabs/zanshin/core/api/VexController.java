package com.asmolabs.zanshin.core.api;

import com.asmolabs.zanshin.common.domain.vex.OpenVexDocument;
import com.asmolabs.zanshin.core.api.security.RequiresAccount;
import com.asmolabs.zanshin.core.services.VexGeneratorService;
import com.asmolabs.zanshin.core.services.VexIngestorService;
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

    public VexController(
            VexGeneratorService vexService,
            VexIngestorService vexIngestor) {
        this.vexService = vexService;
        this.vexIngestor = vexIngestor;
    }

    @GetMapping(value = "/scans/{scanId}/openvex.json", produces = MediaType.APPLICATION_JSON_VALUE)
    public ResponseEntity<OpenVexDocument> getScanVex(@PathVariable("scanId") Long scanId) {
        OpenVexDocument doc = vexService.generateForScan(scanId)
                .orElseThrow(() -> new ResponseStatusException(HttpStatus.NOT_FOUND, "Scan not found: " + scanId));

        return ResponseEntity.ok()
                .header(HttpHeaders.CONTENT_DISPOSITION, "attachment; filename=\"scan-" + scanId + "-openvex.json\"")
                .body(doc);
    }

    @GetMapping(value = "/aggregate.json", produces = MediaType.APPLICATION_JSON_VALUE)
    public ResponseEntity<OpenVexDocument> getAggregateVex() {
        OpenVexDocument doc = vexService.generateAggregate();
        return ResponseEntity.ok()
                .header(HttpHeaders.CONTENT_DISPOSITION, "attachment; filename=\"zanshin-aggregate-openvex.json\"")
                .body(doc);
    }

    @PostMapping(value = "/ingest", consumes = MediaType.APPLICATION_JSON_VALUE)
    public VexIngestorService.IngestionResult ingestVex(@RequestBody String payload) {
        return vexIngestor.ingestPayload(payload);
    }
}
