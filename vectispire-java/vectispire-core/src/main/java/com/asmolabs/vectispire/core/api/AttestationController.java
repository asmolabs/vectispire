package com.asmolabs.zanshin.core.api;

import com.asmolabs.zanshin.common.domain.attestation.InTotoAttestation;
import com.asmolabs.zanshin.core.api.security.RequiresAccount;
import com.asmolabs.zanshin.core.services.AttestationService;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

/**
 * Cryptographic in-toto and SLSA supply chain provenance attestations.
 */
@RestController
@RequestMapping("/api/v1/attestations")
@RequiresAccount
public class AttestationController {

    private final AttestationService service;

    public AttestationController(AttestationService service) {
        this.service = service;
    }

    @GetMapping("/scans/{scanId}")
    public InTotoAttestation forScan(@PathVariable long scanId) {
        return service.generateAttestation(scanId);
    }
}
