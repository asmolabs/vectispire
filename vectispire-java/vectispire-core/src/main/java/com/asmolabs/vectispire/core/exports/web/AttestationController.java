package com.asmolabs.vectispire.core.exports.web;

import com.asmolabs.vectispire.common.domain.attestation.InTotoAttestation;
import com.asmolabs.vectispire.core.access.VisibilityService;
import com.asmolabs.vectispire.core.access.web.security.RequiresAccount;
import com.asmolabs.vectispire.core.access.web.security.VectispirePrincipal;
import com.asmolabs.vectispire.core.exports.AttestationService;
import org.springframework.security.core.annotation.AuthenticationPrincipal;
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
    private final VisibilityService visibility;

    public AttestationController(AttestationService service, VisibilityService visibility) {
        this.service = service;
        this.visibility = visibility;
    }

    /**
     * The same scan under a different format is the same authorization question, and the service
     * asks it: this route once did not, so which document a caller requested decided whether the
     * check happened.
     */
    @GetMapping("/scans/{scanId}")
    public InTotoAttestation forScan(
            @AuthenticationPrincipal VectispirePrincipal principal, @PathVariable long scanId) {
        return service.generateAttestation(
                scanId, visibility.of(principal.user().orElse(null), principal.credentialRestriction()));
    }
}
