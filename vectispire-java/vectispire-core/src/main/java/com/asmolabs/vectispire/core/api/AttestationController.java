package com.asmolabs.vectispire.core.api;

import com.asmolabs.vectispire.common.domain.attestation.InTotoAttestation;
import com.asmolabs.vectispire.core.api.security.RequiresAccount;
import com.asmolabs.vectispire.core.api.security.VectispirePrincipal;
import com.asmolabs.vectispire.core.repositories.Scans;
import com.asmolabs.vectispire.core.services.VisibilityService;
import java.util.NoSuchElementException;
import org.springframework.security.core.annotation.AuthenticationPrincipal;
import com.asmolabs.vectispire.core.services.AttestationService;
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
    private final Scans scans;
    private final VisibilityService visibility;

    public AttestationController(
            AttestationService service, Scans scans, VisibilityService visibility) {
        this.service = service;
        this.scans = scans;
        this.visibility = visibility;
    }

    @GetMapping("/scans/{scanId}")
    public InTotoAttestation forScan(
            @AuthenticationPrincipal VectispirePrincipal principal, @PathVariable long scanId) {
        requireVisibleScan(principal, scanId);
        return service.generateAttestation(scanId);
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

}
