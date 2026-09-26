package com.asmolabs.vectispire.core.services.scanning;

import com.asmolabs.vectispire.core.persistence.ScanEntity;
import com.asmolabs.vectispire.core.repositories.Scans;
import java.util.Optional;
import org.springframework.stereotype.Service;

/**
 * The scan a per-scan document is about — OpenVEX, CycloneDX, CSAF, attestation, SBOM diff.
 *
 * <p><b>It hands the row back rather than deciding whether the caller may have it.</b> The
 * decision is {@code Visibilities.requireVisible} in the controller, and it has to receive the
 * absent scan as an absence — not a refusal worded here — so that "no such scan" and "not your
 * scan" come out as the same 404 in the same words. Ids are sequential; two wordings would let a
 * restricted reader enumerate every scan of the deployment.
 */
@Service
public class ScanDocumentService {

    private final Scans scans;

    public ScanDocumentService(Scans scans) {
        this.scans = scans;
    }

    public Optional<ScanEntity> scan(long scanId) {
        return scans.findById(scanId);
    }
}
