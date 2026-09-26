package com.asmolabs.vectispire.core.services.scanning;

import com.asmolabs.vectispire.common.domain.access.Visibility;
import com.asmolabs.vectispire.core.repositories.Scans;
import com.asmolabs.vectispire.core.services.access.RowVisibility;
import org.springframework.stereotype.Service;

/**
 * The scan a per-scan document is about — OpenVEX, CycloneDX, CSAF, attestation, SBOM diff.
 *
 * <p><b>It refuses an absent scan and a hidden one in the same words.</b> The absent row reaches
 * {@link RowVisibility} as an absence — not a refusal worded here — so that "no such scan" and
 * "not your scan" come out as the same 404. Ids are sequential; two wordings would let a
 * restricted reader enumerate every scan of the deployment.
 *
 * <p>It used to hand the row back for the controller to pass to that same guard, which put a
 * {@code ScanEntity} in {@code api} for the length of one call. The controller names the scan by
 * its id now, and the row stays here.
 */
@Service
public class ScanDocumentService {

    private final Scans scans;

    public ScanDocumentService(Scans scans) {
        this.scans = scans;
    }

    /** @throws java.util.NoSuchElementException absent and hidden alike, as {@link RowVisibility} words it */
    public void requireVisible(long scanId, Visibility visibility) {
        RowVisibility.requireVisible(scans.findById(scanId).orElse(null), visibility);
    }
}
