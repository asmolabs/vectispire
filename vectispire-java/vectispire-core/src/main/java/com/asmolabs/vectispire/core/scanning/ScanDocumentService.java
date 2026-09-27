package com.asmolabs.vectispire.core.scanning;

import com.asmolabs.vectispire.common.domain.access.Visibility;
import com.asmolabs.vectispire.core.access.RowVisibility;
import com.asmolabs.vectispire.core.scanning.persistence.ScanEntity;
import com.asmolabs.vectispire.core.scanning.persistence.ScanRepository;
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
 * {@code ScanEntity} in {@code api} for the length of one call. Then the controllers called it by id
 * and passed the same id on to a document service that trusted them. <b>Its callers are those
 * services now</b>, beside the read it guards: {@code exports} and {@code inventory} use {@code
 * access} from their routes only, and this is {@code scanning}'s refusal, reached through {@code
 * scanning}'s API. {@code ArchitectureTest.routesLeaveTheRefusalToTheirServices} keeps it off the
 * routes.
 */
@Service
public class ScanDocumentService {

    private final ScanRepository scans;

    public ScanDocumentService(ScanRepository scans) {
        this.scans = scans;
    }

    /** @throws com.asmolabs.vectispire.common.domain.errors.NotFoundException absent and hidden alike, as {@link RowVisibility} words it */
    public void requireVisible(long scanId, Visibility visibility) {
        RowVisibility.requireVisibleScan(scans.findById(scanId).orElse(null), ScanEntity::target, visibility);
    }
}
