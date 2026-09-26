package com.asmolabs.vectispire.core.scanning;

import com.asmolabs.vectispire.core.scanning.persistence.Findings;
import com.asmolabs.vectispire.core.scanning.persistence.Scans;
import com.asmolabs.vectispire.core.targets.OrphanedTargetRows;
import com.asmolabs.vectispire.core.targets.TargetPurge;
import java.util.List;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.context.event.EventListener;
import org.springframework.core.annotation.Order;
import org.springframework.stereotype.Component;
import org.springframework.transaction.annotation.Propagation;
import org.springframework.transaction.annotation.Transactional;

/**
 * A purged target's findings and scans.
 *
 * <p><b>Findings by issue and by scan, both.</b> A finding hangs off a scan and, once synced, off an
 * issue; the target's issues and its scans are the same target's, so each selection should find the
 * same rows — and taking both is what makes that an assumption nobody has to hold. This listener takes
 * them by scan; {@code IssuePurge} takes them by issue in the same phase, through {@link
 * PurgedScans#deleteFindingsOfIssues}, since the issues are {@code issues}' to select (decision 0029).
 * Synchronous and in the deleting transaction, like every {@link TargetPurge} listener.
 */
@Component
class ScanPurge {

    private static final Logger log = LoggerFactory.getLogger(ScanPurge.class);

    private final PurgedScans purgedScans;
    private final Scans scans;
    private final Findings findings;

    ScanPurge(PurgedScans purgedScans, Scans scans, Findings findings) {
        this.purgedScans = purgedScans;
        this.scans = scans;
        this.findings = findings;
    }

    @EventListener
    @Order(TargetPurge.Phase.FINDINGS)
    @Transactional(propagation = Propagation.MANDATORY)
    public void purgeFindings(TargetPurge purge) {
        List<Long> scanIds = purgedScans.idsOf(purge);
        if (!scanIds.isEmpty()) {
            findings.deleteByScanIdIn(scanIds);
        }
    }

    @EventListener
    @Order(TargetPurge.Phase.SCANS)
    @Transactional(propagation = Propagation.MANDATORY)
    public void purgeScans(TargetPurge purge) {
        List<Long> scanIds = purgedScans.idsOf(purge);
        if (!scanIds.isEmpty()) {
            scans.deleteByIdIn(scanIds);
            log.info(purge instanceof OrphanedTargetRows
                    ? "Cleaned up {} orphaned scans from deleted targets."
                    : "Purged {} scans of a deleted target.", scanIds.size());
        }
    }
}
