package com.asmolabs.vectispire.core.services.scanning;

import com.asmolabs.vectispire.core.repositories.Findings;
import com.asmolabs.vectispire.core.repositories.Scans;
import com.asmolabs.vectispire.core.services.issues.PurgedIssues;
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
 * same rows — and taking both is what makes that an assumption nobody has to hold. Synchronous and in
 * the deleting transaction, like every {@link TargetPurge} listener.
 */
@Component
class ScanPurge {

    private static final Logger log = LoggerFactory.getLogger(ScanPurge.class);

    private final PurgedIssues purgedIssues;
    private final PurgedScans purgedScans;
    private final Scans scans;
    private final Findings findings;

    ScanPurge(PurgedIssues purgedIssues, PurgedScans purgedScans, Scans scans, Findings findings) {
        this.purgedIssues = purgedIssues;
        this.purgedScans = purgedScans;
        this.scans = scans;
        this.findings = findings;
    }

    @EventListener
    @Order(TargetPurge.Phase.FINDINGS)
    @Transactional(propagation = Propagation.MANDATORY)
    public void purgeFindings(TargetPurge purge) {
        List<Long> issueIds = purgedIssues.idsOf(purge);
        if (!issueIds.isEmpty()) {
            findings.deleteByIssueIdIn(issueIds);
        }
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
