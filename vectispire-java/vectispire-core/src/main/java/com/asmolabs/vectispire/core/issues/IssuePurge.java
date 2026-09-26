package com.asmolabs.vectispire.core.issues;

import com.asmolabs.vectispire.core.issues.persistence.IssueRepository;
import com.asmolabs.vectispire.core.issues.persistence.TriageEventRepository;
import com.asmolabs.vectispire.core.scanning.PurgedScans;
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
 * A purged target's issues and their triage history.
 *
 * <p><b>Three phases, because an issue is a parent twice over.</b> Its triage events go with the other
 * rows that hang off an issue alone; its findings — occurrences that also hang off a scan, and
 * {@code scanning}'s rows — in the findings phase; the issue itself only once they are all gone — see
 * {@link TargetPurge.Phase}. Synchronous and in the deleting transaction,
 * like every {@link TargetPurge} listener.
 */
@Component
class IssuePurge {

    private static final Logger log = LoggerFactory.getLogger(IssuePurge.class);

    private final PurgedIssues purged;
    private final IssueRepository issues;
    private final TriageEventRepository triageEvents;
    private final PurgedScans scans;

    IssuePurge(PurgedIssues purged, IssueRepository issues, TriageEventRepository triageEvents, PurgedScans scans) {
        this.purged = purged;
        this.issues = issues;
        this.triageEvents = triageEvents;
        this.scans = scans;
    }

    @EventListener
    @Order(TargetPurge.Phase.ISSUE_CHILDREN)
    @Transactional(propagation = Propagation.MANDATORY)
    public void purgeTriageHistory(TargetPurge purge) {
        List<Long> issueIds = purged.idsOf(purge);
        if (!issueIds.isEmpty()) {
            triageEvents.deleteByIssueIdIn(issueIds);
        }
    }

    /**
     * The findings that are occurrences of the target's issues — {@code scanning}'s rows, deleted by
     * {@code scanning}, selected here. {@code ScanPurge} takes the same target's findings by scan in
     * this phase; the two selections should meet the same rows, and either order ends the same.
     */
    @EventListener
    @Order(TargetPurge.Phase.FINDINGS)
    @Transactional(propagation = Propagation.MANDATORY)
    public void purgeFindings(TargetPurge purge) {
        List<Long> issueIds = purged.idsOf(purge);
        if (!issueIds.isEmpty()) {
            scans.deleteFindingsOfIssues(issueIds);
        }
    }

    @EventListener
    @Order(TargetPurge.Phase.ISSUES)
    @Transactional(propagation = Propagation.MANDATORY)
    public void purgeIssues(TargetPurge purge) {
        List<Long> issueIds = purged.idsOf(purge);
        if (!issueIds.isEmpty()) {
            issues.deleteByIdIn(issueIds);
            log.info(purge instanceof OrphanedTargetRows
                    ? "Cleaned up {} orphaned issues from deleted targets."
                    : "Purged {} issues of a deleted target.", issueIds.size());
        }
    }
}
