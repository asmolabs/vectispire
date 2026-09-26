package com.asmolabs.vectispire.core.services.issues;

import com.asmolabs.vectispire.common.domain.targets.OrphanedTargetRows;
import com.asmolabs.vectispire.common.domain.targets.TargetPurge;
import com.asmolabs.vectispire.core.repositories.Issues;
import com.asmolabs.vectispire.core.repositories.TriageEvents;
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
 * <p><b>Two phases, because an issue is a parent twice over.</b> Its triage events go with the other
 * rows that hang off an issue alone; the issue itself only once the findings, which also hang off a
 * scan, are gone too — see {@link TargetPurge.Phase}. Synchronous and in the deleting transaction,
 * like every {@link TargetPurge} listener.
 */
@Component
class IssuePurge {

    private static final Logger log = LoggerFactory.getLogger(IssuePurge.class);

    private final Issues issues;
    private final TriageEvents triageEvents;

    IssuePurge(Issues issues, TriageEvents triageEvents) {
        this.issues = issues;
        this.triageEvents = triageEvents;
    }

    @EventListener
    @Order(TargetPurge.Phase.ISSUE_CHILDREN)
    @Transactional(propagation = Propagation.MANDATORY)
    public void purgeTriageHistory(TargetPurge purge) {
        List<Long> issueIds = issues.findIdsPurgedBy(purge);
        if (!issueIds.isEmpty()) {
            triageEvents.deleteByIssueIdIn(issueIds);
        }
    }

    @EventListener
    @Order(TargetPurge.Phase.ISSUES)
    @Transactional(propagation = Propagation.MANDATORY)
    public void purgeIssues(TargetPurge purge) {
        List<Long> issueIds = issues.findIdsPurgedBy(purge);
        if (!issueIds.isEmpty()) {
            issues.deleteByIdIn(issueIds);
            log.info(purge instanceof OrphanedTargetRows
                    ? "Cleaned up {} orphaned issues from deleted targets."
                    : "Purged {} issues of a deleted target.", issueIds.size());
        }
    }
}
