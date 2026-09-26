package com.asmolabs.vectispire.core.services.tickets;

import com.asmolabs.vectispire.common.domain.targets.TargetPurge;
import com.asmolabs.vectispire.core.repositories.IssueTickets;
import com.asmolabs.vectispire.core.repositories.Issues;
import java.util.List;
import org.springframework.context.event.EventListener;
import org.springframework.core.annotation.Order;
import org.springframework.stereotype.Component;
import org.springframework.transaction.annotation.Propagation;
import org.springframework.transaction.annotation.Transactional;

/**
 * The ticket links of a purged target's issues, before the issues themselves.
 *
 * <p>Only the links: the tickets live in the tracker, and closing them on a deletion was never this
 * product's decision. Synchronous and in the deleting transaction, like every {@link TargetPurge}
 * listener.
 */
@Component
class TicketLinkPurge {

    private final Issues issues;
    private final IssueTickets links;

    TicketLinkPurge(Issues issues, IssueTickets links) {
        this.issues = issues;
        this.links = links;
    }

    @EventListener
    @Order(TargetPurge.Phase.ISSUE_CHILDREN)
    @Transactional(propagation = Propagation.MANDATORY)
    public void purge(TargetPurge purge) {
        List<Long> issueIds = issues.findIdsPurgedBy(purge);
        if (!issueIds.isEmpty()) {
            links.deleteByIssueIdIn(issueIds);
        }
    }
}
