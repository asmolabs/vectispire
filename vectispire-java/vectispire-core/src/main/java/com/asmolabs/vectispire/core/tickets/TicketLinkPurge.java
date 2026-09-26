package com.asmolabs.vectispire.core.tickets;

import com.asmolabs.vectispire.core.issues.PurgedIssues;
import com.asmolabs.vectispire.core.targets.TargetPurge;
import com.asmolabs.vectispire.core.tickets.persistence.IssueTicketRepository;
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

    private final PurgedIssues issues;
    private final IssueTicketRepository links;

    TicketLinkPurge(PurgedIssues issues, IssueTicketRepository links) {
        this.issues = issues;
        this.links = links;
    }

    @EventListener
    @Order(TargetPurge.Phase.ISSUE_CHILDREN)
    @Transactional(propagation = Propagation.MANDATORY)
    public void purge(TargetPurge purge) {
        List<Long> issueIds = issues.idsOf(purge);
        if (!issueIds.isEmpty()) {
            links.deleteByIssueIdIn(issueIds);
        }
    }
}
