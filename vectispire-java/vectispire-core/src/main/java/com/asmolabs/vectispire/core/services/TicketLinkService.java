package com.asmolabs.vectispire.core.services;

import com.asmolabs.vectispire.common.domain.access.Visibility;
import com.asmolabs.vectispire.common.domain.audit.AuditOperation;
import com.asmolabs.vectispire.common.domain.targets.ScanTarget;
import com.asmolabs.vectispire.common.domain.ticketing.TicketingProvider;
import com.asmolabs.vectispire.core.persistence.IssueEntity;
import com.asmolabs.vectispire.core.persistence.IssueTicketEntity;
import com.asmolabs.vectispire.core.repositories.IssueTickets;
import com.asmolabs.vectispire.core.repositories.Issues;
import java.time.Clock;
import java.time.Instant;
import java.util.List;
import java.util.Locale;
import java.util.NoSuchElementException;
import org.springframework.stereotype.Service;

/**
 * The tickets an operator attached to an issue by hand — a Jira key, a GitLab URL.
 *
 * <p><b>Every method takes the caller's {@link Visibility} and applies it to the issue.</b> A
 * ticket carries a tracker's key and URL for a finding; listing them for any issue id handed the
 * backlog of a target the caller was never given. A hidden issue is refused exactly as an absent
 * one is — same exception, same message — so the refusal cannot confirm the issue exists.
 */
@Service
public class TicketLinkService {

    private final Issues issues;
    private final IssueTickets tickets;
    private final AuditLogService audit;
    private final Clock clock;

    public TicketLinkService(Issues issues, IssueTickets tickets, AuditLogService audit, Clock clock) {
        this.issues = issues;
        this.tickets = tickets;
        this.audit = audit;
        this.clock = clock;
    }

    /**
     * The issue, if the caller may see it; otherwise "Issue not found.", absent or hidden alike.
     *
     * <p>Public so a route can refuse a hidden issue <em>before</em> it validates the rest of the
     * request: answering 400 to a malformed body on an issue the caller may not see, and 404 to a
     * well-formed one, would tell the two apart.
     */
    public IssueEntity visibleIssue(long issueId, Visibility visibility) {
        IssueEntity issue = issues.findById(issueId).orElse(null);
        if (issue == null || !visibility.permits(targetOf(issue))) {
            throw new NoSuchElementException("Issue not found.");
        }
        return issue;
    }

    public List<IssueTicketEntity> list(long issueId, Visibility visibility) {
        visibleIssue(issueId, visibility);
        return tickets.findByIssueIdOrderByCreatedAtDesc(issueId);
    }

    /**
     * Attaches a ticket to an issue the caller may see.
     *
     * @throws IllegalArgumentException for a provider that is not a {@link TicketingProvider}
     */
    public IssueTicketEntity attach(
            long issueId, Visibility visibility, String provider, String ticketKey, String ticketUrl, RequestActor actor) {

        IssueEntity issue = visibleIssue(issueId, visibility);
        TicketingProvider parsed = TicketingProvider.valueOf(provider.toUpperCase(Locale.ROOT));

        Instant now = clock.instant();
        IssueTicketEntity ticket = new IssueTicketEntity();
        ticket.setIssueId(issue.getId());
        ticket.setProvider(parsed.name());
        ticket.setTicketKey(ticketKey.trim());
        ticket.setTicketUrl(ticketUrl.trim());
        ticket.setStatus("OPEN");
        ticket.setCreatedAt(now);
        ticket.setUpdatedAt(now);

        IssueTicketEntity saved = tickets.save(ticket);

        audit.record(new AuditLogService.Record(
                AuditOperation.USER_UPDATED,
                String.valueOf(issue.getId()),
                "Created " + parsed.getDisplayName() + " ticket: " + saved.getTicketKey(),
                actor.username(),
                actor.ipAddress(),
                actor.userAgent()));

        return saved;
    }

    /**
     * The same reading of an issue's target as the routes' guard in {@code api.Visibilities}: a
     * row attached to neither a repository nor a container is unclassifiable, and left to
     * {@link Visibility#permits} — visible to an unrestricted caller, hidden from a restricted
     * one — rather than decided here in a way the guard beside it does not.
     */
    private static ScanTarget targetOf(IssueEntity issue) {
        if (issue.getRepoId() != null) {
            return new ScanTarget.Repository(issue.getRepoId());
        }
        return issue.getContainerId() == null ? null : new ScanTarget.Container(issue.getContainerId());
    }
}
