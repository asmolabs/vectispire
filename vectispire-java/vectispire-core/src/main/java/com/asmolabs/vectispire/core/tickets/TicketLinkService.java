package com.asmolabs.vectispire.core.tickets;

import com.asmolabs.vectispire.common.domain.access.Visibility;
import com.asmolabs.vectispire.common.domain.audit.AuditOperation;
import com.asmolabs.vectispire.common.domain.text.BoundedText;
import com.asmolabs.vectispire.common.domain.ticketing.TicketingProvider;
import com.asmolabs.vectispire.core.access.RowVisibility;
import com.asmolabs.vectispire.core.audit.AuditLogService;
import com.asmolabs.vectispire.core.audit.RequestActor;
import com.asmolabs.vectispire.core.issues.IssueCatalog;
import com.asmolabs.vectispire.core.issues.IssueView;
import com.asmolabs.vectispire.core.tickets.persistence.IssueTicketEntity;
import com.asmolabs.vectispire.core.tickets.persistence.IssueTicketRepository;
import java.time.Clock;
import java.time.Instant;
import java.util.List;
import java.util.Locale;
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

    /** The widths of {@code t_issue_ticket}'s provider, key and URL columns. */
    private static final int MAX_PROVIDER_LENGTH = 32;

    private static final int MAX_KEY_LENGTH = 128;

    private static final int MAX_URL_LENGTH = 512;

    private final IssueCatalog issues;
    private final IssueTicketRepository tickets;
    private final AuditLogService audit;
    private final Clock clock;

    public TicketLinkService(IssueCatalog issues, IssueTicketRepository tickets, AuditLogService audit, Clock clock) {
        this.issues = issues;
        this.tickets = tickets;
        this.audit = audit;
        this.clock = clock;
    }

    /**
     * Refuses an issue the caller may not see with "Issue not found.", absent or hidden alike.
     *
     * <p>Public so a route can refuse a hidden issue <em>before</em> it validates the rest of the
     * request: answering 400 to a malformed body on an issue the caller may not see, and 404 to a
     * well-formed one, would tell the two apart. It answers nothing: the route only needed the
     * refusal, and the row stays in this layer.
     */
    public void requireVisibleIssue(long issueId, Visibility visibility) {
        visibleIssue(issueId, visibility);
    }

    /** The issue, if the caller may see it; otherwise "Issue not found.", absent or hidden alike. */
    private IssueView visibleIssue(long issueId, Visibility visibility) {
        return RowVisibility.requireVisibleIssue(issues.issue(issueId).orElse(null), TicketLinkService::targetOf, visibility);
    }

    public List<IssueTicketView> list(long issueId, Visibility visibility) {
        visibleIssue(issueId, visibility);
        return tickets.findByIssueIdOrderByCreatedAtDesc(issueId).stream().map(IssueTicketView::of).toList();
    }

    /**
     * Attaches a ticket to an issue the caller may see.
     *
     * <p>The visibility check comes first, so a hidden issue answers 404 whatever the body holds —
     * answering 400 to a malformed body on an issue the caller may not see would tell the two apart.
     *
     * @throws IllegalArgumentException for a provider that is not a {@link TicketingProvider}, and
     *     for a key or URL that is blank or longer than its column
     */
    public IssueTicketView attach(
            long issueId, Visibility visibility, String provider, String ticketKey, String ticketUrl, RequestActor actor) {

        IssueView issue = visibleIssue(issueId, visibility);
        TicketingProvider parsed = TicketingProvider.valueOf(
                BoundedText.required(provider, MAX_PROVIDER_LENGTH, "The provider").toUpperCase(Locale.ROOT));
        // Both columns are non-null and bounded, and both were written as sent: a blank key stored a
        // link to nothing, and a key past 128 or a URL past 512 characters was refused by the
        // database at the write, as a 500.
        String key = BoundedText.required(ticketKey, MAX_KEY_LENGTH, "The ticket key");
        String url = BoundedText.required(ticketUrl, MAX_URL_LENGTH, "The ticket URL");

        Instant now = clock.instant();
        IssueTicketEntity ticket = new IssueTicketEntity();
        ticket.setIssueId(issue.id());
        ticket.setProvider(parsed.name());
        ticket.setTicketKey(key);
        ticket.setTicketUrl(url);
        ticket.setStatus("OPEN");
        ticket.setCreatedAt(now);
        ticket.setUpdatedAt(now);

        IssueTicketEntity saved = tickets.save(ticket);

        audit.record(new AuditLogService.Record(
                AuditOperation.TICKET_LINKED,
                String.valueOf(issue.id()),
                "Linked " + parsed.getDisplayName() + " ticket: " + saved.getTicketKey(),
                actor.username(),
                actor.ipAddress(),
                actor.userAgent()));

        return IssueTicketView.of(saved);
    }

    /** A row attached to neither target is left to {@code Visibility.permits}, as the entity's reading is. */
    private static com.asmolabs.vectispire.common.domain.targets.ScanTarget targetOf(IssueView issue) {
        if (issue.repoId() != null) {
            return new com.asmolabs.vectispire.common.domain.targets.ScanTarget.Repository(issue.repoId());
        }
        return issue.containerId() == null
                ? null
                : new com.asmolabs.vectispire.common.domain.targets.ScanTarget.Container(issue.containerId());
    }
}
