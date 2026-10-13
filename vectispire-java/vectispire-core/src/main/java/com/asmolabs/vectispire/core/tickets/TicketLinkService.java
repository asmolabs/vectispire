package com.asmolabs.vectispire.core.tickets;

import com.asmolabs.vectispire.common.domain.access.Visibility;
import com.asmolabs.vectispire.common.domain.audit.AuditOperation;
import com.asmolabs.vectispire.common.domain.errors.InvalidInputException;
import com.asmolabs.vectispire.common.domain.integrations.Integration;
import com.asmolabs.vectispire.common.domain.text.BoundedText;
import com.asmolabs.vectispire.common.domain.ticketing.TicketingProvider;
import com.asmolabs.vectispire.core.access.RowVisibility;
import com.asmolabs.vectispire.core.audit.AuditLogService;
import com.asmolabs.vectispire.core.audit.RequestActor;
import com.asmolabs.vectispire.core.issues.IssueCatalog;
import com.asmolabs.vectispire.core.issues.IssueView;
import com.asmolabs.vectispire.core.settings.Integrations;
import com.asmolabs.vectispire.core.tickets.persistence.IssueTicketEntity;
import com.asmolabs.vectispire.core.tickets.persistence.IssueTicketRepository;
import java.time.Clock;
import java.time.Instant;
import java.util.List;
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
    private final Integrations integrations;

    public TicketLinkService(
            IssueCatalog issues, IssueTicketRepository tickets, AuditLogService audit, Clock clock,
            Integrations integrations) {
        this.issues = issues;
        this.tickets = tickets;
        this.audit = audit;
        this.clock = clock;
        this.integrations = integrations;
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
     * The missing fields are refused after it, here: the route used to refuse them itself, and so had
     * to call a public "refuse this issue" method first, which answered nothing and which any caller
     * could forget — the order was the route's to keep rather than this method's.
     *
     * @throws com.asmolabs.vectispire.common.domain.errors.NotFoundException "Issue not found." for an
     *     issue absent or hidden alike, whatever the rest holds
     * @throws com.asmolabs.vectispire.common.domain.errors.InvalidInputException for a field missing,
     *     for a provider that is not a {@link TicketingProvider}, and for a key or URL that is blank or
     *     longer than its column
     * @throws com.asmolabs.vectispire.common.domain.integrations.IntegrationDisabledException 409 {@code
     *     integration-disabled} when the provider's tracker is switched off (decision 0040 §3): a ticket of a
     *     suspended tracker is not opened, by the sweep or by hand — after the visibility, so that a hidden issue
     *     still reads as absent, and before the key and URL are judged, as a forge's refusal comes before a form's
     *     other words
     */
    public IssueTicketView attach(
            long issueId, Visibility visibility, String provider, String ticketKey, String ticketUrl, RequestActor actor) {

        IssueView issue = visibleIssue(issueId, visibility);
        if (provider == null || ticketKey == null || ticketUrl == null) {
            throw new InvalidInputException("Provider, ticket key and URL are required.");
        }
        TicketingProvider parsed = TicketingProvider.parse(
                BoundedText.required(provider, MAX_PROVIDER_LENGTH, "The provider"));
        integrations.requireEnabled(Integration.of(parsed.tracker()));
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
