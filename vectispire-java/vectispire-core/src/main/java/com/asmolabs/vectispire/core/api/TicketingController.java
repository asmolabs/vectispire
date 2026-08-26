package com.asmolabs.vectispire.core.api;

import com.asmolabs.vectispire.common.domain.audit.AuditOperation;
import com.asmolabs.vectispire.common.domain.ticketing.TicketingProvider;
import com.asmolabs.vectispire.core.api.security.RequiresAccount;
import com.asmolabs.vectispire.core.api.security.VectispirePrincipal;
import com.asmolabs.vectispire.core.services.VisibilityService;
import com.asmolabs.vectispire.core.api.security.VectispirePrincipal;
import com.asmolabs.vectispire.core.persistence.IssueEntity;
import com.asmolabs.vectispire.core.persistence.IssueTicketEntity;
import com.asmolabs.vectispire.core.repositories.IssueTickets;
import com.asmolabs.vectispire.core.repositories.Issues;
import com.asmolabs.vectispire.core.services.AuditLogService;
import jakarta.servlet.http.HttpServletRequest;
import java.time.Clock;
import java.time.Instant;
import java.util.List;
import java.util.NoSuchElementException;
import org.springframework.http.HttpStatus;
import org.springframework.security.core.annotation.AuthenticationPrincipal;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.ResponseStatus;
import org.springframework.web.bind.annotation.RestController;
import org.springframework.web.server.ResponseStatusException;

/**
 * Bidirectional incident & ticketing integration (Jira, GitHub, GitLab).
 */
@RestController
@RequestMapping("/api/v1/issues/{issueId}/tickets")
@RequiresAccount
public class TicketingController {

    private final Issues issues;
    private final IssueTickets tickets;
    private final AuditLogService audit;
    private final Clock clock;
    private final VisibilityService visibility;

    public TicketingController(Issues issues, IssueTickets tickets, AuditLogService audit, Clock clock,
            VisibilityService visibility) {
        this.issues = issues;
        this.tickets = tickets;
        this.audit = audit;
        this.clock = clock;
        this.visibility = visibility;
    }

    public record CreateTicketRequest(String provider, String ticketKey, String ticketUrl) {}

    @GetMapping
    public List<IssueTicketEntity> list(
            @AuthenticationPrincipal VectispirePrincipal principal, @PathVariable long issueId) {
        // A ticket carries a Jira/GitLab key and URL for a finding. Listing them for any issue id
        // handed the backlog of a target the caller was never given; the issue's own visibility
        // gates the tickets, and a hidden issue reads as absent.
        requireVisibleIssue(principal, issueId);
        return tickets.findByIssueIdOrderByCreatedAtDesc(issueId);
    }

    @PostMapping
    @ResponseStatus(HttpStatus.CREATED)
    public IssueTicketEntity create(
            @PathVariable long issueId,
            @RequestBody CreateTicketRequest body,
            @AuthenticationPrincipal VectispirePrincipal principal,
            HttpServletRequest request) {

        IssueEntity issue = issues.findById(issueId)
                .orElseThrow(() -> new NoSuchElementException("Issue not found."));
        Visibilities.requireVisible(issue,
                visibility.of(principal.user().orElse(null), principal.credentialRestriction()));

        if (body == null || body.provider() == null || body.ticketKey() == null || body.ticketUrl() == null) {
            throw new ResponseStatusException(HttpStatus.BAD_REQUEST, "Provider, ticket key and URL are required.");
        }

        TicketingProvider provider = TicketingProvider.valueOf(body.provider().toUpperCase(java.util.Locale.ROOT));

        Instant now = clock.instant();
        IssueTicketEntity ticket = new IssueTicketEntity();
        ticket.setIssueId(issue.getId());
        ticket.setProvider(provider.name());
        ticket.setTicketKey(body.ticketKey().trim());
        ticket.setTicketUrl(body.ticketUrl().trim());
        ticket.setStatus("OPEN");
        ticket.setCreatedAt(now);
        ticket.setUpdatedAt(now);

        IssueTicketEntity saved = tickets.save(ticket);

        audit.record(new AuditLogService.Record(
                AuditOperation.USER_UPDATED,
                String.valueOf(issue.getId()),
                "Created " + provider.getDisplayName() + " ticket: " + saved.getTicketKey(),
                principal.user().map(u -> u.getUsername()).orElse("unknown"),
                request.getRemoteAddr(),
                request.getHeader("User-Agent")));

        return saved;
    }

    private void requireVisibleIssue(VectispirePrincipal principal, long issueId) {
        Visibilities.requireVisible(
                issues.findById(issueId).orElse(null),
                visibility.of(principal.user().orElse(null), principal.credentialRestriction()));
    }

}
