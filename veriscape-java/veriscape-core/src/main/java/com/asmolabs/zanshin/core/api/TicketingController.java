package com.asmolabs.zanshin.core.api;

import com.asmolabs.zanshin.common.domain.audit.AuditOperation;
import com.asmolabs.zanshin.common.domain.ticketing.TicketingProvider;
import com.asmolabs.zanshin.core.api.security.RequiresAccount;
import com.asmolabs.zanshin.core.api.security.ZanshinPrincipal;
import com.asmolabs.zanshin.core.persistence.IssueEntity;
import com.asmolabs.zanshin.core.persistence.IssueTicketEntity;
import com.asmolabs.zanshin.core.repositories.IssueTickets;
import com.asmolabs.zanshin.core.repositories.Issues;
import com.asmolabs.zanshin.core.services.AuditLogService;
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

    public TicketingController(Issues issues, IssueTickets tickets, AuditLogService audit, Clock clock) {
        this.issues = issues;
        this.tickets = tickets;
        this.audit = audit;
        this.clock = clock;
    }

    public record CreateTicketRequest(String provider, String ticketKey, String ticketUrl) {}

    @GetMapping
    public List<IssueTicketEntity> list(@PathVariable long issueId) {
        return tickets.findByIssueIdOrderByCreatedAtDesc(issueId);
    }

    @PostMapping
    @ResponseStatus(HttpStatus.CREATED)
    public IssueTicketEntity create(
            @PathVariable long issueId,
            @RequestBody CreateTicketRequest body,
            @AuthenticationPrincipal ZanshinPrincipal principal,
            HttpServletRequest request) {

        IssueEntity issue = issues.findById(issueId)
                .orElseThrow(() -> new NoSuchElementException("Issue not found."));

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
}
