package com.asmolabs.vectispire.core.api;

import com.asmolabs.vectispire.common.domain.access.Visibility;
import com.asmolabs.vectispire.core.api.security.RequiresAccount;
import com.asmolabs.vectispire.core.api.security.RequiresWriteAccount;
import com.asmolabs.vectispire.core.api.security.VectispirePrincipal;
import com.asmolabs.vectispire.core.persistence.IssueTicketEntity;
import com.asmolabs.vectispire.core.services.TicketLinkService;
import com.asmolabs.vectispire.core.services.VisibilityService;
import jakarta.servlet.http.HttpServletRequest;
import java.util.List;
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

    private final TicketLinkService ticketLinks;
    private final VisibilityService visibility;

    public TicketingController(TicketLinkService ticketLinks, VisibilityService visibility) {
        this.ticketLinks = ticketLinks;
        this.visibility = visibility;
    }

    public record CreateTicketRequest(String provider, String ticketKey, String ticketUrl) {}

    @GetMapping
    public List<IssueTicketEntity> list(
            @AuthenticationPrincipal VectispirePrincipal principal, @PathVariable long issueId) {
        // A ticket carries a Jira/GitLab key and URL for a finding. Listing them for any issue id
        // handed the backlog of a target the caller was never given; the issue's own visibility
        // gates the tickets, and a hidden issue reads as absent.
        return ticketLinks.list(issueId, visibility.of(principal.user().orElse(null), principal.credentialRestriction()));
    }

    @RequiresWriteAccount
    @PostMapping
    @ResponseStatus(HttpStatus.CREATED)
    public IssueTicketEntity create(
            @PathVariable long issueId,
            @RequestBody CreateTicketRequest body,
            @AuthenticationPrincipal VectispirePrincipal principal,
            HttpServletRequest request) {

        Visibility allowed = visibility.of(principal.user().orElse(null), principal.credentialRestriction());
        // Refused before the body is looked at, so a malformed request on a hidden issue answers
        // 404 like any other, and not a 400 that would confirm the issue is there.
        ticketLinks.visibleIssue(issueId, allowed);

        if (body == null || body.provider() == null || body.ticketKey() == null || body.ticketUrl() == null) {
            throw new ResponseStatusException(HttpStatus.BAD_REQUEST, "Provider, ticket key and URL are required.");
        }

        return ticketLinks.attach(
                issueId,
                allowed,
                body.provider(),
                body.ticketKey(),
                body.ticketUrl(),
                new TicketLinkService.Actor(
                        principal.user().map(u -> u.getUsername()).orElse("unknown"),
                        request.getRemoteAddr(),
                        request.getHeader("User-Agent")));
    }
}
