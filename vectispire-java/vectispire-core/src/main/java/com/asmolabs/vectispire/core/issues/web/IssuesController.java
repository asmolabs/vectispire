package com.asmolabs.vectispire.core.issues.web;

import com.asmolabs.vectispire.common.domain.access.Visibility;
import com.asmolabs.vectispire.common.domain.apikeys.ApiKeyScope;
import com.asmolabs.vectispire.core.access.VisibilityService;
import com.asmolabs.vectispire.core.access.web.security.AcceptsApiKey;
import com.asmolabs.vectispire.core.access.web.security.RequiresAccount;
import com.asmolabs.vectispire.core.access.web.security.RequiresWriteAccount;
import com.asmolabs.vectispire.core.access.web.security.TrustedProxies;
import com.asmolabs.vectispire.core.access.web.security.VectispirePrincipal;
import com.asmolabs.vectispire.core.issues.IssueDecisionService;
import com.asmolabs.vectispire.core.issues.IssueQueryService;
import com.asmolabs.vectispire.core.issues.IssueView;
import com.fasterxml.jackson.annotation.JsonProperty;
import jakarta.servlet.http.HttpServletRequest;
import java.util.List;
import org.springframework.http.HttpStatus;
import org.springframework.security.core.annotation.AuthenticationPrincipal;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.PutMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;
import org.springframework.web.server.ResponseStatusException;

/**
 * The backlog and its triage.
 *
 * <p>Two pagination guard rails worth stating:
 *
 * <ul>
 *   <li><b>{@code limit} is capped at 500.</b> With no ceiling, a caller asking for
 *       {@code limit=1000000} would load the whole backlog into memory — not an attack, just a
 *       client that wants "everything" and does not know what everything weighs.
 *   <li><b>{@code total} is counted with the same filters as the page.</b> See {@code
 *       IssueFilters} for why that is one definition rather than two.
 * </ul>
 */
@RestController
@RequestMapping("/api/v1/issues")
@RequiresAccount
public class IssuesController {

    /** The page ceiling, stated where the route is documented; the service applies it. */
    public static final int MAX_PAGE_SIZE = IssueQueryService.MAX_PAGE_SIZE;

    private final IssueQueryService queries;
    private final IssueDecisionService decisions;
    private final VisibilityService visibility;

    public IssuesController(
            IssueQueryService queries, IssueDecisionService decisions, VisibilityService visibility) {
        this.queries = queries;
        this.decisions = decisions;
        this.visibility = visibility;
    }

    public record TriageRequest(String status, String justification, String comment, @JsonProperty("expires_in_days") Integer expiresInDays) {}

    /**
     * The ticket a human attaches to a finding.
     *
     * @param reference what the tracker calls the ticket — {@code SEC-1234}, {@code #87}
     * @param url where a human will read it; optional, and when absent the reference is shown
     *     without a link rather than requiring a URL for an internal tracker
     */
    public record AttachTicketRequest(String reference, String url) {}

    /**
     * @param ids the issues to decide on. Its own record rather than {@code TriageRequest} plus a
     *     list parameter, so that the single-issue route cannot acquire an optional {@code ids}
     *     field nobody notices is being ignored
     */
    public record BulkTriageRequest(
            List<Long> ids,
            String status,
            String justification,
            String comment,
            @JsonProperty("expires_in_days") Integer expiresInDays) {}

    @AcceptsApiKey(ApiKeyScope.READ)
    @GetMapping
    public IssueQueryService.IssuePage list(
            @AuthenticationPrincipal VectispirePrincipal principal,
            @RequestParam(required = false) String state,
            @RequestParam(required = false) String severity,
            @RequestParam(required = false) String type,
            @RequestParam(name = "triage_status", required = false) String triageStatus,
            @RequestParam(name = "repository_id", required = false) Long repositoryId,
            @RequestParam(name = "container_id", required = false) Long containerId,
            @RequestParam(name = "only_direct", required = false, defaultValue = "false") boolean onlyDirect,
            // The dashboard has linked here since the first version. Nothing read it, so the
            // most actionable figure on that screen opened the whole backlog instead.
            @RequestParam(name = "is_kev", required = false, defaultValue = "false") boolean onlyKev,
            // **The figure on the dashboard has to lead somewhere.** A count of overdue issues
            // that opens the whole backlog is the defect `is_kev` had: the most actionable number
            // on the screen linked to a list nobody could narrow.
            @RequestParam(required = false, defaultValue = "false") boolean overdue,
            // **What the risk figures count, so the list they open agrees with them.** The
            // dashboard's per-severity backlog leaves out settled triage — not_affected, fixed —
            // like the scorecard, the gate and EPSS; a link from "3 critical" to a list of five
            // reads as the figure being wrong. Acts on `true` alone, like the switches above.
            @RequestParam(required = false, defaultValue = "false") boolean unsettled,
            @RequestParam(required = false) String search,
            @RequestParam(required = false, defaultValue = "50") int limit,
            @RequestParam(required = false, defaultValue = "0") int offset) {

        return queries.page(
                new IssueQueryService.BacklogQuery(
                        state, severity, type, triageStatus, repositoryId, containerId,
                        onlyDirect, onlyKev, overdue, unsettled, search, limit, offset),
                // Narrowed here and not by the caller: a filter the request supplies is a filter
                // the request can omit.
                visibility.of(principal.user().orElse(null), principal.credentialRestriction()));
    }

    /**
     * One issue, with what a row cannot carry.
     *
     * <p>The issue itself is unwrapped rather than restated: the list already sends every column,
     * and a second definition of an issue drifts from the first the day a column is added. What
     * is added here is what needs a query of its own — where it was seen, and what was decided.
     */
    @AcceptsApiKey(ApiKeyScope.READ)
    @GetMapping("/{id}")
    public IssueQueryService.IssueDetail detail(
            @AuthenticationPrincipal VectispirePrincipal principal, @PathVariable long id) {
        // 404 rather than 403 when it exists but is not visible — see `Visibilities`, whose rule
        // the service applies.
        return queries.detail(id, visibility.of(principal.user().orElse(null), principal.credentialRestriction()));
    }

    /**
     * Records a triage decision.
     *
     * <p>VEX vocabulary: affected, not_affected, fixed, under_review. A dismissal is a claim
     * about a <em>context</em> — "not reachable in our configuration" — and contexts change:
     * hence the optional review date, at which the issue returns to {@code under_review} with
     * its justification intact.
     */
    @RequiresWriteAccount
    @PostMapping("/{id}/triage")
    public IssueView triage(
            @PathVariable long id,
            @RequestBody TriageRequest body,
            @AuthenticationPrincipal VectispirePrincipal principal,
            HttpServletRequest request) {

        // Checked before the write, and 404 rather than 403 — see `Visibilities`.
        return decisions.triage(
                id,
                new IssueDecisionService.Decision(
                        body.status(), body.justification(), body.comment(), body.expiresInDays()),
                caller(principal, request));
    }

    /**
     * Attaches an existing ticket to a finding.
     *
     * <h2>Why this endpoint, and why on that field</h2>
     *
     * <p><b>The sweep opens tickets, nobody else.</b> {@code TicketSweepService} does so for
     * findings that breach the gate, with the globally configured tracker, and writes the
     * reference onto the finding — that field is the one the list shows, the one the inbound
     * webhook looks up to close the finding, and the one the sweep reads so as not to open twice.
     * The whole of the rest of the product speaks about this field.
     *
     * <p>A finding that breaches no gate, or a tracker that is not configured, therefore had no
     * way of being attached to anything. A team tracking that finding in {@code SEC-1234} could
     * not say so, and the closing webhook could not recognise it.
     *
     * <p><b>Written onto {@code ticketRef}, and not into {@code t_issue_ticket}.</b> That second
     * table exists, with an endpoint of its own, and nothing reads it: not the webhook, not the
     * sweep, not a screen. Writing there would have shipped an attachment that synchronisation
     * ignores — a feature that looks as though it works and never synchronises.
     *
     * <h2>A human may correct, the sweep never erases</h2>
     *
     * <p>The reference the sweep sets is written once and never erased: it is its deduplication
     * key. This one may be replaced, because the case that exists is the typo — and because
     * replacing it is recorded. The sweep's invariant is intact: it never touches a finding that
     * already carries a reference, whatever its origin.
     *
     * <p>A side effect that is intended and said here: attaching a ticket <b>stops</b> the sweep
     * from opening a second one for the same finding.
     */
    @RequiresWriteAccount
    @PutMapping("/{id}/ticket")
    public IssueView attachTicket(
            @PathVariable long id,
            @RequestBody AttachTicketRequest body,
            @AuthenticationPrincipal VectispirePrincipal principal,
            HttpServletRequest request) {

        // Checked before the write, and 404 rather than 403 — see `Visibilities`. The 400s are
        // worded by the service and sent as the route always sent them.
        try {
            return decisions.attachTicket(
                    id,
                    body == null ? null : body.reference(),
                    body == null ? null : body.url(),
                    caller(principal, request));
        } catch (IssueDecisionService.InvalidTicketException invalid) {
            throw new ResponseStatusException(HttpStatus.BAD_REQUEST, invalid.getMessage());
        }
    }

    /**
     * The same decision on many issues.
     *
     * <p>One CVE across forty repositories is one judgement about one context, and deciding it
     * forty times is how a backlog stops being triaged at all. Composes with the filters rather
     * than adding a second concept: narrow the list to an identifier, select what it returned,
     * decide once. That is also why there is no "triage by CVE" route — it would be a second way
     * of choosing rows, and it would not honour the visibility the list already applies.
     *
     * <p><b>Every identifier is checked before the first one is written.</b> Checking as it goes
     * would let a batch containing one invisible issue triage the ones before it and then answer
     * 404 — a partial write reported as a failure, which is the worst of the two.
     */
    @RequiresWriteAccount
    @PostMapping("/triage")
    public List<IssueView> triageMany(
            @RequestBody BulkTriageRequest body,
            @AuthenticationPrincipal VectispirePrincipal principal,
            HttpServletRequest request) {

        return decisions.triageMany(
                body == null || body.ids() == null ? List.of() : body.ids(),
                body == null
                        ? null
                        : new IssueDecisionService.Decision(
                                body.status(), body.justification(), body.comment(), body.expiresInDays()),
                caller(principal, request));
    }

    private IssueDecisionService.Caller caller(VectispirePrincipal principal, HttpServletRequest request) {
        return new IssueDecisionService.Caller(
                principal.user(),
                visibility.of(principal.user().orElse(null), principal.credentialRestriction()),
                TrustedProxies.resolvedClientAddress(request),
                request.getHeader("User-Agent"));
    }
}
