package com.asmolabs.zanshin.core.api;

import com.asmolabs.zanshin.common.domain.audit.AuditOperation;
import com.asmolabs.zanshin.common.domain.issues.IssueState;
import com.asmolabs.zanshin.common.domain.issues.Triage;
import com.asmolabs.zanshin.common.domain.issues.TriageStatus;
import com.asmolabs.zanshin.common.domain.issues.VexJustification;
import com.asmolabs.zanshin.core.api.security.RequiresAccount;
import com.asmolabs.zanshin.core.api.security.ZanshinPrincipal;
import com.asmolabs.zanshin.core.persistence.IssueEntity;
import com.asmolabs.zanshin.core.repositories.IssueFilters;
import com.asmolabs.zanshin.core.repositories.Issues;
import com.asmolabs.zanshin.core.services.AuditLogService;
import com.asmolabs.zanshin.core.services.IssueTriageService;
import jakarta.servlet.http.HttpServletRequest;
import java.time.Period;
import java.util.List;
import org.springframework.data.domain.PageRequest;
import org.springframework.data.domain.Sort;
import org.springframework.security.core.annotation.AuthenticationPrincipal;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;

/**
 * The backlog and its triage.
 *
 * <p>Two pagination guard rails worth stating:
 *
 * <ul>
 *   <li><b>{@code limit} is capped at 500.</b> With no ceiling, a caller asking for
 *       {@code limit=1000000} would load the whole backlog into memory — not an attack, just a
 *       client that wants "everything" and does not know what everything weighs.
 *   <li><b>{@code total} is counted with the same filters as the page.</b> See {@link
 *       IssueFilters} for why that is one definition rather than two.
 * </ul>
 */
@RestController
@RequestMapping("/api/v1/issues")
@RequiresAccount
public class IssuesController {

    public static final int MAX_PAGE_SIZE = 500;
    private static final int DEFAULT_PAGE_SIZE = 50;

    private final Issues issues;
    private final IssueTriageService triage;
    private final AuditLogService audit;

    public IssuesController(Issues issues, IssueTriageService triage, AuditLogService audit) {
        this.issues = issues;
        this.triage = triage;
        this.audit = audit;
    }

    public record Page(List<IssueEntity> items, long total, int limit, int offset) {}

    public record TriageRequest(String status, String justification, String comment, Integer expiresInDays) {}

    @GetMapping
    public Page list(
            @RequestParam(required = false) String state,
            @RequestParam(required = false) String severity,
            @RequestParam(required = false) String type,
            @RequestParam(name = "triage_status", required = false) String triageStatus,
            @RequestParam(name = "repository_id", required = false) Long repositoryId,
            @RequestParam(name = "container_id", required = false) Long containerId,
            @RequestParam(name = "only_direct", required = false, defaultValue = "false") boolean onlyDirect,
            @RequestParam(required = false) String search,
            @RequestParam(required = false, defaultValue = "50") int limit,
            @RequestParam(required = false, defaultValue = "0") int offset) {

        int size = Math.clamp(limit, 1, MAX_PAGE_SIZE);
        int from = Math.max(offset, 0);

        IssueFilters filters = new IssueFilters(
                // `state` has a default and the others do not: a backlog opens on what is open.
                // `state=all` asks explicitly for the opposite.
                "all".equals(state) ? null : (state == null ? IssueState.OPEN.wireName() : state),
                severity,
                type,
                triageStatus,
                repositoryId,
                containerId,
                onlyDirect,
                search);

        var specification = filters.toSpecification();
        var page = issues.findAll(
                specification,
                PageRequest.of(from / Math.max(size, 1), size, Sort.by(Sort.Order.desc("lastSeenAt"), Sort.Order.desc("id"))));

        return new Page(page.getContent(), page.getTotalElements(), size, from);
    }

    /**
     * Records a triage decision.
     *
     * <p>VEX vocabulary: affected, not_affected, fixed, under_review. A dismissal is a claim
     * about a <em>context</em> — "not reachable in our configuration" — and contexts change:
     * hence the optional review date, at which the issue returns to {@code under_review} with
     * its justification intact.
     */
    @PostMapping("/{id}/triage")
    public IssueEntity triage(
            @PathVariable long id,
            @RequestBody TriageRequest body,
            @AuthenticationPrincipal ZanshinPrincipal principal,
            HttpServletRequest request) {

        String actor = principal.user().map(user -> user.getUsername()).orElse("unknown");
        IssueEntity issue = triage.triage(id, new Triage.Request(
                TriageStatus.fromWireName(body.status()).orElse(null),
                actor,
                VexJustification.fromWireName(body.justification()).orElse(null),
                body.comment(),
                body.expiresInDays() == null ? null : Period.ofDays(body.expiresInDays())));

        // A triage can dismiss a finding: that is a security decision, and it belongs in the
        // audit trail as much as a role change does.
        audit.record(new AuditLogService.Record(
                AuditOperation.ISSUE_TRIAGED,
                String.valueOf(id),
                "Triage \"" + issue.getTriageStatus() + "\""
                        + (issue.getTriageJustification() == null ? "" : " (" + issue.getTriageJustification() + ")"),
                actor,
                request.getRemoteAddr(),
                request.getHeader("User-Agent")));

        return issue;
    }
}
