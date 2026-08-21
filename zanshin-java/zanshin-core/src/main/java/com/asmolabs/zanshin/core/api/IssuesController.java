package com.asmolabs.zanshin.core.api;

import com.fasterxml.jackson.annotation.JsonProperty;
import com.fasterxml.jackson.annotation.JsonUnwrapped;
import com.asmolabs.zanshin.common.domain.audit.AuditOperation;
import com.asmolabs.zanshin.common.domain.issues.IssueState;
import com.asmolabs.zanshin.common.domain.issues.Triage;
import com.asmolabs.zanshin.common.domain.issues.TriageStatus;
import com.asmolabs.zanshin.common.domain.issues.VexJustification;
import com.asmolabs.zanshin.core.api.security.RequiresAccount;
import com.asmolabs.zanshin.core.api.security.ZanshinPrincipal;
import com.asmolabs.zanshin.core.persistence.IssueEntity;
import com.asmolabs.zanshin.core.repositories.IssueFilters;
import com.asmolabs.zanshin.core.repositories.IssueOrdering;
import com.asmolabs.zanshin.core.persistence.FindingEntity;
import com.asmolabs.zanshin.core.persistence.ScanEntity;
import com.asmolabs.zanshin.core.repositories.Findings;
import com.asmolabs.zanshin.core.repositories.Issues;
import com.asmolabs.zanshin.core.repositories.TriageEvents;
import com.asmolabs.zanshin.core.services.TriageHistory;
import com.asmolabs.zanshin.core.services.AuditLogService;
import com.asmolabs.zanshin.core.services.TargetNaming;
import com.asmolabs.zanshin.core.services.IssueTriageService;
import com.asmolabs.zanshin.core.services.VisibilityService;
import jakarta.servlet.http.HttpServletRequest;
import java.time.Instant;
import java.time.Period;
import java.util.List;
import java.util.NoSuchElementException;
import java.util.Objects;
import java.util.function.Function;
import org.springframework.data.domain.PageRequest;
import org.springframework.data.domain.Sort;
import org.springframework.data.domain.Limit;
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

    /** A detail page shows where an issue was seen, not every scan that ever ran. */
    private static final int MAX_SIGHTINGS = 100;

    private final Issues issues;
    private final Findings findings;
    private final TriageEvents events;
    private final TargetNaming naming;
    private final IssueTriageService triage;
    private final AuditLogService audit;
    private final VisibilityService visibility;

    public IssuesController(
            Issues issues,
            Findings findings,
            TriageEvents events,
            TargetNaming naming,
            IssueTriageService triage,
            AuditLogService audit,
            VisibilityService visibility) {
        this.issues = issues;
        this.findings = findings;
        this.events = events;
        this.naming = naming;
        this.triage = triage;
        this.audit = audit;
        this.visibility = visibility;
    }

    public record Page(List<BacklogEntry> items, long total, int limit, int offset) {}

    public record TriageRequest(String status, String justification, String comment, @JsonProperty("expires_in_days") Integer expiresInDays) {}

    @GetMapping
    public Page list(
            @AuthenticationPrincipal ZanshinPrincipal principal,
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
                onlyKev,
                search,
                // Narrowed here and not by the caller: a filter the request supplies is a filter
                // the request can omit.
                visibility.of(principal.user().orElse(null), principal.credentialRestriction()));

        var specification = filters.toSpecification();
        var page = issues.findAll(
                specification,
                PageRequest.of(from / Math.max(size, 1), size, IssueOrdering.MOST_SEVERE_FIRST));

        return new Page(named(page.getContent()), page.getTotalElements(), size, from);
    }

    /**
     * Attaches each issue's target name.
     *
     * <p><b>Two queries for the page, not two per row.</b> Resolving a name inside the mapping
     * would issue one select per issue — fifty round trips to render fifty rows, and the cost
     * grows with the page size a caller chooses.
     */
    private List<BacklogEntry> named(List<IssueEntity> page) {
        TargetNaming.Names names = naming.forIds(
                idsOf(page, IssueEntity::getRepoId), idsOf(page, IssueEntity::getContainerId));

        return page.stream()
                .map(issue -> new BacklogEntry(
                        issue,
                        names.kindOf(issue.getContainerId()),
                        names.of(issue.getRepoId(), issue.getContainerId())))
                .toList();
    }

    private static List<Long> idsOf(List<IssueEntity> page, Function<IssueEntity, Long> id) {
        return page.stream().map(id).filter(Objects::nonNull).distinct().toList();
    }

    /**
     * @param sightings the scans that observed this issue, newest first. An issue carries a first
     *     and a last scan and nothing between them; "seen in 1.17.4, still in 1.17.6" is a
     *     question the findings answer, and the version comes from the scan
     * @param decisions every triage transition, from the same table the history screen reads —
     *     one issue's slice of it, so the page that asks "why is this dismissed" has the answer
     *     beside the dismissal rather than three screens away
     */
    public record Detail(
            @JsonUnwrapped IssueEntity issue,
            String targetKind,
            String targetName,
            List<Sighting> sightings,
            List<TriageHistory.Decision> decisions) {}

    /** @param version what the project called itself when this scan saw the issue */
    public record Sighting(
            Long scanId, String status, String branch, String version, Instant scannedAt, String severity) {}

    /**
     * One issue, with what a row cannot carry.
     *
     * <p>The issue itself is unwrapped rather than restated: the list already sends every column,
     * and a second definition of an issue drifts from the first the day a column is added. What
     * is added here is what needs a query of its own — where it was seen, and what was decided.
     */
    @GetMapping("/{id}")
    public Detail detail(@AuthenticationPrincipal ZanshinPrincipal principal, @PathVariable long id) {
        IssueEntity issue = issues.findById(id).orElse(null);
        // 404 rather than 403 when it exists but is not visible — see `Visibilities`.
        Visibilities.requireVisible(
                issue, visibility.of(principal.user().orElse(null), principal.credentialRestriction()));
        if (issue == null) {
            throw new NoSuchElementException("Issue not found.");
        }

        TargetNaming.Names names = naming.all();
        List<Sighting> sightings = findings.sightingsOf(id, Limit.of(MAX_SIGHTINGS)).stream()
                .map(row -> {
                    FindingEntity finding = (FindingEntity) row[0];
                    ScanEntity scan = (ScanEntity) row[1];
                    return new Sighting(
                            scan.getId(),
                            scan.getStatus(),
                            scan.getBranch(),
                            scan.getVersion(),
                            scan.getCreatedAt(),
                            finding.getSeverity());
                })
                .toList();

        List<TriageHistory.Decision> decisions = events.findForIssues(List.of(id)).stream()
                .map(event -> new TriageHistory.Decision(
                        event.getFromStatus(),
                        event.getToStatus(),
                        event.getJustification(),
                        event.getComment(),
                        event.getActor(),
                        event.getOrigin(),
                        event.getOccurredAt(),
                        event.getExpiresAt(),
                        event.getScanId(),
                        null))
                .toList();

        return new Detail(
                issue,
                issue.getRepoId() != null ? "repository" : "container",
                names.of(issue.getRepoId(), issue.getContainerId()),
                sightings,
                decisions);
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
        // Checked before the write, and 404 rather than 403 — see `Visibilities`.
        Visibilities.requireVisible(
                issues.findById(id).orElse(null),
                visibility.of(principal.user().orElse(null), principal.credentialRestriction()));
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
