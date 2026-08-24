package com.asmolabs.vectispire.core.api;

import com.fasterxml.jackson.annotation.JsonProperty;
import com.fasterxml.jackson.annotation.JsonUnwrapped;
import com.asmolabs.vectispire.common.domain.access.Visibility;
import com.asmolabs.vectispire.common.domain.audit.AuditOperation;
import com.asmolabs.vectispire.common.domain.issues.InvalidTriageException;
import com.asmolabs.vectispire.common.domain.issues.IssueState;
import com.asmolabs.vectispire.common.domain.issues.RemediationSla;
import com.asmolabs.vectispire.common.domain.issues.Triage;
import com.asmolabs.vectispire.common.domain.issues.TriageStatus;
import com.asmolabs.vectispire.common.domain.issues.VexJustification;
import com.asmolabs.vectispire.common.domain.users.Role;
import com.asmolabs.vectispire.core.api.security.RequiresAccount;
import com.asmolabs.vectispire.core.api.security.VectispirePrincipal;
import com.asmolabs.vectispire.core.persistence.IssueEntity;
import com.asmolabs.vectispire.core.repositories.IssueFilters;
import com.asmolabs.vectispire.core.repositories.IssueOrdering;
import com.asmolabs.vectispire.core.persistence.FindingEntity;
import com.asmolabs.vectispire.core.persistence.ScanEntity;
import com.asmolabs.vectispire.core.repositories.Findings;
import com.asmolabs.vectispire.core.repositories.Issues;
import com.asmolabs.vectispire.core.repositories.TriageEvents;
import com.asmolabs.vectispire.core.services.TriageHistory;
import com.asmolabs.vectispire.core.services.AuditLogService;
import com.asmolabs.vectispire.core.services.SlaService;
import com.asmolabs.vectispire.core.services.TargetNaming;
import com.asmolabs.vectispire.core.services.IssueTriageService;
import com.asmolabs.vectispire.core.services.VisibilityService;
import jakarta.servlet.http.HttpServletRequest;
import java.time.Instant;
import java.time.Period;
import java.util.List;
import java.util.Locale;
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
    private final SlaService sla;

    public IssuesController(
            Issues issues,
            Findings findings,
            TriageEvents events,
            TargetNaming naming,
            IssueTriageService triage,
            AuditLogService audit,
            VisibilityService visibility,
            SlaService sla) {
        this.issues = issues;
        this.findings = findings;
        this.events = events;
        this.naming = naming;
        this.triage = triage;
        this.audit = audit;
        this.visibility = visibility;
        this.sla = sla;
    }

    public record Page(List<BacklogEntry> items, long total, int limit, int offset) {}

    public record TriageRequest(String status, String justification, String comment, @JsonProperty("expires_in_days") Integer expiresInDays) {}

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

    /**
     * The same ceiling as the list route returns.
     *
     * <p>Deliberately equal: a screen that can show 500 rows can decide on 500 rows, and a limit
     * below what the list hands back would make "select all" an action the interface offers and
     * the API refuses.
     */
    private static final int MAX_BULK_TRIAGE = 500;

    @GetMapping
    public Page list(
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
                // Asking for the overdue also excludes what triage settled: a dismissed issue is
                // not late, and a list that showed it would disagree with the figure that led here.
                overdue,
                overdue ? sla.overdueThresholds() : java.util.Map.of(),
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
        // The policy read once for the page, not once per row: it is four settings reads, and
        // fifty rows would make it two hundred.
        RemediationSla policy = sla.policy();

        return page.stream()
                .map(issue -> {
                    var assessment = sla.assess(policy, issue);
                    return new BacklogEntry(
                            issue,
                            names.kindOf(issue.getContainerId()),
                            names.of(issue.getRepoId(), issue.getContainerId()),
                            assessment.map(RemediationSla.Assessment::dueAt).orElse(null),
                            assessment.map(found -> found.state().name().toLowerCase(Locale.ROOT)).orElse(null),
                            assessment.map(RemediationSla.Assessment::days).orElse(null));
                })
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
    public Detail detail(@AuthenticationPrincipal VectispirePrincipal principal, @PathVariable long id) {
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
            @AuthenticationPrincipal VectispirePrincipal principal,
            HttpServletRequest request) {

        String actor = principal.user().map(user -> user.getUsername()).orElse("unknown");
        boolean canApprove = principal.user()
                .flatMap(user -> Role.of(user.getRole()))
                .map(Role::canApproveTriage)
                .orElse(true);
        // Checked before the write, and 404 rather than 403 — see `Visibilities`.
        Visibilities.requireVisible(
                issues.findById(id).orElse(null),
                visibility.of(principal.user().orElse(null), principal.credentialRestriction()));
        IssueEntity issue = triage.triage(id, new Triage.Request(
                TriageStatus.fromWireName(body.status()).orElse(null),
                actor,
                VexJustification.fromWireName(body.justification()).orElse(null),
                body.comment(),
                body.expiresInDays() == null ? null : Period.ofDays(body.expiresInDays())),
                canApprove);

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
    @PostMapping("/triage")
    public List<IssueEntity> triageMany(
            @RequestBody BulkTriageRequest body,
            @AuthenticationPrincipal VectispirePrincipal principal,
            HttpServletRequest request) {

        List<Long> ids = body == null || body.ids() == null ? List.of() : body.ids();
        if (ids.isEmpty()) {
            throw new InvalidTriageException("Select at least one issue to triage.");
        }
        // **Refused, not truncated.** Silently triaging the first 500 of 900 would report success
        // for a decision that did not reach 400 issues, and the caller has no way to see which.
        // The cap matches the list route's, so anything the screen can show, it can decide on.
        if (ids.size() > MAX_BULK_TRIAGE) {
            throw new InvalidTriageException(
                    "Too many issues at once: " + ids.size() + ", the limit is " + MAX_BULK_TRIAGE + ".");
        }

        String actor = principal.user().map(user -> user.getUsername()).orElse("unknown");
        boolean canApprove = principal.user()
                .flatMap(user -> Role.of(user.getRole()))
                .map(Role::canApproveTriage)
                .orElse(true);
        Visibility visible = visibility.of(principal.user().orElse(null), principal.credentialRestriction());
        for (Long id : ids) {
            Visibilities.requireVisible(issues.findById(id).orElse(null), visible);
        }

        List<IssueEntity> triaged = triage.triageAll(ids, new Triage.Request(
                TriageStatus.fromWireName(body.status()).orElse(null),
                actor,
                VexJustification.fromWireName(body.justification()).orElse(null),
                body.comment(),
                body.expiresInDays() == null ? null : Period.ofDays(body.expiresInDays())),
                canApprove);

        // **One entry for the action, not one per issue.** The audit log is never purged, and a
        // single dismissal of six hundred issues would bury every other entry around it. What is
        // lost is not traceability: each issue carries its own recorded transition in the triage
        // history, which is the document a compliance reader is handed. This entry says a bulk
        // decision happened, by whom, and how wide it was — which is what the audit log is for.
        audit.record(new AuditLogService.Record(
                AuditOperation.ISSUE_TRIAGED,
                ids.size() + " issues",
                "Bulk triage \"" + body.status() + "\" on " + ids.size() + " issues"
                        + (body.justification() == null ? "" : " (" + body.justification() + ")")
                        + " — per-issue transitions are in each issue's triage history",
                actor,
                request.getRemoteAddr(),
                request.getHeader("User-Agent")));

        return triaged;
    }
}
