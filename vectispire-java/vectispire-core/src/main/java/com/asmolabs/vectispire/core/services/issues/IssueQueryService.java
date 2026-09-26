package com.asmolabs.vectispire.core.services.issues;

import com.asmolabs.vectispire.common.domain.access.Visibility;
import com.asmolabs.vectispire.common.domain.issues.FindingType;
import com.asmolabs.vectispire.common.domain.issues.IssueState;
import com.asmolabs.vectispire.common.domain.issues.RemediationSla;
import com.asmolabs.vectispire.common.domain.issues.Severity;
import com.asmolabs.vectispire.core.access.RowVisibility;
import com.asmolabs.vectispire.core.persistence.IssueEntity;
import com.asmolabs.vectispire.core.repositories.IssueFilters;
import com.asmolabs.vectispire.core.repositories.IssueOrdering;
import com.asmolabs.vectispire.core.repositories.IssueSpecifications;
import com.asmolabs.vectispire.core.repositories.Issues;
import com.asmolabs.vectispire.core.repositories.TriageEvents;
import com.asmolabs.vectispire.core.scanning.persistence.FindingEntity;
import com.asmolabs.vectispire.core.scanning.persistence.Findings;
import com.asmolabs.vectispire.core.scanning.persistence.ScanEntity;
import com.asmolabs.vectispire.core.targets.TargetNaming;
import com.fasterxml.jackson.annotation.JsonUnwrapped;
import java.time.Instant;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.Objects;
import java.util.function.Function;
import org.springframework.data.domain.Limit;
import org.springframework.data.domain.PageRequest;
import org.springframework.stereotype.Service;

/**
 * The backlog as the issues routes read it: one page, one issue.
 *
 * <p>The narrative — the page ceiling, why {@code total} shares the page's filters — is on {@code
 * IssuesController}, where somebody reading the API finds it. This class holds what the
 * controller used to do by hand, so that the lookup and the visibility applied to it cannot be
 * separated again.
 */
@Service
public class IssueQueryService {

    /**
     * With no ceiling, a caller asking for {@code limit=1000000} would load the whole backlog into
     * memory — not an attack, just a client that wants "everything" and does not know what
     * everything weighs.
     */
    public static final int MAX_PAGE_SIZE = 500;

    /** A detail page shows where an issue was seen, not every scan that ever ran. */
    private static final int MAX_SIGHTINGS = 100;

    private final Issues issues;
    private final Findings findings;
    private final TriageEvents events;
    private final TargetNaming naming;
    private final SlaService sla;

    public IssueQueryService(
            Issues issues, Findings findings, TriageEvents events, TargetNaming naming, SlaService sla) {
        this.issues = issues;
        this.findings = findings;
        this.events = events;
        this.naming = naming;
        this.sla = sla;
    }

    /** What a backlog request can ask for, as the query string spells it. */
    public record BacklogQuery(
            String state,
            String severity,
            String type,
            String triageStatus,
            Long repositoryId,
            Long containerId,
            boolean onlyDirect,
            boolean onlyKev,
            boolean overdue,
            boolean unsettled,
            String search,
            int limit,
            int offset) {}

    public record IssuePage(List<BacklogEntry> items, long total, int limit, int offset) {}

    /**
     * @param sightings the scans that observed this issue, newest first. An issue carries a first
     *     and a last scan and nothing between them; "seen in 1.17.4, still in 1.17.6" is a
     *     question the findings answer, and the version comes from the scan
     * @param decisions every triage transition, from the same table the history screen reads —
     *     one issue's slice of it, so the page that asks "why is this dismissed" has the answer
     *     beside the dismissal rather than three screens away
     */
    public record IssueDetail(
            @JsonUnwrapped IssueView issue,
            String targetKind,
            String targetName,
            List<Sighting> sightings,
            List<TriageHistory.Decision> decisions) {}

    /** @param version what the project called itself when this scan saw the issue */
    public record Sighting(
            Long scanId, String status, String branch, String version, Instant scannedAt, String severity) {}

    /**
     * One page of the backlog, narrowed to what {@code allowed} permits.
     *
     * <p><b>The visibility is a parameter, not a filter the request carries</b>: a filter the
     * request supplies is a filter the request can omit.
     */
    public IssuePage page(BacklogQuery query, Visibility allowed) {
        int size = Math.clamp(query.limit(), 1, MAX_PAGE_SIZE);
        int from = Math.max(query.offset(), 0);

        IssueFilters filters = new IssueFilters(
                state(query.state()),
                severity(query.severity()),
                type(query.type()),
                query.triageStatus(),
                query.repositoryId(),
                query.containerId(),
                query.onlyDirect(),
                query.onlyKev(),
                query.search(),
                // Asking for the overdue also excludes what triage settled: a dismissed issue is
                // not late, and a list that showed it would disagree with the figure that led here.
                query.overdue() || query.unsettled(),
                query.overdue() ? sla.overdueThresholds() : Map.of(),
                allowed);

        var page = issues.findAll(
                IssueSpecifications.of(filters),
                PageRequest.of(from / Math.max(size, 1), size, IssueOrdering.MOST_SEVERE_FIRST));

        return new IssuePage(named(page.getContent()), page.getTotalElements(), size, from);
    }

    /**
     * The state filter, read against the two states that exist.
     *
     * <p>It has a default and the others do not: a backlog opens on what is open, and {@code all}
     * asks explicitly for the opposite. <b>An unknown value is refused</b> — like the severity and
     * the type below. Each used to go into the query as typed, so {@code state=opne} or
     * {@code severity=HIGH} answered an empty page with a 200: a filter that matched nothing,
     * indistinguishable from a backlog with nothing in it.
     */
    private static String state(String raw) {
        if (raw == null || raw.isBlank()) {
            return IssueState.OPEN.wireName();
        }
        String value = raw.trim().toLowerCase(Locale.ROOT);
        if (value.equals("all")) {
            return null;
        }
        return IssueState.byWireName(value)
                .map(IssueState::wireName)
                .orElseThrow(() -> new IllegalArgumentException(
                        "Unknown state \"" + raw.trim() + "\". Expected open, resolved or all."));
    }

    /** A severity by its wire name, case aside; blank is no filter. */
    private static String severity(String raw) {
        if (raw == null || raw.isBlank()) {
            return null;
        }
        String value = raw.trim().toLowerCase(Locale.ROOT);
        return java.util.Arrays.stream(Severity.values())
                .map(Severity::wireName)
                .filter(value::equals)
                .findFirst()
                .orElseThrow(() -> new IllegalArgumentException("Unknown severity \"" + raw.trim() + "\". Expected one of: "
                        + java.util.Arrays.stream(Severity.values()).map(Severity::wireName)
                                .collect(java.util.stream.Collectors.joining(", ")) + "."));
    }

    /** A finding type by its wire name, case aside; blank is no filter. */
    private static String type(String raw) {
        if (raw == null || raw.isBlank()) {
            return null;
        }
        return FindingType.fromWireName(raw.trim().toLowerCase(Locale.ROOT))
                .map(FindingType::wireName)
                .orElseThrow(() -> new IllegalArgumentException("Unknown finding type \"" + raw.trim() + "\". Expected one of: "
                        + java.util.Arrays.stream(FindingType.values()).map(FindingType::wireName)
                                .collect(java.util.stream.Collectors.joining(", ")) + "."));
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
                            IssueView.of(issue),
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
     * One issue, with what a row cannot carry — where it was seen, and what was decided.
     *
     * @throws java.util.NoSuchElementException when it does not exist <em>or</em> is not visible,
     *     in the same words, so a refusal reads as an absence
     */
    public IssueDetail detail(long id, Visibility allowed) {
        IssueEntity issue = RowVisibility.requireVisibleIssue(issues.findById(id).orElse(null), IssueEntity::target, allowed);

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

        return new IssueDetail(
                IssueView.of(issue),
                issue.getRepoId() != null ? "repository" : "container",
                names.of(issue.getRepoId(), issue.getContainerId()),
                sightings,
                decisions);
    }
}
