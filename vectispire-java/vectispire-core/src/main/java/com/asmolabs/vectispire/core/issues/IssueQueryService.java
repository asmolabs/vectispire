package com.asmolabs.vectispire.core.issues;

import com.asmolabs.vectispire.common.domain.access.Visibility;
import com.asmolabs.vectispire.common.domain.errors.InvalidInputException;
import com.asmolabs.vectispire.common.domain.issues.FindingType;
import com.asmolabs.vectispire.common.domain.issues.IssueState;
import com.asmolabs.vectispire.common.domain.issues.RemediationSla;
import com.asmolabs.vectispire.common.domain.issues.Severity;
import com.asmolabs.vectispire.common.domain.owasp.OwaspCoverage;
import com.asmolabs.vectispire.core.access.RowVisibility;
import com.asmolabs.vectispire.core.issues.persistence.IssueEntity;
import com.asmolabs.vectispire.core.issues.persistence.IssueOrdering;
import com.asmolabs.vectispire.core.issues.persistence.IssueSpecifications;
import com.asmolabs.vectispire.core.issues.persistence.IssueRepository;
import com.asmolabs.vectispire.core.issues.persistence.TriageEventRepository;
import com.asmolabs.vectispire.core.issues.persistence.queries.IssueFilters;
import com.asmolabs.vectispire.core.scanning.ScanCatalog;
import com.asmolabs.vectispire.core.targets.SolutionQueryService;
import com.asmolabs.vectispire.core.targets.TargetNaming;
import com.fasterxml.jackson.annotation.JsonUnwrapped;
import java.time.Instant;
import java.time.LocalDate;
import java.time.ZoneOffset;
import java.time.format.DateTimeParseException;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.Objects;
import java.util.function.Function;
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

    private final IssueRepository issues;
    private final ScanCatalog findings;
    private final TriageEventRepository events;
    private final TargetNaming naming;
    private final SlaService sla;
    private final SolutionQueryService solutions;

    public IssueQueryService(
            IssueRepository issues,
            ScanCatalog findings,
            TriageEventRepository events,
            TargetNaming naming,
            SlaService sla,
            SolutionQueryService solutions) {
        this.issues = issues;
        this.findings = findings;
        this.events = events;
        this.naming = naming;
        this.sla = sla;
        this.solutions = solutions;
    }

    /**
     * What a backlog request can ask for, as the query string spells it.
     *
     * @param projectId the issues of the repositories and images filed in this project now — see {@link #page}
     *     for what a reader who sees part of it, or none, is answered
     * @param solutionId the same over every project of the solution; with {@code projectId}, both hold
     * @param owaspCategory {@code A01}…{@code A10}: the issues the OWASP grid places there — see {@link #page}
     * @param openAt an ISO date: the issues open at the end of that day, UTC
     * @param firstSeenFrom an ISO date: first seen on that day or after, UTC
     * @param firstSeenTo an ISO date: first seen on that day or before, UTC
     * @param resolvedFrom an ISO date: resolved on that day or after, UTC
     * @param resolvedTo an ISO date: resolved on that day or before, UTC
     */
    public record BacklogQuery(
            String state,
            String severity,
            String type,
            String triageStatus,
            Long repositoryId,
            Long containerId,
            Long projectId,
            Long solutionId,
            boolean onlyDirect,
            boolean onlyKev,
            boolean overdue,
            boolean unsettled,
            String search,
            int limit,
            int offset,
            String owaspCategory,
            String openAt,
            String firstSeenFrom,
            String firstSeenTo,
            String resolvedFrom,
            String resolvedTo) {

        /** Every filter but the drill-down's, which none of these callers asks. */
        public BacklogQuery(
                String state,
                String severity,
                String type,
                String triageStatus,
                Long repositoryId,
                Long containerId,
                Long projectId,
                Long solutionId,
                boolean onlyDirect,
                boolean onlyKev,
                boolean overdue,
                boolean unsettled,
                String search,
                int limit,
                int offset) {
            this(state, severity, type, triageStatus, repositoryId, containerId, projectId, solutionId, onlyDirect,
                    onlyKev, overdue, unsettled, search, limit, offset, null, null, null, null, null, null);
        }
    }

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
     *
     * <p><b>A project or a solution narrows like a repository does: intersected with the visibility,
     * never refused.</b> Its repositories and images are asked of {@code targets}, which owns the membership, at
     * the moment of asking, and the query keeps those of them the caller sees. A reader who sees part
     * of the project gets the issues of that part — what the tree shows them of it, and what the
     * unfiltered list already showed. One who sees none of it, and one naming a project that does not
     * exist, both get an empty page, as {@code repository_id} answers for a repository hidden or
     * absent: the two are indistinguishable, and a 404 here would be the list's one filter that could.
     * The checklist refuses a partial project (404) because its answers speak for the whole of it; a
     * page of issues speaks for no more than its rows.
     *
     * <p><b>The weekly OWASP view's drill-down</b>: a category, and the dates of an issue's life. A
     * category is placed as the grid places it ({@code OwaspCoverage.placementOf}). A date asks about the
     * past, and <b>with one the state defaults to every state, not to open</b>: "open at the end of that
     * Sunday" is mostly issues resolved since, "resolved that week" is only resolved ones, and "first seen
     * that week" is what the week's opened bar counted, resolved or not. Defaulting to open would answer
     * each with a page the figure it came from disagrees with. A state the caller names still holds.
     */
    public IssuePage page(BacklogQuery query, Visibility allowed) {
        int size = Math.clamp(query.limit(), 1, MAX_PAGE_SIZE);
        int from = Math.max(query.offset(), 0);
        IssueFilters.Lifetime lifetime = lifetime(query);

        IssueFilters filters = new IssueFilters(
                state(query.state(), lifetime != null),
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
                allowed)
                .placedIn(owaspCategory(query.owaspCategory()))
                .living(lifetime);
        if (query.projectId() != null) {
            filters = filters.within(solutions.members(query.projectId())
                    .map(SolutionQueryService.ProjectMembers::targets)
                    .orElse(List.of()));
        }
        if (query.solutionId() != null) {
            filters = filters.within(solutions.targetsOfSolution(query.solutionId()));
        }

        var page = issues.findAll(
                IssueSpecifications.of(filters),
                PageRequest.of(from / Math.max(size, 1), size, IssueOrdering.MOST_SEVERE_FIRST));

        return new IssuePage(named(page.getContent()), page.getTotalElements(), size, from);
    }

    /**
     * The state filter, read against the two states that exist.
     *
     * <p>It has a default and the others do not: a backlog opens on what is open, and {@code all}
     * asks explicitly for the opposite — unless the query asks a date, which asks about the past and
     * defaults to every state ({@link #page}). <b>An unknown value is refused</b> — like the severity and
     * the type below. Each used to go into the query as typed, so {@code state=opne} or
     * {@code severity=HIGH} answered an empty page with a 200: a filter that matched nothing,
     * indistinguishable from a backlog with nothing in it.
     */
    private static String state(String raw, boolean datesAsked) {
        if (raw == null || raw.isBlank()) {
            return datesAsked ? null : IssueState.OPEN.wireName();
        }
        String value = raw.trim().toLowerCase(Locale.ROOT);
        if (value.equals("all")) {
            return null;
        }
        return IssueState.byWireName(value)
                .map(IssueState::wireName)
                .orElseThrow(() -> new InvalidInputException(
                        "Unknown state \"" + raw.trim() + "\". Expected open, resolved or all."));
    }

    /** An OWASP Top 10 category, case aside; blank is no filter, and a code the grid does not hold is refused. */
    private static String owaspCategory(String raw) {
        if (raw == null || raw.isBlank()) {
            return null;
        }
        String value = raw.trim().toUpperCase(Locale.ROOT);
        if (!OwaspCoverage.CATEGORIES.containsKey(value)) {
            throw new InvalidInputException("Unknown OWASP category \"" + raw.trim() + "\". Expected one of: "
                    + String.join(", ", OwaspCoverage.CATEGORIES.keySet()) + ".");
        }
        return value;
    }

    /**
     * The dates of the query as instants, or null when none is given. A day is read in UTC — the cut
     * the weekly view's weeks use — and a {@code _to} includes its day, so the bound is the next
     * midnight, excluded. A range whose end comes before its start is refused rather than answered empty.
     */
    private static IssueFilters.Lifetime lifetime(BacklogQuery query) {
        Instant openAt = nextMidnight("open_at", query.openAt());
        Instant firstSeenFrom = midnight("first_seen_from", query.firstSeenFrom());
        Instant firstSeenBefore = nextMidnight("first_seen_to", query.firstSeenTo());
        Instant resolvedFrom = midnight("resolved_from", query.resolvedFrom());
        Instant resolvedBefore = nextMidnight("resolved_to", query.resolvedTo());
        requireOrdered("first_seen", firstSeenFrom, firstSeenBefore);
        requireOrdered("resolved", resolvedFrom, resolvedBefore);
        IssueFilters.Lifetime lifetime =
                new IssueFilters.Lifetime(openAt, firstSeenFrom, firstSeenBefore, resolvedFrom, resolvedBefore);
        return lifetime.asksAnything() ? lifetime : null;
    }

    private static void requireOrdered(String name, Instant from, Instant before) {
        if (from != null && before != null && !from.isBefore(before)) {
            throw new InvalidInputException(name + "_to comes before " + name + "_from.");
        }
    }

    private static Instant midnight(String name, String raw) {
        LocalDate day = day(name, raw);
        return day == null ? null : day.atStartOfDay(ZoneOffset.UTC).toInstant();
    }

    private static Instant nextMidnight(String name, String raw) {
        LocalDate day = day(name, raw);
        return day == null ? null : day.plusDays(1).atStartOfDay(ZoneOffset.UTC).toInstant();
    }

    /** An ISO date, refused in words — {@code LocalDate.parse} on a caller's value is a 500 otherwise. */
    private static LocalDate day(String name, String raw) {
        if (raw == null || raw.isBlank()) {
            return null;
        }
        try {
            LocalDate day = LocalDate.parse(raw.trim());
            // Bounded before MySQL's year 9999, and before the instant arithmetic a year past it would
            // need: a date no issue can carry asks nothing a bounded one does not.
            if (day.getYear() < 1970 || day.getYear() > 9998) {
                throw new InvalidInputException(name + " must be a date between 1970 and 9998.");
            }
            return day;
        } catch (DateTimeParseException unreadable) {
            throw new InvalidInputException(name + " must be an ISO date, YYYY-MM-DD: \"" + raw.trim() + "\".");
        }
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
                .orElseThrow(() -> new InvalidInputException("Unknown severity \"" + raw.trim() + "\". Expected one of: "
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
                .orElseThrow(() -> new InvalidInputException("Unknown finding type \"" + raw.trim() + "\". Expected one of: "
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
     * @throws com.asmolabs.vectispire.common.domain.errors.NotFoundException when it does not exist <em>or</em> is not visible,
     *     in the same words, so a refusal reads as an absence
     */
    public IssueDetail detail(long id, Visibility allowed) {
        IssueEntity issue = RowVisibility.requireVisibleIssue(issues.findById(id).orElse(null), IssueEntity::target, allowed);

        TargetNaming.Names names = naming.all();
        List<Sighting> sightings = findings.sightings(id, MAX_SIGHTINGS).stream()
                .map(seen -> new Sighting(
                        seen.scan().id(),
                        seen.scan().status(),
                        seen.scan().branch(),
                        seen.scan().version(),
                        seen.scan().createdAt(),
                        seen.finding().severity()))
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
