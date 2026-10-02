package com.asmolabs.vectispire.core.compliance;

import com.asmolabs.vectispire.common.domain.access.Visibility;
import com.asmolabs.vectispire.common.domain.access.VisibleScope;
import com.asmolabs.vectispire.common.domain.errors.InvalidInputException;
import com.asmolabs.vectispire.common.domain.issues.FindingType;
import com.asmolabs.vectispire.common.domain.owasp.CoverageWeek;
import com.asmolabs.vectispire.common.domain.owasp.OwaspCoverage;
import com.asmolabs.vectispire.core.access.VisibilityService;
import com.asmolabs.vectispire.core.compliance.persistence.OwaspWeeklyCoverageRepository;
import com.asmolabs.vectispire.core.compliance.persistence.OwaspWeeklyStateCount;
import com.asmolabs.vectispire.core.issues.IssueCatalog;
import com.asmolabs.vectispire.core.issues.persistence.queries.IssueAggregates;
import com.asmolabs.vectispire.core.issues.persistence.queries.IssueFilters;
import com.asmolabs.vectispire.core.targets.SolutionQueryService;
import java.time.Clock;
import java.time.Instant;
import java.time.LocalDate;
import java.time.ZoneOffset;
import java.time.format.DateTimeParseException;
import java.time.temporal.ChronoUnit;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.stream.Collectors;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

/**
 * The OWASP Top 10 week by week, for one reader, over their estate or one project or solution.
 *
 * <h2>Two sources, said apart</h2>
 *
 * <p>A week the weekly record captured ({@link OwaspWeeklyCoverageService}) reads its <b>state</b>, its
 * open and its settled counts from the record, summed over the reader's targets — as at the week's last
 * capture. A week before the record, or one it holds nothing of for these targets, is
 * <b>reconstructed</b> from the issues' dates: its counts are approximate, and its state is null, since
 * the settings and rules that decided it have moved since and a state computed with today's would be
 * invented. The opened and resolved flows are counted from the dates on every week.
 *
 * <h2>Settled, in the past, is not known — and is not guessed</h2>
 *
 * <p>The triage history ({@code t_issue_triage_event}) records each decision, but not every change of an
 * issue's triage: a reopening before V68 cleared the issue's {@code fixed} with no entry, and decisions
 * taken before the history existed have none. Reading "settled at that Sunday" from
 * it would count a regression as settled for every week after its reopening. So a reconstructed week's
 * {@code settled} is null and its {@code open} counts every issue open at its end, whatever its triage —
 * a figure stated, rather than one corrected by a guess.
 *
 * <h2>Who sees what</h2>
 *
 * <p>The reader's visibility, intersected with the scope; a project or a solution the reader sees
 * nothing of answers 404 in the words one that does not exist answers ({@code SolutionQueryService}). A
 * restricted reader gets the sum of their targets and of no others, on both sources.
 */
@Service
public class OwaspWeeklyHistoryService {

    /** How many weeks one request may span: a year. A wider window is refused, not cut. */
    public static final int MAX_WEEKS = 52;

    /** How many weeks a request that names no window reads: a quarter, ending with the current week. */
    public static final int DEFAULT_WEEKS = 12;

    private final OwaspWeeklyCoverageRepository records;
    private final IssueCatalog issues;
    private final SolutionQueryService solutions;
    private final Clock clock;

    public OwaspWeeklyHistoryService(
            OwaspWeeklyCoverageRepository records, IssueCatalog issues, SolutionQueryService solutions, Clock clock) {
        this.records = records;
        this.issues = issues;
        this.solutions = solutions;
        this.clock = clock;
    }

    /**
     * What a request asks, as the query string spells it.
     *
     * @param from an ISO date, read as the Monday of its week; default {@value #DEFAULT_WEEKS} weeks before {@code to}
     * @param to an ISO date, read as the Monday of its week; default the current week. A week after the
     *     current one is read as the current one: its figures would be today's, dated in the future
     */
    public record Request(String from, String to, Long projectId, Long solutionId) {}

    /**
     * @param from the Monday (UTC) of the first week answered
     * @param to the Monday (UTC) of the last week answered
     * @param scope the project or solution asked for, or null for the reader's estate
     * @param weeks every week of the window, oldest first, recorded or not
     */
    public record OwaspWeeklyCoverage(LocalDate from, LocalDate to, OwaspWeeklyScope scope, List<OwaspWeek> weeks) {}

    /**
     * @param kind {@code project} or {@code solution}
     * @param partial the scope holds targets the reader does not see; every figure covers the visible ones
     * @param targetCount the visible targets the figures were computed over
     */
    public record OwaspWeeklyScope(String kind, long id, String name, boolean partial, int targetCount) {}

    /**
     * One week, ten categories.
     *
     * @param weekStart its Monday, the week running to the next Monday at 00:00 UTC, excluded
     * @param reconstructed true when the record holds nothing of this week for these targets: the
     *     categories' {@code state} and {@code settled} are null and {@code open} is counted from the
     *     issues' dates, triage aside
     * @param capturedAt when the record last captured this week, or null when reconstructed
     * @param categoriesMeasured how many categories read {@code FINDINGS} or {@code NO_FINDING} — a scanner
     *     looked; null when reconstructed
     * @param open the categories' {@code open}, summed — an issue is placed in one category at most
     * @param settled the categories' {@code settled}, summed; null when reconstructed
     * @param opened the categories' {@code opened}, summed
     * @param resolved the categories' {@code resolved}, summed
     */
    public record OwaspWeek(
            LocalDate weekStart,
            boolean reconstructed,
            Instant capturedAt,
            Integer categoriesMeasured,
            long open,
            Long settled,
            long opened,
            long resolved,
            List<OwaspWeekCategory> categories) {}

    /**
     * One category in one week.
     *
     * @param state the recorded state, combined over the targets as {@code OwaspCoverage.acrossTargets}
     *     says; <b>null when not recorded</b>, never one computed now for then
     * @param open on a recorded week, the open issues whose triage is not settled, as the grid counts
     *     them at the week's last capture; on a reconstructed week, every issue placed here that was open
     *     at the week's end, whatever its triage. A reopened issue keeps only its latest resolution
     * @param settled on a recorded week, the open issues whose triage is settled; null on a reconstructed
     *     one, where the triage of that date is not known
     * @param opened issues placed here first seen during the week, from their dates, on every week
     * @param resolved issues placed here resolved during the week, from their dates, on every week
     */
    public record OwaspWeekCategory(
            String category,
            String title,
            OwaspCoverage.State state,
            long open,
            Long settled,
            long opened,
            long resolved) {}

    /**
     * The weeks, for this reader.
     *
     * @throws com.asmolabs.vectispire.common.domain.errors.NotFoundException for a project or a solution
     *     that does not exist and one the reader sees nothing of, in the same words
     * @throws InvalidInputException for an unreadable date, a window that runs backwards or spans more
     *     than {@value #MAX_WEEKS} weeks, or both a project and a solution
     */
    @Transactional(readOnly = true)
    public OwaspWeeklyCoverage weeks(Request request, VisibilityService.Allowance allowance) {
        if (request.projectId() != null && request.solutionId() != null) {
            throw new InvalidInputException("Name a project or a solution, not both.");
        }
        List<Instant> weeks = window(request);

        VisibleScope scope = request.projectId() != null
                ? solutions.visibleProject(request.projectId(), allowance)
                : request.solutionId() != null ? solutions.visibleSolution(request.solutionId(), allowance) : null;
        Visibility allowed = scope != null ? scope.visibility() : allowance.visibility();

        Map<Instant, List<OwaspWeeklyStateCount>> recorded = records
                .sumByWeekCategoryAndState(weeks.getFirst(), weeks.getLast(), allowed).stream()
                .collect(Collectors.groupingBy(OwaspWeeklyStateCount::weekStart));
        Map<Instant, Map<String, Flow>> flows = flows(weeks, allowed);

        List<OwaspWeek> answered = weeks.stream()
                .map(week -> week(week, recorded.getOrDefault(week, List.of()), flows.getOrDefault(week, Map.of())))
                .toList();
        return new OwaspWeeklyCoverage(
                day(weeks.getFirst()),
                day(weeks.getLast()),
                scope == null ? null : new OwaspWeeklyScope(
                        scope.kind().wireName(), scope.id(), scope.name(), scope.partial(), scope.targets().size()),
                answered);
    }

    /** The Mondays asked for, oldest first. */
    private List<Instant> window(Request request) {
        Instant current = CoverageWeek.startOf(clock.instant());
        Instant to = request.to() == null || request.to().isBlank() ? current : weekOf("to", request.to());
        if (to.isAfter(current)) {
            to = current;
        }
        Instant from = request.from() == null || request.from().isBlank()
                ? to.minus(7L * (DEFAULT_WEEKS - 1), ChronoUnit.DAYS)
                : weekOf("from", request.from());
        if (from.isAfter(to)) {
            throw new InvalidInputException("from comes after to.");
        }
        long count = ChronoUnit.DAYS.between(from, to) / 7 + 1;
        if (count > MAX_WEEKS) {
            throw new InvalidInputException("At most " + MAX_WEEKS + " weeks per request; this one spans " + count + ".");
        }
        List<Instant> weeks = new ArrayList<>();
        for (Instant week = from; !week.isAfter(to); week = week.plus(7, ChronoUnit.DAYS)) {
            weeks.add(week);
        }
        return weeks;
    }

    private static Instant weekOf(String name, String raw) {
        try {
            LocalDate day = LocalDate.parse(raw.trim());
            if (day.getYear() < 1970 || day.getYear() > 9998) {
                throw new InvalidInputException(name + " must be a date between 1970 and 9998.");
            }
            return CoverageWeek.startOf(day.atStartOfDay(ZoneOffset.UTC).toInstant());
        } catch (DateTimeParseException unreadable) {
            throw new InvalidInputException(name + " must be an ISO date, YYYY-MM-DD: \"" + raw.trim() + "\".");
        }
    }

    /** What the dates say of each week, per category, the placement read from {@code OwaspCoverage}. */
    private Map<Instant, Map<String, Flow>> flows(List<Instant> weeks, Visibility allowed) {
        Map<Instant, Map<String, Flow>> flows = new HashMap<>();
        // Every state, every triage: the dates decide, and settled triage is not knowable for the past.
        IssueFilters every = new IssueFilters(null, null, null, null, null, null, false, false, null, allowed);
        for (IssueAggregates.WeeklyFlow row : issues.weeklyFlows(every, weeks)) {
            Optional<String> category = FindingType.fromWireName(row.type())
                    .flatMap(type -> OwaspCoverage.placementOf(type, row.owaspCategory()));
            category.ifPresent(placed -> flows
                    .computeIfAbsent(row.weekStart(), week -> new HashMap<>())
                    .merge(placed, new Flow(row.openAtEnd(), row.opened(), row.resolved()), Flow::plus));
        }
        return flows;
    }

    private record Flow(long openAtEnd, long opened, long resolved) {

        static final Flow NONE = new Flow(0, 0, 0);

        Flow plus(Flow other) {
            return new Flow(openAtEnd + other.openAtEnd, opened + other.opened, resolved + other.resolved);
        }
    }

    private static OwaspWeek week(Instant week, List<OwaspWeeklyStateCount> recorded, Map<String, Flow> flows) {
        boolean reconstructed = recorded.isEmpty();
        Map<String, List<OwaspWeeklyStateCount>> byCategory =
                recorded.stream().collect(Collectors.groupingBy(OwaspWeeklyStateCount::category));

        List<OwaspWeekCategory> categories = OwaspCoverage.CATEGORIES.entrySet().stream()
                .map(category -> {
                    Flow flow = flows.getOrDefault(category.getKey(), Flow.NONE);
                    if (reconstructed) {
                        return new OwaspWeekCategory(category.getKey(), category.getValue(), null,
                                flow.openAtEnd(), null, flow.opened(), flow.resolved());
                    }
                    List<OwaspWeeklyStateCount> rows = byCategory.getOrDefault(category.getKey(), List.of());
                    return new OwaspWeekCategory(
                            category.getKey(),
                            category.getValue(),
                            OwaspCoverage.acrossTargets(rows.stream().map(row -> stateOf(row.state())).flatMap(Optional::stream).toList())
                                    .orElse(null),
                            rows.stream().mapToLong(OwaspWeeklyStateCount::open).sum(),
                            rows.stream().mapToLong(OwaspWeeklyStateCount::settled).sum(),
                            flow.opened(),
                            flow.resolved());
                })
                .toList();

        return new OwaspWeek(
                day(week),
                reconstructed,
                recorded.stream().map(OwaspWeeklyStateCount::capturedAt).max(Instant::compareTo).orElse(null),
                reconstructed ? null : (int) categories.stream()
                        .filter(line -> line.state() == OwaspCoverage.State.FINDINGS
                                || line.state() == OwaspCoverage.State.NO_FINDING)
                        .count(),
                categories.stream().mapToLong(OwaspWeekCategory::open).sum(),
                reconstructed ? null : categories.stream().mapToLong(line -> line.settled() == null ? 0 : line.settled()).sum(),
                categories.stream().mapToLong(OwaspWeekCategory::opened).sum(),
                categories.stream().mapToLong(OwaspWeekCategory::resolved).sum(),
                categories);
    }

    /**
     * A recorded state by its name. One this version does not know — written by a later one — is left
     * out of the combination rather than read as one it is not.
     */
    private static Optional<OwaspCoverage.State> stateOf(String name) {
        return java.util.Arrays.stream(OwaspCoverage.State.values()).filter(state -> state.name().equals(name)).findFirst();
    }

    private static LocalDate day(Instant week) {
        return LocalDate.ofInstant(week, ZoneOffset.UTC);
    }
}
