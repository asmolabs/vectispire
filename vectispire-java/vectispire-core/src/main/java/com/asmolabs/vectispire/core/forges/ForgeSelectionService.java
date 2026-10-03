package com.asmolabs.vectispire.core.forges;

import com.asmolabs.vectispire.common.domain.errors.InvalidInputException;
import com.asmolabs.vectispire.common.domain.forges.SelectionFilter;
import com.asmolabs.vectispire.common.domain.text.BoundedText;
import com.asmolabs.vectispire.core.forges.ForgeImports.ForgeCandidate;
import com.asmolabs.vectispire.core.forges.ForgeImports.ForgeCandidatePage;
import com.asmolabs.vectispire.core.forges.ForgeImports.ForgeFirstScans;
import com.asmolabs.vectispire.core.forges.ForgeImports.ForgeImportPreview;
import com.asmolabs.vectispire.core.forges.ForgeImports.ForgeImportRequest;
import com.asmolabs.vectispire.core.forges.ForgeImports.ForgePlannedTarget;
import com.asmolabs.vectispire.core.forges.ForgeImports.ForgeProjectPlan;
import com.asmolabs.vectispire.core.forges.ForgeImports.ForgeSelection;
import com.asmolabs.vectispire.core.forges.ForgeImports.ForgeSelectionChange;
import com.asmolabs.vectispire.core.forges.ForgeImports.ForgeSelectionFilters;
import com.asmolabs.vectispire.core.forges.ForgeImports.ForgeSolutionPlan;
import com.asmolabs.vectispire.core.forges.internal.ImportPlanner;
import com.asmolabs.vectispire.core.forges.internal.ImportPlanner.Plan;
import com.asmolabs.vectispire.core.forges.internal.ImportPlanner.Row;
import com.asmolabs.vectispire.core.forges.internal.ImportPlanner.Source;
import java.time.Clock;
import java.time.Instant;
import java.util.ArrayList;
import java.util.EnumMap;
import java.util.LinkedHashMap;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.Set;
import java.util.UUID;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

/**
 * Choosing which of a discovery's repositories to import, and seeing what the import would do (decision 0037 §4,
 * lot D5). Nothing here writes.
 *
 * <p><b>The selection is a set of forge ids</b>, held by the screen and sent with each gesture: what is imported is
 * what was ticked, never what a filter matches at import time. The server helps where the screen cannot — the
 * table is filtered and paged here, over up to twenty thousand repositories, and "all matching", "none" and
 * "invert" are applied here to what the filters match, the screen holding only a page.
 *
 * <p><b>Read from the connection's latest ended discovery</b>, completed or partial ({@link ImportPlanner#source}):
 * a partial run's listing is whole as far as it goes, and nothing is inferred from what it did not reach.
 */
@Service
public class ForgeSelectionService {

    /** The largest page of the table a request reads. */
    static final int MAX_LIMIT = 500;

    /** A selection's operations, as a screen names them. */
    enum Operation {
        PROPOSED,
        ALL,
        NONE,
        INVERT,
        ADD,
        REMOVE;

        static Operation parse(String raw) {
            String wanted = raw == null ? "" : raw.trim().toLowerCase(Locale.ROOT);
            for (Operation operation : values()) {
                if (operation.name().toLowerCase(Locale.ROOT).equals(wanted)) {
                    return operation;
                }
            }
            throw new InvalidInputException("\"" + BoundedText.clip(raw == null ? "" : raw.trim(), 40)
                    + "\" is not a selection operation: proposed, all, none, invert, add or remove.");
        }
    }

    private final ImportPlanner planner;
    private final Clock clock;

    public ForgeSelectionService(ImportPlanner planner, Clock clock) {
        this.planner = planner;
        this.clock = clock;
    }

    /**
     * A page of the discovery's repositories the filters match, by full path, each with whether it may be ticked,
     * whether it is offered ticked, and where it would be filed.
     */
    @Transactional(readOnly = true)
    public ForgeCandidatePage candidates(
            UUID connectionId, long discoveryId, ForgeSelectionFilters filters, Integer limit, Integer offset) {
        Source source = planner.source(connectionId, discoveryId);
        SelectionFilter filter = filterOf(filters);
        int size = limit == null ? 100 : limit;
        int from = offset == null ? 0 : offset;
        if (size < 1 || size > MAX_LIMIT) {
            throw new InvalidInputException("The limit is between 1 and " + MAX_LIMIT + ".");
        }
        if (from < 0 || from % size != 0) {
            throw new InvalidInputException("The offset is zero or a multiple of the limit.");
        }
        Instant now = clock.instant();
        List<Row> rows = planner.rows(source);
        Map<SelectionFilter.Judged, Long> unjudged = new EnumMap<>(SelectionFilter.Judged.class);
        List<ForgeCandidate> matching = new ArrayList<>();
        for (Row row : rows) {
            SelectionFilter.Verdict verdict = filter.judge(candidate(row), now);
            verdict.unjudged().forEach(judged -> unjudged.merge(judged, 1L, Long::sum));
            if (verdict.matches()) {
                matching.add(view(row, offered(row, now)));
            }
        }
        Map<String, Long> counted = new LinkedHashMap<>();
        unjudged.forEach((judged, count) -> counted.put(judged.wireName(), count));
        List<ForgeCandidate> page = matching.subList(Math.min(from, matching.size()), Math.min(from + size, matching.size()));
        return new ForgeCandidatePage(source.discoveryId(), List.copyOf(page), matching.size(), size, from, rows.size(),
                counted);
    }

    /**
     * The selection after one operation, over what the filters match. Only a selectable repository stays ticked:
     * one already a target, empty or no longer listed is dropped and named, so the screen says why.
     */
    @Transactional(readOnly = true)
    public ForgeSelection select(UUID connectionId, long discoveryId, ForgeSelectionChange change) {
        if (change == null) {
            throw new InvalidInputException("Say how the selection changes: an operation, and the forge ids ticked so far.");
        }
        Source source = planner.source(connectionId, discoveryId);
        Operation operation = Operation.parse(change.operation());
        SelectionFilter filter = filterOf(change.filters());
        Set<String> selected = ImportPlanner.forgeIds(change.selected(), ImportPlanner.MAX_SELECTION, "A selection");
        Set<String> named = ImportPlanner.forgeIds(change.forgeIds(), ImportPlanner.MAX_SELECTION, "A selection");
        if ((operation == Operation.ADD || operation == Operation.REMOVE) == named.isEmpty()) {
            throw new InvalidInputException(operation == Operation.ADD || operation == Operation.REMOVE
                    ? "Name the forge ids to " + operation.name().toLowerCase(Locale.ROOT) + "."
                    : "forgeIds is for add and remove; " + operation.name().toLowerCase(Locale.ROOT)
                            + " applies to what the filters match.");
        }

        Instant now = clock.instant();
        List<Row> rows = planner.rows(source);
        Set<String> result = new LinkedHashSet<>(selected);
        if (operation == Operation.PROPOSED) {
            result.clear();
        }
        // Every operation works on ids; what may not be ticked leaves the selection once, below, whatever put it there.
        for (Row row : rows) {
            String id = row.repository().getForgeId();
            boolean matches = filter.judge(candidate(row), now).matches();
            switch (operation) {
                case PROPOSED -> {
                    if (matches && !row.repository().getPersonal()) {
                        result.add(id);
                    }
                }
                case ALL -> {
                    if (matches) {
                        result.add(id);
                    }
                }
                case NONE -> {
                    if (matches) {
                        result.remove(id);
                    }
                }
                case INVERT -> {
                    if (matches && !result.remove(id)) {
                        result.add(id);
                    }
                }
                case ADD -> {
                    if (named.contains(id)) {
                        result.add(id);
                    }
                }
                case REMOVE -> {
                    if (named.contains(id)) {
                        result.remove(id);
                    }
                }
            }
        }

        // Kept in the table's order, and only what may be ticked: a forge id the discovery does not list, or one
        // that is already a target, leaves the selection here rather than at the import.
        List<String> ordered = new ArrayList<>();
        Set<String> selectableIds = new LinkedHashSet<>();
        for (Row row : rows) {
            if (row.notSelectable().isEmpty()) {
                selectableIds.add(row.repository().getForgeId());
                if (result.contains(row.repository().getForgeId())) {
                    ordered.add(row.repository().getForgeId());
                }
            }
        }
        List<String> dropped = new ArrayList<>();
        Set<String> asked = new LinkedHashSet<>(selected);
        if (operation == Operation.ADD) {
            asked.addAll(named);
        }
        for (String id : asked) {
            if (!selectableIds.contains(id) && !(operation == Operation.REMOVE && named.contains(id))) {
                dropped.add(id);
            }
        }
        return new ForgeSelection(source.discoveryId(), List.copyOf(ordered), ordered.size(), List.copyOf(dropped));
    }

    /**
     * What the import of this request would do — the targets, solutions and projects it would create or reuse, what
     * it would skip and why, what it would refuse, the credential per host, the schedule, the first scans and who
     * would see the new targets. Nothing is written; the import plans again in its own transaction.
     */
    @Transactional(readOnly = true)
    public ForgeImportPreview preview(UUID connectionId, ForgeImportRequest request) {
        Source source = planner.source(connectionId, request == null ? null : request.discoveryId());
        Plan plan = planner.plan(source, request);
        List<ForgePlannedTarget> targets = plan.targets().stream()
                .map(target -> new ForgePlannedTarget(target.repository().getForgeId(), target.repository().getFullPath(),
                        target.changes().url(), target.changes().branch(), target.credential(),
                        target.placement().solution(), target.placement().project(), plan.visibleTo(target.placement()),
                        target.firstScanNotBefore(), target.warning()))
                .toList();
        return new ForgeImportPreview(source.connectionId(), source.discoveryId(), targets, plan.skipped(), plan.refused(),
                plan.solutions().stream()
                        .map(solution -> new ForgeSolutionPlan(solution.name(),
                                solution.existing().map(existing -> existing.id()).orElse(null)))
                        .toList(),
                projects(plan), plan.credentials(), plan.defaultInterval().toDays(),
                plan.visibilityMode().wireName(), firstScans(plan));
    }

    static List<ForgeProjectPlan> projects(Plan plan) {
        return plan.projects().stream()
                .map(project -> new ForgeProjectPlan(project.solution(), project.name(),
                        project.existing().map(existing -> existing.id()).orElse(null), project.reach().accounts(),
                        project.reach().teams(), project.targets()))
                .toList();
    }

    static ForgeFirstScans firstScans(Plan plan) {
        return plan.spacing().map(gap -> new ForgeFirstScans(plan.targets().size(), (int) gap.toSeconds(),
                        plan.targets().isEmpty() ? null : plan.targets().getFirst().firstScanNotBefore(),
                        plan.targets().isEmpty() ? null : plan.targets().getLast().firstScanNotBefore()))
                .orElse(null);
    }

    /** Offered ticked: selectable, kept by the default filters, and not in a personal namespace (answer 7). */
    private static boolean offered(Row row, Instant now) {
        return row.notSelectable().isEmpty() && !row.repository().getPersonal()
                && SelectionFilter.DEFAULT.judge(candidate(row), now).matches();
    }

    private static SelectionFilter.Candidate candidate(Row row) {
        var repository = row.repository();
        return new SelectionFilter.Candidate(repository.getArchived(), repository.getFork(), repository.getLastActivityAt(),
                repository.getLanguage(), repository.getVisibility(), repository.getNamespacePath(),
                repository.getFullPath(), repository.getPersonal(), row.notSelectable().isPresent()
                        && (row.importedAs() != null || !row.presentAs().isEmpty()));
    }

    private static ForgeCandidate view(Row row, boolean offered) {
        return new ForgeCandidate(ForgeDiscoveryService.view(row.repository()), row.presentAs(), row.importedAs(),
                row.notSelectable().isEmpty(), row.notSelectable().orElse(null), offered,
                row.proposed().solution(), row.proposed().project());
    }

    private static SelectionFilter filterOf(ForgeSelectionFilters filters) {
        ForgeSelectionFilters raw = filters == null ? ForgeSelectionFilters.DEFAULT : filters;
        return SelectionFilter.parse(raw.archived(), raw.forks(), raw.inactiveDays(), raw.language(), raw.visibility(),
                raw.namespace(), raw.path(), raw.personal(), raw.present());
    }
}
