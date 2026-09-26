package com.asmolabs.vectispire.core.issues.persistence;

import com.asmolabs.vectispire.common.domain.issues.TriageStatus;
import com.asmolabs.vectispire.common.domain.targets.ScanTarget;
import com.asmolabs.vectispire.core.issues.persistence.queries.IssueFilters;
import jakarta.persistence.criteria.Predicate;
import java.time.Instant;
import java.util.ArrayList;
import java.util.List;
import java.util.Locale;
import org.springframework.data.jpa.domain.Specification;

/**
 * {@link IssueFilters} as the predicate every query over the issues applies — the one translation.
 *
 * <p>It was {@code IssueFilters.toSpecification()}, with the criteria. The criteria are what other
 * modules hand the backlog; the predicate names the entity, and stays beside the repository that
 * runs it (decision 0029) — in {@code persistence}, where a change to it is a change to the query
 * layer and runs the engine campaign on push. Authorization lives here too — the visibility is a criterion like the
 * others — so a query that took the filters cannot forget it.
 */
public final class IssueSpecifications {

    private IssueSpecifications() {}

    /** The criteria as the predicate every query over the issues applies. */
    public static Specification<IssueEntity> of(IssueFilters filters) {
        return (root, query, builder) -> predicate(filters, root, builder);
    }

    private static Predicate predicate(
            IssueFilters filters,
            jakarta.persistence.criteria.Root<IssueEntity> root,
            jakarta.persistence.criteria.CriteriaBuilder builder) {
        List<Predicate> predicates = new ArrayList<>();

        equalIfPresent(predicates, builder, root.get("state"), filters.state());
        equalIfPresent(predicates, builder, root.get("severity"), filters.severity());
        equalIfPresent(predicates, builder, root.get("type"), filters.type());
        equalIfPresent(predicates, builder, root.get("triageStatus"), filters.triageStatus());
        if (filters.repoId() != null) {
            predicates.add(builder.equal(root.get("repoId"), filters.repoId()));
        }
        if (filters.containerId() != null) {
            predicates.add(builder.equal(root.get("containerId"), filters.containerId()));
        }
        if (filters.onlyDirect()) {
            predicates.add(builder.isTrue(root.get("isDirectDependency")));
        }
        if (filters.onlyKev()) {
            predicates.add(builder.isTrue(root.get("isKev")));
        }
        if (filters.excludeSettled()) {
            // Named after what it does rather than after the SLA that wanted it: "not
            // dismissed and not fixed" is a filter a backlog screen will want on its own day.
            //
            // **`not in` the settled statuses, not `in` the unsettled ones.** The two agree on
            // every value this version writes and part on the rest: a status written by a later
            // version, by hand or by an import — `untriaged` was one, in a test fixture — was
            // dropped by `in`, so an issue nobody had decided on vanished from the overdue
            // figure and from the grade. `IssueViews` reads an unreadable triage as under
            // review for exactly that reason; the clause now takes the same side.
            predicates.add(builder.not(root.get("triageStatus").in(TriageStatus.settledWireNames())));
        }
        if (filters.overdueBefore() != null && !filters.overdueBefore().isEmpty()) {
            // **A union, not a single comparison.** Late means "critical older than fifteen
            // days *or* high older than thirty *or* …", so one predicate per severity, or-ed.
            // Expressed here rather than by four queries, so the figure a dashboard shows and
            // the rows this list returns come from the same clause.
            List<Predicate> late = new ArrayList<>();
            filters.overdueBefore().forEach((forSeverity, threshold) -> late.add(builder.and(
                    builder.equal(root.get("severity"), forSeverity.wireName()),
                    builder.lessThan(root.get("firstSeenAt"), threshold))));
            predicates.add(builder.or(late.toArray(Predicate[]::new)));
        }
        filters.visibility().asFilter().ifPresent(allowed -> predicates.add(visible(root, builder, allowed)));

        if (filters.search() != null && !filters.search().isBlank()) {
            String pattern = "%" + filters.search().trim().toLowerCase(Locale.ROOT) + "%";
            predicates.add(builder.or(
                    builder.like(builder.lower(root.get("identifier")), pattern),
                    builder.like(builder.lower(root.get("packageName")), pattern),
                    builder.like(builder.lower(root.get("filePath")), pattern)));
        }

        if (filters.touchingSince() != null) {
            // This is `PostureTrendAnalytics.touchesWindow` written as a query, and the two have to
            // say the same thing: an issue resolved before the window opened cannot appear in any of
            // its days' backlogs, cannot be newly discovered in it and cannot be newly resolved in it.
            // The last clause covers a row whose resolution precedes its first sighting — nonsense
            // that exists in real data, and which the unfiltered engine still counts as opened.
            Instant windowStart = filters.touchingSince();
            predicates.add(builder.or(
                    builder.isNull(root.get("resolvedAt")),
                    builder.greaterThanOrEqualTo(root.get("resolvedAt"), windowStart),
                    builder.greaterThanOrEqualTo(root.get("firstSeenAt"), windowStart)));
        }
        if (filters.cveOnly()) {
            predicates.add(builder.like(builder.upper(root.get("identifier")), "CVE-%"));
        }

        return builder.and(predicates.toArray(Predicate[]::new));
    }

    /**
     * The rows whose target the caller may see.
     *
     * <p>An empty allowance yields {@code builder.disjunction()} — a predicate that is false —
     * rather than no predicate at all. The alternative reads the same in code and means the
     * opposite: an unassigned account would receive the whole backlog.
     */
    private static Predicate visible(
            jakarta.persistence.criteria.Root<IssueEntity> root,
            jakarta.persistence.criteria.CriteriaBuilder builder,
            java.util.Set<ScanTarget> allowed) {

        List<Predicate> perTarget = new ArrayList<>();
        for (ScanTarget target : allowed) {
            switch (target) {
                case ScanTarget.Repository repository ->
                        perTarget.add(builder.equal(root.get("repoId"), repository.id()));
                case ScanTarget.Container container ->
                        perTarget.add(builder.equal(root.get("containerId"), container.id()));
            }
        }
        return perTarget.isEmpty() ? builder.disjunction() : builder.or(perTarget.toArray(Predicate[]::new));
    }

    private static void equalIfPresent(
            List<Predicate> predicates,
            jakarta.persistence.criteria.CriteriaBuilder builder,
            jakarta.persistence.criteria.Path<Object> path,
            String value) {
        if (value != null && !value.isBlank()) {
            predicates.add(builder.equal(path, value));
        }
    }
}
