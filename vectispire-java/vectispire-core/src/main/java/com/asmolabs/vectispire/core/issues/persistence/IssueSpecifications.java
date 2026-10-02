package com.asmolabs.vectispire.core.issues.persistence;

import com.asmolabs.vectispire.common.domain.issues.FindingType;
import com.asmolabs.vectispire.common.domain.issues.TriageOrigin;
import com.asmolabs.vectispire.common.domain.issues.TriageStatus;
import com.asmolabs.vectispire.common.domain.owasp.OwaspCoverage;
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
        return (root, query, builder) -> predicate(filters, root, query, builder);
    }

    private static Predicate predicate(
            IssueFilters filters,
            jakarta.persistence.criteria.Root<IssueEntity> root,
            jakarta.persistence.criteria.CommonAbstractCriteria query,
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
        if (filters.targetsWithin() != null) {
            predicates.add(within(root, builder, filters.targetsWithin()));
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
        if (filters.owaspPlacement() != null) {
            predicates.add(switch (filters.owaspPlacement()) {
                case IssueFilters.OwaspPlacement.In in -> placedIn(root, builder, in.category());
                case IssueFilters.OwaspPlacement.Anywhere anywhere -> placedAnywhere(root, builder);
            });
        }
        if (filters.lifetime() != null) {
            lived(predicates, root, query, builder, filters.lifetime());
        }

        return builder.and(predicates.toArray(Predicate[]::new));
    }

    /**
     * The issues {@code OwaspCoverage.placementOf} puts in this category: of a type placed there, or of
     * the type that declares its category and declaring this one. Both halves are read from {@code
     * OwaspCoverage}, which the grid and the weekly flows place with, so the list a figure opens holds
     * what the figure counted.
     */
    private static Predicate placedIn(
            jakarta.persistence.criteria.Root<IssueEntity> root,
            jakarta.persistence.criteria.CriteriaBuilder builder,
            String category) {
        List<Predicate> either = new ArrayList<>(2);
        List<String> types = OwaspCoverage.typesPlacedIn(category).stream().map(FindingType::wireName).sorted().toList();
        if (!types.isEmpty()) {
            either.add(root.get("type").in(types));
        }
        either.add(builder.and(
                builder.equal(root.get("type"), OwaspCoverage.DECLARES_ITS_CATEGORY.wireName()),
                builder.equal(root.get("owaspCategory"), category)));
        return builder.or(either.toArray(Predicate[]::new));
    }

    /**
     * The issues {@code OwaspCoverage.placementOf} puts in some category — a week's total, and the list
     * it opens. The same two halves as {@link #placedIn}, over every category at once: a type placed
     * somewhere, or the type that declares its category declaring one of the ten. A licence or a quality
     * finding is in none, and listing it would make the list longer than the bar that opened it.
     */
    private static Predicate placedAnywhere(
            jakarta.persistence.criteria.Root<IssueEntity> root,
            jakarta.persistence.criteria.CriteriaBuilder builder) {
        List<Predicate> either = new ArrayList<>(2);
        List<String> types = OwaspCoverage.typesPlacedAnywhere().stream().map(FindingType::wireName).sorted().toList();
        if (!types.isEmpty()) {
            either.add(root.get("type").in(types));
        }
        either.add(builder.and(
                builder.equal(root.get("type"), OwaspCoverage.DECLARES_ITS_CATEGORY.wireName()),
                root.get("owaspCategory").in(OwaspCoverage.CATEGORIES.keySet().stream().sorted().toList())));
        return builder.or(either.toArray(Predicate[]::new));
    }

    /**
     * The dates' clauses, each half open, through {@link #openAt}, {@link #resolvedWithin} and {@link
     * #reopenedWithin} — the rules
     * the weekly reconstruction counts with, so that a figure and the list it opens agree.
     */
    private static void lived(
            List<Predicate> predicates,
            jakarta.persistence.criteria.Root<IssueEntity> root,
            jakarta.persistence.criteria.CommonAbstractCriteria query,
            jakarta.persistence.criteria.CriteriaBuilder builder,
            IssueFilters.Lifetime lifetime) {
        jakarta.persistence.criteria.Path<Instant> firstSeen = root.get("firstSeenAt");
        if (lifetime.openAt() != null) {
            predicates.add(openAt(root, query, builder, new Bound.Value(lifetime.openAt())));
        }
        if (lifetime.firstSeenFrom() != null) {
            predicates.add(builder.greaterThanOrEqualTo(firstSeen, lifetime.firstSeenFrom()));
        }
        if (lifetime.firstSeenBefore() != null) {
            predicates.add(builder.lessThan(firstSeen, lifetime.firstSeenBefore()));
        }
        if (lifetime.resolvedFrom() != null || lifetime.resolvedBefore() != null) {
            predicates.add(resolvedWithin(root, query, builder,
                    lifetime.resolvedFrom() == null ? null : new Bound.Value(lifetime.resolvedFrom()),
                    lifetime.resolvedBefore() == null ? null : new Bound.Value(lifetime.resolvedBefore())));
        }
        if (lifetime.reopenedFrom() != null || lifetime.reopenedBefore() != null) {
            predicates.add(reopenedWithin(root, query, builder,
                    lifetime.reopenedFrom() == null ? null : new Bound.Value(lifetime.reopenedFrom()),
                    lifetime.reopenedBefore() == null ? null : new Bound.Value(lifetime.reopenedBefore())));
        }
    }

    /**
     * An instant a clause compares a column with: a value the criteria bind themselves (the backlog's
     * filters), or a parameter the statement binds (the weekly flows, thirteen weeks in one select). Never
     * a literal: a timestamp written into the statement is rendered by each dialect its own way, and that
     * is where the engines differ.
     */
    sealed interface Bound {

        /** The column is before the bound: {@code column < bound}. */
        Predicate isBefore(jakarta.persistence.criteria.CriteriaBuilder builder, jakarta.persistence.criteria.Expression<Instant> column);

        /** The column is at or after the bound: {@code column >= bound}. */
        Predicate isNotBefore(jakarta.persistence.criteria.CriteriaBuilder builder, jakarta.persistence.criteria.Expression<Instant> column);

        record Value(Instant instant) implements Bound {
            @Override
            public Predicate isBefore(jakarta.persistence.criteria.CriteriaBuilder builder, jakarta.persistence.criteria.Expression<Instant> column) {
                return builder.lessThan(column, instant);
            }

            @Override
            public Predicate isNotBefore(jakarta.persistence.criteria.CriteriaBuilder builder, jakarta.persistence.criteria.Expression<Instant> column) {
                return builder.greaterThanOrEqualTo(column, instant);
            }
        }

        record Parameter(jakarta.persistence.criteria.Expression<Instant> parameter) implements Bound {
            @Override
            public Predicate isBefore(jakarta.persistence.criteria.CriteriaBuilder builder, jakarta.persistence.criteria.Expression<Instant> column) {
                return builder.lessThan(column, parameter);
            }

            @Override
            public Predicate isNotBefore(jakarta.persistence.criteria.CriteriaBuilder builder, jakarta.persistence.criteria.Expression<Instant> column) {
                return builder.greaterThanOrEqualTo(column, parameter);
            }
        }
    }

    /**
     * Open at an instant — the weekly reconstruction's rule, and the backlog's {@code open_at}: seen
     * before it, not resolved before it, and <b>not inside an earlier resolution</b> either.
     *
     * <p>An issue resolved at that very instant was still open until then; the intervals are half open
     * the same way, so an issue counts as not open at {@code at} when a resolution began before it and
     * the reopening that ended it came at or after it — {@code [previous resolved_at, reopened at)}.
     *
     * <p><b>The earlier resolutions come from the triage history</b>: a reopening is an entry of origin
     * {@code reopen} carrying the resolution it ended (V68). The issue itself keeps only its latest
     * resolution, so before V68 a reopened issue read as open from its first sighting on — and still does
     * for a reopening older than V68, which left no entry. One correlated {@code not exists} per instant,
     * on the history's index by issue: the rule is the same clause in the list and in the grouped count,
     * never a correction applied to one of them.
     */
    static Predicate openAt(
            jakarta.persistence.criteria.Root<IssueEntity> issue,
            jakarta.persistence.criteria.CommonAbstractCriteria query,
            jakarta.persistence.criteria.CriteriaBuilder builder,
            Bound at) {
        jakarta.persistence.criteria.Path<Instant> resolved = issue.get("resolvedAt");
        return builder.and(
                at.isBefore(builder, issue.get("firstSeenAt")),
                builder.or(builder.isNull(resolved), at.isNotBefore(builder, resolved)),
                builder.not(builder.exists(reopenings(issue, query, builder, (event, ended) -> builder.and(
                        at.isBefore(builder, ended), at.isNotBefore(builder, event.get("occurredAt")))))));
    }

    /**
     * Resolved within {@code [from, before)} — its latest resolution, or one a reopening ended. Either
     * bound may be null, and asks nothing. An issue is counted once, however many of its resolutions fall
     * in the interval: the figure is the issues resolved in a week, as the opened one is the issues seen.
     */
    static Predicate resolvedWithin(
            jakarta.persistence.criteria.Root<IssueEntity> issue,
            jakarta.persistence.criteria.CommonAbstractCriteria query,
            jakarta.persistence.criteria.CriteriaBuilder builder,
            Bound from,
            Bound before) {
        return builder.or(
                within(builder, issue.get("resolvedAt"), from, before),
                builder.exists(reopenings(issue, query, builder, (event, ended) -> within(builder, ended, from, before))));
    }

    /**
     * Reopened within {@code [from, before)}: a reopening the triage history recorded at an instant of the
     * interval (origin {@code reopen}, V68). Either bound may be null, and asks nothing. An issue is counted
     * once, however many times it came back in the interval — the figure is the issues reopened in a week,
     * as the opened one is the issues seen. A reopening older than V68 wrote no entry and is not here; the
     * weekly view says so by answering no figure for a week before the entries began.
     */
    static Predicate reopenedWithin(
            jakarta.persistence.criteria.Root<IssueEntity> issue,
            jakarta.persistence.criteria.CommonAbstractCriteria query,
            jakarta.persistence.criteria.CriteriaBuilder builder,
            Bound from,
            Bound before) {
        jakarta.persistence.criteria.Subquery<Long> reopening = query.subquery(Long.class);
        jakarta.persistence.criteria.Root<TriageEventEntity> event = reopening.from(TriageEventEntity.class);
        return builder.exists(reopening.select(event.get("id")).where(
                builder.equal(event.get("issueId"), issue.get("id")),
                builder.equal(event.get("origin"), TriageOrigin.REOPENING.wireName()),
                within(builder, event.get("occurredAt"), from, before)));
    }

    private static Predicate within(
            jakarta.persistence.criteria.CriteriaBuilder builder,
            jakarta.persistence.criteria.Expression<Instant> column,
            Bound from,
            Bound before) {
        List<Predicate> bounds = new ArrayList<>(3);
        // Null is no resolution: `>=` and `<` say so on their own, and a bound-less call says it here.
        bounds.add(builder.isNotNull(column));
        if (from != null) {
            bounds.add(from.isNotBefore(builder, column));
        }
        if (before != null) {
            bounds.add(before.isBefore(builder, column));
        }
        return builder.and(bounds.toArray(Predicate[]::new));
    }

    /** The issue's reopenings that satisfy {@code condition}, given the entry and the resolution it ended. */
    private static jakarta.persistence.criteria.Subquery<Long> reopenings(
            jakarta.persistence.criteria.Root<IssueEntity> issue,
            jakarta.persistence.criteria.CommonAbstractCriteria query,
            jakarta.persistence.criteria.CriteriaBuilder builder,
            java.util.function.BiFunction<jakarta.persistence.criteria.Root<TriageEventEntity>,
                    jakarta.persistence.criteria.Path<Instant>, Predicate> condition) {
        jakarta.persistence.criteria.Subquery<Long> reopening = query.subquery(Long.class);
        jakarta.persistence.criteria.Root<TriageEventEntity> event = reopening.from(TriageEventEntity.class);
        jakarta.persistence.criteria.Path<Instant> ended = event.get("previousResolvedAt");
        return reopening.select(event.get("id")).where(
                builder.equal(event.get("issueId"), issue.get("id")),
                builder.equal(event.get("origin"), TriageOrigin.REOPENING.wireName()),
                builder.isNotNull(ended),
                condition.apply(event, ended));
    }

    /**
     * The rows whose target the caller may see.
     *
     * <p>An empty allowance yields {@code builder.disjunction()} — a predicate that is false —
     * rather than no predicate at all. The alternative reads the same in code and means the
     * opposite: an unassigned account would receive the whole backlog.
     *
     * <p><b>Written as literals, like {@link #within}, and for the same reason.</b> The allowance is
     * the account's grants, its teams' and its projects' repositories, resolved in Java and intersected
     * with the credential's restriction, so its size is the estate's; it narrows the one statement that
     * pages, orders and counts, which cannot be split. It was one bound {@code equal} per target, and a
     * reader granted more than 65,535 targets had every backlog read fail on PostgreSQL — the issues
     * list, and every figure built on this predicate — which {@code WideAllowanceIntegrationTest}
     * measured before this was written. A repository and an image are still told apart by their own
     * column: one identifier may name both, and a grant on one is no grant on the other.
     */
    private static Predicate visible(
            jakarta.persistence.criteria.Root<IssueEntity> root,
            jakarta.persistence.criteria.CriteriaBuilder builder,
            java.util.Set<ScanTarget> allowed) {

        List<Long> repositories = new ArrayList<>();
        List<Long> containers = new ArrayList<>();
        for (ScanTarget target : allowed) {
            switch (target) {
                case ScanTarget.Repository repository -> repositories.add(repository.id());
                case ScanTarget.Container container -> containers.add(container.id());
            }
        }
        List<Predicate> either = new ArrayList<>(2);
        if (!repositories.isEmpty()) {
            either.add(literalIn(builder, root.<Long>get("repoId"), repositories));
        }
        if (!containers.isEmpty()) {
            either.add(literalIn(builder, root.<Long>get("containerId"), containers));
        }
        return either.isEmpty() ? builder.disjunction() : builder.or(either.toArray(Predicate[]::new));
    }

    /** How many identifiers one {@code in} list carries: the batch every id-list lookup here uses. */
    static final int IN_LIST_BATCH = 1_000;

    /**
     * The rows of these targets — a project's or a solution's repositories and images.
     *
     * <p><b>Empty is false, not absent</b>, like {@link #visible}: a project that holds no target has
     * no issue, and the whole backlog would be the opposite answer.
     *
     * <p><b>One statement, and the identifiers written into it rather than bound.</b> A lookup is split
     * into statements of a thousand identifiers each ({@code TargetCatalog.carryingCredentials}); a page
     * and its count cannot be, since the order and the total span every target at once. Bound, one
     * parameter per repository, the statement failed on PostgreSQL past 65,535 — the driver's ceiling,
     * measured by {@code ProjectBacklogIntegrationTest} before this was written. So each identifier is a
     * {@code literal}, which Hibernate renders into the SQL: they are {@code Long}s read from {@code
     * targets}' own tables, so there is nothing to inject, and the cost accepted is a statement text that
     * differs per project. They are still grouped in lists of {@link #IN_LIST_BATCH}, the batch every
     * id-list query here uses, sorted so the same project renders the same SQL. It is {@link #visible}'s
     * predicate, and for the same reason a repository and an image are each matched by their own column.
     */
    private static Predicate within(
            jakarta.persistence.criteria.Root<IssueEntity> root,
            jakarta.persistence.criteria.CriteriaBuilder builder,
            java.util.Set<ScanTarget> targets) {

        return visible(root, builder, targets);
    }

    /**
     * {@code column in (…)} over identifiers written into the statement, in sorted lists of {@link
     * #IN_LIST_BATCH} or-ed together; {@code ids} must not be empty. {@code Long} and nothing else: a
     * literal is rendered into the SQL, and a number is the one value that cannot carry a statement.
     */
    private static Predicate literalIn(
            jakarta.persistence.criteria.CriteriaBuilder builder,
            jakarta.persistence.criteria.Path<Long> column,
            java.util.Collection<Long> ids) {
        List<Long> sorted = ids.stream().distinct().sorted().toList();
        List<Predicate> lists = new ArrayList<>();
        for (int from = 0; from < sorted.size(); from += IN_LIST_BATCH) {
            jakarta.persistence.criteria.CriteriaBuilder.In<Long> list = builder.in(column);
            sorted.subList(from, Math.min(from + IN_LIST_BATCH, sorted.size())).forEach(id -> list.value(builder.literal(id)));
            lists.add(list);
        }
        return lists.size() == 1 ? lists.getFirst() : builder.or(lists.toArray(Predicate[]::new));
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
