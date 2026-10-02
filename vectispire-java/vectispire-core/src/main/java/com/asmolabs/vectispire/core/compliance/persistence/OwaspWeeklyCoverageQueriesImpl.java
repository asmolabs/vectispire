package com.asmolabs.vectispire.core.compliance.persistence;

import com.asmolabs.vectispire.common.domain.access.Visibility;
import com.asmolabs.vectispire.common.domain.targets.ScanTarget;
import com.asmolabs.vectispire.common.domain.teams.TeamRules;
import jakarta.persistence.EntityManager;
import jakarta.persistence.PersistenceContext;
import jakarta.persistence.criteria.CriteriaBuilder;
import jakarta.persistence.criteria.CriteriaQuery;
import jakarta.persistence.criteria.Path;
import jakarta.persistence.criteria.Predicate;
import jakarta.persistence.criteria.Root;
import java.time.Instant;
import java.util.ArrayList;
import java.util.Collection;
import java.util.List;
import java.util.Set;

/**
 * {@link OwaspWeeklyCoverageQueries}, in criteria form. Found by Spring Data because it is the fragment's
 * name plus {@code Impl}; renaming either half leaves the repository unimplementable at startup.
 */
public class OwaspWeeklyCoverageQueriesImpl implements OwaspWeeklyCoverageQueries {

    /** Identifiers per {@code in} list — the batch every id-list query here uses. */
    static final int IN_LIST_BATCH = 1_000;

    @PersistenceContext
    private EntityManager entityManager;

    @Override
    public List<OwaspWeeklyStateCount> sumByWeekCategoryAndState(Instant fromWeek, Instant toWeek, Visibility allowed) {
        CriteriaBuilder builder = entityManager.getCriteriaBuilder();
        CriteriaQuery<Object[]> query = builder.createQuery(Object[].class);
        Root<OwaspWeeklyCoverageEntity> row = query.from(OwaspWeeklyCoverageEntity.class);

        List<Predicate> where = new ArrayList<>();
        where.add(builder.greaterThanOrEqualTo(row.get("weekStart"), fromWeek));
        where.add(builder.lessThanOrEqualTo(row.get("weekStart"), toWeek));
        allowed.asFilter().ifPresent(targets -> where.add(visible(row, builder, targets)));

        query.select(builder.array(
                        row.get("weekStart"),
                        row.get("category"),
                        row.get("state"),
                        builder.count(row.get("id")),
                        builder.sum(row.<Long>get("openCount")),
                        builder.sum(row.<Long>get("settledCount")),
                        builder.greatest(row.<Instant>get("capturedAt"))))
                .where(where.toArray(Predicate[]::new))
                .groupBy(row.get("weekStart"), row.get("category"), row.get("state"));

        return entityManager.createQuery(query).getResultList().stream()
                .map(found -> new OwaspWeeklyStateCount(
                        (Instant) found[0],
                        (String) found[1],
                        (String) found[2],
                        count(found[3]),
                        count(found[4]),
                        count(found[5]),
                        (Instant) found[6]))
                .toList();
    }

    /**
     * The rows of the targets the reader may see, each kind by its own column value — a repository and
     * an image may carry the same number. <b>Empty is false</b>: a reader who sees nothing reads no row,
     * never the estate's.
     *
     * <p>The identifiers are written into the statement, in sorted lists of {@link #IN_LIST_BATCH}, as
     * {@code IssueSpecifications} writes the backlog's: a reader's allowance is sized by the estate, and
     * bound one parameter each it fails on PostgreSQL past 65,535. They are {@code Long}s from the
     * allowance, which nothing can turn into a statement.
     */
    private static Predicate visible(Root<OwaspWeeklyCoverageEntity> row, CriteriaBuilder builder, Set<ScanTarget> targets) {
        List<Long> repositories = new ArrayList<>();
        List<Long> containers = new ArrayList<>();
        for (ScanTarget target : targets) {
            switch (target) {
                case ScanTarget.Repository repository -> repositories.add(repository.id());
                case ScanTarget.Container container -> containers.add(container.id());
            }
        }
        List<Predicate> either = new ArrayList<>(2);
        if (!repositories.isEmpty()) {
            either.add(builder.and(
                    builder.equal(row.get("targetKind"), TeamRules.KIND_REPOSITORY),
                    literalIn(builder, row.get("targetId"), repositories)));
        }
        if (!containers.isEmpty()) {
            either.add(builder.and(
                    builder.equal(row.get("targetKind"), TeamRules.KIND_CONTAINER),
                    literalIn(builder, row.get("targetId"), containers)));
        }
        return either.isEmpty() ? builder.disjunction() : builder.or(either.toArray(Predicate[]::new));
    }

    private static Predicate literalIn(CriteriaBuilder builder, Path<Long> column, Collection<Long> ids) {
        List<Long> sorted = ids.stream().distinct().sorted().toList();
        List<Predicate> lists = new ArrayList<>();
        for (int from = 0; from < sorted.size(); from += IN_LIST_BATCH) {
            CriteriaBuilder.In<Long> list = builder.in(column);
            sorted.subList(from, Math.min(from + IN_LIST_BATCH, sorted.size())).forEach(id -> list.value(builder.literal(id)));
            lists.add(list);
        }
        return lists.size() == 1 ? lists.getFirst() : builder.or(lists.toArray(Predicate[]::new));
    }

    /** A driver may answer an aggregate with any {@link Number} it likes; only the value matters. */
    private static long count(Object value) {
        return value == null ? 0L : ((Number) value).longValue();
    }
}
