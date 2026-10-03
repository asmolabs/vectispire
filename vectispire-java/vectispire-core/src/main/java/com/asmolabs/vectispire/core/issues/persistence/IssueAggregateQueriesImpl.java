package com.asmolabs.vectispire.core.issues.persistence;

import com.asmolabs.vectispire.common.domain.issues.FindingType;
import com.asmolabs.vectispire.common.domain.issues.Severity;
import com.asmolabs.vectispire.common.domain.owasp.OwaspCoverage;
import com.asmolabs.vectispire.core.issues.persistence.queries.IssueAggregates;
import com.asmolabs.vectispire.core.issues.persistence.queries.IssueAggregates.OpenBacklog;
import com.asmolabs.vectispire.core.issues.persistence.queries.IssueAggregates.OwaspCategoryCount;
import com.asmolabs.vectispire.core.issues.persistence.queries.IssueAggregates.PackageDetail;
import com.asmolabs.vectispire.core.issues.persistence.queries.IssueAggregates.PackageWeight;
import com.asmolabs.vectispire.core.issues.persistence.queries.IssueAggregates.ResolvedDuration;
import com.asmolabs.vectispire.core.issues.persistence.queries.IssueAggregates.SeverityTypeCount;
import com.asmolabs.vectispire.core.issues.persistence.queries.IssueAggregates.TargetGradingCount;
import com.asmolabs.vectispire.core.issues.persistence.queries.IssueAggregates.TargetResolutions;
import com.asmolabs.vectispire.core.issues.persistence.queries.IssueAggregates.TargetSeverityCount;
import com.asmolabs.vectispire.core.issues.persistence.queries.IssueAggregates.TypePackaging;
import com.asmolabs.vectispire.core.issues.persistence.queries.IssueAggregates.WeeklyFlow;
import jakarta.persistence.EntityManager;
import jakarta.persistence.PersistenceContext;
import jakarta.persistence.criteria.CriteriaBuilder;
import jakarta.persistence.criteria.CriteriaQuery;
import jakarta.persistence.criteria.Expression;
import jakarta.persistence.criteria.Predicate;
import jakarta.persistence.criteria.Root;
import java.time.Instant;
import java.util.Collection;
import java.util.List;
import java.util.Map;
import org.springframework.data.jpa.domain.Specification;

/**
 * {@link IssueAggregateQueries}, in criteria form.
 *
 * <p>The name is load-bearing: Spring Data finds this class because it is the fragment interface
 * plus {@code Impl}. Renaming either half leaves {@link IssueRepository} unimplementable at startup.
 */
public class IssueAggregateQueriesImpl implements IssueAggregateQueries {

    /**
     * A CVE identifier is nullable, and {@code count(distinct …)} does not count nulls.
     *
     * <p>Left as a literal rather than dropped, because the Java it replaced counted a
     * null-identifier issue as one unnamed CVE. Ignoring them instead would give a package whose
     * findings are all unnamed a count of zero, and a count of zero removes it from the list —
     * a silent change of behaviour hiding inside a performance fix.
     */
    private static final String UNNAMED = "UNKNOWN-CVE";

    @PersistenceContext
    private EntityManager entityManager;

    @Override
    public List<Object[]> countGrouped(Specification<IssueEntity> filter, Axis axis, int limit) {
        CriteriaBuilder builder = entityManager.getCriteriaBuilder();
        CriteriaQuery<Object[]> query = builder.createQuery(Object[].class);
        Root<IssueEntity> issue = query.from(IssueEntity.class);

        Expression<Long> total = builder.count(issue.get("id"));
        query.select(builder.array(issue.get(axis.attribute), total))
                .groupBy(issue.get(axis.attribute))
                .orderBy(builder.desc(total));
        // The repository axis leaves out the images' issues, as the query it replaced did: a null
        // repository is not a repository to rank.
        if (axis == Axis.REPOSITORY) {
            restrict(query, filter, issue, builder, builder.isNotNull(issue.get(axis.attribute)));
        } else {
            restrict(query, filter, issue, builder);
        }

        return entityManager.createQuery(query).setMaxResults(limit).getResultList();
    }

    @Override
    public long countDistinct(Specification<IssueEntity> filter, Axis axis) {
        CriteriaBuilder builder = entityManager.getCriteriaBuilder();
        CriteriaQuery<Long> query = builder.createQuery(Long.class);
        Root<IssueEntity> issue = query.from(IssueEntity.class);

        query.select(builder.countDistinct(issue.get(axis.attribute)));
        restrict(query, filter, issue, builder);

        return entityManager.createQuery(query).getSingleResult();
    }

    @Override
    public List<SeverityTypeCount> countGroupedBySeverityAndType(Specification<IssueEntity> filter) {
        CriteriaBuilder builder = entityManager.getCriteriaBuilder();
        CriteriaQuery<Object[]> query = builder.createQuery(Object[].class);
        Root<IssueEntity> issue = query.from(IssueEntity.class);

        query.select(builder.array(issue.get("severity"), issue.get("type"), builder.count(issue.get("id"))))
                .groupBy(issue.get("severity"), issue.get("type"));
        restrict(query, filter, issue, builder);

        return entityManager.createQuery(query).getResultList().stream()
                .map(row -> new SeverityTypeCount((String) row[0], (String) row[1], count(row[2])))
                .toList();
    }

    @Override
    public List<IssueAggregates.StateCount> countGroupedByTypeSeverityStateAndTriage(Specification<IssueEntity> filter) {
        CriteriaBuilder builder = entityManager.getCriteriaBuilder();
        CriteriaQuery<Object[]> query = builder.createQuery(Object[].class);
        Root<IssueEntity> issue = query.from(IssueEntity.class);

        query.select(builder.array(issue.get("type"), issue.get("severity"), issue.get("state"),
                        issue.get("triageStatus"), builder.count(issue.get("id"))))
                .groupBy(issue.get("type"), issue.get("severity"), issue.get("state"), issue.get("triageStatus"));
        restrict(query, filter, issue, builder);

        return entityManager.createQuery(query).getResultList().stream()
                .map(row -> new IssueAggregates.StateCount(
                        (String) row[0], (String) row[1], (String) row[2], (String) row[3], count(row[4])))
                .toList();
    }

    @Override
    public List<TargetSeverityCount> countOpenByTargetAndSeverity(Specification<IssueEntity> filter) {
        CriteriaBuilder builder = entityManager.getCriteriaBuilder();
        CriteriaQuery<Object[]> query = builder.createQuery(Object[].class);
        Root<IssueEntity> issue = query.from(IssueEntity.class);

        query.select(builder.array(
                        issue.get("repoId"),
                        issue.get("containerId"),
                        issue.get("severity"),
                        builder.count(issue.get("id"))))
                .groupBy(issue.get("repoId"), issue.get("containerId"), issue.get("severity"));
        // **Open means unresolved, not `state = OPEN`.** The scoreboard has always counted rows
        // with no resolution instant, and the two are not the same set — a dismissed issue is
        // not in the OPEN state and is still unresolved. Using the state here would change
        // published grades while claiming to be a refactoring.
        restrict(query, filter, issue, builder, builder.isNull(issue.get("resolvedAt")));

        return entityManager.createQuery(query).getResultList().stream()
                .map(row -> new TargetSeverityCount(
                        (Long) row[0], (Long) row[1], (String) row[2], count(row[3])))
                .toList();
    }

    @Override
    public List<TargetGradingCount> countForGradingByTarget(Specification<IssueEntity> filter) {
        CriteriaBuilder builder = entityManager.getCriteriaBuilder();
        CriteriaQuery<Object[]> query = builder.createQuery(Object[].class);
        Root<IssueEntity> issue = query.from(IssueEntity.class);

        // No clause of its own on the state: see `TargetGradingCount` — the open test is the
        // reader's, in Java, exactly as the scorecard has always written it.
        query.select(builder.array(
                        issue.get("repoId"),
                        issue.get("containerId"),
                        issue.get("severity"),
                        issue.get("isKev"),
                        issue.get("state"),
                        builder.count(issue.get("id"))))
                .groupBy(
                        issue.get("repoId"),
                        issue.get("containerId"),
                        issue.get("severity"),
                        issue.get("isKev"),
                        issue.get("state"));
        restrict(query, filter, issue, builder);

        return entityManager.createQuery(query).getResultList().stream()
                .map(row -> new TargetGradingCount(
                        (Long) row[0],
                        (Long) row[1],
                        (String) row[2],
                        Boolean.TRUE.equals(row[3]),
                        (String) row[4],
                        count(row[5])))
                .toList();
    }

    @Override
    public List<TargetResolutions> countResolvedByTarget(Specification<IssueEntity> filter) {
        CriteriaBuilder builder = entityManager.getCriteriaBuilder();
        CriteriaQuery<Object[]> query = builder.createQuery(Object[].class);
        Root<IssueEntity> issue = query.from(IssueEntity.class);

        // **Two aggregates over different subsets in one pass.** The count is every closed
        // issue; the average is over `resolution_seconds`, which is null for the ones that
        // closed in the instant they were seen or were never seen at all. `avg` skips those, so
        // one query answers both without the counts contaminating the mean.
        query.select(builder.array(
                        issue.get("repoId"),
                        issue.get("containerId"),
                        builder.count(issue.get("id")),
                        builder.avg(issue.get("resolutionSeconds"))))
                .groupBy(issue.get("repoId"), issue.get("containerId"));
        restrict(query, filter, issue, builder, builder.isNotNull(issue.get("resolvedAt")));

        return entityManager.createQuery(query).getResultList().stream()
                .map(row -> new TargetResolutions(
                        (Long) row[0],
                        (Long) row[1],
                        count(row[2]),
                        row[3] == null ? null : ((Number) row[3]).doubleValue()))
                .toList();
    }

    @Override
    public List<ResolvedDuration> resolvedDurationsSince(Specification<IssueEntity> filter, Instant since) {
        CriteriaBuilder builder = entityManager.getCriteriaBuilder();
        CriteriaQuery<Object[]> query = builder.createQuery(Object[].class);
        Root<IssueEntity> issue = query.from(IssueEntity.class);

        query.select(builder.array(issue.get("severity"), issue.get("resolutionSeconds")));
        // `resolutionSeconds` is null for an issue closed in the instant it was seen, or one with
        // no sighting — the cases `V24` deliberately leaves unmeasured. They are not resolutions
        // of zero length, so they are absent from the distribution rather than at its floor.
        restrict(
                query,
                filter,
                issue,
                builder,
                builder.isNotNull(issue.get("resolutionSeconds")),
                builder.greaterThanOrEqualTo(issue.get("resolvedAt"), since));

        return entityManager.createQuery(query).getResultList().stream()
                .map(row -> new ResolvedDuration((String) row[0], ((Number) row[1]).longValue()))
                .toList();
    }

    @Override
    public List<OpenBacklog> openBacklogBySeverity(Specification<IssueEntity> filter) {
        CriteriaBuilder builder = entityManager.getCriteriaBuilder();
        CriteriaQuery<Object[]> query = builder.createQuery(Object[].class);
        Root<IssueEntity> issue = query.from(IssueEntity.class);

        query.select(builder.array(
                        issue.get("severity"),
                        builder.count(issue.get("id")),
                        builder.least(issue.<java.time.Instant>get("firstSeenAt"))))
                .groupBy(issue.get("severity"));
        restrict(query, filter, issue, builder, builder.isNull(issue.get("resolvedAt")));

        return entityManager.createQuery(query).getResultList().stream()
                .map(row -> new OpenBacklog(
                        (String) row[0], count(row[1]), (java.time.Instant) row[2]))
                .toList();
    }

    @Override
    public List<TypePackaging> countOpenByTypeAndPackaging(Specification<IssueEntity> filter) {
        CriteriaBuilder builder = entityManager.getCriteriaBuilder();
        CriteriaQuery<Object[]> query = builder.createQuery(Object[].class);
        Root<IssueEntity> issue = query.from(IssueEntity.class);

        Predicate named = packageIsNamed(builder, issue);
        query.select(builder.array(
                        issue.get("type"),
                        builder.sum(builder.<Long>selectCase().when(named, 1L).otherwise(0L)),
                        builder.sum(builder.<Long>selectCase().when(named, 0L).otherwise(1L))))
                .groupBy(issue.get("type"));
        restrict(query, filter, issue, builder);

        return entityManager.createQuery(query).getResultList().stream()
                .map(row -> new TypePackaging((String) row[0], count(row[1]), count(row[2])))
                .toList();
    }

    @Override
    public List<OwaspCategoryCount> countOpenSastByOwaspCategory(Specification<IssueEntity> filter) {
        CriteriaBuilder builder = entityManager.getCriteriaBuilder();
        CriteriaQuery<Object[]> query = builder.createQuery(Object[].class);
        Root<IssueEntity> issue = query.from(IssueEntity.class);

        query.select(builder.array(issue.get("owaspCategory"), builder.count(issue.get("id"))))
                .groupBy(issue.get("owaspCategory"));
        restrict(query, filter, issue, builder,
                // The type the grid reads the column of, named where the placement is (`OwaspCoverage`),
                // so the backlog's `owasp_category` filter and this count cannot name two.
                builder.equal(issue.get("type"), OwaspCoverage.DECLARES_ITS_CATEGORY.wireName()),
                builder.isNotNull(issue.get("owaspCategory")));

        return entityManager.createQuery(query).getResultList().stream()
                .map(row -> new OwaspCategoryCount((String) row[0], count(row[1])))
                .toList();
    }

    /**
     * Weeks per statement. Each week is four conditional sums over two bound instants: thirteen weeks
     * — a quarter — keep the select list and the binds small on every engine, and a year is four reads.
     */
    static final int WEEKS_PER_STATEMENT = 13;

    /** The conditional sums of one week, in the order they are selected. */
    private static final int FIGURES = 4;

    @Override
    public List<WeeklyFlow> weeklyFlows(Specification<IssueEntity> filter, List<Instant> weekStarts) {
        List<Instant> weeks = weekStarts.stream().distinct().sorted().toList();
        List<WeeklyFlow> flows = new java.util.ArrayList<>();
        for (int from = 0; from < weeks.size(); from += WEEKS_PER_STATEMENT) {
            flows.addAll(weeklyFlowsOf(filter, weeks.subList(from, Math.min(from + WEEKS_PER_STATEMENT, weeks.size()))));
        }
        return List.copyOf(flows);
    }

    private List<WeeklyFlow> weeklyFlowsOf(Specification<IssueEntity> filter, List<Instant> weeks) {
        CriteriaBuilder builder = entityManager.getCriteriaBuilder();
        CriteriaQuery<Object[]> query = builder.createQuery(Object[].class);
        Root<IssueEntity> issue = query.from(IssueEntity.class);
        Expression<Instant> firstSeen = issue.get("firstSeenAt");
        Expression<Instant> resolved = issue.get("resolvedAt");

        // **Parameters, not literals**: an instant written into the statement is rendered by each
        // dialect its own way, and a timestamp literal is where the engines differ.
        Map<String, Instant> bound = new java.util.LinkedHashMap<>();
        List<jakarta.persistence.criteria.Selection<?>> columns = new java.util.ArrayList<>();
        columns.add(issue.get("type"));
        columns.add(issue.get("owaspCategory"));
        for (int week = 0; week < weeks.size(); week++) {
            Expression<Instant> start = builder.parameter(Instant.class, "start" + week);
            Expression<Instant> end = builder.parameter(Instant.class, "end" + week);
            bound.put("start" + week, weeks.get(week));
            bound.put("end" + week, weeks.get(week).plus(java.time.Duration.ofDays(7)));
            // Open at the end and resolved within: the backlog's own clauses (`IssueSpecifications`), so
            // the cell and the list it opens cannot disagree — an earlier resolution a reopening recorded
            // included, on both.
            columns.add(builder.sum(oneWhen(builder,
                    IssueSpecifications.openAt(issue, query, builder, new IssueSpecifications.Bound.Parameter(end)))));
            columns.add(builder.sum(oneWhen(builder, builder.and(
                    builder.greaterThanOrEqualTo(firstSeen, start), builder.lessThan(firstSeen, end)))));
            columns.add(builder.sum(oneWhen(builder, IssueSpecifications.resolvedWithin(issue, query, builder,
                    new IssueSpecifications.Bound.Parameter(start), new IssueSpecifications.Bound.Parameter(end)))));
            columns.add(builder.sum(oneWhen(builder, IssueSpecifications.reopenedWithin(issue, query, builder,
                    new IssueSpecifications.Bound.Parameter(start), new IssueSpecifications.Bound.Parameter(end)))));
        }
        query.select(builder.array(columns.toArray(jakarta.persistence.criteria.Selection<?>[]::new))).groupBy(issue.get("type"), issue.get("owaspCategory"));

        // Only the issues that can count in one of these weeks: seen before the last one ends, and not
        // resolved before the first one starts.
        Expression<Instant> firstStart = builder.parameter(Instant.class, "firstStart");
        Expression<Instant> lastEnd = builder.parameter(Instant.class, "lastEnd");
        bound.put("firstStart", weeks.getFirst());
        bound.put("lastEnd", weeks.getLast().plus(java.time.Duration.ofDays(7)));
        restrict(query, filter, issue, builder,
                builder.lessThan(firstSeen, lastEnd),
                builder.or(builder.isNull(resolved), builder.greaterThanOrEqualTo(resolved, firstStart)));

        var typed = entityManager.createQuery(query);
        bound.forEach(typed::setParameter);

        List<WeeklyFlow> flows = new java.util.ArrayList<>();
        for (Object[] row : typed.getResultList()) {
            for (int week = 0; week < weeks.size(); week++) {
                long open = count(row[2 + FIGURES * week]);
                long opened = count(row[3 + FIGURES * week]);
                long closed = count(row[4 + FIGURES * week]);
                long reopened = count(row[5 + FIGURES * week]);
                if (open + opened + closed + reopened > 0) {
                    flows.add(new WeeklyFlow(
                            weeks.get(week), (String) row[0], (String) row[1], open, opened, closed, reopened));
                }
            }
        }
        return flows;
    }

    private static Expression<Long> oneWhen(CriteriaBuilder builder, Predicate condition) {
        return builder.<Long>selectCase().when(condition, 1L).otherwise(0L);
    }

    @Override
    public List<PackageWeight> weighPackages(Specification<IssueEntity> filter) {
        CriteriaBuilder builder = entityManager.getCriteriaBuilder();
        CriteriaQuery<Object[]> query = builder.createQuery(Object[].class);
        Root<IssueEntity> issue = query.from(IssueEntity.class);

        // **The version is the smallest, not the first one seen.** The Java this replaced
        // labelled the group with whichever issue the result set happened to yield first while
        // summing CVEs across every version — so the same data could produce two different
        // labels on two runs. Grouping by name alone is kept deliberately: splitting by version
        // would change which fixes appear, and that is a product decision, not a refactor.
        query.select(builder.array(
                        issue.get("packageName"),
                        builder.least(issue.<String>get("packageVersion")),
                        builder.countDistinct(identifier(builder, issue)),
                        builder.sum(oneWhenSeverityIs(builder, issue, Severity.CRITICAL)),
                        builder.sum(oneWhenSeverityIs(builder, issue, Severity.HIGH))))
                .groupBy(issue.get("packageName"));
        restrict(query, filter, issue, builder, vulnerabilityWithAPackage(builder, issue));

        return entityManager.createQuery(query).getResultList().stream()
                .map(row -> new PackageWeight(
                        (String) row[0], (String) row[1], count(row[2]), count(row[3]), count(row[4])))
                .toList();
    }

    @Override
    public List<PackageDetail> detailPackages(
            Specification<IssueEntity> filter, Collection<String> packageNames) {

        if (packageNames.isEmpty()) {
            return List.of();
        }

        CriteriaBuilder builder = entityManager.getCriteriaBuilder();
        CriteriaQuery<Object[]> query = builder.createQuery(Object[].class);
        Root<IssueEntity> issue = query.from(IssueEntity.class);

        // Distinct because two findings of the same CVE on the same target are one line on the
        // report, and because this is the only unbounded-by-nature read left: without it a
        // package rescanned nightly would return a row per scan.
        query.select(builder.array(
                        issue.get("packageName"),
                        identifier(builder, issue),
                        issue.get("repoId"),
                        issue.get("containerId"),
                        issue.get("fixVersions")))
                .distinct(true);
        restrict(query, filter, issue, builder,
                vulnerabilityWithAPackage(builder, issue),
                issue.get("packageName").in(packageNames));

        return entityManager.createQuery(query).getResultList().stream()
                .map(row -> new PackageDetail(
                        (String) row[0], (String) row[1], (Long) row[2], (Long) row[3], (String) row[4]))
                .toList();
    }

    /** The caller's filter — visibility included — and whatever else this particular read needs. */
    private static void restrict(
            CriteriaQuery<?> query,
            Specification<IssueEntity> filter,
            Root<IssueEntity> issue,
            CriteriaBuilder builder,
            Predicate... extra) {

        Predicate caller = filter.toPredicate(issue, query, builder);
        Predicate[] all = new Predicate[extra.length + (caller == null ? 0 : 1)];
        System.arraycopy(extra, 0, all, 0, extra.length);
        if (caller != null) {
            all[all.length - 1] = caller;
        }
        query.where(all);
    }

    /**
     * Vulnerabilities that name a package.
     *
     * <p>{@code trim} rather than {@code <> ''}: the Java tested {@code isBlank()}, and a package
     * name of three spaces would otherwise start appearing as a recommended upgrade.
     */
    private static Predicate vulnerabilityWithAPackage(CriteriaBuilder builder, Root<IssueEntity> issue) {
        return builder.and(
                builder.equal(issue.get("type"), FindingType.VULNERABILITY.wireName()),
                packageIsNamed(builder, issue));
    }

    /**
     * The package is named.
     *
     * <p>Extracted so it can be shared with {@link #countOpenByTypeAndPackaging}, which tells the
     * screen what the ranking leaves out: the two reads must agree to the finding, and two copies
     * of one predicate end up no longer agreeing.
     */
    private static Predicate packageIsNamed(CriteriaBuilder builder, Root<IssueEntity> issue) {
        return builder.and(
                builder.isNotNull(issue.get("packageName")),
                builder.notEqual(builder.trim(issue.<String>get("packageName")), ""));
    }

    private static Expression<String> identifier(CriteriaBuilder builder, Root<IssueEntity> issue) {
        return builder.coalesce(issue.<String>get("identifier"), builder.literal(UNNAMED));
    }

    private static Expression<Long> oneWhenSeverityIs(
            CriteriaBuilder builder, Root<IssueEntity> issue, Severity severity) {
        return builder.<Long>selectCase()
                .when(builder.equal(issue.get("severity"), severity.wireName()), 1L)
                .otherwise(0L);
    }

    /** A driver may answer an aggregate with any {@link Number} it likes; only the value matters. */
    private static long count(Object value) {
        return value == null ? 0L : ((Number) value).longValue();
    }
}
