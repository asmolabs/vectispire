package com.asmolabs.vectispire.core.issues.persistence;

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
import java.time.Instant;
import java.util.Collection;
import java.util.List;
import org.springframework.data.jpa.domain.Specification;

/**
 * The aggregations Spring Data cannot express, over the same filter the list screens use.
 *
 * <p><b>Why a fragment and not three {@code @Query} methods.</b> These reads have to honour
 * {@link com.asmolabs.vectispire.common.domain.access.Visibility}, and that predicate is built by
 * {@code IssueSpecifications} — one definition, deliberately, because authorization written twice
 * is authorization that disagrees with itself on the day one copy is edited.
 * Spring Data will run a {@code Specification} or a grouped JPQL string, but not both, so the
 * grouping is built here against the very same predicate rather than restated in JPQL.
 *
 * <p><b>What this replaced.</b> The debt report loaded every open issue as a managed entity and
 * both target tables in full, then counted in Java. Not an N+1 — three queries — but three
 * queries with no upper bound, and the counting it did needs no rows at all: an effort estimate
 * is a function of {@code (type, severity)} and a count.
 *
 * <p>Rows come back as {@code Object[]} and are read tolerantly. A {@code count} is a mapped
 * attribute nowhere: it is an expression, and the type a driver hands back for
 * {@code sum(case … end)} is its own business — {@code Long} on one, {@code BigDecimal} on
 * another. That is the difference between these and the projections in {@link IssueRepository}, which
 * select mapped attributes Hibernate normalises.
 */
public interface IssueAggregateQueries {

    /**
     * What a ranking of the backlog may be grouped by: an attribute of the entity, chosen from a
     * closed set. A column name that arrived as a string would be a column name that can arrive from
     * a request, and "the grouping axis is injectable" is how a filter becomes an injection point.
     */
    enum Axis {
        RULE("identifier"),
        FILE("filePath"),
        REPOSITORY("repoId");

        final String attribute;

        Axis(String attribute) {
            this.attribute = attribute;
        }
    }

    /**
     * The heaviest values of one axis, heaviest first: each row the value and its count.
     *
     * <p>These three and {@link #countDistinct} were {@code @Query} strings with {@code repoId in
     * :repoIds}, one bind parameter per repository the reader may see; the quality overview of a
     * reader granted more than 65,535 repositories failed on PostgreSQL. Here the narrowing is {@code
     * IssueSpecifications}' own, identifiers written into the one statement — a ranking and a distinct
     * count cannot be added up over batches.
     */
    List<Object[]> countGrouped(Specification<IssueEntity> filter, Axis axis, int limit);

    /** How many distinct values of one axis the filtered issues carry. */
    long countDistinct(Specification<IssueEntity> filter, Axis axis);

    List<SeverityTypeCount> countGroupedBySeverityAndType(Specification<IssueEntity> filter);

    /**
     * The open half of the scoreboard, as a {@code group by} rather than as rows.
     *
     * <p>This is what the posture dashboard used to get by loading every open issue in the
     * estate and counting them in a loop. The backlog is the larger half of an issue table, and
     * counting is what a database is for.
     */
    List<TargetSeverityCount> countOpenByTargetAndSeverity(Specification<IssueEntity> filter);

    /**
     * What every target's scorecard is graded on, as a {@code group by}: the per-target card reads
     * it for one target, the portfolio sums it, and the maturity ranking reads it for every target
     * the caller may see — so the three grade the same rows the same way.
     */
    List<TargetGradingCount> countForGradingByTarget(Specification<IssueEntity> filter);

    /** The closed half of the scoreboard, counted and averaged by the database. */
    List<TargetResolutions> countResolvedByTarget(Specification<IssueEntity> filter);

    List<ResolvedDuration> resolvedDurationsSince(Specification<IssueEntity> filter, Instant since);

    List<OpenBacklog> openBacklogBySeverity(Specification<IssueEntity> filter);

    List<TypePackaging> countOpenByTypeAndPackaging(Specification<IssueEntity> filter);

    List<OwaspCategoryCount> countOpenSastByOwaspCategory(Specification<IssueEntity> filter);

    /**
     * For each of these weeks, the filtered issues open at its end, first seen in it and resolved in
     * it, per {@code (type, owasp_category)} — see {@link WeeklyFlow} for the boundaries.
     *
     * <p><b>Grouped in the database, a few weeks per statement</b>: one conditional sum per week and
     * figure, so a year of weeks reads the backlog four times rather than once per issue or per week.
     * Pairs with nothing in any week are left out; the reader reads absent as zero.
     *
     * @param weekStarts each the Monday at 00:00 UTC of a week, in any order, each at most once
     */
    List<WeeklyFlow> weeklyFlows(Specification<IssueEntity> filter, List<Instant> weekStarts);

    /**
     * The vulnerable packages, weighted.
     *
     * <p>Restricted to vulnerabilities carrying a package name: a finding with no package cannot
     * be resolved by an upgrade, so it belongs to the hours and not to this list.
     */
    List<PackageWeight> weighPackages(Specification<IssueEntity> filter);

    /** The identifiers and targets of the named packages, and of no others. */
    List<PackageDetail> detailPackages(Specification<IssueEntity> filter, Collection<String> packageNames);
}
