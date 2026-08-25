package com.asmolabs.vectispire.core.repositories;

import com.asmolabs.vectispire.core.persistence.IssueEntity;
import java.util.Collection;
import java.util.List;
import org.springframework.data.jpa.domain.Specification;

/**
 * The aggregations Spring Data cannot express, over the same filter the list screens use.
 *
 * <p><b>Why a fragment and not three {@code @Query} methods.</b> These reads have to honour
 * {@link com.asmolabs.vectispire.common.domain.access.Visibility}, and that predicate lives in
 * {@link IssueFilters#toSpecification()} — one definition, deliberately, because authorization
 * written twice is authorization that disagrees with itself on the day one copy is edited.
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
 * another. That is the difference between these and the projections in {@link Issues}, which
 * select mapped attributes Hibernate normalises.
 */
public interface IssueAggregates {

    /** How many issues carry each {@code (severity, type)} pair. At most one row per pair. */
    record SeverityTypeCount(String severity, String type, long count) {}

    /**
     * One vulnerable package, and everything the leverage score is computed from.
     *
     * @param distinctIdentifiers CVEs counted once however many targets carry them — the fix is
     *     one upgrade, not one per repository
     */
    record PackageWeight(
            String packageName, String version, long distinctIdentifiers, long criticalCount, long highCount) {}

    /** One {@code (package, CVE, target)} row, read only for the packages that made the cut. */
    record PackageDetail(String packageName, String identifier, Long repoId, Long containerId) {}

    List<SeverityTypeCount> countGroupedBySeverityAndType(Specification<IssueEntity> filter);

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
