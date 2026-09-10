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

    /**
     * One {@code (package, CVE, target)} row, read only for the packages that made the cut.
     *
     * @param fixVersions les versions qui corrigent ce constat, telles que le scanner les a
     *     remontées — une énumération séparée par des virgules, souvent vide. C'est la seule
     *     source de la version à conseiller : elle est ramenée ici, avec les lignes déjà lues
     *     pour les paquets retenus, plutôt que par une requête de plus.
     */
    record PackageDetail(
            String packageName, String identifier, Long repoId, Long containerId, String fixVersions) {}

    /**
     * Open issues of one target at one severity. {@code repoId} and {@code containerId} are
     * mutually exclusive, exactly as on the row.
     */
    record TargetSeverityCount(Long repoId, Long containerId, String severity, long count) {}

    /**
     * What one target has closed, and how long those took on average.
     *
     * <p><b>An aggregate, since {@code V24}.</b> This was a row per closed issue, because the
     * average needed the difference between two timestamps and the three engines spell that
     * three ways. {@code t_issue.resolution_seconds} is written when the issue is resolved, so
     * the average is now {@code avg} of a number — the same statement everywhere, computed where
     * the rows are.
     *
     * @param averageSeconds null when the target has closed nothing that lived measurably. Not
     *     zero: {@code avg} skips nulls, and so must whoever reads this
     */
    record TargetResolutions(Long repoId, Long containerId, long resolved, Double averageSeconds) {}

    List<SeverityTypeCount> countGroupedBySeverityAndType(Specification<IssueEntity> filter);

    /**
     * The open half of the scoreboard, as a {@code group by} rather than as rows.
     *
     * <p>This is what the posture dashboard used to get by loading every open issue in the
     * estate and counting them in a loop. The backlog is the larger half of an issue table, and
     * counting is what a database is for.
     */
    List<TargetSeverityCount> countOpenByTargetAndSeverity(Specification<IssueEntity> filter);

    /** The closed half of the scoreboard, counted and averaged by the database. */
    List<TargetResolutions> countResolvedByTarget(Specification<IssueEntity> filter);

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
