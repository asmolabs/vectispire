package com.asmolabs.vectispire.core.repositories;

import com.asmolabs.vectispire.common.domain.issues.FindingType;
import com.asmolabs.vectispire.common.domain.issues.Severity;
import com.asmolabs.vectispire.core.persistence.IssueEntity;
import jakarta.persistence.EntityManager;
import jakarta.persistence.PersistenceContext;
import jakarta.persistence.criteria.CriteriaBuilder;
import jakarta.persistence.criteria.CriteriaQuery;
import jakarta.persistence.criteria.Expression;
import jakarta.persistence.criteria.Predicate;
import jakarta.persistence.criteria.Root;
import java.util.Collection;
import java.time.Instant;
import java.util.List;
import org.springframework.data.jpa.domain.Specification;

/**
 * {@link IssueAggregates}, in criteria form.
 *
 * <p>The name is load-bearing: Spring Data finds this class because it is the fragment interface
 * plus {@code Impl}. Renaming either half leaves {@link Issues} unimplementable at startup.
 */
public class IssueAggregatesImpl implements IssueAggregates {

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
                builder.equal(issue.get("type"), FindingType.SAST.wireName()),
                builder.isNotNull(issue.get("owaspCategory")));

        return entityManager.createQuery(query).getResultList().stream()
                .map(row -> new OwaspCategoryCount((String) row[0], count(row[1])))
                .toList();
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
     * Le paquet est nommé.
     *
     * <p>Extrait pour être partagé avec {@link #countOpenByTypeAndPackaging}, qui annonce à
     * l'écran ce que le classement laisse de côté : les deux lectures doivent s'accorder au
     * constat près, et deux copies d'un même prédicat finissent par ne plus s'accorder.
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
