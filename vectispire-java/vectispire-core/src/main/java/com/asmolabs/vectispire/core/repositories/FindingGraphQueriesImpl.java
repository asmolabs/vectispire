package com.asmolabs.vectispire.core.repositories;

import com.asmolabs.vectispire.common.domain.access.Visibility;
import com.asmolabs.vectispire.common.domain.issues.FindingType;
import com.asmolabs.vectispire.common.domain.targets.ScanTarget;
import com.asmolabs.vectispire.core.persistence.FindingEntity;
import com.asmolabs.vectispire.core.persistence.ScanEntity;
import jakarta.persistence.EntityManager;
import jakarta.persistence.PersistenceContext;
import jakarta.persistence.criteria.CriteriaBuilder;
import jakarta.persistence.criteria.CriteriaQuery;
import jakarta.persistence.criteria.Predicate;
import jakarta.persistence.criteria.Root;
import java.util.ArrayList;
import java.util.List;
import java.util.Locale;

/**
 * {@link FindingGraphQueries}, in criteria form.
 *
 * <p>The name is load-bearing: Spring Data finds this class because it is the fragment interface
 * plus {@code Impl}.
 */
public class FindingGraphQueriesImpl implements FindingGraphQueries {

    @PersistenceContext
    private EntityManager entityManager;

    @Override
    public List<GraphRow> forGraph(
            String query, boolean cveQuery, boolean excludeSecrets, Visibility allowed) {

        // An allowance of nothing is not an absent filter. Answering it with the estate is the
        // inversion `Visibility` exists to prevent, and the round trip is not worth making.
        if (allowed.isEmpty()) {
            return List.of();
        }

        CriteriaBuilder builder = entityManager.getCriteriaBuilder();
        CriteriaQuery<Object[]> criteria = builder.createQuery(Object[].class);
        Root<FindingEntity> finding = criteria.from(FindingEntity.class);
        Root<ScanEntity> scan = criteria.from(ScanEntity.class);

        List<Predicate> predicates = new ArrayList<>();
        predicates.add(builder.equal(finding.get("scanId"), scan.get("id")));

        // A graph node is a package; a finding with none cannot be one. `trim` rather than
        // `<> ''` because the Java this replaced tested `isBlank()`.
        predicates.add(builder.isNotNull(finding.get("packageName")));
        predicates.add(builder.notEqual(builder.trim(finding.<String>get("packageName")), ""));

        if (excludeSecrets) {
            predicates.add(builder.or(
                    builder.isNull(finding.get("type")),
                    builder.notEqual(
                            builder.lower(finding.<String>get("type")),
                            FindingType.SECRET.wireName())));
        }

        if (query != null && !query.isBlank()) {
            String trimmed = query.trim();
            if (cveQuery) {
                // Exact, case-insensitively: a substring match here would answer a query for
                // CVE-2021-4 with every identifier that happens to contain it.
                predicates.add(builder.equal(
                        builder.lower(finding.<String>get("identifier")),
                        trimmed.toLowerCase(Locale.ROOT)));
            } else {
                String pattern = "%" + trimmed.toLowerCase(Locale.ROOT) + "%";
                predicates.add(builder.or(
                        builder.like(builder.lower(finding.<String>get("packageName")), pattern),
                        builder.like(builder.lower(finding.<String>get("purl")), pattern)));
            }
        }

        visible(allowed, scan, builder).ifPresent(predicates::add);

        criteria.select(builder.array(finding, scan))
                .where(predicates.toArray(Predicate[]::new));

        return entityManager.createQuery(criteria).getResultList().stream()
                .map(row -> new GraphRow((FindingEntity) row[0], (ScanEntity) row[1]))
                .toList();
    }

    /**
     * The scans whose target the caller may see, or nothing to add when they may see everything.
     *
     * <p>Applied to the <b>scan</b> rather than to the finding, because that is where a finding's
     * target lives: a finding names a scan, and the scan names a repository or an image.
     */
    private static java.util.Optional<Predicate> visible(
            Visibility allowed, Root<ScanEntity> scan, CriteriaBuilder builder) {

        return allowed.asFilter().map(targets -> {
            List<Predicate> perTarget = new ArrayList<>();
            for (ScanTarget target : targets) {
                switch (target) {
                    case ScanTarget.Repository repository ->
                            perTarget.add(builder.equal(scan.get("repoId"), repository.id()));
                    case ScanTarget.Container container ->
                            perTarget.add(builder.equal(scan.get("containerId"), container.id()));
                }
            }
            // A false predicate rather than none: the two read alike and mean the opposite.
            return perTarget.isEmpty()
                    ? builder.disjunction()
                    : builder.or(perTarget.toArray(Predicate[]::new));
        });
    }
}
