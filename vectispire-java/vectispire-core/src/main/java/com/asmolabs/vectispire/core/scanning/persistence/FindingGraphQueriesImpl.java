package com.asmolabs.vectispire.core.scanning.persistence;

import com.asmolabs.vectispire.common.domain.access.Visibility;
import com.asmolabs.vectispire.common.domain.issues.FindingType;
import com.asmolabs.vectispire.common.domain.targets.ScanTarget;
import com.asmolabs.vectispire.core.scanning.persistence.queries.PackageImpact;
import jakarta.persistence.EntityManager;
import jakarta.persistence.PersistenceContext;
import jakarta.persistence.Tuple;
import jakarta.persistence.criteria.CriteriaBuilder;
import jakarta.persistence.criteria.CriteriaQuery;
import jakarta.persistence.criteria.Expression;
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

    // Named rather than positional: a tuple read by index is a silent transposition away
    // from reporting one package's direct count as another's.
    private static final String PACKAGE = "packageName";
    private static final String PURL = "purl";
    private static final String REPOS = "repos";
    private static final String CONTAINERS = "containers";
    private static final String DIRECT = "direct";
    private static final String TOTAL = "total";
    private static final String CVES = "cves";
    private static final String CVSS = "cvss";

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

    @Override
    public List<PackageImpact> packageImpacts(Visibility allowed) {

        // Same reason as above: an allowance of nothing is answered without a round trip.
        if (allowed.isEmpty()) {
            return List.of();
        }

        CriteriaBuilder builder = entityManager.getCriteriaBuilder();
        CriteriaQuery<Tuple> criteria = builder.createTupleQuery();
        Root<FindingEntity> finding = criteria.from(FindingEntity.class);
        Root<ScanEntity> scan = criteria.from(ScanEntity.class);

        List<Predicate> predicates = new ArrayList<>();
        predicates.add(builder.equal(finding.get("scanId"), scan.get("id")));
        predicates.add(builder.isNotNull(finding.get("packageName")));
        predicates.add(builder.notEqual(builder.trim(finding.<String>get("packageName")), ""));
        visible(allowed, scan, builder).ifPresent(predicates::add);

        Expression<String> packageName = finding.get("packageName");

        // A null column is not a zero here: `is_direct_dependency` is nullable, and the Java this
        // replaces tested `Boolean.TRUE.equals`, which reads null as "not direct". `isTrue` on a
        // null yields unknown, so the CASE falls to its `otherwise` — the same answer.
        Expression<Integer> directFlag = builder.<Integer>selectCase()
                .when(builder.isTrue(finding.<Boolean>get("isDirectDependency")), 1)
                .otherwise(0);

        // Counted distinct, and only over the identifiers that are CVEs — `count(distinct ...)`
        // skips nulls, which is what the CASE relies on to leave the others out. The Java it
        // replaces collected them into a Set after testing `startsWith("CVE-")` on the uppercase
        // form; `like 'cve-%'` on the lowercase one is the same test.
        Expression<String> cveIdentifier = builder.<String>selectCase()
                .when(
                        builder.like(builder.lower(finding.<String>get("identifier")), "cve-%"),
                        finding.<String>get("identifier"))
                .otherwise(builder.nullLiteral(String.class));

        criteria.select(builder.tuple(
                        packageName.alias(PACKAGE),
                        // `least` — the string `min` — rather than "the first one seen": the
                        // Java picked whichever row
                        // the driver happened to return first, so this is the same value
                        // made reproducible. It is read for its `pkg:` prefix, nothing else.
                        builder.least(finding.<String>get("purl")).alias(PURL),
                        // **Distinct targets, not distinct scans.** The count feeds the
                        // dispersion term of the score, which saturates at five: counting scans
                        // meant a package in one nightly-scanned repository hit the cap within
                        // the week, so the term that was supposed to say "this is everywhere"
                        // said 40 for everything and the list collapsed into a CVSS sort. A scan
                        // carries one of these two columns and never both, so the two counts sum
                        // to the targets — and `count(distinct)` drops the nulls that make it so.
                        builder.countDistinct(scan.get("repoId")).alias(REPOS),
                        builder.countDistinct(scan.get("containerId")).alias(CONTAINERS),
                        builder.sum(directFlag).alias(DIRECT),
                        builder.count(finding.get("id")).alias(TOTAL),
                        builder.countDistinct(cveIdentifier).alias(CVES),
                        builder.max(finding.<Double>get("cvssScore")).alias(CVSS)))
                .where(predicates.toArray(Predicate[]::new))
                .groupBy(packageName);

        return entityManager.createQuery(criteria).getResultList().stream()
                .map(row -> {
                    long total = row.get(TOTAL, Long.class);
                    // `sum` over an int expression is a Long on one engine and an Integer on
                    // another; the Number is the portable read.
                    long direct = ((Number) row.get(DIRECT)).longValue();
                    return new PackageImpact(
                            row.get(PACKAGE, String.class),
                            row.get(PURL, String.class),
                            row.get(REPOS, Long.class),
                            row.get(CONTAINERS, Long.class),
                            direct,
                            total - direct,
                            row.get(CVES, Long.class),
                            row.get(CVSS, Double.class));
                })
                .toList();
    }

    /**
     * The scans whose target the caller may see, or nothing to add when they may see everything.
     *
     * <p>Applied to the <b>scan</b> rather than to the finding, because that is where a finding's
     * target lives: a finding names a scan, and the scan names a repository or an image.
     *
     * <p><b>Identifiers written into the statement, a thousand to a list</b> — as {@code
     * IssueSpecifications.visible} does, for the same reason: the allowance is sized by the estate, and
     * the grouped read cannot be split. One bound {@code equal} per target failed on PostgreSQL for a
     * reader granted more than 65,535 targets ({@code WideAllowanceIntegrationTest}). {@code Long}s
     * only: a literal is rendered into the SQL.
     */
    private static java.util.Optional<Predicate> visible(
            Visibility allowed, Root<ScanEntity> scan, CriteriaBuilder builder) {

        return allowed.asFilter().map(targets -> {
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
                either.add(literalIn(builder, scan.<Long>get("repoId"), repositories));
            }
            if (!containers.isEmpty()) {
                either.add(literalIn(builder, scan.<Long>get("containerId"), containers));
            }
            // A false predicate rather than none: the two read alike and mean the opposite.
            return either.isEmpty()
                    ? builder.disjunction()
                    : builder.or(either.toArray(Predicate[]::new));
        });
    }

    /** How many identifiers one {@code in} list carries. */
    private static final int IN_LIST_BATCH = 1_000;

    /** {@code column in (…)} over sorted literal identifiers, in or-ed lists; {@code ids} is not empty. */
    private static Predicate literalIn(CriteriaBuilder builder, jakarta.persistence.criteria.Path<Long> column,
            List<Long> ids) {
        List<Long> sorted = ids.stream().distinct().sorted().toList();
        List<Predicate> lists = new ArrayList<>();
        for (int from = 0; from < sorted.size(); from += IN_LIST_BATCH) {
            CriteriaBuilder.In<Long> list = builder.in(column);
            sorted.subList(from, Math.min(from + IN_LIST_BATCH, sorted.size())).forEach(id -> list.value(builder.literal(id)));
            lists.add(list);
        }
        return lists.size() == 1 ? lists.getFirst() : builder.or(lists.toArray(Predicate[]::new));
    }
}
