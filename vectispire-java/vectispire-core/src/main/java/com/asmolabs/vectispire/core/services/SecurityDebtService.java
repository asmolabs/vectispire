package com.asmolabs.vectispire.core.services;

import com.asmolabs.vectispire.common.domain.access.Visibility;
import com.asmolabs.vectispire.common.domain.issues.FindingType;
import com.asmolabs.vectispire.common.domain.issues.IssueState;
import com.asmolabs.vectispire.common.domain.issues.Severity;
import com.asmolabs.vectispire.common.domain.remediation.HighImpactFix;
import com.asmolabs.vectispire.common.domain.remediation.SecurityDebtReport;
import com.asmolabs.vectispire.core.persistence.ContainerEntity;
import com.asmolabs.vectispire.core.persistence.IssueEntity;
import com.asmolabs.vectispire.core.persistence.RepositoryEntity;
import com.asmolabs.vectispire.core.repositories.Containers;
import com.asmolabs.vectispire.core.repositories.GitRepositories;
import com.asmolabs.vectispire.core.repositories.IssueAggregates;
import com.asmolabs.vectispire.core.repositories.IssueFilters;
import com.asmolabs.vectispire.core.repositories.Issues;
import java.util.ArrayList;
import java.util.Comparator;
import java.util.HashSet;
import java.util.LinkedHashMap;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.stream.Collectors;
import org.springframework.data.jpa.domain.Specification;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

/**
 * Quantifies engineering effort required to resolve security debt and discovers high-leverage fixes.
 *
 * <p><b>Nothing here reads a whole table.</b> It used to: every open issue arrived as a managed
 * entity — thirty-nine columns each, plus the dirty-checking snapshot the persistence context
 * keeps beside it — and both target tables were loaded in full to build two name maps of which a
 * handful of entries were ever used. Three queries, so not an N+1, but three queries whose cost
 * grew with the backlog while the answer did not: an effort estimate is a function of
 * {@code (type, severity)} and a count, and needs no rows at all.
 *
 * <p>The report has two halves with opposite appetites, and they are computed separately for
 * that reason. The <b>tallies</b> reduce to one grouped read of at most a few dozen rows. The
 * <b>high-impact fixes</b> genuinely need identifiers and target names, but only for the ten
 * packages that survive the ranking — so the ranking runs first, on aggregates, and the detail is
 * fetched afterwards for those ten alone.
 *
 * <p><b>The estimates themselves are unchanged, deliberately.</b> {@code SecurityDebtDatabaseTest}
 * pins them, including one figure that is wrong: half the finding types cost nothing. Correcting
 * that would move every number the product has ever displayed, which is a decision to take on its
 * own rather than inside a change about queries.
 */
@Service
public class SecurityDebtService {

    /** How long one finding of each type is assumed to take. Zero for the types nobody costed. */
    private static final double SECRET_HOURS = 2.0;
    private static final double QUALITY_HOURS = 2.5;
    private static final double IAC_HOURS = 1.0;
    private static final double SEVERE_VULNERABILITY_HOURS = 1.5;
    private static final double ORDINARY_VULNERABILITY_HOURS = 0.8;

    /** The list is a work order, and nobody works a hundred items at once. */
    private static final int MOST_LEVERAGE = 10;

    private final Issues issues;
    private final GitRepositories repositories;
    private final Containers containers;

    public SecurityDebtService(
            Issues issues,
            GitRepositories repositories,
            Containers containers) {
        this.issues = issues;
        this.repositories = repositories;
        this.containers = containers;
    }

    @Transactional(readOnly = true)
    public SecurityDebtReport calculateDebt(Long repoId, Long containerId, Visibility allowed) {
        Specification<IssueEntity> filter = openIssuesOf(repoId, containerId, allowed);

        Tallies tallies = tally(issues.countGroupedBySeverityAndType(filter));

        double totalHours = round(
                tallies.vulnerabilityHours + tallies.secretHours + tallies.qualityHours + tallies.iacHours);

        return new SecurityDebtReport(
                tallies.total,
                tallies.critical,
                tallies.high,
                tallies.medium,
                tallies.low,
                totalHours,
                // From the rounded total, not from the raw sum: the two differ at the boundary,
                // and the figure beside it on screen is the rounded one.
                round(totalHours / 8.0),
                round(tallies.vulnerabilityHours),
                round(tallies.secretHours),
                round(tallies.qualityHours),
                round(tallies.iacHours),
                rank(filter));
    }

    /**
     * The ranked fixes alone, for the endpoint that wants only those.
     *
     * <p>It used to call {@link #calculateDebt} and keep the last field — so a page showing ten
     * upgrade suggestions counted the entire backlog by severity first, and discarded it.
     */
    @Transactional(readOnly = true)
    public List<HighImpactFix> highImpactFixes(Long repoId, Long containerId, Visibility allowed) {
        return rank(openIssuesOf(repoId, containerId, allowed));
    }

    private static Specification<IssueEntity> openIssuesOf(Long repoId, Long containerId, Visibility allowed) {
        return new IssueFilters(
                        IssueState.OPEN.wireName(), null, null, null, repoId, containerId,
                        false, false, null, allowed)
                .toSpecification();
    }

    /**
     * The severity counts and the effort, from grouped rows.
     *
     * <p>Effort per finding depends on nothing but its type and severity, so {@code count ×
     * effort} is the same arithmetic the per-issue loop did — not an approximation of it.
     */
    private static Tallies tally(List<IssueAggregates.SeverityTypeCount> rows) {
        Tallies tallies = new Tallies();

        for (IssueAggregates.SeverityTypeCount row : rows) {
            Severity severity = Severity.of(row.severity());
            // An unrecognised type counts as a vulnerability, as it always has: the alternative
            // is a finding that appears in the issue count and in no estimate.
            FindingType type = FindingType.fromWireName(row.type()).orElse(FindingType.VULNERABILITY);
            long count = row.count();

            tallies.total += count;
            switch (severity) {
                case CRITICAL -> tallies.critical += count;
                case HIGH -> tallies.high += count;
                case MEDIUM -> tallies.medium += count;
                case LOW, NEGLIGIBLE, UNKNOWN -> tallies.low += count;
            }

            switch (type) {
                case VULNERABILITY -> tallies.vulnerabilityHours += count
                        * (severity == Severity.CRITICAL || severity == Severity.HIGH
                                ? SEVERE_VULNERABILITY_HOURS
                                : ORDINARY_VULNERABILITY_HOURS);
                case SECRET -> tallies.secretHours += count * SECRET_HOURS;
                case QUALITY -> tallies.qualityHours += count * QUALITY_HOURS;
                case IAC -> tallies.iacHours += count * IAC_HOURS;
                // SAST, LICENSE, EOL and AI_REVIEW cost nothing, which is the defect
                // `SecurityDebtDatabaseTest.onlyFourOfEightTypesCostAnything` records. Listed
                // rather than left to a `default`, so the day it is fixed the compiler shows
                // where.
                case SAST, LICENSE, EOL, AI_REVIEW -> { }
            }
        }
        return tallies;
    }

    /**
     * The ten upgrades worth doing first.
     *
     * <p>Two reads, in this order for a reason: the score needs only counts, so the whole estate
     * is ranked on aggregate rows, and the identifiers and target names — the only part whose
     * size follows the backlog — are fetched for the survivors alone.
     */
    private List<HighImpactFix> rank(Specification<IssueEntity> filter) {
        List<IssueAggregates.PackageWeight> weights = issues.weighPackages(filter).stream()
                // A package whose findings are all unnamed still has one unnamed CVE, so this
                // only drops rows a filter already emptied.
                .filter(weight -> weight.distinctIdentifiers() > 0)
                .sorted(Comparator.comparingDouble(SecurityDebtService::leverageOf).reversed()
                        // Ties broken by name so two runs on the same data agree; the map this
                        // replaced had no order at all.
                        .thenComparing(IssueAggregates.PackageWeight::packageName))
                .limit(MOST_LEVERAGE)
                .toList();

        if (weights.isEmpty()) {
            return List.of();
        }

        Map<String, Detail> details = detailsOf(filter, weights);

        List<HighImpactFix> fixes = new ArrayList<>();
        for (IssueAggregates.PackageWeight weight : weights) {
            Detail detail = details.getOrDefault(weight.packageName(), Detail.empty());
            fixes.add(new HighImpactFix(
                    weight.packageName(),
                    weight.version() != null ? weight.version() : "various",
                    "latest-patch",
                    weight.distinctIdentifiers(),
                    weight.criticalCount(),
                    weight.highCount(),
                    effortOf(weight),
                    leverageOf(weight),
                    List.copyOf(detail.cves()),
                    List.copyOf(detail.targetNames())));
        }
        return fixes;
    }

    /** The CVEs and target names of the ranked packages, and the names of those targets only. */
    private Map<String, Detail> detailsOf(
            Specification<IssueEntity> filter, List<IssueAggregates.PackageWeight> weights) {

        List<IssueAggregates.PackageDetail> rows = issues.detailPackages(
                filter, weights.stream().map(IssueAggregates.PackageWeight::packageName).toList());

        Set<Long> repoIds = new HashSet<>();
        Set<Long> containerIds = new HashSet<>();
        for (IssueAggregates.PackageDetail row : rows) {
            if (row.repoId() != null) {
                repoIds.add(row.repoId());
            } else if (row.containerId() != null) {
                containerIds.add(row.containerId());
            }
        }

        // By identifier, not `findAll()`: the names wanted are those of the targets that appeared
        // above, and there are at most a few per package.
        Map<Long, String> repoNames = repositories.findAllById(repoIds).stream()
                .collect(Collectors.toMap(RepositoryEntity::getId, RepositoryEntity::getName, (a, b) -> a));
        Map<Long, String> containerNames = containers.findAllById(containerIds).stream()
                .collect(Collectors.toMap(
                        ContainerEntity::getId, c -> c.getImageName() + ":" + c.getTag(), (a, b) -> a));

        Map<String, Detail> details = new LinkedHashMap<>();
        for (IssueAggregates.PackageDetail row : rows) {
            Detail detail = details.computeIfAbsent(row.packageName(), name -> Detail.empty());
            detail.cves().add(row.identifier());
            if (row.repoId() != null && repoNames.containsKey(row.repoId())) {
                detail.targetNames().add(repoNames.get(row.repoId()));
            } else if (row.containerId() != null && containerNames.containsKey(row.containerId())) {
                detail.targetNames().add(containerNames.get(row.containerId()));
            }
        }
        return details;
    }

    private static double effortOf(IssueAggregates.PackageWeight weight) {
        return round(1.0 + weight.distinctIdentifiers() * 0.1);
    }

    /** What the upgrade buys, over what it costs. Severe CVEs weigh more than their number. */
    private static double leverageOf(IssueAggregates.PackageWeight weight) {
        return round((weight.distinctIdentifiers() * 2.0
                        + weight.criticalCount() * 3.0
                        + weight.highCount() * 1.5)
                / effortOf(weight));
    }

    private static double round(double value) {
        return Math.round(value * 10.0) / 10.0;
    }

    /** Insertion-ordered, so a report built twice from one database reads the same twice. */
    private record Detail(Set<String> cves, Set<String> targetNames) {
        static Detail empty() {
            return new Detail(new LinkedHashSet<>(), new LinkedHashSet<>());
        }
    }

    private static final class Tallies {
        private long total;
        private long critical;
        private long high;
        private long medium;
        private long low;
        private double vulnerabilityHours;
        private double secretHours;
        private double qualityHours;
        private double iacHours;
    }
}
