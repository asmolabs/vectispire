package com.asmolabs.vectispire.core.repositories;

import com.asmolabs.vectispire.common.domain.access.Visibility;
import com.asmolabs.vectispire.common.domain.issues.Severity;
import com.asmolabs.vectispire.common.domain.issues.TriageStatus;
import com.asmolabs.vectispire.common.domain.targets.ScanTarget;
import com.asmolabs.vectispire.core.persistence.IssueEntity;
import jakarta.persistence.criteria.Predicate;
import java.time.Instant;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import java.util.Locale;
import org.springframework.data.jpa.domain.Specification;

/**
 * The backlog's filters, as one specification.
 *
 * <p><b>One definition, used by the page and by its count.</b> Two separately built queries end
 * up disagreeing, and the symptom is a pagination announcing pages the list does not contain.
 *
 * @param onlyDirect restricts to declared dependencies. <b>It only acts on {@code true}</b>:
 *     "show transitive ones too" is the default, and filtering on {@code false} would hide the
 *     issues whose nature is unknown — the majority on any target with no dependency graph
 * @param onlyKev restricts to actively exploited vulnerabilities, and like {@code onlyDirect}
 *     acts on {@code true} alone. The dashboard has always linked to this filter; nothing read
 *     it, so the most actionable figure on the screen opened the entire backlog
 */
public record IssueFilters(
        String state,
        String severity,
        String type,
        String triageStatus,
        Long repoId,
        Long containerId,
        boolean onlyDirect,
        boolean onlyKev,
        String search,
        boolean excludeSettled,
        Map<Severity, Instant> overdueBefore,
        Visibility visibility) {

    /** Everything the caller asked for, seen by somebody the deployment does not restrict. */
    public IssueFilters(
            String state,
            String severity,
            String type,
            String triageStatus,
            Long repoId,
            Long containerId,
            boolean onlyDirect,
            boolean onlyKev,
            String search) {
        this(state, severity, type, triageStatus, repoId, containerId, onlyDirect, onlyKev, search,
                false, Map.of(), Visibility.everything());
    }

    /** The nine filters a request can carry, with the visibility resolved for its caller. */
    public IssueFilters(
            String state,
            String severity,
            String type,
            String triageStatus,
            Long repoId,
            Long containerId,
            boolean onlyDirect,
            boolean onlyKev,
            String search,
            Visibility visibility) {
        this(state, severity, type, triageStatus, repoId, containerId, onlyDirect, onlyKev, search,
                false, Map.of(), visibility);
    }

    public Specification<IssueEntity> toSpecification() {
        return (root, query, builder) -> {
            List<Predicate> predicates = new ArrayList<>();

            equalIfPresent(predicates, builder, root.get("state"), state);
            equalIfPresent(predicates, builder, root.get("severity"), severity);
            equalIfPresent(predicates, builder, root.get("type"), type);
            equalIfPresent(predicates, builder, root.get("triageStatus"), triageStatus);
            if (repoId != null) {
                predicates.add(builder.equal(root.get("repoId"), repoId));
            }
            if (containerId != null) {
                predicates.add(builder.equal(root.get("containerId"), containerId));
            }
            if (onlyDirect) {
                predicates.add(builder.isTrue(root.get("isDirectDependency")));
            }
            if (onlyKev) {
                predicates.add(builder.isTrue(root.get("isKev")));
            }
            if (excludeSettled) {
                // Named after what it does rather than after the SLA that wanted it: "not
                // dismissed and not fixed" is a filter a backlog screen will want on its own day.
                predicates.add(root.get("triageStatus").in(TriageStatus.unsettledWireNames()));
            }
            if (overdueBefore != null && !overdueBefore.isEmpty()) {
                // **A union, not a single comparison.** Late means "critical older than fifteen
                // days *or* high older than thirty *or* …", so one predicate per severity, or-ed.
                // Expressed here rather than by four queries, so the figure a dashboard shows and
                // the rows this list returns come from the same clause.
                List<Predicate> late = new ArrayList<>();
                overdueBefore.forEach((forSeverity, threshold) -> late.add(builder.and(
                        builder.equal(root.get("severity"), forSeverity.wireName()),
                        builder.lessThan(root.get("firstSeenAt"), threshold))));
                predicates.add(builder.or(late.toArray(Predicate[]::new)));
            }
            visibility.asFilter().ifPresent(allowed -> predicates.add(visible(root, builder, allowed)));

            if (search != null && !search.isBlank()) {
                String pattern = "%" + search.trim().toLowerCase(Locale.ROOT) + "%";
                predicates.add(builder.or(
                        builder.like(builder.lower(root.get("identifier")), pattern),
                        builder.like(builder.lower(root.get("packageName")), pattern),
                        builder.like(builder.lower(root.get("filePath")), pattern)));
            }

            return builder.and(predicates.toArray(Predicate[]::new));
        };
    }

    /**
     * The rows whose target the caller may see.
     *
     * <p>An empty allowance yields {@code builder.disjunction()} — a predicate that is false —
     * rather than no predicate at all. The alternative reads the same in code and means the
     * opposite: an unassigned account would receive the whole backlog.
     */
    private static Predicate visible(
            jakarta.persistence.criteria.Root<IssueEntity> root,
            jakarta.persistence.criteria.CriteriaBuilder builder,
            java.util.Set<ScanTarget> allowed) {

        List<Predicate> perTarget = new ArrayList<>();
        for (ScanTarget target : allowed) {
            switch (target) {
                case ScanTarget.Repository repository ->
                        perTarget.add(builder.equal(root.get("repoId"), repository.id()));
                case ScanTarget.Container container ->
                        perTarget.add(builder.equal(root.get("containerId"), container.id()));
            }
        }
        return perTarget.isEmpty() ? builder.disjunction() : builder.or(perTarget.toArray(Predicate[]::new));
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
