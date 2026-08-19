package com.asmolabs.zanshin.core.repositories;

import com.asmolabs.zanshin.common.domain.access.Visibility;
import com.asmolabs.zanshin.common.domain.targets.ScanTarget;
import com.asmolabs.zanshin.core.persistence.IssueEntity;
import jakarta.persistence.criteria.Predicate;
import java.util.ArrayList;
import java.util.List;
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
 */
public record IssueFilters(
        String state,
        String severity,
        String type,
        String triageStatus,
        Long repoId,
        Long containerId,
        boolean onlyDirect,
        String search,
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
            String search) {
        this(state, severity, type, triageStatus, repoId, containerId, onlyDirect, search,
                Visibility.everything());
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
