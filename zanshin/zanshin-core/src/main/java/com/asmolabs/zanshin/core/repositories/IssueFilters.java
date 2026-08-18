package com.asmolabs.zanshin.core.repositories;

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
        String search) {

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
