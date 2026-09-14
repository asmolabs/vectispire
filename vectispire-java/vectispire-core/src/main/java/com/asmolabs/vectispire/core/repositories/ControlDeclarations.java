package com.asmolabs.vectispire.core.repositories;

import com.asmolabs.vectispire.core.persistence.ControlDeclarationEntity;
import java.time.Instant;
import java.util.List;
import java.util.Optional;
import java.util.UUID;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Query;
import org.springframework.data.repository.query.Param;

/**
 * The declaration of applicability, by framework.
 *
 * <p><b>No visibility clause anywhere below, and for once that is not the usual reason.</b> A
 * declaration is a statement about the management system, not about a repository: "is A.8.28
 * applicable to us" has no target to belong to, so there is nothing for an allowance to narrow.
 * The routes are gated on the role instead.
 */
public interface ControlDeclarations extends JpaRepository<ControlDeclarationEntity, UUID> {

    List<ControlDeclarationEntity> findByFramework(String framework);

    Optional<ControlDeclarationEntity> findByFrameworkAndControlId(String framework, String controlId);

    /** Lines whose review has lapsed — the ISMS dashboard's question, across every framework. */
    @Query("""
            select d from ControlDeclarationEntity d
             where d.reviewDueAt is not null and d.reviewDueAt < :now
             order by d.reviewDueAt asc""")
    List<ControlDeclarationEntity> findReviewOverdue(@Param("now") Instant now);
}
