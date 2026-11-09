package com.asmolabs.vectispire.core.checklists.persistence;

import java.util.Optional;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Modifying;
import org.springframework.data.jpa.repository.Query;
import org.springframework.data.repository.query.Param;
import org.springframework.transaction.annotation.Transactional;

/** The signed documents of signed-off revisions, read one at a time by the document route. */
public interface ChecklistDocumentRepository extends JpaRepository<ChecklistDocumentEntity, Long> {

    Optional<ChecklistDocumentEntity> findByChecklistId(Long checklistId);

    /** A project's documents, for its deletion; found by their own project column, like the proofs' files. */
    @Transactional
    @Modifying(flushAutomatically = true, clearAutomatically = true)
    @Query("delete from ChecklistDocumentEntity d where d.projectId = :projectId")
    int deleteByProject(@Param("projectId") long projectId);
}
