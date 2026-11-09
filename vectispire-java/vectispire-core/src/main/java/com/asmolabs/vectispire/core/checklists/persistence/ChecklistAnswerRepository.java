package com.asmolabs.vectispire.core.checklists.persistence;

import java.util.List;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Modifying;
import org.springframework.data.jpa.repository.Query;
import org.springframework.data.repository.query.Param;
import org.springframework.transaction.annotation.Transactional;

/**
 * The answers of the checklists — append-only: this interface declares no update, and the one delete
 * is a project's deletion. A service that saved a row it had read would rewrite the history the table
 * exists to keep.
 */
public interface ChecklistAnswerRepository extends JpaRepository<ChecklistAnswerEntity, Long> {

    /** Every answer of a revision, oldest first: the newest per item is the current one. */
    List<ChecklistAnswerEntity> findByChecklistIdOrderByIdAsc(Long checklistId);

    /** One line's history, oldest first. */
    List<ChecklistAnswerEntity> findByChecklistIdAndItemIdOrderByIdAsc(Long checklistId, Long itemId);

    /** A project's answers, for its deletion; before its checklists, which they are found through. */
    @Transactional
    @Modifying(flushAutomatically = true, clearAutomatically = true)
    @Query("delete from ChecklistAnswerEntity a where a.checklistId in"
            + " (select c.id from ChecklistEntity c where c.projectId = :projectId)")
    int deleteByProject(@Param("projectId") long projectId);
}
