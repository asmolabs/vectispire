package com.asmolabs.vectispire.core.checklists.persistence;

import java.util.List;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Modifying;
import org.springframework.data.jpa.repository.Query;
import org.springframework.data.repository.query.Param;
import org.springframework.transaction.annotation.Transactional;

/**
 * The stored measurements of the checklists — append-only, like the answers: no update, and the one
 * delete is a project's deletion.
 */
public interface ChecklistMeasurementRepository extends JpaRepository<ChecklistMeasurementEntity, Long> {

    /** A revision's measurements stored for one purpose, oldest first: the newest per line is the one relied on. */
    List<ChecklistMeasurementEntity> findByChecklistIdAndPurposeOrderByIdAsc(Long checklistId, String purpose);

    /** A project's measurements, for its deletion; before its checklists, which they are found through. */
    @Transactional
    @Modifying(flushAutomatically = true, clearAutomatically = true)
    @Query("delete from ChecklistMeasurementEntity m where m.checklistId in"
            + " (select c.id from ChecklistEntity c where c.projectId = :projectId)")
    int deleteByProject(@Param("projectId") long projectId);
}
