package com.asmolabs.vectispire.core.checklists.persistence;

import java.time.Instant;
import java.util.List;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Modifying;
import org.springframework.data.jpa.repository.Query;
import org.springframework.data.repository.query.Param;
import org.springframework.transaction.annotation.Transactional;

/** The proofs attached to checklist lines: added, withdrawn, never deleted but with their project. */
public interface ChecklistEvidenceRepository extends JpaRepository<ChecklistEvidenceEntity, Long> {

    List<ChecklistEvidenceEntity> findByChecklistIdOrderByIdAsc(Long checklistId);

    List<ChecklistEvidenceEntity> findByChecklistIdAndItemIdOrderByIdAsc(Long checklistId, Long itemId);

    /** Withdraws a proof, if nobody has yet: the withdrawal is dated and attributed, the row kept. */
    @Transactional
    @Modifying(flushAutomatically = true, clearAutomatically = true)
    @Query("update ChecklistEvidenceEntity e set e.withdrawnAt = :at, e.withdrawnBy = :by, e.withdrawnById = :byId,"
            + " e.withdrawnEdition = :edition where e.id = :id and e.withdrawnAt is null")
    int withdraw(
            @Param("id") long id,
            @Param("at") Instant at,
            @Param("by") String by,
            @Param("byId") long byId,
            @Param("edition") int edition);

    /** A project's proofs, for its deletion; before its checklists, which they are found through. */
    @Transactional
    @Modifying(flushAutomatically = true, clearAutomatically = true)
    @Query("delete from ChecklistEvidenceEntity e where e.checklistId in"
            + " (select c.id from ChecklistEntity c where c.projectId = :projectId)")
    int deleteByProject(@Param("projectId") long projectId);
}
