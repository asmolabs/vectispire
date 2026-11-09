package com.asmolabs.vectispire.core.checklists.persistence;

import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Modifying;
import org.springframework.data.jpa.repository.Query;
import org.springframework.data.repository.query.Param;
import org.springframework.transaction.annotation.Transactional;

/** The bytes of uploaded proofs, read one at a time by the download and by nothing that lists. */
public interface ChecklistFileRepository extends JpaRepository<ChecklistFileEntity, Long> {

    /** A project's files, for its deletion. */
    @Transactional
    @Modifying(flushAutomatically = true, clearAutomatically = true)
    @Query("delete from ChecklistFileEntity f where f.projectId = :projectId")
    int deleteByProject(@Param("projectId") long projectId);
}
