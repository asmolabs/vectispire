package com.asmolabs.vectispire.core.checklists.persistence;

import java.util.List;
import java.util.Optional;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Modifying;
import org.springframework.data.jpa.repository.Query;
import org.springframework.data.repository.query.Param;
import org.springframework.transaction.annotation.Transactional;

/** The accounts a project's checklist profiles are linked to (decision 0044). */
public interface ChecklistContactRepository extends JpaRepository<ChecklistContactEntity, Long> {

    List<ChecklistContactEntity> findByProjectIdOrderByProfileAsc(Long projectId);

    Optional<ChecklistContactEntity> findByProjectIdAndProfile(Long projectId, String profile);

    @Transactional
    @Modifying(flushAutomatically = true, clearAutomatically = true)
    @Query("delete from ChecklistContactEntity c where c.projectId = :projectId and c.profile = :profile")
    int deleteLink(@Param("projectId") long projectId, @Param("profile") String profile);

    /** A project's links, for its deletion. */
    @Transactional
    @Modifying(flushAutomatically = true, clearAutomatically = true)
    @Query("delete from ChecklistContactEntity c where c.projectId = :projectId")
    int deleteByProject(@Param("projectId") long projectId);
}
