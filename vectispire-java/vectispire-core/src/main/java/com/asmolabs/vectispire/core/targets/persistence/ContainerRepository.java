package com.asmolabs.vectispire.core.targets.persistence;

import java.time.Instant;
import java.util.Collection;
import java.util.List;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Modifying;
import org.springframework.data.jpa.repository.Query;
import org.springframework.data.repository.query.Param;
import org.springframework.transaction.annotation.Transactional;

/** The container images under watch. */
public interface ContainerRepository extends JpaRepository<ContainerEntity, Long> {

    /** See {@link GitRepositoryRepository#stampScheduled}: same reason, same shape. */
    @Transactional
    @Modifying(clearAutomatically = true)
    @Query("update ContainerEntity c set c.lastScheduledScanAt = :at where c.id = :id")
    int stampScheduled(@Param("id") Long id, @Param("at") Instant at);

    /**
     * The images filed in any of these projects, at the moment of asking — what a project grant means
     * for images, as {@link GitRepositoryRepository#findIdsByProjectIdIn} is for repositories.
     *
     * <p>Callers must not pass an empty collection, and pass at most a thousand: the list is bound one
     * parameter per project ({@code TargetsForAccess} batches).
     */
    @Query("select c.id from ContainerEntity c where c.projectId in :projectIds")
    List<Long> findIdsByProjectIdIn(@Param("projectIds") Collection<Long> projectIds);

    /** The images filed in this project now, whole, as {@link GitRepositoryRepository#findByProjectId}. */
    List<ContainerEntity> findByProjectId(Long projectId);

    /** The images filed in any project of this solution, as {@link GitRepositoryRepository#findIdsBySolutionId}. */
    @Query("""
            select c.id from ContainerEntity c
             where c.projectId in (select p.id from ProjectEntity p where p.solutionId = :solutionId)""")
    List<Long> findIdsBySolutionId(@Param("solutionId") Long solutionId);

    /**
     * Files an image into a project, moves it, or — with {@code null} — takes it out of any. The only
     * writer of the column, as {@link GitRepositoryRepository#assignProject} is for repositories.
     */
    @Transactional
    @Modifying(clearAutomatically = true)
    @Query("update ContainerEntity c set c.projectId = :projectId where c.id = :id")
    int assignProject(@Param("id") Long id, @Param("projectId") Long projectId);

    /**
     * Every image of a project back to "no project", for the project's deletion — explicit rather than
     * left to the key's {@code set null}, and counted for the audit entry, as for repositories.
     */
    @Transactional
    @Modifying(clearAutomatically = true)
    @Query("update ContainerEntity c set c.projectId = null where c.projectId = :projectId")
    int detachProject(@Param("projectId") Long projectId);
}
