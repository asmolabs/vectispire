package com.asmolabs.vectispire.core.inventory.persistence;

import java.time.Instant;
import java.util.List;
import org.springframework.data.domain.Pageable;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Modifying;
import org.springframework.data.jpa.repository.Query;
import org.springframework.data.repository.query.Param;
import org.springframework.transaction.annotation.Transactional;

/** The accepted build SBOMs. */
public interface BuildSbomRepository extends JpaRepository<BuildSbomEntity, Long> {

    /** A repository's imports, newest first — newest by id, which the engines hand out in writing order. */
    List<BuildSbomEntity> findByRepoIdOrderByIdDesc(long repoId, Pageable page);

    /**
     * The newest import of a repository that may speak for a scan of {@code branch}: one stating that
     * branch, or none. A page of one, newest by id.
     */
    @Query("""
            select b from BuildSbomEntity b
             where b.repoId = :repoId and (b.branch is null or b.branch = :branch)
             order by b.id desc""")
    List<BuildSbomEntity> newestFor(@Param("repoId") long repoId, @Param("branch") String branch, Pageable page);

    /** The imports accepted before an instant — the evidence window's purge reads their ids first. */
    @Query("select b.id from BuildSbomEntity b where b.importedAt < :before")
    List<Long> idsImportedBefore(@Param("before") Instant before, Pageable page);

    /** A repository's import ids, when the repository goes. */
    @Query("select b.id from BuildSbomEntity b where b.repoId = :repoId")
    List<Long> idsOfRepository(@Param("repoId") long repoId);

    @Transactional
    @Modifying(flushAutomatically = true, clearAutomatically = true)
    @Query("delete from BuildSbomEntity b where b.id in :ids")
    int deleteByIds(@Param("ids") List<Long> ids);
}
