package com.asmolabs.vectispire.core.plugins.persistence;

import java.util.Collection;
import java.util.List;
import org.springframework.data.domain.Pageable;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Modifying;
import org.springframework.data.jpa.repository.Query;
import org.springframework.data.repository.query.Param;
import org.springframework.transaction.annotation.Transactional;

/** The accepted coverage imports. */
public interface CoverageImportRepository extends JpaRepository<CoverageImportEntity, Long> {

    List<CoverageImportEntity> findByRepoIdOrderByImportedAtDescIdDesc(long repoId, Pageable page);

    /**
     * The newest import of each repository named — newest by id, which the engines hand out in the
     * order the rows were written, so two imports in the same instant still have one newest. The
     * caller batches the ids: an {@code in} list sized by the data fails one day.
     */
    @Query("select c from CoverageImportEntity c where c.repoId in :repositoryIds and c.id = "
            + "(select max(o.id) from CoverageImportEntity o where o.repoId = c.repoId)")
    List<CoverageImportEntity> findNewestByRepoIdIn(@Param("repositoryIds") Collection<Long> repositoryIds);

    /** A repository's imports, when the repository goes — its listener's, in the deleting transaction. */
    @Transactional
    @Modifying(flushAutomatically = true, clearAutomatically = true)
    @Query("delete from CoverageImportEntity c where c.repoId = :repositoryId")
    int deleteByRepository(@Param("repositoryId") long repositoryId);
}
