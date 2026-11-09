package com.asmolabs.vectispire.core.plugins.persistence;

import java.util.Collection;
import java.util.List;
import org.springframework.data.domain.Pageable;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Modifying;
import org.springframework.data.jpa.repository.Query;
import org.springframework.data.repository.query.Param;
import org.springframework.transaction.annotation.Transactional;

/** The accepted test-report imports. */
public interface TestReportImportRepository extends JpaRepository<TestReportImportEntity, Long> {

    List<TestReportImportEntity> findByRepoIdOrderByImportedAtDescIdDesc(long repoId, Pageable page);

    /** The newest import of each repository named, by id; the caller batches the ids. */
    @Query("select t from TestReportImportEntity t where t.repoId in :repositoryIds and t.id = "
            + "(select max(o.id) from TestReportImportEntity o where o.repoId = t.repoId)")
    List<TestReportImportEntity> findNewestByRepoIdIn(@Param("repositoryIds") Collection<Long> repositoryIds);

    /** A repository's imports, when the repository goes; their suites are removed first. */
    @Transactional
    @Modifying(flushAutomatically = true, clearAutomatically = true)
    @Query("delete from TestReportImportEntity t where t.repoId = :repositoryId")
    int deleteByRepository(@Param("repositoryId") long repositoryId);
}
