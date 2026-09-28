package com.asmolabs.vectispire.core.plugins.persistence;

import java.util.Collection;
import java.util.List;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Modifying;
import org.springframework.data.jpa.repository.Query;
import org.springframework.data.repository.query.Param;
import org.springframework.transaction.annotation.Transactional;

/** The suites of the accepted test reports. */
public interface TestSuiteResultRepository extends JpaRepository<TestSuiteResultEntity, Long> {

    /** The suites of the imports named, in the order they were read; the caller batches the ids. */
    List<TestSuiteResultEntity> findByImportIdInOrderByImportIdAscIdAsc(Collection<Long> importIds);

    /**
     * The suites of a repository's imports, before the imports themselves go: the subquery reaches
     * them through the import rows, so it must run while those still exist.
     */
    @Transactional
    @Modifying(flushAutomatically = true, clearAutomatically = true)
    @Query("delete from TestSuiteResultEntity s where s.importId in "
            + "(select t.id from TestReportImportEntity t where t.repoId = :repositoryId)")
    int deleteByRepository(@Param("repositoryId") long repositoryId);
}
