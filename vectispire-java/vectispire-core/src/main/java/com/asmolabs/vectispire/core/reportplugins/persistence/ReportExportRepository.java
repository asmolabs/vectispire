package com.asmolabs.vectispire.core.reportplugins.persistence;

import java.time.Instant;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Modifying;
import org.springframework.data.jpa.repository.Query;
import org.springframework.data.repository.query.Param;
import org.springframework.transaction.annotation.Transactional;

/**
 * The exports produced runs were given. Read by id only; nothing lists them. How large one may be is the
 * database's to say ({@link ReportExportCapacity}).
 */
public interface ReportExportRepository extends JpaRepository<ReportExportEntity, Long>, ReportExportCapacity {

    /** The exports kept past the evidence window — the bytes go, the run and its digest stay. */
    @Transactional
    @Modifying(flushAutomatically = true, clearAutomatically = true)
    @Query("delete from ReportExportEntity e where e.createdAt < :cutoff")
    int deleteCreatedBefore(@Param("cutoff") Instant cutoff);

    /** Every export of a project that is going away — its listener's, in the deleting transaction. */
    @Transactional
    @Modifying(flushAutomatically = true, clearAutomatically = true)
    @Query("delete from ReportExportEntity e where e.runId in "
            + "(select r.id from ReportRunEntity r where r.projectId = :projectId)")
    int deleteByProject(@Param("projectId") long projectId);
}
