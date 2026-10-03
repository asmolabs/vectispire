package com.asmolabs.vectispire.core.reportplugins.persistence;

import java.time.Instant;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Modifying;
import org.springframework.data.jpa.repository.Query;
import org.springframework.data.repository.query.Param;
import org.springframework.transaction.annotation.Transactional;

/** The packages produced runs are downloaded as. Read by run id only; nothing lists them. */
public interface ReportDocumentRepository extends JpaRepository<ReportDocumentEntity, Long> {

    /** The packages kept past the evidence window — the bytes go, the run and its digests stay. */
    @Transactional
    @Modifying(flushAutomatically = true, clearAutomatically = true)
    @Query("delete from ReportDocumentEntity d where d.createdAt < :cutoff")
    int deleteCreatedBefore(@Param("cutoff") Instant cutoff);

    /** Every package of a project that is going away — its listener's, in the deleting transaction. */
    @Transactional
    @Modifying(flushAutomatically = true, clearAutomatically = true)
    @Query("delete from ReportDocumentEntity d where d.runId in "
            + "(select r.id from ReportRunEntity r where r.projectId = :projectId)")
    int deleteByProject(@Param("projectId") long projectId);
}
