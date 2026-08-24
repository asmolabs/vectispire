package com.asmolabs.zanshin.core.repositories;

import com.asmolabs.zanshin.core.persistence.AiReviewResultEntity;
import java.util.List;
import org.springframework.data.domain.Limit;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Query;
import org.springframework.data.repository.query.Param;

public interface AiReviewResults extends JpaRepository<AiReviewResultEntity, Long> {

    /**
     * The most recent report about one repository, whichever scan it was built from.
     *
     * <p>Keyed through the scan rather than stored against the repository: a report is a
     * statement about a moment, and the scan is what dates it and names the version. Asking for
     * "the latest" is then a question about scans, which is the only ordering that means
     * anything here.
     */
    @Query("""
            select r from AiReviewResultEntity r, ScanEntity s
             where r.scanId = s.id and s.repoId = :repoId
             order by r.createdAt desc, r.id desc""")
    List<AiReviewResultEntity> latestForRepository(@Param("repoId") long repoId, Limit limit);

    void deleteByScanIdIn(java.util.Collection<Long> scanIds);
}
