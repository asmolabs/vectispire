package com.asmolabs.vectispire.core.repositories;

import com.asmolabs.vectispire.core.persistence.FindingEntity;
import java.util.List;
import org.springframework.data.domain.Limit;
import org.springframework.data.jpa.repository.Query;
import org.springframework.data.repository.query.Param;
import org.springframework.data.jpa.repository.JpaRepository;

public interface Findings extends JpaRepository<FindingEntity, Long>, FindingGraphQueries {
    List<FindingEntity> findByScanId(Long scanId);

    /**
     * One scan's findings, most severe first and capped.
     *
     * <p>Ordered by rank and not by the stored string: alphabetically, "critical" sorts before
     * "high" by luck and "low" before "medium" by accident, and the list would look sorted while
     * being wrong in the middle.
     */
    @Query("""
            select f from FindingEntity f
             where f.scanId = :scanId
             order by case f.severity
                        when 'critical' then 0 when 'high' then 1 when 'medium' then 2
                        when 'low' then 3 when 'negligible' then 4 else 5 end asc,
                      f.id asc""")
    List<FindingEntity> findByScanId(@Param("scanId") Long scanId, Limit limit);

    /**
     * The findings of several scans at once.
     *
     * <p>For a page showing a whole dossier: asking scan by scan turns fifty scans into fifty
     * round trips, which is invisible on a demo database and is not on a real history.
     */
    List<FindingEntity> findByScanIdIn(java.util.Collection<Long> scanIds);

    /**
     * The licence findings of these scans.
     *
     * <p>The predicate was applied in Java over every finding in the deployment — {@code type =
     * 'license'} or a source naming one — which is a whole-table read to keep a handful of rows.
     */
    @Query("""
            select f from FindingEntity f
             where f.scanId in :scanIds
               and (lower(f.type) = 'license' or lower(f.source) like '%license%')""")
    List<FindingEntity> findLicenseFindings(@Param("scanIds") java.util.Collection<Long> scanIds);

    /**
     * Every scan that observed one issue, newest first, with the scan itself.
     *
     * <p>The sighting list of a detail page. An issue carries {@code firstSeenScanId} and
     * {@code lastSeenScanId} and nothing between them; "seen in 1.17.4, still in 1.17.6, gone in
     * 1.18.0" is a question about the findings, and the join to the scan is what supplies the
     * version each sighting happened on.
     */
    @Query("""
            select f, s from FindingEntity f, ScanEntity s
             where f.scanId = s.id and f.issueId = :issueId
             order by s.createdAt desc, s.id desc""")
    List<Object[]> sightingsOf(@Param("issueId") Long issueId, Limit limit);

    long countByScanId(Long scanId);

    long countByScanIdAndSeverity(Long scanId, String severity);

    void deleteByScanIdIn(java.util.Collection<Long> scanIds);

    void deleteByIssueIdIn(java.util.Collection<Long> issueIds);
}
