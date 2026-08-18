package com.asmolabs.zanshin.core.repositories;

import com.asmolabs.zanshin.core.persistence.FindingEntity;
import java.util.List;
import org.springframework.data.domain.Limit;
import org.springframework.data.jpa.repository.Query;
import org.springframework.data.repository.query.Param;
import org.springframework.data.jpa.repository.JpaRepository;

public interface Findings extends JpaRepository<FindingEntity, Long> {
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

    long countByScanId(Long scanId);
}
