package com.asmolabs.vectispire.core.repositories;

import com.asmolabs.vectispire.core.persistence.ComponentEntity;
import java.util.Collection;
import java.util.List;
import org.springframework.data.domain.Limit;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Query;
import org.springframework.data.repository.query.Param;

public interface Components extends JpaRepository<ComponentEntity, Long> {

    /**
     * Where a component was seen, and in which version of which project.
     *
     * <p><b>The join to the scan is the answer, not a detail.</b> "Do we ship log4j 2.14.1" is
     * only half a question: what the person asking needs is the release it went out in, so they
     * can say which of their deliveries is affected. The scan carries that — its target and the
     * project version read from the manifest — so the component alone would answer "yes,
     * somewhere, once".
     *
     * <p>The version filter is optional and matched exactly: a search for {@code 2.14.1} must not
     * return {@code 2.14.10}, which is a different release with a different verdict. The name is
     * matched loosely, because nobody remembers whether it is {@code log4j-core} or
     * {@code org.apache.logging.log4j:log4j-core}.
     */
    @Query("""
            select c, s from ComponentEntity c, ScanEntity s
             where c.scanId = s.id
               and (lower(c.name) like :name or lower(c.purl) like :name)
               and (:version is null or c.version = :version)
             order by s.createdAt desc, c.name asc""")
    List<Object[]> search(@Param("name") String name, @Param("version") String version, Limit limit);

    /** Every version of one component ever catalogued, for the filter the screen offers. */
    @Query("""
            select distinct c.version from ComponentEntity c
             where lower(c.name) like :name or lower(c.purl) like :name
             order by c.version desc""")
    List<String> versionsOf(@Param("name") String name, Limit limit);

    List<ComponentEntity> findByScanId(long scanId);

    List<ComponentEntity> findByScanIdIn(Collection<Long> scanIds);

    void deleteByScanId(long scanId);

    void deleteByScanIdIn(Collection<Long> scanIds);

    long countByScanIdIn(Collection<Long> scanIds);
}
