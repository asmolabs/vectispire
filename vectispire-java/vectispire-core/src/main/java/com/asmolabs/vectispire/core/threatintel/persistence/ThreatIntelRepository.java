package com.asmolabs.vectispire.core.threatintel.persistence;

import java.util.Collection;
import java.util.List;
import java.util.Optional;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Query;
import org.springframework.data.repository.query.Param;
import org.springframework.stereotype.Repository;

@Repository
public interface ThreatIntelRepository extends JpaRepository<ThreatIntelEntity, String> {
    Optional<ThreatIntelEntity> findByCveIdIgnoreCase(String cveId);

    /**
     * The intel for many CVE ids at once, matched case-insensitively.
     *
     * <p><b>One query where the sync used one per issue.</b> Written as JPQL rather than a derived
     * {@code findByCveIdIn} because the ids in {@code t_issue} and the ids from the feed do not
     * agree on case, and a derived {@code In} compares them as given.
     */
    @Query("select t from ThreatIntelEntity t where lower(t.cveId) in :ids")
    List<ThreatIntelEntity> findByCveIdInIgnoreCase(@Param("ids") Collection<String> ids);

    /**
     * Those of these identifiers the stored KEV catalogue lists, as stored (upper-case).
     *
     * @param ids lower-case, for the reason {@link #findByCveIdInIgnoreCase} gives
     */
    @Query("select t.cveId from ThreatIntelEntity t where t.isKev = true and lower(t.cveId) in :ids")
    List<String> exploitedAmong(@Param("ids") Collection<String> ids);
}
