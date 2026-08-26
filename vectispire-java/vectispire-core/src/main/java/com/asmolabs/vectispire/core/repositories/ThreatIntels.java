package com.asmolabs.vectispire.core.repositories;

import com.asmolabs.vectispire.core.persistence.ThreatIntelEntity;
import java.util.List;
import java.util.Optional;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.stereotype.Repository;

@Repository
public interface ThreatIntels extends JpaRepository<ThreatIntelEntity, String> {
    Optional<ThreatIntelEntity> findByCveIdIgnoreCase(String cveId);

    /**
     * The intel for many CVE ids at once, matched case-insensitively.
     *
     * <p><b>One query where the sync used one per issue.</b> Written as JPQL rather than a derived
     * {@code findByCveIdIn} because the ids in {@code t_issue} and the ids from the feed do not
     * agree on case, and a derived {@code In} compares them as given.
     */
    @org.springframework.data.jpa.repository.Query(
            "select t from ThreatIntelEntity t where lower(t.cveId) in :ids")
    List<ThreatIntelEntity> findByCveIdInIgnoreCase(
            @org.springframework.data.repository.query.Param("ids") java.util.Collection<String> ids);
}
