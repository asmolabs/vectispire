package com.asmolabs.zanshin.core.repositories;

import com.asmolabs.zanshin.core.persistence.ThreatIntelEntity;
import java.util.Optional;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.stereotype.Repository;

@Repository
public interface ThreatIntels extends JpaRepository<ThreatIntelEntity, String> {
    Optional<ThreatIntelEntity> findByCveIdIgnoreCase(String cveId);
}
