package com.asmolabs.vectispire.core.repositories;

import com.asmolabs.vectispire.core.persistence.ThreatIntelSyncEntity;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.stereotype.Repository;

@Repository
public interface ThreatIntelSyncs extends JpaRepository<ThreatIntelSyncEntity, Long> {
}
