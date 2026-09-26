package com.asmolabs.vectispire.core.threatintel.persistence;

import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.stereotype.Repository;

@Repository
public interface ThreatIntelSyncs extends JpaRepository<ThreatIntelSyncEntity, Long> {
}
