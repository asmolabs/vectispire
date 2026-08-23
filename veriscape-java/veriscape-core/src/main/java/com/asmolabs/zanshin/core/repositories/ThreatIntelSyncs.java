package com.asmolabs.zanshin.core.repositories;

import com.asmolabs.zanshin.core.persistence.ThreatIntelSyncEntity;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.stereotype.Repository;

@Repository
public interface ThreatIntelSyncs extends JpaRepository<ThreatIntelSyncEntity, Long> {
}
