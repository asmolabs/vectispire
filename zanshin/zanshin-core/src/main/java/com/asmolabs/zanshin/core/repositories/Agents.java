package com.asmolabs.zanshin.core.repositories;

import com.asmolabs.zanshin.core.persistence.AgentEntity;
import java.time.Instant;
import java.util.Optional;
import java.util.UUID;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Modifying;
import org.springframework.data.jpa.repository.Query;
import org.springframework.data.repository.query.Param;
import org.springframework.transaction.annotation.Transactional;

/** The workers allowed to run scans, remote and built-in alike. */
public interface Agents extends JpaRepository<AgentEntity, UUID> {

    Optional<AgentEntity> findByApiKeyId(UUID apiKeyId);

    Optional<AgentEntity> findByName(String name);

    /**
     * Records that an agent has just been heard from, and what it announced.
     *
     * <p>The sealing key is refreshed on every claim on purpose: it is ephemeral, a restarted
     * agent is a new recipient, and sealing for the key it announced last week would produce an
     * envelope it cannot open — which reads as a failed scan, not as a stale key.
     */
    @Transactional
    @Modifying(clearAutomatically = true)
    @Query("""
            update AgentEntity a
               set a.lastSeenAt = :at, a.hostname = :hostname, a.platform = :platform,
                   a.version = :version, a.scannerEngine = :scannerEngine,
                   a.capabilities = :capabilities, a.contractVersion = :contractVersion,
                   a.sealingPublicKey = :sealingPublicKey
             where a.id = :id""")
    int recordHeartbeat(
            @Param("id") UUID id,
            @Param("at") Instant at,
            @Param("hostname") String hostname,
            @Param("platform") String platform,
            @Param("version") String version,
            @Param("scannerEngine") String scannerEngine,
            @Param("capabilities") String capabilities,
            @Param("contractVersion") String contractVersion,
            @Param("sealingPublicKey") String sealingPublicKey);
}
