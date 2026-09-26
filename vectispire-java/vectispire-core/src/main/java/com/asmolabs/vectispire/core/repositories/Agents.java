package com.asmolabs.vectispire.core.repositories;

import com.asmolabs.vectispire.core.persistence.AgentEntity;
import java.time.Instant;
import java.util.List;
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

    List<AgentEntity> findAllByOrderByNameAsc();

    List<AgentEntity> findByEnabledTrue();

    /**
     * Takes the agent's row for the rest of the transaction, and records that it was heard from.
     *
     * <p><b>A write because a write is what every engine serializes</b> — see {@code
     * ScanQueue.claimWithin}. {@code select … for update} would do on PostgreSQL and MySQL and
     * nothing on SQLite, where it is not even syntax, and a read there pins a snapshot whose later
     * upgrade to a write is refused at once with {@code SQLITE_BUSY} instead of waiting. The
     * column written is the one a claim makes true anyway.
     *
     * @return 0 when the agent no longer exists
     */
    @Transactional
    @Modifying(clearAutomatically = true)
    @Query("update AgentEntity a set a.lastSeenAt = :at where a.id = :id")
    int lockForClaim(@Param("id") UUID id, @Param("at") Instant at);

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
