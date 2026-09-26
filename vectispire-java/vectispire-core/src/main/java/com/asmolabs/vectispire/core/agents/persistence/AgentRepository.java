package com.asmolabs.vectispire.core.agents.persistence;

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
public interface AgentRepository extends JpaRepository<AgentEntity, UUID> {

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
     * Records that an agent has just been heard from, and what it said about itself.
     *
     * <p><b>Not the sealing key</b>, which this statement wrote until decision 0031 — from every
     * {@code hello}, unsigned, and blank included, so the last announcement to arrive decided what
     * the control plane sealed for. The key is {@link #acceptSealingKey}'s alone now, and an
     * announcement that carries none, or one nobody signed, leaves the accepted key where it is.
     */
    @Transactional
    @Modifying(clearAutomatically = true)
    @Query("""
            update AgentEntity a
               set a.lastSeenAt = :at, a.hostname = :hostname, a.platform = :platform,
                   a.version = :version, a.scannerEngine = :scannerEngine,
                   a.capabilities = :capabilities, a.contractVersion = :contractVersion
             where a.id = :id""")
    int recordHeartbeat(
            @Param("id") UUID id,
            @Param("at") Instant at,
            @Param("hostname") String hostname,
            @Param("platform") String platform,
            @Param("version") String version,
            @Param("scannerEngine") String scannerEngine,
            @Param("capabilities") String capabilities,
            @Param("contractVersion") String contractVersion);

    /**
     * Records a sealing key whose signature the caller verified, <b>if it is newer</b> than the one
     * held.
     *
     * <p>A conditional statement, not a read then a save: two processes sharing an agent's key, or a
     * recorded announcement sent again, would otherwise let whichever wrote last win. The row count
     * names the outcome — 0 means the agent already holds a newer key (or no longer exists), and the
     * key offered is not the one to seal for. The same key under the same generation is accepted
     * again, so an agent repeating its announcement is not refused for being consistent.
     *
     * @return 1 when the key is now the agent's, 0 otherwise
     */
    @Transactional
    @Modifying(clearAutomatically = true)
    @Query("""
            update AgentEntity a
               set a.sealingPublicKey = :key, a.sealingKeyGeneration = :generation
             where a.id = :id
               and (a.sealingKeyGeneration is null
                    or a.sealingKeyGeneration < :generation
                    or (a.sealingKeyGeneration = :generation and a.sealingPublicKey = :key))""")
    int acceptSealingKey(@Param("id") UUID id, @Param("key") String key, @Param("generation") long generation);

    /**
     * Forgets the agent's sealing key and its generation: an administrator's reset, or a signing key
     * pinned anew, which no longer vouches for the key the old one signed.
     *
     * <p>Until the agent announces a key signed with its pinned key again, it is handed no delegated
     * credential — never a clear one.
     *
     * @return 0 when the agent no longer exists
     */
    @Transactional
    @Modifying(clearAutomatically = true, flushAutomatically = true)
    @Query("update AgentEntity a set a.sealingPublicKey = null, a.sealingKeyGeneration = null where a.id = :id")
    int forgetSealingKey(@Param("id") UUID id);
}
