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
     * ScanQueue.claimWithin}. {@code select … for update} would do the same on PostgreSQL and MySQL;
     * the write was chosen while the SQLite fixture, which has no row lock, was among the engines,
     * and it stays because the column written is the one a claim makes true anyway and the claim's
     * interleaving is what {@code ScanQueueIntegrationTest} forces on both engines.
     *
     * @return 0 when the agent no longer exists
     */
    @Transactional
    @Modifying(clearAutomatically = true)
    @Query("update AgentEntity a set a.lastSeenAt = :at where a.id = :id")
    int lockForClaim(@Param("id") UUID id, @Param("at") Instant at);

    /**
     * Records that an agent was heard from, <b>unless it already was since {@code staleBefore}</b>.
     *
     * <p>Conditional so that a fleet polling every few seconds does not write its rows at the same
     * rate: the column feeds "online", a two-minute window, and a write per poll per agent would buy
     * nothing it does not already say. The condition is in the statement rather than read first, so
     * two polls of one agent racing on it write once or twice, never an older instant over a newer.
     *
     * @return 0 when the row was recent enough, or the agent no longer exists
     */
    @Transactional
    @Modifying(clearAutomatically = true)
    @Query("""
            update AgentEntity a set a.lastSeenAt = :at
             where a.id = :id and (a.lastSeenAt is null or a.lastSeenAt < :staleBefore)""")
    int recordSeen(@Param("id") UUID id, @Param("at") Instant at, @Param("staleBefore") Instant staleBefore);

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
