package com.asmolabs.zanshin.core.repositories;

import com.asmolabs.zanshin.core.persistence.AuditLogEntity;
import com.asmolabs.zanshin.core.persistence.ContainerEntity;
import com.asmolabs.zanshin.core.persistence.FindingEntity;
import com.asmolabs.zanshin.core.persistence.IssueEntity;
import com.asmolabs.zanshin.core.persistence.LoginAttemptEntity;
import com.asmolabs.zanshin.core.persistence.RepositoryEntity;
import com.asmolabs.zanshin.core.persistence.SemgrepRuleSetEntity;
import com.asmolabs.zanshin.core.persistence.SessionEntity;
import com.asmolabs.zanshin.core.persistence.SshKeyEntity;
import com.asmolabs.zanshin.core.persistence.SettingEntity;
import com.asmolabs.zanshin.core.persistence.UserEntity;
import java.time.Instant;
import java.util.List;
import java.util.Optional;
import java.util.UUID;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Modifying;
import org.springframework.data.jpa.repository.Query;
import org.springframework.data.repository.query.Param;

/**
 * The repositories whose whole content is a derived query.
 *
 * <p>Grouped in one file on purpose: each is three lines, and nineteen files of three lines
 * makes "which queries exist" a directory listing instead of something you can read. The ones
 * that carry a decision — the queue's claim, the audit chain's ordering — live on their own,
 * where the reasoning has somewhere to go.
 */
public final class Repositories {

    private Repositories() {}

    public interface Users extends JpaRepository<UserEntity, Long> {
        Optional<UserEntity> findByUsername(String username);

        /**
         * How many active administrators there are apart from this one.
         *
         * <p>The count the lockout rules consume. Asked of the database rather than of a loaded
         * list, because two administrators demoting each other in parallel is exactly the case
         * a stale in-memory count gets wrong.
         */
        @Query("""
                select count(u) from UserEntity u
                 where u.isActive = true and u.role in :adminRoles and u.id <> :excluding""")
        long countActiveAdministratorsExcluding(
                @Param("adminRoles") List<String> adminRoles, @Param("excluding") Long excluding);
    }

    public interface Sessions extends JpaRepository<SessionEntity, String> {
        void deleteByUserId(Long userId);

        /** Sessions past their absolute lifetime, whatever their idle state. */
        @Modifying
        @Query("delete from SessionEntity s where s.expiresAt < :asOf")
        int deleteExpired(@Param("asOf") Instant asOf);
    }

    public interface LoginAttempts extends JpaRepository<LoginAttemptEntity, UUID> {
        List<LoginAttemptEntity> findByCounterKeyAndOccurredAtAfter(String counterKey, Instant after);

        /**
         * Drops what has left the window.
         *
         * <p>Without it the table grows for every failed login ever made, and the throttle's own
         * query slows down in proportion to how long the deployment has been under attack.
         */
        @Modifying
        @Query("delete from LoginAttemptEntity a where a.occurredAt < :cutoff")
        int deleteBefore(@Param("cutoff") Instant cutoff);
    }

    public interface Settings extends JpaRepository<SettingEntity, String> {
        /**
         * Writes a value onto an existing row, and says whether there was one.
         *
         * <p>Zero rows means "the key has never been set", which is the only signal the caller
         * needs to decide between an update and an insert without a read of its own.
         */
        @Modifying(clearAutomatically = true, flushAutomatically = true)
        @Query("update SettingEntity s set s.value = :value where s.key = :key")
        int updateValue(@Param("key") String key, @Param("value") String value);
    }

    public interface MonitoredRepositories extends JpaRepository<RepositoryEntity, Long> {}

    public interface Containers extends JpaRepository<ContainerEntity, Long> {}

    public interface SshKeys extends JpaRepository<SshKeyEntity, UUID> {}

    public interface Findings extends JpaRepository<FindingEntity, Long> {
        List<FindingEntity> findByScanId(Long scanId);
    }

    public interface Issues extends JpaRepository<IssueEntity, Long> {
        Optional<IssueEntity> findByFingerprint(String fingerprint);

        List<IssueEntity> findByFingerprintIn(java.util.Collection<String> fingerprints);

        /**
         * The open issues of one target, restricted to the types a scan actually looked at.
         *
         * <p>The type filter is the whole safety of the resolution pass: without it a scan that
         * only looked for secrets would resolve the target's vulnerabilities as well.
         */
        @Query("""
                select i from IssueEntity i
                 where i.state = :state and i.type in :types
                   and ((:repoId is not null and i.repoId = :repoId)
                        or (:containerId is not null and i.containerId = :containerId))""")
        List<IssueEntity> findOpenByTarget(
                @Param("state") String state,
                @Param("types") java.util.Collection<String> types,
                @Param("repoId") Long repoId,
                @Param("containerId") Long containerId);

        /**
         * Open issues of one type, counted by the identifier that produced them.
         *
         * <p>Read from the issue alone: it carries its own type and identifier, and that
         * identifier <em>is</em> the analyser's rule id. Joining the findings to reach it would
         * add a join for a column already here, and would count an issue once per scan that saw
         * it.
         */
        @Query("""
                select i.identifier, count(i.id) from IssueEntity i
                 where i.state = :state and i.type = :type and i.identifier is not null
                 group by i.identifier""")
        List<Object[]> countOpenByIdentifier(@Param("state") String state, @Param("type") String type);
    }

    /**
     * The uploaded Semgrep rule sets.
     *
     * <p>{@code isActive} is {@code Boolean}, and {@code null} rather than {@code false} is
     * what "not active" means: the unique index over that column is what enforces "at most one
     * active", and an index only counts NULLs as distinct.
     */
    public interface RuleSets extends JpaRepository<SemgrepRuleSetEntity, Long> {
        Optional<SemgrepRuleSetEntity> findByIsActiveTrue();

        Optional<SemgrepRuleSetEntity> findByContentHash(String contentHash);

        /**
         * The listing, without the files.
         *
         * <p>The files are megabytes of YAML. A listing that carried them would be a listing
         * nobody opens twice, and the projection is what stops a lazy `findAll` from becoming
         * that by accident.
         */
        @Query("""
                select new com.asmolabs.zanshin.core.repositories.RuleSetSummary(
                        r.id, r.name, r.contentHash, r.ruleCount, r.fileCount, r.sizeBytes,
                        r.isActive, r.uploadedBy, r.uploadedAt, r.activationNote)
                  from SemgrepRuleSetEntity r
                 order by r.uploadedAt desc, r.id desc""")
        List<RuleSetSummary> summaries();

        @Modifying(clearAutomatically = true, flushAutomatically = true)
        @Query("update SemgrepRuleSetEntity r set r.isActive = null where r.isActive = true")
        int deactivateAll();

        @Modifying(clearAutomatically = true, flushAutomatically = true)
        @Query("update SemgrepRuleSetEntity r set r.isActive = true, r.activationNote = :note where r.id = :id")
        int activate(@Param("id") Long id, @Param("note") String note);
    }

    public interface AuditLog extends JpaRepository<AuditLogEntity, UUID> {
        /**
         * The whole log in chain order.
         *
         * <p>Ordered by instant then id, which is the order the integrity chain was written in
         * and the only one verification can follow. Two entries written in the same millisecond
         * by two instances are a legitimate fork, and the id breaks the tie deterministically.
         */
        List<AuditLogEntity> findAllByOrderByTimestampAscIdAsc();
    }
}
