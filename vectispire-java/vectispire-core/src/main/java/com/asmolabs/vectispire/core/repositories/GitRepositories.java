package com.asmolabs.vectispire.core.repositories;

import com.asmolabs.vectispire.core.persistence.RepositoryEntity;
import java.time.Instant;
import java.util.List;
import java.util.UUID;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Modifying;
import org.springframework.data.jpa.repository.Query;
import org.springframework.data.repository.query.Param;
import org.springframework.transaction.annotation.Transactional;

/** The git repositories under watch. */
public interface GitRepositories extends JpaRepository<RepositoryEntity, Long> {

    /**
     * Records that the scheduler has taken this target up.
     *
     * <p>A targeted update rather than a save: the scheduler holds an entity it read at the top
     * of the tick, and a dirty check would write back every column of it — including whatever an
     * operator changed on the settings screen in between.
     */
    @Transactional
    @Modifying(clearAutomatically = true)
    @Query("update RepositoryEntity r set r.lastScheduledScanAt = :at where r.id = :id")
    int stampScheduled(@Param("id") Long id, @Param("at") Instant at);

    /**
     * The repository a published badge names.
     *
     * <p>Empty for a token nobody issued or one that was revoked, and the route answers 404 to
     * both — a revoked badge and an imaginary one must look alike, or the difference says a
     * repository exists.
     */
    java.util.Optional<RepositoryEntity> findByBadgeToken(String badgeToken);

    long countBySshKeyId(UUID sshKeyId);

    long countByHttpsTokenId(UUID httpsTokenId);

    @Query("""
            select r.httpsTokenId, count(r.id) from RepositoryEntity r
             where r.httpsTokenId is not null
             group by r.httpsTokenId""")
    List<Object[]> countByHttpsToken();

    /**
     * The repositories filed in any of these projects, <b>at the moment of asking</b>.
     *
     * <p>This is what a project grant means (decision 0023): it is resolved on every request, so
     * a repository filed into the project after the grant was made is visible at once, and one
     * moved out stops being visible at once, with nothing re-granted or revoked.
     *
     * <p>Callers must not pass an empty collection — {@code in ()} is a syntax error on some
     * engines and matches everything on others. {@code VisibilityService} short-circuits first.
     */
    @Query("select r.id from RepositoryEntity r where r.projectId in :projectIds")
    List<Long> findIdsByProjectIdIn(@Param("projectIds") java.util.Collection<Long> projectIds);

    /**
     * Files a repository into a project, moves it to another, or — with {@code null} — takes it
     * out of any.
     *
     * <p>A targeted update, and the only writer of the column: the entity maps it read-only, so a
     * save of a repository read before a move cannot write the old project back.
     */
    @Transactional
    @Modifying(clearAutomatically = true)
    @Query("update RepositoryEntity r set r.projectId = :projectId where r.id = :id")
    int assignProject(@Param("id") Long id, @Param("projectId") Long projectId);

    /**
     * Every repository of a project back to "no project", for the project's deletion.
     *
     * <p>Explicit rather than left to the foreign key's {@code set null}: the application does
     * not depend on the engine to cascade (see V19), and the count is what the audit entry names.
     */
    @Transactional
    @Modifying(clearAutomatically = true)
    @Query("update RepositoryEntity r set r.projectId = null where r.projectId = :projectId")
    int detachProject(@Param("projectId") Long projectId);

    long countByProjectId(Long projectId);

    /** How many repositories use each key, so the list can refuse a deletion that would break one. */
    @Query("""
            select r.sshKeyId, count(r.id) from RepositoryEntity r
             where r.sshKeyId is not null
             group by r.sshKeyId""")
    List<Object[]> countBySshKey();
}
