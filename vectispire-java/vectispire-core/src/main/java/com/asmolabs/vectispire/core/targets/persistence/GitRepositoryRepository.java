package com.asmolabs.vectispire.core.targets.persistence;

import java.time.Instant;
import java.util.List;
import java.util.UUID;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Modifying;
import org.springframework.data.jpa.repository.Query;
import org.springframework.data.repository.query.Param;
import org.springframework.transaction.annotation.Transactional;

/** The git repositories under watch. */
public interface GitRepositoryRepository extends JpaRepository<RepositoryEntity, Long> {

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
     * The repositories filed in this project now, whole — what a read of the project on its own lists and
     * names. One parameter, the project, however many it holds.
     */
    List<RepositoryEntity> findByProjectId(Long projectId);

    /**
     * The repositories filed in any project of this solution, at the moment of asking — a solution
     * holds no repository of its own (decision 0023). A subquery rather than the projects' ids bound
     * one by one, so a solution of many projects is one parameter.
     */
    @Query("""
            select r.id from RepositoryEntity r
             where r.projectId in (select p.id from ProjectEntity p where p.solutionId = :solutionId)""")
    List<Long> findIdsBySolutionId(@Param("solutionId") Long solutionId);

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

    /** The target holding this guard — at most one, the index is unique (V73). */
    java.util.Optional<RepositoryEntity> findByIdentityGuard(String identityGuard);

    /**
     * The rows holding no guard, oldest first: those written before V73 or by an instance of an earlier
     * version during a rolling upgrade, the second filing of a target filed twice before the rule, and a
     * URL that names no host. Oldest first, so that of two twins the one with the longer history keeps
     * the guard.
     */
    List<RepositoryEntity> findByIdentityGuardIsNullOrderByIdAsc();

    /**
     * Writes a row's identity, and its guard when it is free ({@code null} otherwise).
     *
     * <p><b>A targeted update, conditional on what was read.</b> The keying runs beside the routes: a
     * save would write back every column of a row an operator may have edited since, and a URL, branch
     * or sub-path changed in between would get the identity of the old one. A row that moved is left
     * alone — the update that moved it keyed it — and so is one keyed in between.
     *
     * @param subPath the sub-path as read, {@code ""} for none: a null bound beside a comparison is
     *     typed differently by each engine's driver
     * @return 1 when written, 0 when the row had changed
     */
    @Transactional
    @Modifying(clearAutomatically = true)
    @Query("""
            update RepositoryEntity r set r.urlIdentity = :urlIdentity, r.identityGuard = :guard
             where r.id = :id and r.identityGuard is null
               and r.url = :url and r.branch = :branch and coalesce(r.subPath, '') = :subPath""")
    int key(
            @Param("id") Long id,
            @Param("url") String url,
            @Param("branch") String branch,
            @Param("subPath") String subPath,
            @Param("urlIdentity") String urlIdentity,
            @Param("guard") String guard);
}
