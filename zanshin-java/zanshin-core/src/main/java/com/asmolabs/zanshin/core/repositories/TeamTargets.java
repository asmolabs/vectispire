package com.asmolabs.zanshin.core.repositories;

import com.asmolabs.zanshin.core.persistence.TeamTargetEntity;
import java.util.List;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Modifying;
import org.springframework.data.jpa.repository.Query;
import org.springframework.data.repository.query.Param;
import org.springframework.transaction.annotation.Transactional;

/** Which targets each team owns. */
public interface TeamTargets extends JpaRepository<TeamTargetEntity, TeamTargetEntity.Id> {

    @Query("select t from TeamTargetEntity t where t.id.teamId = :teamId")
    List<TeamTargetEntity> findByTeamId(@Param("teamId") Long teamId);

    /**
     * Every target owned by any of these teams, in one query.
     *
     * <p>One query and not one per team: an account in five teams would otherwise cost five
     * round trips on <b>every request</b>, since visibility is resolved per request.
     *
     * <p>Callers must not pass an empty collection — {@code in ()} is a syntax error on some
     * engines and matches everything on others, which is the worst possible pair of behaviours
     * for an authorization query. {@code VisibilityService} short-circuits before calling.
     */
    @Query("select t from TeamTargetEntity t where t.id.teamId in :teamIds")
    List<TeamTargetEntity> findByTeamIdIn(@Param("teamIds") List<Long> teamIds);

    /** Replaced wholesale: what matters is that a removal really removes. */
    @Transactional
    @Modifying(clearAutomatically = true)
    @Query("delete from TeamTargetEntity t where t.id.teamId = :teamId")
    int deleteByTeamId(@Param("teamId") Long teamId);

    /**
     * Every team's claim on one target, dropped.
     *
     * <p>For target deletion: there is no foreign key to cascade through, so the rows would
     * otherwise outlive the repository they name. See {@link UserTargets#deleteByTarget} for why
     * that is an access-control matter and not housekeeping — SQLite reuses a freed
     * {@code rowid}, so a stale row can come to name a different target.
     */
    @Transactional
    @Modifying(clearAutomatically = true)
    @Query("delete from TeamTargetEntity t where t.id.targetKind = :kind and t.id.targetId = :targetId")
    int deleteByTarget(@Param("kind") String kind, @Param("targetId") Long targetId);
}
