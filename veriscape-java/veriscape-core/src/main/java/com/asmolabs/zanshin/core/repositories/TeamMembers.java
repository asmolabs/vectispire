package com.asmolabs.zanshin.core.repositories;

import com.asmolabs.zanshin.core.persistence.TeamMemberEntity;
import java.util.List;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Modifying;
import org.springframework.data.jpa.repository.Query;
import org.springframework.data.repository.query.Param;
import org.springframework.transaction.annotation.Transactional;

/** Who is in which team. */
public interface TeamMembers extends JpaRepository<TeamMemberEntity, TeamMemberEntity.Id> {

    @Query("select m from TeamMemberEntity m where m.id.teamId = :teamId")
    List<TeamMemberEntity> findByTeamId(@Param("teamId") Long teamId);

    @Query("select m from TeamMemberEntity m where m.id.userId = :userId")
    List<TeamMemberEntity> findByUserId(@Param("userId") Long userId);

    /** Replaced wholesale, for the reason given on {@link UserTargets#deleteByUserId}. */
    @Transactional
    @Modifying(clearAutomatically = true)
    @Query("delete from TeamMemberEntity m where m.id.teamId = :teamId")
    int deleteByTeamId(@Param("teamId") Long teamId);

    /**
     * Every membership of one account, dropped.
     *
     * <p>The database cascades this when the account row goes, and this exists for the other
     * direction: an administrator removing somebody from every team without deleting them.
     */
    @Transactional
    @Modifying(clearAutomatically = true)
    @Query("delete from TeamMemberEntity m where m.id.userId = :userId")
    int deleteByUserId(@Param("userId") Long userId);
}
