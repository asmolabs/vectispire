package com.asmolabs.vectispire.core.access.persistence;

import java.util.List;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Modifying;
import org.springframework.data.jpa.repository.Query;
import org.springframework.data.repository.query.Param;
import org.springframework.transaction.annotation.Transactional;

/** Who is in which team. */
public interface TeamMemberRepository extends JpaRepository<TeamMemberEntity, TeamMemberEntity.Id> {

    @Query("select m from TeamMemberEntity m where m.id.teamId = :teamId")
    List<TeamMemberEntity> findByTeamId(@Param("teamId") Long teamId);

    /**
     * Every team's members with their usernames, in one statement.
     *
     * <p>The SCIM group listing read the memberships one team at a time and every account whole to
     * name them — a statement per team, and each account's hash and secrets loaded to print its name.
     */
    @Query("""
            select new com.asmolabs.vectispire.core.access.persistence.TeamMembership(m.id.teamId, m.id.userId, u.username)
            from TeamMemberEntity m left join UserEntity u on u.id = m.id.userId
            order by m.id.teamId, m.id.userId
            """)
    List<TeamMembership> findAllMemberships();

    /** One team's members with their usernames — {@link #findAllMemberships()} for a single team. */
    @Query("""
            select new com.asmolabs.vectispire.core.access.persistence.TeamMembership(m.id.teamId, m.id.userId, u.username)
            from TeamMemberEntity m left join UserEntity u on u.id = m.id.userId
            where m.id.teamId = :teamId
            order by m.id.userId
            """)
    List<TeamMembership> findMembershipsOf(@Param("teamId") Long teamId);

    @Query("select m from TeamMemberEntity m where m.id.userId = :userId")
    List<TeamMemberEntity> findByUserId(@Param("userId") Long userId);

    /** Replaced wholesale, for the reason given on {@link UserTargetRepository#deleteByUserId}. */
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
