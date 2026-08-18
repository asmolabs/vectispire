package com.asmolabs.zanshin.core.repositories;

import com.asmolabs.zanshin.core.persistence.SessionEntity;
import java.time.Instant;
import java.util.List;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Modifying;
import org.springframework.data.jpa.repository.Query;
import org.springframework.data.repository.query.Param;
import org.springframework.transaction.annotation.Transactional;

public interface UserSessions extends JpaRepository<SessionEntity, String> {
    void deleteByUserId(Long userId);

    /** Sessions past their absolute lifetime, whatever their idle state. */
    @Transactional
    @Modifying
    @Query("delete from SessionEntity s where s.expiresAt < :asOf")
    int deleteExpired(@Param("asOf") Instant asOf);

    /**
     * Closes an account's other sessions, keeping the one making the request.
     *
     * <p>Keeping the caller's is not a convenience: without it the screen bounces back to the
     * login page immediately after a successful password change, which teaches people that
     * changing a password breaks something.
     */
    @Transactional
    @Modifying(clearAutomatically = true)
    @Query("delete from SessionEntity s where s.userId = :userId and s.token <> :keep")
    int deleteByUserIdExcept(@Param("userId") Long userId, @Param("keep") String keep);

    /**
     * How many live sessions each account has, for the administration screen.
     *
     * <p>Counted on the absolute expiry alone. The idle window is not applied here on purpose:
     * it is re-evaluated on every request, so a session idle past it is refused the moment it is
     * used, and applying it to a count would make the number change while nobody did anything.
     */
    @Query("""
            select s.userId, count(s.token) from SessionEntity s
             where s.expiresAt > :asOf
             group by s.userId""")
    List<Object[]> countActiveByUser(@Param("asOf") Instant asOf);
}
