package com.asmolabs.zanshin.core.repositories;

import com.asmolabs.zanshin.core.persistence.SessionEntity;
import java.time.Instant;
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
}
