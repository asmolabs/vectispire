package com.asmolabs.zanshin.core.repositories;

import com.asmolabs.zanshin.core.persistence.UserTargetEntity;
import java.util.List;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Modifying;
import org.springframework.data.jpa.repository.Query;
import org.springframework.data.repository.query.Param;
import org.springframework.transaction.annotation.Transactional;

/** Which targets each account may see, when the deployment restricts visibility. */
public interface UserTargets extends JpaRepository<UserTargetEntity, UserTargetEntity.Id> {

    @Query("select t from UserTargetEntity t where t.id.userId = :userId")
    List<UserTargetEntity> findByUserId(@Param("userId") Long userId);

    /**
     * Replaces an account's assignments wholesale: delete, then insert.
     *
     * <p>A diff would be fewer statements and one more thing to get wrong — the case that
     * matters is <em>removing</em> an assignment, and a diff that computes additions correctly
     * and deletions not at all looks like it works.
     */
    @Transactional
    @Modifying(clearAutomatically = true)
    @Query("delete from UserTargetEntity t where t.id.userId = :userId")
    int deleteByUserId(@Param("userId") Long userId);
}
