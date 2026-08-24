package com.asmolabs.zanshin.core.repositories;

import com.asmolabs.zanshin.core.persistence.ContainerEntity;
import java.time.Instant;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Modifying;
import org.springframework.data.jpa.repository.Query;
import org.springframework.data.repository.query.Param;
import org.springframework.transaction.annotation.Transactional;

/** The container images under watch. */
public interface Containers extends JpaRepository<ContainerEntity, Long> {

    /** See {@link GitRepositories#stampScheduled}: same reason, same shape. */
    @Transactional
    @Modifying(clearAutomatically = true)
    @Query("update ContainerEntity c set c.lastScheduledScanAt = :at where c.id = :id")
    int stampScheduled(@Param("id") Long id, @Param("at") Instant at);
}
