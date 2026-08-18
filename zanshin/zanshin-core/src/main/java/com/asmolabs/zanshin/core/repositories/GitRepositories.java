package com.asmolabs.zanshin.core.repositories;

import com.asmolabs.zanshin.core.persistence.RepositoryEntity;
import java.time.Instant;
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
}
