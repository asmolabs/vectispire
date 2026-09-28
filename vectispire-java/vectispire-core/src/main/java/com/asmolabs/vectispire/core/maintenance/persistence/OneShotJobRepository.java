package com.asmolabs.vectispire.core.maintenance.persistence;

import java.time.Instant;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Modifying;
import org.springframework.data.jpa.repository.Query;
import org.springframework.data.repository.query.Param;
import org.springframework.transaction.annotation.Propagation;
import org.springframework.transaction.annotation.Transactional;

/** The jobs that ran once. No {@code save}: a merge reads, then writes, and would let both callers win. */
public interface OneShotJobRepository extends JpaRepository<OneShotJobEntity, String> {

    /**
     * Records the job as run, or fails because it has been.
     *
     * <p>Native, because JPQL has no insert. {@code MANDATORY}: the row must commit with the job's
     * work or not at all, so it is written in the caller's transaction — on its own it would mark the
     * job run and leave the work to a transaction that may still roll back.
     */
    @Transactional(propagation = Propagation.MANDATORY)
    @Modifying
    @Query(value = "insert into t_one_shot_job (name, ran_at) values (:name, :at)", nativeQuery = true)
    int claim(@Param("name") String name, @Param("at") Instant at);
}
