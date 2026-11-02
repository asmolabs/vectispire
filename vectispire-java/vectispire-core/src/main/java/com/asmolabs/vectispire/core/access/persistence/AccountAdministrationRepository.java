package com.asmolabs.vectispire.core.access.persistence;

import java.time.Instant;
import java.util.Collection;
import java.util.List;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Query;
import org.springframework.data.repository.query.Param;

public interface AccountAdministrationRepository extends JpaRepository<AccountAdministrationEntity, Long> {

    /** What this administrator did to this account since an instant, newest first. */
    List<AccountAdministrationEntity> findByAccountIdAndAdministratorIdAndOccurredAtGreaterThanEqualOrderByOccurredAtDesc(
            Long accountId, Long administratorId, Instant since);

    /** Whether any other account had its role changed out of one of these roles since an instant. */
    @Query("""
            select count(a) > 0 from AccountAdministrationEntity a
             where a.gesture = :gesture and a.heldRole in :roles and a.occurredAt >= :since and a.accountId <> :excluding""")
    boolean anyChangedFromSince(
            @Param("gesture") String gesture,
            @Param("roles") Collection<String> roles,
            @Param("since") Instant since,
            @Param("excluding") Long excluding);
}
