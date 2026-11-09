package com.asmolabs.vectispire.core.access.persistence;

import jakarta.persistence.LockModeType;
import java.util.List;
import java.util.Optional;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Lock;
import org.springframework.data.jpa.repository.Query;
import org.springframework.data.repository.query.Param;

public interface AccountRequestRepository extends JpaRepository<AccountRequestEntity, Long> {

    /** The requests in one status, oldest first — the order they were filed in, and the id after it. */
    List<AccountRequestEntity> findByStatusOrderByRequestedAtAscIdAsc(String status);

    boolean existsByStatusAndAccountId(String status, Long accountId);

    boolean existsByStatusAndKindAndUsername(String status, String kind, String username);

    /**
     * {@code select … for update} on one request, held until the caller's transaction ends: two
     * administrators deciding the same request at once — an approval and a rejection, or two approvals —
     * are ordered by it, and the second reads the first one's decision rather than applying the change
     * again.
     */
    @Lock(LockModeType.PESSIMISTIC_WRITE)
    @Query("select r from AccountRequestEntity r where r.id = :id")
    Optional<AccountRequestEntity> lockForDecision(@Param("id") Long id);
}
