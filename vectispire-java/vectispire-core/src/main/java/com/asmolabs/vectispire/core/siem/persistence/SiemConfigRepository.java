package com.asmolabs.vectispire.core.siem.persistence;

import jakarta.persistence.LockModeType;
import java.util.Optional;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Lock;
import org.springframework.data.jpa.repository.Query;
import org.springframework.data.repository.query.Param;
import org.springframework.stereotype.Repository;

@Repository
public interface SiemConfigRepository extends JpaRepository<SiemConfigEntity, Long> {

    /**
     * The configuration read {@code for share}, inside the governor's switch of a SIEM transport: a save
     * still open is waited for and then read as it committed, whatever snapshot the engine's isolation
     * would otherwise have answered — "not in use" must be true of the configuration that will stand.
     */
    @Lock(LockModeType.PESSIMISTIC_READ)
    @Query("select c from SiemConfigEntity c where c.id = :id")
    Optional<SiemConfigEntity> readLocked(@Param("id") Long id);
}
