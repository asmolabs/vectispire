package com.asmolabs.vectispire.core.access.persistence;

import java.util.Optional;
import org.springframework.data.jpa.repository.JpaRepository;

/** The teams. */
public interface TeamRepository extends JpaRepository<TeamEntity, Long> {

    /**
     * <b>Case-insensitively</b>, because the uniqueness an administrator perceives is not the
     * database's. "Backend" and "backend" are one team to everybody looking at the screen, and
     * the unique constraint on the column would happily accept both.
     */
    Optional<TeamEntity> findByNameIgnoreCase(String name);
}
