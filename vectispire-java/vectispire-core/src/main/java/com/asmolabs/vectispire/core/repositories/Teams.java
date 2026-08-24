package com.asmolabs.vectispire.core.repositories;

import com.asmolabs.vectispire.core.persistence.TeamEntity;
import java.util.Optional;
import org.springframework.data.jpa.repository.JpaRepository;

/** The teams. */
public interface Teams extends JpaRepository<TeamEntity, Long> {

    /**
     * <b>Case-insensitively</b>, because the uniqueness an administrator perceives is not the
     * database's. "Backend" and "backend" are one team to everybody looking at the screen, and
     * the unique constraint on the column would happily accept both.
     */
    Optional<TeamEntity> findByNameIgnoreCase(String name);
}
