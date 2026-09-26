package com.asmolabs.vectispire.core.targets.persistence;

import java.util.Optional;
import org.springframework.data.jpa.repository.JpaRepository;

/** The solutions, each a group of projects (decision 0023). */
public interface Solutions extends JpaRepository<SolutionEntity, Long> {

    /**
     * Case-insensitively, as for teams: "Payments" and "payments" are one solution to everybody
     * reading the screen, and the unique constraint folds case on MySQL and not on PostgreSQL.
     */
    Optional<SolutionEntity> findByNameIgnoreCase(String name);
}
