package com.asmolabs.vectispire.core.repositories;

import com.asmolabs.vectispire.core.persistence.ProjectEntity;
import java.util.Optional;
import org.springframework.data.jpa.repository.JpaRepository;

/** The projects, each in one solution (decision 0023). */
public interface Projects extends JpaRepository<ProjectEntity, Long> {

    /** Unique within its solution, case-insensitively — see {@link Solutions#findByNameIgnoreCase}. */
    Optional<ProjectEntity> findBySolutionIdAndNameIgnoreCase(Long solutionId, String name);

    boolean existsBySolutionId(Long solutionId);

    long countBySolutionId(Long solutionId);
}
