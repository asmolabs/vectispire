package com.asmolabs.vectispire.core.targets.persistence;

import java.util.Optional;
import org.springframework.data.jpa.repository.JpaRepository;

/** The projects, each in one solution (decision 0023). */
public interface ProjectRepository extends JpaRepository<ProjectEntity, Long> {

    /** Unique within its solution, case-insensitively — see {@link SolutionRepository#findByNameIgnoreCase}. */
    Optional<ProjectEntity> findBySolutionIdAndNameIgnoreCase(Long solutionId, String name);

    boolean existsBySolutionId(Long solutionId);

    long countBySolutionId(Long solutionId);
}
