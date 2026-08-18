package com.asmolabs.zanshin.core.repositories;

import com.asmolabs.zanshin.core.persistence.FindingEntity;
import java.util.List;
import org.springframework.data.jpa.repository.JpaRepository;

public interface Findings extends JpaRepository<FindingEntity, Long> {
    List<FindingEntity> findByScanId(Long scanId);
}
