package com.asmolabs.zanshin.repository.repositories;

import com.asmolabs.zanshin.repository.entities.VexDecision;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.stereotype.Repository;

@Repository
public interface VexDecisionRepository extends JpaRepository<VexDecision, Long> {
}
