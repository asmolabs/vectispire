package com.asmolabs.zanshin.repository.repositories;

import com.asmolabs.zanshin.repository.entities.Scan;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.stereotype.Repository;

@Repository
public interface ScanRepository extends JpaRepository<Scan, Long> {
}
