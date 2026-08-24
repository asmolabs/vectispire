package com.asmolabs.vectispire.core.repositories;

import com.asmolabs.vectispire.core.persistence.SiemConfigEntity;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.stereotype.Repository;

@Repository
public interface SiemConfigs extends JpaRepository<SiemConfigEntity, Long> {
}
