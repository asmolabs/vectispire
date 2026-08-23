package com.asmolabs.zanshin.core.repositories;

import com.asmolabs.zanshin.core.persistence.SiemConfigEntity;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.stereotype.Repository;

@Repository
public interface SiemConfigs extends JpaRepository<SiemConfigEntity, Long> {
}
