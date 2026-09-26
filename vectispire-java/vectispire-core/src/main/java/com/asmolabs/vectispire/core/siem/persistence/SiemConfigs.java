package com.asmolabs.vectispire.core.siem.persistence;

import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.stereotype.Repository;

@Repository
public interface SiemConfigs extends JpaRepository<SiemConfigEntity, Long> {
}
