package com.asmolabs.vectispire.core.targets.persistence;

import java.util.List;
import java.util.UUID;
import org.springframework.data.jpa.repository.JpaRepository;

/** HTTPS clone tokens. The token is stored encrypted and never selected on its own. */
public interface GitTokenRepository extends JpaRepository<GitTokenEntity, UUID> {

    List<GitTokenEntity> findAllByOrderByCreatedAtDesc();
}
