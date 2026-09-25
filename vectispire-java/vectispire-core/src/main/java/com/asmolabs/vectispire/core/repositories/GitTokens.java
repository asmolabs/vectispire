package com.asmolabs.vectispire.core.repositories;

import com.asmolabs.vectispire.core.persistence.GitTokenEntity;
import java.util.List;
import java.util.UUID;
import org.springframework.data.jpa.repository.JpaRepository;

/** HTTPS clone tokens. The token is stored encrypted and never selected on its own. */
public interface GitTokens extends JpaRepository<GitTokenEntity, UUID> {

    List<GitTokenEntity> findAllByOrderByCreatedAtDesc();
}
