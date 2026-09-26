package com.asmolabs.vectispire.core.targets.persistence;

import java.util.List;
import java.util.UUID;
import org.springframework.data.jpa.repository.JpaRepository;

/** The deployment keys. The private half is stored encrypted and never selected on its own. */
public interface SshKeys extends JpaRepository<SshKeyEntity, UUID> {

    List<SshKeyEntity> findAllByOrderByCreatedAtDesc();
}
