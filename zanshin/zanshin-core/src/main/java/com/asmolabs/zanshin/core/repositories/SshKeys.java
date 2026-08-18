package com.asmolabs.zanshin.core.repositories;

import com.asmolabs.zanshin.core.persistence.SshKeyEntity;
import java.util.UUID;
import org.springframework.data.jpa.repository.JpaRepository;

public interface SshKeys extends JpaRepository<SshKeyEntity, UUID> {}
