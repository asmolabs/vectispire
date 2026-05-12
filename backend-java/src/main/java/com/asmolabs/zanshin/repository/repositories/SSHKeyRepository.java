package com.asmolabs.zanshin.repository.repositories;

import com.asmolabs.zanshin.repository.entities.SSHKey;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.stereotype.Repository;

import java.util.UUID;

@Repository
public interface SSHKeyRepository extends JpaRepository<SSHKey, UUID> {
}
