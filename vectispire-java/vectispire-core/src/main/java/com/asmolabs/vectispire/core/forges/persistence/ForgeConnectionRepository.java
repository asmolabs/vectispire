package com.asmolabs.vectispire.core.forges.persistence;

import java.util.List;
import java.util.UUID;
import org.springframework.data.jpa.repository.JpaRepository;

/** Forge connections. The token is stored encrypted and never selected on its own. */
public interface ForgeConnectionRepository extends JpaRepository<ForgeConnectionEntity, UUID> {

    List<ForgeConnectionEntity> findAllByOrderByNameAsc();

    boolean existsByNameIgnoreCase(String name);

    boolean existsByNameIgnoreCaseAndIdNot(String name, UUID id);
}
