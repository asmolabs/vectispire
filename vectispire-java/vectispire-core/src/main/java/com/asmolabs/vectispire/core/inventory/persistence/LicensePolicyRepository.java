package com.asmolabs.vectispire.core.inventory.persistence;

import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.stereotype.Repository;

@Repository
public interface LicensePolicyRepository extends JpaRepository<LicensePolicyEntity, Long> {
}
