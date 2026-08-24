package com.asmolabs.vectispire.core.repositories;

import com.asmolabs.vectispire.core.persistence.LicensePolicyEntity;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.stereotype.Repository;

@Repository
public interface LicensePolicies extends JpaRepository<LicensePolicyEntity, Long> {
}
