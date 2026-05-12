package com.asmolabs.zanshin.repository.repositories;

import com.asmolabs.zanshin.repository.entities.ZanshinRepository;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.stereotype.Repository;

@Repository
public interface ZanshinRepositoryRepository extends JpaRepository<ZanshinRepository, Long> {
}
