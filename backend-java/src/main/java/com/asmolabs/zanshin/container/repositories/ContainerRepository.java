package com.asmolabs.zanshin.container.repositories;

import com.asmolabs.zanshin.container.entities.Container;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.stereotype.Repository;

@Repository
public interface ContainerRepository extends JpaRepository<Container, Long> {
}
