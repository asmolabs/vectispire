package com.asmolabs.zanshin.auth.repositories;

import com.asmolabs.zanshin.auth.entities.User;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.stereotype.Repository;

import java.util.Optional;

@Repository
public interface UserRepository extends JpaRepository<User, Long> {
    Optional<User> findByUsername(String username);
    Optional<User> findByEmail(String email);
    Optional<User> findByGithubId(String githubId);
    Optional<User> findByKeycloakId(String keycloakId);
}
