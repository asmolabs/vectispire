package com.asmolabs.zanshin.core.repositories;

import com.asmolabs.zanshin.core.persistence.UserEntity;
import java.util.List;
import java.util.Optional;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Query;
import org.springframework.data.repository.query.Param;

public interface Users extends JpaRepository<UserEntity, Long> {
    Optional<UserEntity> findByUsername(String username);

    /**
     * How many active administrators there are apart from this one.
     *
     * <p>The count the lockout rules consume. Asked of the database rather than of a loaded
     * list, because two administrators demoting each other in parallel is exactly the case
     * a stale in-memory count gets wrong.
     */
    @Query("""
            select count(u) from UserEntity u
             where u.isActive = true and u.role in :adminRoles and u.id <> :excluding""")
    long countActiveAdministratorsExcluding(
            @Param("adminRoles") List<String> adminRoles, @Param("excluding") Long excluding);
}
