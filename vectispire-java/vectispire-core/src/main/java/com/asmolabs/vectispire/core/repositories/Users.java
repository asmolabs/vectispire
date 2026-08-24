package com.asmolabs.vectispire.core.repositories;

import com.asmolabs.vectispire.core.persistence.UserEntity;
import java.time.Instant;
import java.util.List;
import java.util.Optional;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Modifying;
import org.springframework.transaction.annotation.Transactional;
import org.springframework.data.jpa.repository.Query;
import org.springframework.data.repository.query.Param;

public interface Users extends JpaRepository<UserEntity, Long> {
    Optional<UserEntity> findByUsername(String username);

    /**
     * The account bound to an identity provider's subject.
     *
     * <p>The column predates single sign-on by a whole implementation and was written by nothing;
     * it is unique, which is what makes it usable as an identity rather than a note.
     */
    Optional<UserEntity> findByKeycloakId(String keycloakId);


    List<UserEntity> findAllByOrderByUsernameAsc();

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

    /**
     * Sets a new password and clears the forced-change flag.
     *
     * <p>A targeted update rather than a save: the caller holds a user it read through the
     * authentication filter, and a dirty check there would write back every column of it,
     * including anything an administrator changed on another screen in between.
     */
    @Transactional
    @Modifying(clearAutomatically = true)
    @Query("""
            update UserEntity u
               set u.password = :password, u.mustChangePassword = false, u.updatedAt = :at
             where u.id = :id""")
    int changePassword(@Param("id") Long id, @Param("password") String password, @Param("at") Instant at);
}
