package com.asmolabs.vectispire.core.settings.persistence;

import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Modifying;
import org.springframework.data.jpa.repository.Query;
import org.springframework.data.repository.query.Param;
import org.springframework.transaction.annotation.Transactional;

public interface SettingRepository extends JpaRepository<SettingEntity, String> {
    /**
     * Writes a value onto an existing row, and says whether there was one.
     *
     * <p>Zero rows means "the key has never been set", which is the only signal the caller
     * needs to decide between an update and an insert without a read of its own.
     */
    @Transactional
    @Modifying(clearAutomatically = true, flushAutomatically = true)
    @Query("update SettingEntity s set s.value = :value where s.key = :key")
    int updateValue(@Param("key") String key, @Param("value") String value);

    /**
     * Creates a row, and fails when the key already has one.
     *
     * <p>An insert and nothing else. {@code save} on an entity whose identifier is assigned merges —
     * reads, then inserts or updates — so of two writers the last one won and the first never knew
     * it had lost. Here the primary key arbitrates, and the loser hears about it.
     *
     * @throws org.springframework.dao.DataAccessException when the key is taken — an integrity
     *     violation on the two engines, a generic JPA failure on SQLite
     */
    @Transactional
    @Modifying
    @Query("insert into SettingEntity (key, value) values (:key, :value)")
    int insert(@Param("key") String key, @Param("value") String value);
}
