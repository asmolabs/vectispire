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
     * Writes a value onto a row only if it still holds the one its writer read, and says whether it did.
     *
     * <p>The arbiter between instances: two that read the same value and both want to move it — two instances'
     * hourly turns noticing the same change of a token's state — both issue this; the second waits on the first's
     * row lock, then finds the value moved, on both engines (an update reads the committed row, whatever the
     * isolation level), and is told zero.
     */
    @Transactional
    @Modifying(clearAutomatically = true, flushAutomatically = true)
    @Query("update SettingEntity s set s.value = :value where s.key = :key and s.value = :expected")
    int replaceValue(@Param("key") String key, @Param("expected") String expected, @Param("value") String value);

    /**
     * Creates a row, and fails when the key already has one.
     *
     * <p>An insert and nothing else. {@code save} on an entity whose identifier is assigned merges —
     * reads, then inserts or updates — so of two writers the last one won and the first never knew
     * it had lost. Here the primary key arbitrates, and the loser hears about it.
     *
     * @throws org.springframework.dao.DataAccessException when the key is taken — an integrity
     *     violation — or the statement failed for another reason
     */
    @Transactional
    @Modifying
    @Query("insert into SettingEntity (key, value) values (:key, :value)")
    int insert(@Param("key") String key, @Param("value") String value);
}
