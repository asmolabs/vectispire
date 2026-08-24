package com.asmolabs.vectispire.core.repositories;

import com.asmolabs.vectispire.core.persistence.SettingEntity;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Modifying;
import org.springframework.data.jpa.repository.Query;
import org.springframework.data.repository.query.Param;
import org.springframework.transaction.annotation.Transactional;

public interface Settings extends JpaRepository<SettingEntity, String> {
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
}
