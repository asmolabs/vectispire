package com.asmolabs.zanshin.settings.repositories;

import com.asmolabs.zanshin.settings.entities.Setting;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.stereotype.Repository;

@Repository
public interface SettingRepository extends JpaRepository<Setting, String> {
}
