package com.asmolabs.zanshin.core.persistence;

import jakarta.persistence.Column;
import jakarta.persistence.Entity;
import jakarta.persistence.Id;
import jakarta.persistence.Table;

/**
 * A key and its value. The catalog that gives them meaning lives in the domain — this table
 * knows nothing about which keys exist, which is what lets a setting be removed from the
 * catalog without a migration.
 */
@Entity
@Table(name = "t_setting")
public class SettingEntity {

    @Id
    @Column(name = "key", nullable = false)
    private String key;

    @Column(name = "value", length = 255)
    private String value;

    public String getKey() {
        return key;
    }

    public void setKey(String key) {
        this.key = key;
    }

    public String getValue() {
        return value;
    }

    public void setValue(String value) {
        this.value = value;
    }
}
