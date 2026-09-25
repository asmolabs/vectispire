package com.asmolabs.vectispire.core.persistence;

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
    @Column(name = "\"key\"", nullable = false)
    private String key;

    // `text` since V38: an encrypted credential is "v2:" and the Base64 of nonce, text and tag, and
    // at 255 characters every secret longer than about 160 was refused by the database as a 500.
    // The service bounds the value now, before the database has to.
    @Column(name = "value", columnDefinition = "text")
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
