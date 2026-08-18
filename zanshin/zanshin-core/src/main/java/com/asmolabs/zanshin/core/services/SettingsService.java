package com.asmolabs.zanshin.core.services;

import com.asmolabs.zanshin.common.domain.settings.Setting;
import com.asmolabs.zanshin.core.persistence.SettingEntity;
import com.asmolabs.zanshin.core.repositories.Repositories;
import java.util.HashMap;
import java.util.Map;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

/**
 * The settings, as text keyed by name.
 *
 * <p><b>The catalog is the domain's, the storage is this table's.</b> A row whose key is not
 * in {@link Setting} is not an error — it is a setting that has been removed, and the reader
 * that no longer asks for it simply never sees it. That is what lets a setting be retired
 * without a migration.
 *
 * <p><b>Reads go through {@link Setting}, and the default comes from the catalog.</b> The
 * NestJS version took a key and a fallback at every call site, which put the same default in
 * several places and let them drift: a caller that passed the wrong fallback got the opposite
 * behaviour of the settings screen, silently, for an absent row. Here the default has exactly
 * one definition, next to the label and the help text that describe it to the operator.
 */
@Service
public class SettingsService {

    private final Repositories.Settings settings;

    public SettingsService(Repositories.Settings settings) {
        this.settings = settings;
    }

    /** Every stored value, with no defaults filled in — what is on disk, not what applies. */
    @Transactional(readOnly = true)
    public Map<String, String> stored() {
        Map<String, String> values = new HashMap<>();
        settings.findAll().forEach(row -> values.put(row.getKey(), row.getValue() == null ? "" : row.getValue()));
        return values;
    }

    /** Every setting in the catalog with its effective value: stored if present, default if not. */
    @Transactional(readOnly = true)
    public Map<String, String> effective() {
        Map<String, String> values = new HashMap<>(Setting.defaults());
        values.putAll(stored());
        return values;
    }

    @Transactional(readOnly = true)
    public String get(Setting setting) {
        return settings.findById(setting.key())
                // The stored value wins even when empty: an operator who deliberately cleared a
                // field means it, and substituting the default there is how a cleared webhook URL
                // comes back to life.
                .map(row -> row.getValue() == null ? "" : row.getValue())
                .orElseGet(setting::defaultValue);
    }

    /** A boolean setting. Anything that is not {@code "true"} is false — the absent row included. */
    @Transactional(readOnly = true)
    public boolean isEnabled(Setting setting) {
        return "true".equals(get(setting));
    }

    @Transactional(readOnly = true)
    public int asInt(Setting setting) {
        try {
            return Integer.parseInt(get(setting).trim());
        } catch (NumberFormatException notANumber) {
            // A row written before a validation rule tightened must not take a screen down. The
            // catalog's default is the documented behaviour, so falling back to it is the same
            // answer the deployment would give with no row at all.
            return Integer.parseInt(setting.defaultValue().trim());
        }
    }

    /**
     * Writes a value, creating the row if it is not there.
     *
     * <p><b>Update first, insert only if nothing was updated.</b> Read-then-write would let two
     * concurrent writers of the same key both decide to insert, and the primary key would fail
     * the second rather than merging it. The residual race — both find nothing, both insert —
     * is left to raise: settings are written from an administration screen at human speed, and
     * a caught-and-retried insert inside a transaction already marked rollback-only cannot
     * commit anyway.
     */
    @Transactional
    public void set(Setting setting, String value) {
        if (settings.updateValue(setting.key(), value) == 0) {
            SettingEntity row = new SettingEntity();
            row.setKey(setting.key());
            row.setValue(value);
            settings.save(row);
        }
    }
}
