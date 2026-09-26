package com.asmolabs.vectispire.core.settings;

import com.asmolabs.vectispire.common.domain.settings.Setting;
import com.asmolabs.vectispire.core.settings.persistence.SettingEntity;
import com.asmolabs.vectispire.core.settings.persistence.SettingRepository;
import java.util.HashMap;
import java.util.Map;
import java.util.Optional;
import org.springframework.dao.DataAccessException;
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

    private final SettingRepository settings;

    public SettingsService(SettingRepository settings) {
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

    /**
     * Whether the key has a row of its own, rather than falling back to the catalog's default.
     *
     * <p>Not the same question as {@link #get(Setting)} returning the default value: an operator
     * may have deliberately written the value the catalog also proposes, and overwriting that is
     * overwriting a decision. The distinction is what lets {@link FirstInstallDefaults} seed a
     * fresh install without ever undoing a choice.
     */
    @Transactional(readOnly = true)
    public boolean isStored(Setting setting) {
        return settings.findById(setting.key()).isPresent();
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
     * A row no {@link Setting} names: a value the deployment keeps for itself and never shows on the
     * settings screen — the document signing key, encrypted, is the one there is. Empty when absent,
     * and when the row holds no value.
     *
     * <p>Here rather than in its caller's hands because the table is this module's: {@code crypto}
     * read and wrote {@code t_setting} through the repository while the code was packaged by layer,
     * a dependency on settings nothing showed. No transaction of its own, as before the move — the
     * repository call opens one.
     */
    public Optional<String> internalValue(String key) {
        return settings.findById(key).map(SettingEntity::getValue);
    }

    /**
     * Stores such a row unless one exists, and says whether it did.
     *
     * <p><b>Insert-if-absent, never overwrite.</b> This was a merge, and a merge overwrites: two
     * instances starting together each generated a signing key, each wrote it and each read back
     * its own — the second write replaced the first after the first instance had already started
     * signing with it, so its signatures verified against nothing stored. The insert now fails for
     * whoever comes second, and the caller reads back the row that won.
     *
     * @return false when the key already had a row, which is left as it was
     */
    public boolean storeInternalIfAbsent(String key, String value) {
        try {
            return settings.insert(key, value) == 1;
        } catch (DataAccessException refused) {
            // Decided by what is there, not by the exception's type: SQLite's dialect reports the
            // primary key as a generic JPA failure, the two engines as an integrity violation. A
            // refusal with no row behind it is some other failure, and is not swallowed.
            if (settings.existsById(key)) {
                return false;
            }
            throw refused;
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
