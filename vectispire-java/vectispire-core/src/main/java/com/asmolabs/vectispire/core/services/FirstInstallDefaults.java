package com.asmolabs.vectispire.core.services;

import com.asmolabs.vectispire.common.domain.access.VisibilityMode;
import com.asmolabs.vectispire.common.domain.settings.Setting;
import java.util.LinkedHashMap;
import java.util.Map;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

/**
 * The settings a <b>fresh</b> installation starts with, where the safe value and the
 * backwards-compatible value disagree.
 *
 * <p><b>Why this class exists.</b> A default has to answer two questions at once, and they want
 * opposite answers. For a deployment that already runs, changing a default is a silent change of
 * behaviour: {@code target_visibility} moving to {@code assigned} on an upgrade would blank the
 * screens of every non-administrator overnight, and nobody would connect the empty backlog to a
 * release note. For a deployment being created, the permissive value means the partitioning
 * exists in the catalog and is off in reality — and the operator best placed to switch it on is
 * the one who does not yet know it is there.
 *
 * <p>Both readings are right, and the catalog can only hold one number. So the catalog keeps the
 * compatible value, {@link Setting#defaultValue()} stays what an absent row is worth, and a
 * database with <b>no account in it</b> — which is the one moment nothing can be broken, because
 * nothing has been configured yet — is written the safe value explicitly instead.
 *
 * <p><b>A written row, not a second default.</b> The value lands in {@code t_setting} like any
 * operator's choice, so exactly one rule decides what applies at read time and the screen shows
 * the mode in force rather than a mode this class knows about and {@code SettingsService} does
 * not. Two sources for one setting is the shape {@code ddl-auto} is kept at {@code validate} to
 * avoid.
 *
 * <p><b>Never overwrites.</b> A key that already has a row is left alone, so an operator who
 * deliberately chose {@code everyone} before creating their first account keeps it, and a restart
 * of an install whose bootstrap credentials were never set does not undo their decision.
 */
@Service
public class FirstInstallDefaults {

    private static final Logger log = LoggerFactory.getLogger(FirstInstallDefaults.class);

    /**
     * The settings whose safe value differs from the one an upgrade may keep.
     *
     * <p>One entry today. It is a map rather than a special case because the next one that
     * appears must land next to this reasoning instead of growing a second mechanism beside it —
     * and because a reader has to be able to see the whole list of what a fresh install is
     * silently given.
     */
    private static final Map<Setting, String> SAFE_DEFAULTS = safeDefaults();

    private final SettingsService settings;

    public FirstInstallDefaults(SettingsService settings) {
        this.settings = settings;
    }

    private static Map<Setting, String> safeDefaults() {
        Map<Setting, String> defaults = new LinkedHashMap<>();
        // Restricted rather than open. An account with no assignment sees nothing, and the
        // administrator who creates it is the one who can assign — where a deployment left on
        // `everyone` has no partitioning at all and no moment at which anybody is told so.
        defaults.put(Setting.TARGET_VISIBILITY, VisibilityMode.ASSIGNED.wireName());
        return Map.copyOf(defaults);
    }

    /**
     * Writes the safe values for the keys nobody has set.
     *
     * <p>Called only where the caller has established that this database is new — see {@link
     * BootstrapService}, which holds that condition, and holds it in one place on purpose: a
     * second listener deciding "is this a fresh install" for itself would race the creation of
     * the first account and get the opposite answer depending on which ran first.
     */
    @Transactional
    public void apply() {
        SAFE_DEFAULTS.forEach((setting, value) -> {
            if (settings.isStored(setting)) {
                return;
            }
            settings.set(setting, value);
            log.info("Fresh installation: \"{}\" set to \"{}\" rather than the compatible default \"{}\".",
                    setting.key(), value, setting.defaultValue());
        });
    }
}
