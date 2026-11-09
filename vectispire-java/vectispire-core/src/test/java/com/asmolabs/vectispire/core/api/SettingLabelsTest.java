package com.asmolabs.vectispire.core.api;

import static org.assertj.core.api.Assertions.assertThat;

import com.asmolabs.vectispire.common.domain.settings.Setting;
import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import java.io.IOException;
import java.nio.file.Path;
import java.util.Arrays;
import java.util.Set;
import java.util.TreeSet;
import java.util.stream.Collectors;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

/**
 * Every setting of the catalogue has French words on the settings screen, and no French entry
 * describes a setting that is gone.
 *
 * <p><b>The defect this closes.</b> The screen falls back on the server's English label and help when
 * the bundle has no {@code settings.keys.<key>}, silently — the right fallback for a server newer than
 * its interface, and the wrong way for a setting to ship. Twenty-one settings were English on the
 * French screen, the whole tracker card among them, while five French entries described settings
 * renamed or removed long before; the 0.11.0 screenshots showed it. The keys are built from the
 * server's, so the front end's i18n check cannot see them (its one stated exception).
 *
 * <p><b>Here, like {@code AuditOperationLabelsTest}</b>: the enum is authoritative and is here, and
 * {@code fr.json} is a declared input of the {@code test} task, or Gradle would replay a stale success.
 */
@DisplayName("the settings screen's French labels")
class SettingLabelsTest {

    private static final Path FRENCH = Path.of("../../vectispire-angular/public/i18n/fr.json");

    @Test
    @DisplayName("name every setting, with a label and a help written as text, and nothing else")
    void everySettingIsInFrench() throws IOException {
        JsonNode keys = new ObjectMapper().readTree(FRENCH.toFile()).path("settings").path("keys");
        Set<String> french = new TreeSet<>();
        keys.fieldNames().forEachRemaining(french::add);
        Set<String> catalogue = Arrays.stream(Setting.values())
                .map(Setting::key)
                .collect(Collectors.toCollection(TreeSet::new));

        assertThat(catalogue).as("settings with no French entry").isSubsetOf(french);
        assertThat(french).as("French entries naming no setting").isSubsetOf(catalogue);
        for (String key : catalogue) {
            for (String field : new String[] {"label", "help"}) {
                // Rendered as text, like the server's own: an asterisk is shown, not read as emphasis.
                assertThat(keys.path(key).path(field).asText())
                        .as("settings.keys.%s.%s", key, field)
                        .isNotBlank()
                        .doesNotContain("*");
            }
        }
    }
}
