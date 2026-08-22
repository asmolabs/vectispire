package com.asmolabs.zanshin.common.domain.settings;

import static org.assertj.core.api.Assertions.assertThat;

import java.util.Arrays;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Nested;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.EnumSource;
import org.junit.jupiter.params.provider.ValueSource;

@DisplayName("the settings catalog")
class SettingTest {

    @Test
    @DisplayName("every key is unique, because the key is what the database stores")
    void keysAreUnique() {
        assertThat(Arrays.stream(Setting.values()).map(Setting::key).distinct())
                .hasSize(Setting.values().length);
    }

    @ParameterizedTest(name = "{0} carries a label, help and a default its own type accepts")
    @EnumSource(Setting.class)
    void everySettingIsUsable(Setting setting) {
        // A default its own validation refuses is a screen that opens with an error on a
        // value nobody typed — and it makes "save" impossible until the operator guesses.
        assertThat(setting.label()).isNotBlank();
        assertThat(setting.help()).isNotBlank();
        assertThat(setting.validate(setting.defaultValue()))
                .as("%s default %s", setting, setting.defaultValue())
                .isEmpty();
    }

    @Test
    @DisplayName("every setting whose value is a bearer capability is marked secret")
    void secretsAreMarked() {
        // A webhook URL is not configuration: whoever knows it can post in the channel where
        // the team awaits Zanshin's alerts, which is the channel where a forged message
        // carries most weight. Reading it needs no write permission.
        //
        // The list is exhaustive on purpose. A setting added here without `Sensitivity.SECRET`
        // fails this test rather than quietly becoming readable by every account — which is the
        // only way anybody would find out.
        assertThat(Arrays.stream(Setting.values()).filter(Setting::isSecret))
                .containsExactlyInAnyOrder(
                        Setting.WEBHOOK_URL,
                        // Same reasoning, and if anything sharper: a Teams workflow URL needs no
                        // credential at all — whoever holds it posts into the channel as Zanshin.
                        Setting.TEAMS_WEBHOOK_URL,
                        // The signing secret is the sharpest case in this list: whoever reads it
                        // can produce a message every receiver accepts as Zanshin's — including
                        // "no new vulnerabilities". It is the one value here whose disclosure
                        // turns a protection into a forgery tool.
                        Setting.WEBHOOK_SIGNING_SECRET,
                        Setting.TICKET_BASE_URL,
                        Setting.TICKET_TOKEN,
                        Setting.AI_REVIEW_OLLAMA_URL);
    }

    @Test
    @DisplayName("the dangerous switches are off by default")
    void dangerousDefaultsAreOff() {
        // Each of these, on, sends something somewhere it was not going before.
        assertThat(Setting.AI_REVIEW_ALLOW_REMOTE.defaultValue()).isEqualTo("false");
        assertThat(Setting.NOTIFICATION_ALLOW_PRIVATE_URL.defaultValue()).isEqualTo("false");
        assertThat(Setting.SAST_ENABLED.defaultValue()).isEqualTo("false");
        assertThat(Setting.AI_REVIEW_ENABLED.defaultValue()).isEqualTo("false");
    }

    @Test
    @DisplayName("an unexposed key has no definition, and says so")
    void unknownKeysAreAbsent() {
        assertThat(Setting.byKey("enrichment_enabled")).contains(Setting.ENRICHMENT_ENABLED);
        assertThat(Setting.byKey("invented_setting")).isEmpty();
    }

    @Test
    @DisplayName("the defaults cover every key")
    void defaultsCoverEveryKey() {
        assertThat(Setting.defaults()).hasSize(Setting.values().length);
    }

    @Nested
    @DisplayName("validation, at the point of entry")
    class Validation {

        @ParameterizedTest(name = "boolean refuses [{0}]")
        @ValueSource(strings = {"", "yes", "TRUE", "1", " true"})
        void booleanIsStrict(String value) {
            assertThat(SettingType.BOOLEAN.validate(value)).isPresent();
        }

        @ParameterizedTest(name = "integer refuses [{0}]")
        @ValueSource(strings = {"", "   ", "-1", "1.5", "ten"})
        void integerIsStrict(String value) {
            // An unreadable integer read later falls back to its default, and the operator
            // never learns their value was ignored.
            assertThat(SettingType.INTEGER.validate(value)).isPresent();
        }

        @Test
        @DisplayName("integer accepts zero, which is a meaningful value here")
        void zeroIsValid() {
            // Zero means "no limit on this axis" for retention. Refusing it would remove a
            // documented state.
            assertThat(SettingType.INTEGER.validate("0")).isEmpty();
        }

        @Test
        @DisplayName("a severity threshold cannot be unknown or negligible")
        void thresholdsAreNarrower() {
            // A threshold of "unknown" notifies on everything, including every advisory the
            // OSV backend returns with no normalized severity. Offering it in a dropdown is
            // offering a way to flood the channel by accident.
            assertThat(SettingType.SEVERITY.validate("critical")).isEmpty();
            assertThat(SettingType.SEVERITY.validate("low")).isEmpty();
            assertThat(SettingType.SEVERITY.validate("negligible")).isPresent();
            assertThat(SettingType.SEVERITY.validate("unknown")).isPresent();
        }

        @Test
        @DisplayName("text accepts anything, because what it must mean is not knowable here")
        void textIsFree() {
            // Whether a URL resolves somewhere allowed is checked by whoever reads it: only
            // they know which of the three outbound policies applies.
            assertThat(SettingType.TEXT.validate("anything at all")).isEmpty();
            assertThat(SettingType.TEXT.validate("")).isEmpty();
        }
    }
}
