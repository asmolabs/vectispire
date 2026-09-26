package com.asmolabs.vectispire.core.api;

import static org.assertj.core.api.Assertions.assertThat;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.put;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

import com.asmolabs.vectispire.common.domain.settings.Setting;
import com.asmolabs.vectispire.core.audit.persistence.AuditLogEntity;
import com.asmolabs.vectispire.core.audit.persistence.AuditLogRepository;
import java.util.Arrays;
import java.util.Map;
import java.util.stream.Stream;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.MethodSource;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.MediaType;

/**
 * What a settings write leaves in the audit trail.
 *
 * <p>The trail is read by auditors and CISOs, forwarded to the SIEM, copied to the mirror and into
 * the evidence bundle, and never purged. A {@code SECRET} setting — a webhook URL that posts in a
 * channel, a tracker or model URL that maps the internal network — is hidden from the catalog of a
 * non-administrator, and was written in full into the entry anybody with the audit screen reads.
 *
 * <p>The cases come from the catalog, so a secret added later is covered the day it is marked.
 */
@DisplayName("a settings write, in the audit trail")
class SettingsAuditRoutesTest extends ApiTestBase {

    @Autowired
    private AuditLogRepository entries;

    /** The secrets the generic route writes; the encrypted ones it refuses have their own suite. */
    static Stream<Setting> writableSecrets() {
        return Arrays.stream(Setting.values()).filter(setting -> setting.isSecret() && !setting.isEncrypted());
    }

    /** A value each accepts, carrying a marker the entry must not contain. */
    private static String valueFor(Setting setting) {
        // The model endpoint must stay local unless the remote risk was acknowledged.
        return setting == Setting.AI_REVIEW_OLLAMA_URL
                ? "http://127.0.0.1:11434/MARKER-" + setting.key()
                : "https://hooks.example.test/services/MARKER-" + setting.key();
    }

    @ParameterizedTest(name = "{0}")
    @MethodSource("writableSecrets")
    @DisplayName("a secret setting is named in the entry, and its value is not")
    void theValueStaysOut(Setting setting) throws Exception {
        mvc.perform(authenticated(put("/api/v1/settings"), asAdmin())
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(write(Map.of(setting.key(), valueFor(setting)))))
                .andExpect(status().isOk());

        assertThat(entries.findAll())
                .extracting(AuditLogEntity::getDescription)
                .anySatisfy(description -> assertThat(description).contains(setting.key()))
                .noneSatisfy(description -> assertThat(description).contains("MARKER"));
    }

    @Test
    @DisplayName("an ordinary setting keeps its value in the entry")
    void anOrdinaryValueStays() throws Exception {
        // The counterpart: a rule that withheld every value would pass the case above and cost an
        // auditor the retention periods and SLA windows the trail exists to show.
        mvc.perform(authenticated(put("/api/v1/settings"), asAdmin())
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(write(Map.of(Setting.EOL_WARN_DAYS.key(), "45"))))
                .andExpect(status().isOk());

        assertThat(entries.findAll())
                .extracting(AuditLogEntity::getDescription)
                .anySatisfy(description -> assertThat(description).contains("eol_warn_days = 45"));
    }
}
