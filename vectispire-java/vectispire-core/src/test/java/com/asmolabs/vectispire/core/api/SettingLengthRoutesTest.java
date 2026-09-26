package com.asmolabs.vectispire.core.api;

import static org.assertj.core.api.Assertions.assertThat;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.put;

import com.asmolabs.vectispire.common.domain.settings.Setting;
import com.asmolabs.vectispire.common.domain.text.BoundedText;
import com.asmolabs.vectispire.core.services.shared.SettingsService;
import com.asmolabs.vectispire.core.services.TicketService;
import java.util.Map;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.MediaType;

/**
 * How long a setting may be, asked over HTTP.
 *
 * <p><b>The defect.</b> {@code t_setting.value} was {@code varchar(255)} and a credential is stored
 * encrypted — "v2:" and the Base64 of nonce, text and tag — so every secret over about 160
 * characters was refused by MySQL and PostgreSQL at the write, as a 500. An Atlassian token is 192
 * characters. This suite runs on SQLite, which enforces no length, so it cannot see the column: that
 * half is {@code LongSettingIntegrationTest}'s, on the real engines. What it pins is the other half
 * — that a real token goes through the real route, and that the ceiling which replaced the column's
 * is a 400 and not the database's error.
 */
@DisplayName("the length of a setting")
class SettingLengthRoutesTest extends ApiTestBase {

    /** The length of an Atlassian API token, and more than the old column could hold encrypted. */
    private static final String REAL_TOKEN = "A".repeat(200);

    @Autowired
    private TicketService tickets;

    @Autowired
    private SettingsService settings;

    private static Map<String, String> secretRoutes(String value) {
        return Map.of(
                "/api/v1/settings/ticket-token", "{\"token\":\"" + value + "\"}",
                "/api/v1/settings/webhook-secret", "{\"secret\":\"" + value + "\"}",
                "/api/v1/settings/ticket-webhook-secret", "{\"secret\":\"" + value + "\"}",
                "/api/v1/settings/ai-openai-key", "{\"secret\":\"" + value + "\"}");
    }

    @Test
    @DisplayName("a 200-character credential is stored by each of the four routes, and reads back")
    void aRealTokenIsStored() throws Exception {
        String admin = asAdmin();
        for (Map.Entry<String, String> route : secretRoutes(REAL_TOKEN).entrySet()) {
            int status = send(admin, route.getKey(), route.getValue());
            assertThat(status).as("PUT %s with a 200-character secret", route.getKey()).isEqualTo(200);
        }
        assertThat(tickets.token()).as("decrypted, the token is the one that was typed").isEqualTo(REAL_TOKEN);
    }

    @Test
    @DisplayName("a credential past the ceiling is a 400, and nothing is stored")
    void anOversizedSecretIsRefused() throws Exception {
        String admin = asAdmin();
        String oversized = "A".repeat(8_193);
        for (Map.Entry<String, String> route : secretRoutes(oversized).entrySet()) {
            int status = send(admin, route.getKey(), route.getValue());
            assertThat(status).as("PUT %s with 8,193 characters", route.getKey()).isEqualTo(400);
        }
        assertThat(settings.isStored(Setting.TICKET_TOKEN)).isFalse();
    }

    @Test
    @DisplayName("a free-text setting past the ceiling is a 400, and one at it is stored")
    void anOversizedTextSettingIsRefused() throws Exception {
        String admin = asAdmin();
        String key = Setting.ISMS_SCOPE_STATEMENT.key();

        int refused = send(admin, "/api/v1/settings",
                write(Map.of(key, "x".repeat(BoundedText.TEXT_MAX + 1))));
        assertThat(refused).isEqualTo(400);
        assertThat(settings.isStored(Setting.ISMS_SCOPE_STATEMENT)).isFalse();

        int stored = send(admin, "/api/v1/settings", write(Map.of(key, "x".repeat(BoundedText.TEXT_MAX))));
        assertThat(stored).isEqualTo(200);
        assertThat(settings.get(Setting.ISMS_SCOPE_STATEMENT)).hasSize(BoundedText.TEXT_MAX);
    }

    private int send(String token, String path, String body) throws Exception {
        return mvc.perform(authenticated(put(path), token)
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(body))
                .andReturn().getResponse().getStatus();
    }
}
