package com.asmolabs.vectispire.core.api;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.put;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.jsonPath;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

import com.asmolabs.vectispire.common.domain.aireview.AiProvider;
import com.asmolabs.vectispire.common.domain.audit.AuditOperation;
import com.asmolabs.vectispire.common.domain.forges.ForgeKind;
import com.asmolabs.vectispire.common.domain.integrations.Integration;
import com.asmolabs.vectispire.common.domain.integrations.IntegrationDisabledException;
import com.asmolabs.vectispire.common.domain.settings.Setting;
import com.asmolabs.vectispire.common.domain.users.Role;
import com.asmolabs.vectispire.core.audit.persistence.AuditLogEntity;
import com.asmolabs.vectispire.core.audit.persistence.AuditLogRepository;
import com.asmolabs.vectispire.core.outbox.persistence.OutboxMessageRepository;
import com.asmolabs.vectispire.core.settings.Integrations;
import com.asmolabs.vectispire.core.settings.SettingsService;
import com.asmolabs.vectispire.core.siem.SiemEvents;
import com.fasterxml.jackson.databind.JsonNode;
import java.util.List;
import java.util.Map;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.MediaType;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.test.web.servlet.ResultActions;

/**
 * The integrations' registry (decision 0040, lot I1), through the real routes, filter chain and database:
 * what an installation starts with, who switches an integration, what a switch records — and the refusal
 * the adapters will call.
 *
 * <p><b>{@code t_integration} is not emptied between tests</b> (see {@code TableEmptyingTest}): its rows
 * are V83's seed, and emptied every integration would read disabled. Each case here puts the rows back as
 * it found them, so the one asserting the seed reads what the migration wrote, whatever ran before it.
 */
@DisplayName("integrations' registry, through the routes")
class IntegrationsRoutesTest extends ApiTestBase {

    @Autowired
    private Integrations integrations;

    @Autowired
    private SettingsService settings;

    @Autowired
    private AuditLogRepository auditLog;

    @Autowired
    private OutboxMessageRepository outbox;

    @Autowired
    private JdbcTemplate jdbc;

    private List<Map<String, Object>> found;

    @BeforeEach
    void remember() {
        found = jdbc.queryForList("select integration_key, enabled, updated_at, updated_by from t_integration");
    }

    @AfterEach
    void putBack() {
        jdbc.update("delete from t_integration");
        for (Map<String, Object> row : found) {
            jdbc.update("insert into t_integration (integration_key, enabled, updated_at, updated_by) values (?, ?, ?, ?)",
                    row.get("integration_key"), row.get("enabled"), row.get("updated_at"), row.get("updated_by"));
        }
    }

    private String governor() {
        return tokenFor("governor-" + System.nanoTime(), Role.SUPERUSER, false);
    }

    private ResultActions switchTo(String token, String key, Object body) throws Exception {
        return mvc.perform(authenticated(put("/api/v1/integrations/" + key + "/enabled"), token)
                .contentType(MediaType.APPLICATION_JSON).content(write(body)));
    }

    private JsonNode list(String token) throws Exception {
        return json.readTree(mvc.perform(authenticated(get("/api/v1/integrations"), token))
                .andExpect(status().isOk()).andReturn().getResponse().getContentAsString());
    }

    private static JsonNode entry(JsonNode list, String key) {
        for (JsonNode integration : list) {
            if (integration.path("key").asText().equals(key)) {
                return integration;
            }
        }
        throw new AssertionError("no integration " + key);
    }

    private List<AuditLogEntity> entries() {
        return auditLog.findAll().stream()
                .filter(entry -> AuditOperation.INTEGRATION_ENABLED_CHANGED.wireName().equals(entry.getOperationType()))
                .toList();
    }

    @Test
    @DisplayName("an installation starts with every integration enabled, switched by nobody, read by any account")
    void everythingStartsEnabled() throws Exception {
        JsonNode all = list(asReader());
        assertThat(all).hasSize(Integration.all().size());
        assertThat(all).extracting(integration -> integration.path("key").asText())
                .containsExactlyElementsOf(Integration.all().stream().map(Integration::key).toList());
        for (JsonNode integration : all) {
            assertThat(integration.path("enabled").asBoolean()).as(integration.path("key").asText()).isTrue();
            assertThat(integration.path("updatedAt").isNull()).isTrue();
            assertThat(integration.path("updatedBy").isNull()).isTrue();
        }
        JsonNode jira = entry(all, "tracker.jira");
        assertThat(jira.path("family").asText()).isEqualTo("tracker");
        assertThat(jira.path("name").asText()).isEqualTo("jira");
        assertThat(Integration.all()).allMatch(integrations::isEnabled);
    }

    @Test
    @DisplayName("an integration with no row — one added after V83 — reads disabled, and is refused")
    void absentIsDisabled() throws Exception {
        Integration openAi = Integration.of(AiProvider.OPENAI);
        jdbc.update("delete from t_integration where integration_key = ?", openAi.key());

        assertThat(integrations.isEnabled(openAi)).isFalse();
        assertThat(entry(list(asAdmin()), "ai.openai").path("enabled").asBoolean()).isFalse();
        assertThatThrownBy(() -> integrations.requireEnabled(openAi))
                .isInstanceOfSatisfying(IntegrationDisabledException.class,
                        refused -> assertThat(refused.integration()).isEqualTo(openAi));

        // Off again is the same state: nothing written, nothing recorded.
        String governor = governor();
        switchTo(governor, "ai.openai", Map.of("enabled", false)).andExpect(status().isOk())
                .andExpect(jsonPath("$.enabled").value(false));
        assertThat(jdbc.queryForObject("select count(*) from t_integration where integration_key = 'ai.openai'",
                Integer.class)).isZero();
        assertThat(entries()).isEmpty();

        // Enabling it is a gesture like any other, and gives it its row.
        switchTo(governor, "ai.openai", Map.of("enabled", true)).andExpect(status().isOk())
                .andExpect(jsonPath("$.enabled").value(true));
        integrations.requireEnabled(openAi);
        assertThat(entries()).hasSize(1);
    }

    @Test
    @DisplayName("switching is the platform governor's alone: an administrator, a CISO, an auditor and a reader are refused")
    void governorOnly() throws Exception {
        for (String token : List.of(asAdmin(), asCiso(), asAuditor(), asReader(), asSecurityChampion())) {
            switchTo(token, "forge.gitlab", Map.of("enabled", false)).andExpect(status().isForbidden());
        }
        assertThat(integrations.isEnabled(Integration.of(ForgeKind.GITLAB))).isTrue();
        assertThat(entries()).isEmpty();

        switchTo(governor(), "forge.gitlab", Map.of("enabled", false)).andExpect(status().isOk());
        assertThat(integrations.isEnabled(Integration.of(ForgeKind.GITLAB))).isFalse();
    }

    @Test
    @DisplayName("a switch is attributed and audited once; the same state again changes and records nothing")
    void switchingIsAuditedOnce() throws Exception {
        String governorName = "governor-" + System.nanoTime();
        String governor = tokenFor(governorName, Role.SUPERUSER, false);

        switchTo(governor, "notification.discord", Map.of("enabled", false))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.key").value("notification.discord"))
                .andExpect(jsonPath("$.family").value("notification"))
                .andExpect(jsonPath("$.enabled").value(false))
                .andExpect(jsonPath("$.updatedBy").value(governorName));
        String switchedAt = entry(list(governor), "notification.discord").path("updatedAt").asText();
        assertThat(switchedAt).isNotEmpty();

        assertThat(entries()).singleElement().satisfies(entry -> {
            assertThat(entry.getResourceId()).isEqualTo("notification.discord");
            assertThat(entry.getUserId()).isEqualTo(governorName);
            assertThat(entry.getDescription()).contains("disabled");
        });

        switchTo(governor, "notification.discord", Map.of("enabled", false)).andExpect(status().isOk());
        assertThat(entries()).hasSize(1);
        assertThat(entry(list(governor), "notification.discord").path("updatedAt").asText()).isEqualTo(switchedAt);

        // The other integrations did not move.
        assertThat(Integration.all().stream().filter(integration -> !integration.key().equals("notification.discord")))
                .allMatch(integrations::isEnabled);

        switchTo(governor, "notification.discord", Map.of("enabled", true))
                .andExpect(status().isOk()).andExpect(jsonPath("$.enabled").value(true));
        assertThat(entries()).hasSize(2);
        assertThat(entries()).anySatisfy(entry -> assertThat(entry.getDescription()).contains("enabled"));
    }

    @Test
    @DisplayName("who switched it is shown to the roles that read governance, never to an ordinary account")
    void authorForGovernanceReaders() throws Exception {
        String governorName = "governor-" + System.nanoTime();
        switchTo(tokenFor(governorName, Role.SUPERUSER, false), "siem.webhook", Map.of("enabled", false))
                .andExpect(status().isOk());

        assertThat(entry(list(asAuditor()), "siem.webhook").path("updatedBy").asText()).isEqualTo(governorName);
        JsonNode seenByReader = entry(list(asReader()), "siem.webhook");
        assertThat(seenByReader.path("enabled").asBoolean()).isFalse();
        assertThat(seenByReader.path("updatedAt").isNull()).isFalse();
        assertThat(seenByReader.path("updatedBy").isNull()).isTrue();
    }

    @Test
    @DisplayName("an unknown key is a 404, a missing state a 400, an anonymous caller a 401")
    void refusals() throws Exception {
        String governor = governor();
        assertThat(detailOf(switchTo(governor, "forge.bitbucket", Map.of("enabled", true))
                .andExpect(status().isNotFound()).andReturn())).isEqualTo("Integration not found.");
        switchTo(governor, "gitlab", Map.of("enabled", true)).andExpect(status().isNotFound());
        assertThat(detailOf(switchTo(governor, "forge.gitlab", Map.of()).andExpect(status().isBadRequest()).andReturn()))
                .isEqualTo("Say whether the integration is enabled.");
        mvc.perform(get("/api/v1/integrations")).andExpect(status().isUnauthorized());
        assertThat(entries()).isEmpty();
    }

    @Test
    @DisplayName("each switch is queued for the SIEM as a security setting change, VECTI-SEC-019")
    void signalled() throws Exception {
        settings.set(Setting.SIEM_ALLOW_PRIVATE_DESTINATION, "true");
        mvc.perform(authenticated(put("/api/v1/siem/config"), asAdmin())
                        .contentType(MediaType.APPLICATION_JSON)
                        .content("""
                                {"enabled": true, "protocol": "SYSLOG_UDP", "endpoint": "127.0.0.1:9", "minSeverity": "LOW"}"""))
                .andExpect(status().isOk());
        outbox.deleteAll();

        String governor = governor();
        switchTo(governor, "tracker.servicenow", Map.of("enabled", false)).andExpect(status().isOk());
        switchTo(governor, "tracker.servicenow", Map.of("enabled", false)).andExpect(status().isOk());

        List<JsonNode> queued = outbox.findAll().stream()
                .filter(row -> SiemEvents.TYPE.equals(row.getMessageType()))
                .map(row -> {
                    try {
                        return json.readTree(row.getPayload());
                    } catch (Exception unreadable) {
                        throw new IllegalStateException(unreadable);
                    }
                })
                .toList();
        assertThat(queued).singleElement().satisfies(event -> {
            assertThat(event.path("eventType").asText()).isEqualTo("SECURITY_SETTING_CHANGED");
            assertThat(event.at("/extensions/act").asText()).isEqualTo("INTEGRATION_ENABLED_CHANGED");
        });
    }
}
