package com.asmolabs.vectispire.core.api;

import static org.assertj.core.api.Assertions.assertThat;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.put;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.jsonPath;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

import com.asmolabs.vectispire.common.domain.settings.Setting;
import com.asmolabs.vectispire.core.persistence.SiemConfigEntity;
import com.asmolabs.vectispire.core.repositories.SiemConfigs;
import com.asmolabs.vectispire.core.services.SettingsService;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.MediaType;

@DisplayName("the SIEM configuration and test routes")
class SiemRoutesTest extends ApiTestBase {

    @Autowired
    private SiemConfigs configs;

    @Autowired
    private SettingsService settings;

    @Test
    @DisplayName("allows CISO and Admin to read and update SIEM streaming configuration")
    void managesSiemConfig() throws Exception {
        String adminToken = asAdmin();

        // 1. Initial config
        mvc.perform(authenticated(get("/api/v1/siem/config"), adminToken))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.enabled").value(false))
                .andExpect(jsonPath("$.protocol").value("WEBHOOK"));

        // 2. Update config
        String updateJson = """
                {
                    "enabled": true,
                    "protocol": "WEBHOOK",
                    "endpoint": "https://siem.example.com/api/v1/events",
                    "authHeader": "Bearer secret-siem-token-123",
                    "minSeverity": "HIGH"
                }
                """;

        mvc.perform(authenticated(put("/api/v1/siem/config"), adminToken)
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(updateJson))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.enabled").value(true))
                .andExpect(jsonPath("$.endpoint").value("https://siem.example.com/api/v1/events"))
                .andExpect(jsonPath("$.hasAuthHeader").value(true));

        // 3. Test ping endpoint (returns error for non-existent server, but responds HTTP 200 with success: false)
        String testJson = """
                {
                    "endpoint": "https://localhost:59999/invalid",
                    "authHeader": "Bearer test"
                }
                """;

        mvc.perform(authenticated(post("/api/v1/siem/test"), adminToken)
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(testJson))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.success").value(false));
    }

    @Test
    @DisplayName("the authorization header is stored encrypted, never as typed")
    void theHeaderIsEncryptedAtRest() throws Exception {
        save("Bearer secret-siem-token-123");

        String stored = configs.findById(SiemConfigEntity.SINGLETON_ID).orElseThrow().getAuthHeader();
        assertThat(stored).startsWith("v2:").doesNotContain("secret-siem-token-123");
    }

    @Test
    @DisplayName("a save that leaves the header blank keeps the one already stored")
    void aBlankHeaderKeepsTheStoredOne() throws Exception {
        // The screen says "leave empty to keep current", and the response never carries the
        // header back. Writing what arrived erased it on every save that changed anything else.
        save("Bearer secret-siem-token-123");
        String before = configs.findById(SiemConfigEntity.SINGLETON_ID).orElseThrow().getAuthHeader();

        save(null);

        assertThat(configs.findById(SiemConfigEntity.SINGLETON_ID).orElseThrow().getAuthHeader()).isEqualTo(before);
        mvc.perform(authenticated(get("/api/v1/siem/config"), asAdmin()))
                .andExpect(jsonPath("$.hasAuthHeader").value(true));
    }

    @Test
    @DisplayName("a private address is refused unless the operator allowed private URLs")
    void privateAddressesFollowTheSetting() throws Exception {
        // It was allowed unconditionally. With the raw error answered to a security lead, that
        // made the test route a scanner of the internal network.
        String testJson = """
                {"endpoint": "http://127.0.0.1:59999/events"}""";

        String refused = mvc.perform(authenticated(post("/api/v1/siem/test"), asAdmin())
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(testJson))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.success").value(false))
                .andReturn().getResponse().getContentAsString();
        assertThat(refused).doesNotContainIgnoringCase("connection refused");

        settings.set(Setting.NOTIFICATION_ALLOW_PRIVATE_URL, "true");
        String attempted = mvc.perform(authenticated(post("/api/v1/siem/test"), asAdmin())
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(testJson))
                .andExpect(jsonPath("$.success").value(false))
                .andReturn().getResponse().getContentAsString();
        // Allowed, the request is actually made — and fails on the closed port, not on the policy.
        assertThat(attempted).isNotEqualTo(refused);
    }

    @Test
    @DisplayName("a new endpoint does not inherit the stored header: it has to be typed again")
    void aMovedEndpointDropsTheHeader() throws Exception {
        // "Blank keeps the header" also held when the endpoint changed, so a security lead could
        // point the collector at their own host and receive the header an administrator stored.
        save("Bearer secret-siem-token-123");

        save(null, "https://collector.attacker.example/e", asCiso());

        assertThat(configs.findById(SiemConfigEntity.SINGLETON_ID).orElseThrow().getAuthHeader()).isNull();
        mvc.perform(authenticated(get("/api/v1/siem/config"), asAdmin()))
                .andExpect(jsonPath("$.hasAuthHeader").value(false));

        // Moving it with a header typed for the new collector keeps that one.
        save("Bearer for-the-new-collector", "https://siem2.example.com/e", asAdmin());
        assertThat(configs.findById(SiemConfigEntity.SINGLETON_ID).orElseThrow().getAuthHeader()).startsWith("v2:");
    }

    private void save(String authHeader) throws Exception {
        save(authHeader, "https://siem.example.com/e", asAdmin());
    }

    private void save(String authHeader, String endpoint, String token) throws Exception {
        String header = authHeader == null ? "" : ", \"authHeader\": \"" + authHeader + "\"";
        mvc.perform(authenticated(put("/api/v1/siem/config"), token)
                        .contentType(MediaType.APPLICATION_JSON)
                        .content("""
                                {"enabled": true, "protocol": "WEBHOOK", "endpoint": "%s",
                                 "minSeverity": "HIGH"%s}""".formatted(endpoint, header)))
                .andExpect(status().isOk());
    }
}
