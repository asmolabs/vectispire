package com.asmolabs.vectispire.core.api;

import static org.assertj.core.api.Assertions.assertThat;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.put;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.jsonPath;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

import com.asmolabs.vectispire.common.domain.settings.Setting;
import com.asmolabs.vectispire.core.settings.SettingsService;
import com.asmolabs.vectispire.core.siem.persistence.SiemConfigEntity;
import com.asmolabs.vectispire.core.siem.persistence.SiemConfigs;
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

    @Test
    @DisplayName("an endpoint is read for its protocol at the save, not discovered at the first event")
    void theEndpointMatchesTheProtocol() throws Exception {
        String token = asAdmin();
        // A URL under a syslog protocol, and host:port under the webhook: both stored before, and
        // both failed every delivery for four hours before the outbox gave up.
        assertThat(saveStatus(token, "SYSLOG_TLS", "https://collector.example.com/cef", null)).isEqualTo(400);
        assertThat(saveStatus(token, "SYSLOG_TCP", "syslog+tls://collector.example.com:6514", null)).isEqualTo(400);
        assertThat(saveStatus(token, "SYSLOG_UDP", "collector.example.com", null)).isEqualTo(400);
        assertThat(saveStatus(token, "WEBHOOK", "collector.example.com:514", null)).isEqualTo(400);
        assertThat(saveStatus(token, "SYSLOG_TLS", "", null)).isEqualTo(400);

        assertThat(saveStatus(token, "SYSLOG_TLS", "collector.example.com:6514", null)).isEqualTo(200);
        assertThat(saveStatus(token, "SYSLOG_UDP", "[2001:db8::1]:514", null)).isEqualTo(200);
    }

    @Test
    @DisplayName("the authorization header is refused for a syslog protocol, which cannot carry it")
    void theHeaderIsWebhookOnly() throws Exception {
        String response = mvc.perform(authenticated(put("/api/v1/siem/config"), asAdmin())
                        .contentType(MediaType.APPLICATION_JSON)
                        .content("""
                                {"enabled": true, "protocol": "SYSLOG_TCP", "endpoint": "collector.example.com:514",
                                 "authHeader": "Bearer never-sent", "minSeverity": "HIGH"}"""))
                .andExpect(status().isBadRequest())
                .andReturn().getResponse().getContentAsString();

        assertThat(response).contains("webhook protocol only");
        assertThat(configs.findById(SiemConfigEntity.SINGLETON_ID)).isEmpty();
    }

    @Test
    @DisplayName("the connection test speaks the protocol it is given, and reaches a syslog collector")
    void theTestUsesTheProtocol() throws Exception {
        settings.set(Setting.NOTIFICATION_ALLOW_PRIVATE_URL, "true");
        try (java.net.DatagramSocket collector =
                new java.net.DatagramSocket(0, java.net.InetAddress.getLoopbackAddress())) {
            collector.setSoTimeout(3_000);

            mvc.perform(authenticated(post("/api/v1/siem/test"), asAdmin())
                            .contentType(MediaType.APPLICATION_JSON)
                            .content("""
                                    {"protocol": "SYSLOG_UDP", "endpoint": "127.0.0.1:%d"}"""
                                    .formatted(collector.getLocalPort())))
                    .andExpect(status().isOk())
                    .andExpect(jsonPath("$.success").value(true));

            java.net.DatagramPacket packet = new java.net.DatagramPacket(new byte[8_192], 8_192);
            collector.receive(packet);
            assertThat(new String(packet.getData(), 0, packet.getLength(), java.nio.charset.StandardCharsets.UTF_8))
                    .contains(" ZAN-SEC-999 - CEF:0|Vectispire|ASPM|");
        }
    }

    @Test
    @DisplayName("a syslog test to loopback is refused unless private destinations are allowed")
    void aSyslogTestFollowsThePrivatePolicy() throws Exception {
        mvc.perform(authenticated(post("/api/v1/siem/test"), asAdmin())
                        .contentType(MediaType.APPLICATION_JSON)
                        .content("""
                                {"protocol": "SYSLOG_TCP", "endpoint": "127.0.0.1:59998"}"""))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.success").value(false))
                .andExpect(jsonPath("$.message").value(org.hamcrest.Matchers.containsString("private or local")));
    }

    private int saveStatus(String token, String protocol, String endpoint, String authHeader) throws Exception {
        String header = authHeader == null ? "" : ", \"authHeader\": \"" + authHeader + "\"";
        return mvc.perform(authenticated(put("/api/v1/siem/config"), token)
                        .contentType(MediaType.APPLICATION_JSON)
                        .content("""
                                {"enabled": true, "protocol": "%s", "endpoint": "%s", "minSeverity": "HIGH"%s}"""
                                .formatted(protocol, endpoint, header)))
                .andReturn().getResponse().getStatus();
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
