package com.asmolabs.vectispire.core.api;

import static org.assertj.core.api.Assertions.assertThat;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.put;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.jsonPath;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

import com.asmolabs.vectispire.common.domain.settings.Setting;
import com.asmolabs.vectispire.core.settings.SettingsService;
import com.sun.net.httpserver.HttpServer;
import java.net.InetAddress;
import java.net.InetSocketAddress;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.MediaType;

@DisplayName("the Notification Center REST routes")
class NotificationCenterRoutesTest extends ApiTestBase {

    @Test
    @DisplayName("retrieves list of all configured notification channels")
    void retrievesChannels() throws Exception {
        String token = asAdmin();

        mvc.perform(authenticated(get("/api/v1/notifications/channels"), token))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$").isArray())
                .andExpect(jsonPath("$[?(@.type == 'scan_delta_slack')]").exists())
                .andExpect(jsonPath("$[?(@.type == 'scan_delta_discord')]").exists())
                .andExpect(jsonPath("$[?(@.type == 'scan_delta_teams')]").exists());

        mvc.perform(authenticated(post("/api/v1/notifications/test/scan_delta_slack"), token))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.type").value("scan_delta_slack"))
                .andExpect(jsonPath("$.testedAt").exists());
    }

    @Autowired
    private SettingsService settings;

    @Test
    @DisplayName("the channel test answers delivered or not, never the sender's own words")
    void theTestAnswersAnOutcomeOnly() throws Exception {
        // "Connection refused", a timeout and "HTTP 404" tell a closed port from a filtered one from a
        // listening server: answered to a security lead pointing a channel at host after host, a
        // scanner of the internal network.
        HttpServer listening = HttpServer.create(new InetSocketAddress(InetAddress.getLoopbackAddress(), 0), 0);
        listening.createContext("/", exchange -> {
            exchange.sendResponseHeaders(404, -1);
            exchange.close();
        });
        listening.start();
        settings.set(Setting.NOTIFICATION_ALLOW_PRIVATE_URL, "true");
        try {
            String closed = testMessage("http://127.0.0.1:59997/hook");
            String answering = testMessage("http://127.0.0.1:" + listening.getAddress().getPort() + "/hook");

            assertThat(closed).isEqualTo(answering).doesNotContainIgnoringCase("connection refused").doesNotContain("404");
        } finally {
            listening.stop(0);
            settings.set(Setting.NOTIFICATION_ALLOW_PRIVATE_URL, "false");
            settings.set(Setting.SLACK_WEBHOOK_URL, "");
        }
    }

    @Test
    @DisplayName("a refused destination is not named back: the address a host name resolves to stays in the log")
    void aRefusalNamesNoAddress() throws Exception {
        // With private destinations refused, the guard's sentence names the address it refused: typing
        // host names one after another read the internal DNS back from the button.
        settings.set(Setting.NOTIFICATION_ALLOW_PRIVATE_URL, "false");
        try {
            assertThat(testMessage("http://localhost:59997/hook"))
                    .doesNotContain("127.0.0.1")
                    .doesNotContain("localhost");
        } finally {
            settings.set(Setting.SLACK_WEBHOOK_URL, "");
        }
    }

    @Test
    @DisplayName("only an administrator opens the notification channels to the internal network")
    void onlyAnAdministratorAllowsPrivateChannels() throws Exception {
        settings.set(Setting.NOTIFICATION_ALLOW_PRIVATE_URL, "false");
        try {
            mvc.perform(authenticated(put("/api/v1/settings"), asCiso())
                            .contentType(MediaType.APPLICATION_JSON)
                            .content("{\"notification_allow_private_url\":\"true\"}"))
                    .andExpect(status().isForbidden());
            assertThat(settings.get(Setting.NOTIFICATION_ALLOW_PRIVATE_URL)).isEqualTo("false");

            mvc.perform(authenticated(put("/api/v1/settings"), asAdmin())
                            .contentType(MediaType.APPLICATION_JSON)
                            .content("{\"notification_allow_private_url\":\"true\"}"))
                    .andExpect(status().isOk());
            assertThat(settings.get(Setting.NOTIFICATION_ALLOW_PRIVATE_URL)).isEqualTo("true");
        } finally {
            settings.set(Setting.NOTIFICATION_ALLOW_PRIVATE_URL, "false");
        }
    }

    /** The Slack channel pointed at {@code url}, tested by a CISO — the role the route admits. */
    private String testMessage(String url) throws Exception {
        settings.set(Setting.SLACK_WEBHOOK_URL, url);
        return json.readTree(mvc.perform(authenticated(post("/api/v1/notifications/test/scan_delta_slack"), asCiso()))
                        .andExpect(status().isOk())
                        .andExpect(jsonPath("$.success").value(false))
                        .andReturn().getResponse().getContentAsString())
                .get("message").asText();
    }
}
