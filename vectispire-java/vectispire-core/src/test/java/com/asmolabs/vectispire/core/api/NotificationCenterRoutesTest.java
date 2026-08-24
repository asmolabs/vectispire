package com.asmolabs.vectispire.core.api;

import static org.assertj.core.api.Assertions.assertThat;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.jsonPath;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

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
}
