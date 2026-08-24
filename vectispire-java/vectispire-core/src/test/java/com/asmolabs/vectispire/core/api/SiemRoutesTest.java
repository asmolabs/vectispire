package com.asmolabs.vectispire.core.api;

import static org.assertj.core.api.Assertions.assertThat;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.put;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.jsonPath;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.springframework.http.MediaType;

@DisplayName("the SIEM configuration and test routes")
class SiemRoutesTest extends ApiTestBase {

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
}
