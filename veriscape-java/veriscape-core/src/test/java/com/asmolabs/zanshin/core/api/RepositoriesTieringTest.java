package com.asmolabs.zanshin.core.api;

import static org.assertj.core.api.Assertions.assertThat;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.jsonPath;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

import com.asmolabs.zanshin.common.domain.targets.AssetTier;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.springframework.http.MediaType;

@DisplayName("the repository tiering and SLA management")
class RepositoriesTieringTest extends ApiTestBase {

    @Test
    @DisplayName("creates a repository with Tier 1 Mission Critical tier")
    void createsTier1Repository() throws Exception {
        String token = asAdmin();
        String json = """
                {
                    "url": "https://github.com/asmolabs/payment-gateway.git",
                    "branch": "main",
                    "name": "Payment Gateway",
                    "tier": "TIER_1_MISSION_CRITICAL"
                }
                """;

        mvc.perform(authenticated(post("/api/v1/repositories"), token)
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(json))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.name").value("Payment Gateway"))
                .andExpect(jsonPath("$.tier").value("TIER_1_MISSION_CRITICAL"));

        mvc.perform(authenticated(get("/api/v1/repositories"), token))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$[?(@.name == 'Payment Gateway')].tier").value("TIER_1_MISSION_CRITICAL"));
    }
}
