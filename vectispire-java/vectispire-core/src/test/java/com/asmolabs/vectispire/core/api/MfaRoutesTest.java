package com.asmolabs.zanshin.core.api;

import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.jsonPath;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

import com.asmolabs.zanshin.common.domain.auth.Totp;
import com.asmolabs.zanshin.core.services.TotpService;
import java.time.Clock;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.MediaType;

@DisplayName("MFA / TOTP authentication routes")
class MfaRoutesTest extends ApiTestBase {

    @Autowired
    private TotpService totpService;

    @Autowired
    private Clock clock;

    @Test
    @DisplayName("sets up, enables and verifies MFA flow")
    void fullMfaLifecycle() throws Exception {
        String token = asAdmin();

        // 1. Setup
        String setupJson = mvc.perform(authenticated(post("/api/v1/auth/mfa/setup"), token))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.secret").isString())
                .andExpect(jsonPath("$.qrCodeUri").isString())
                .andReturn().getResponse().getContentAsString();

        String secret = com.jayway.jsonpath.JsonPath.read(setupJson, "$.secret");
        String code = Totp.generateCode(secret, clock.instant());

        // 2. Enable
        mvc.perform(authenticated(post("/api/v1/auth/mfa/enable"), token)
                        .contentType(MediaType.APPLICATION_JSON)
                        .content("{\"secret\":\"" + secret + "\",\"code\":\"" + code + "\"}"))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.success").value(true))
                .andExpect(jsonPath("$.backupCodes").isArray());

        // 3. Disable with code
        String disableCode = Totp.generateCode(secret, clock.instant());
        mvc.perform(authenticated(post("/api/v1/auth/mfa/disable"), token)
                        .contentType(MediaType.APPLICATION_JSON)
                        .content("{\"code\":\"" + disableCode + "\"}"))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.mfaEnabled").value(false));
    }
}
