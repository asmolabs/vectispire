package com.asmolabs.vectispire.core.api;

import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.jsonPath;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

import com.asmolabs.vectispire.common.domain.auth.Totp;
import com.asmolabs.vectispire.core.access.TotpService;
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
                        .content("{\"password\":\"correct horse battery staple\",\"secret\":\"" + secret + "\",\"code\":\"" + code + "\"}"))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.success").value(true))
                .andExpect(jsonPath("$.backupCodes").isArray());

        // 3. Disable with the next code: the one that enrolled has been used, and a code opens once
        String disableCode = Totp.generateCode(secret, clock.instant().plusSeconds(30));
        mvc.perform(authenticated(post("/api/v1/auth/mfa/disable"), token)
                        .contentType(MediaType.APPLICATION_JSON)
                        .content("{\"code\":\"" + disableCode + "\"}"))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.mfaEnabled").value(false));
    }

    @org.junit.jupiter.api.Test
    @org.junit.jupiter.api.DisplayName("disabling counts wrong codes against the account, and stops at its budget")
    void disablingIsThrottledLikeSignIn() throws Exception {
        // It had no ceiling: a session left open could try codes against /mfa/disable for as long
        // as it lived, and a six-digit space does not survive that.
        String token = asAdmin();
        String setupJson = mvc.perform(authenticated(post("/api/v1/auth/mfa/setup"), token))
                .andReturn().getResponse().getContentAsString();
        String secret = com.jayway.jsonpath.JsonPath.read(setupJson, "$.secret");
        mvc.perform(authenticated(post("/api/v1/auth/mfa/enable"), token)
                        .contentType(MediaType.APPLICATION_JSON)
                        .content("{\"password\":\"correct horse battery staple\",\"secret\":\"" + secret + "\",\"code\":\"" + Totp.generateCode(secret, clock.instant()) + "\"}"))
                .andExpect(status().isOk());

        for (int attempt = 0; attempt < com.asmolabs.vectispire.common.domain.auth.LoginThrottle.MAX_SECOND_FACTOR_FAILURES; attempt++) {
            mvc.perform(authenticated(post("/api/v1/auth/mfa/disable"), token)
                            .contentType(MediaType.APPLICATION_JSON)
                            .content("{\"code\":\"00000" + attempt + "\"}"))
                    .andExpect(status().isBadRequest());
        }

        // Locked now, even for the right code.
        mvc.perform(authenticated(post("/api/v1/auth/mfa/disable"), token)
                        .contentType(MediaType.APPLICATION_JSON)
                        .content("{\"code\":\"" + Totp.generateCode(secret, clock.instant().plusSeconds(30)) + "\"}"))
                .andExpect(status().isTooManyRequests());
    }

    /**
     * Enrolling needed a session only: whoever held one put the account's factor on their own phone, and
     * the owner, with no code to disable it, was locked out until somebody edited the database.
     */
    @Test
    @DisplayName("enrolling asks for the current password, and a wrong one counts like a sign-in failure")
    void enrollingAsksForThePassword() throws Exception {
        String token = tokenFor("mfa-enrol-" + System.nanoTime(), com.asmolabs.vectispire.common.domain.users.Role.USER, false);
        String setupJson = mvc.perform(authenticated(post("/api/v1/auth/mfa/setup"), token))
                .andReturn().getResponse().getContentAsString();
        String secret = com.jayway.jsonpath.JsonPath.read(setupJson, "$.secret");
        String code = Totp.generateCode(secret, clock.instant());

        mvc.perform(authenticated(post("/api/v1/auth/mfa/enable"), token)
                        .contentType(MediaType.APPLICATION_JSON)
                        .content("{\"secret\":\"" + secret + "\",\"code\":\"" + code + "\"}"))
                .andExpect(status().isBadRequest());
        mvc.perform(authenticated(post("/api/v1/auth/mfa/enable"), token)
                        .contentType(MediaType.APPLICATION_JSON)
                        .content("{\"password\":\"not the password\",\"secret\":\"" + secret + "\",\"code\":\"" + code + "\"}"))
                .andExpect(status().isUnauthorized());
        mvc.perform(authenticated(get("/api/v1/auth/me"), token))
                .andExpect(jsonPath("$.mfaEnabled").value(false));

        for (int attempt = 1; attempt < com.asmolabs.vectispire.common.domain.auth.LoginThrottle.MAX_ATTEMPTS_PER_USER; attempt++) {
            mvc.perform(authenticated(post("/api/v1/auth/mfa/enable"), token)
                            .contentType(MediaType.APPLICATION_JSON)
                            .content("{\"password\":\"guess " + attempt + "\",\"secret\":\"" + secret + "\",\"code\":\"" + code + "\"}"))
                    .andExpect(status().isUnauthorized());
        }
        // The budget is the sign-in's: spent, even the right password waits.
        mvc.perform(authenticated(post("/api/v1/auth/mfa/enable"), token)
                        .contentType(MediaType.APPLICATION_JSON)
                        .content("{\"password\":\"correct horse battery staple\",\"secret\":\"" + secret + "\",\"code\":\"" + code + "\"}"))
                .andExpect(status().isTooManyRequests());
    }

    @Test
    @DisplayName("enrolling a secret that is no key is refused as a wrong code, not a 500")
    void aSecretWithNoKeyIsABadRequest() throws Exception {
        String token = asAdmin();

        mvc.perform(authenticated(post("/api/v1/auth/mfa/enable"), token)
                        .contentType(MediaType.APPLICATION_JSON)
                        .content("{\"password\":\"correct horse battery staple\",\"secret\":\"!!!\",\"code\":\"123456\"}"))
                .andExpect(status().isBadRequest())
                .andExpect(jsonPath("$.detail").value("Invalid TOTP verification code."));
    }
}
