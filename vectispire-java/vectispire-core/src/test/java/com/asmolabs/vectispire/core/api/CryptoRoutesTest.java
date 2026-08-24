package com.asmolabs.vectispire.core.api;

import static org.assertj.core.api.Assertions.assertThat;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.header;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.jsonPath;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

import com.asmolabs.vectispire.core.services.SigningKeyService;
import java.nio.charset.StandardCharsets;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.MediaType;
import org.springframework.test.web.servlet.MvcResult;

@DisplayName("the cryptographic signing and verification routes")
class CryptoRoutesTest extends ApiTestBase {

    @Autowired
    private SigningKeyService signingKeyService;

    @Test
    @DisplayName("downloads the active instance public key in PEM format")
    void downloadsPublicKey() throws Exception {
        MvcResult result = mvc.perform(get("/api/v1/crypto/public-key.pub"))
                .andExpect(status().isOk())
                .andExpect(header().string("Content-Disposition", "attachment; filename=\"vectispire-signing-key.pub\""))
                .andReturn();

        String body = result.getResponse().getContentAsString();
        assertThat(body).contains("-----BEGIN PUBLIC KEY-----");
        assertThat(body).contains("-----END PUBLIC KEY-----");
    }

    @Test
    @DisplayName("verifies digital signature of a payload")
    void verifiesSignature() throws Exception {
        String token = asAdmin();
        String payload = "{\"status\": \"passed\", \"scanId\": 42}";
        String signature = signingKeyService.sign(payload.getBytes(StandardCharsets.UTF_8));

        String requestJson = String.format("""
                {
                  "payload": "%s",
                  "signature": "%s"
                }
                """, payload.replace("\"", "\\\""), signature);

        mvc.perform(authenticated(post("/api/v1/crypto/verify")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(requestJson), token))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.valid").value(true))
                .andExpect(jsonPath("$.algorithm").value("SHA256withECDSA"));

        String tamperedRequest = String.format("""
                {
                  "payload": "{\\"status\\": \\"failed\\", \\"scanId\\": 42}",
                  "signature": "%s"
                }
                """, signature);

        mvc.perform(authenticated(post("/api/v1/crypto/verify")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(tamperedRequest), token))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.valid").value(false));
    }

    @Test
    @DisplayName("returns cosign CLI helper commands")
    void returnsCosignCliHelper() throws Exception {
        String token = asAdmin();

        mvc.perform(authenticated(get("/api/v1/crypto/cosign-cli-helper"), token))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.keyAlgorithm").value("ECDSA_P256"))
                .andExpect(jsonPath("$.commands.cosignVerifyManifest").exists());
    }
}
