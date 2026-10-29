package com.asmolabs.vectispire.core.api;

import static org.assertj.core.api.Assertions.assertThat;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

import com.fasterxml.jackson.databind.JsonNode;
import java.util.ArrayList;
import java.util.List;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

/**
 * The census of every sealed store, as the rotation procedure reads it.
 *
 * <p><b>Asserted on the composition</b>: each store is a bean of the module that owns it, and a
 * module whose line is missing makes the census say a rotation is finished while its values still
 * need the old key — which is what the procedure said for three stores out of eleven.
 */
@DisplayName("the encryption census")
class EncryptionCensusRoutesTest extends ApiTestBase {

    @Test
    @DisplayName("lists every sealed store, to an administrator's session")
    void listsEveryStore() throws Exception {
        JsonNode report = json.readTree(mvc.perform(authenticated(get("/actuator/encryption"), asAdmin()))
                .andExpect(status().isOk())
                .andReturn().getResponse().getContentAsString());

        List<String> stores = new ArrayList<>();
        report.path("stores").forEach(store -> stores.add(store.path("store").asText()));
        assertThat(stores).containsExactlyInAnyOrder(
                "SSH deploy keys",
                "HTTPS clone tokens",
                "Forge connection tokens",
                "Document signing key",
                "TOTP secrets",
                "TOTP backup codes",
                "Tracker access token",
                "Inbound tracker webhook secret",
                "Notification webhook signing secret",
                "OpenAI API key",
                "SIEM authorization header");
        assertThat(report.path("rotationFinished").isBoolean()).isTrue();
    }
}
