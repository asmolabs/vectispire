package com.asmolabs.vectispire.core.api;

import static org.assertj.core.api.Assertions.assertThat;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

import java.util.List;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.springframework.http.MediaType;

/**
 * {@code /actuator/prometheus}, served by the running application through the real filter chain, and
 * who may read it and the rest of Actuator.
 *
 * <p><b>Why a scrape and not the registry.</b> The meters can all be registered while the page that
 * ships them is not exposed, not on the classpath, or refused to the one credential a Prometheus
 * server can hold — each a monitoring that sees nothing, with every unit test green. Only reading the
 * page as a scraper does tells those apart from a working one.
 */
@DisplayName("the Prometheus scrape")
class PrometheusScrapeTest extends ApiTestBase {

    /** As {@code application-apitest.yaml} sets it. */
    private static final String SCRAPE_TOKEN = "apitest-scrape-token-0123456789abcdef";

    @Test
    @DisplayName("serves the Vectispire meters and Spring Boot's to the scrape token")
    void servesTheMetersToTheScrapeToken() throws Exception {
        String page = mvc.perform(authenticated(get("/actuator/prometheus"), SCRAPE_TOKEN))
                .andExpect(status().isOk())
                .andReturn().getResponse().getContentAsString();

        assertThat(page).contains(
                // The queue, by kind.
                "vectispire_scans_queued{",
                "kind=\"repository\"",
                "kind=\"container\"",
                "vectispire_scans_queued_oldest_age_seconds{",
                "vectispire_scans_running",
                // The scans' lives, at zero before the first: a rate over an absent series is no line.
                "vectispire_scans_started_total{",
                "vectispire_scans_completed_total{",
                "vectispire_scans_failed_total{",
                "vectispire_scans_lapsed_total{",
                // The agents.
                "vectispire_agents_enabled",
                "vectispire_agents_online",
                "vectispire_agents_last_seen_age_seconds",
                "vectispire_agents_polls_total{",
                "vectispire_agents_claims_total{",
                "vectispire_scans_credential_unserved",
                "vectispire_outbox_pending",
                "vectispire_metrics_snapshot_age_seconds{",
                // What Spring Boot already measures: the JVM and the connection pool.
                "jvm_memory_used_bytes",
                "hikaricp_connections_active");
        assertThat(page)
                .as("every series says which instance produced it")
                .contains("application=\"");
    }

    @Test
    @DisplayName("is refused to an anonymous scrape")
    void refusesAnAnonymousScrape() throws Exception {
        mvc.perform(get("/actuator/prometheus")).andExpect(status().isUnauthorized());
        mvc.perform(authenticated(get("/actuator/prometheus"), "apitest-scrape-token-0123456789abcdeX"))
                .andExpect(status().isUnauthorized());
    }

    @Test
    @DisplayName("opens nothing but the Prometheus page to the scrape token")
    void theScrapeTokenOpensThatPageOnly() throws Exception {
        // Elsewhere it is an unknown bearer: not the SCIM token's mistake again, a static secret held
        // by a third system authenticating on every route.
        for (String elsewhere : List.of(
                "/actuator/metrics", "/actuator/encryption", "/actuator/info", "/api/v1/auth/me", "/api/v1/repositories")) {
            mvc.perform(authenticated(get(elsewhere), SCRAPE_TOKEN)).andExpect(status().isUnauthorized());
        }
        mvc.perform(get("/actuator/prometheus").header("X-API-Key", SCRAPE_TOKEN)).andExpect(status().isUnauthorized());
    }

    @Test
    @DisplayName("is behind authentication, because a probe is not a metrics scrape")
    void areBehindAuthentication() throws Exception {
        mvc.perform(get("/actuator/metrics")).andExpect(status().isUnauthorized());
        mvc.perform(get("/actuator/health")).andExpect(status().isOk());
    }

    @Test
    @DisplayName("is an administrator's session's to read, and no other credential's but the scrape token")
    void areAnAdministratorsSessionsOnly() throws Exception {
        // The MVC confinement — an agent key to the agent protocol, an integration key to the
        // routes of its scope, a session owing a password change to that change — does not reach
        // Actuator, whose endpoints are not the application's handlers. Each of these read the
        // instance's internal structure and volumes.
        String agentKey = json.readTree(mvc.perform(authenticated(post("/api/v1/admin/agents"), asAdmin())
                        .contentType(MediaType.APPLICATION_JSON)
                        .content("{\"name\": \"metrics-probe-" + System.nanoTime() + "\"}"))
                .andReturn().getResponse().getContentAsString()).get("secret").asText();
        String integrationKey = json.readTree(mvc.perform(authenticated(post("/api/v1/api-keys"), asAdmin())
                        .contentType(MediaType.APPLICATION_JSON)
                        .content("{\"name\": \"metrics-probe\", \"scopes\": [\"read\"]}"))
                .andReturn().getResponse().getContentAsString()).get("secret").asText();

        for (String endpoint : List.of("/actuator/metrics", "/actuator/info", "/actuator/encryption", "/actuator/prometheus")) {
            for (String refused : List.of(agentKey, integrationKey, asReader(), asCiso(), asPendingPasswordChange())) {
                mvc.perform(authenticated(get(endpoint), refused)).andExpect(status().isForbidden());
            }
            mvc.perform(authenticated(get(endpoint), asAdmin())).andExpect(status().isOk());
        }
        // The probe stays open: a container's health check has no session.
        mvc.perform(get("/actuator/health/liveness")).andExpect(status().isOk());
    }
}
