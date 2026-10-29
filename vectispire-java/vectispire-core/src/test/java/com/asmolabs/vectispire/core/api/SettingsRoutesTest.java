package com.asmolabs.vectispire.core.api;

import static org.assertj.core.api.Assertions.assertThat;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.put;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

import com.asmolabs.vectispire.common.domain.settings.Setting;
import com.asmolabs.vectispire.common.domain.users.Role;
import java.util.Map;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.springframework.http.MediaType;
import org.springframework.test.web.servlet.MvcResult;

/**
 * Who may write a setting, asked over HTTP.
 *
 * <p><b>Why this exists.</b> {@code AuthorizationCoverageTest} exempts {@code SettingsController}
 * by name — correctly, since it serves nothing belonging to a scan target — and the exemption
 * takes the whole file with it, every route added later included. So the only thing standing
 * between a plain reader and the account's tracker token was one annotation with nothing behind
 * it: deleting {@code @RequiresAdministrator} from the route that writes the model provider key
 * left the entire {@code vectispire-core} suite green. That is the shape of defect this project
 * has already shipped three times — a control that works, and an assertion that cannot notice when
 * it stops.
 *
 * <p><b>Through the filter chain, not by calling the controller.</b> A direct call proves the
 * method body; the annotation is enforced by the chain, so a direct call is exactly the test that
 * cannot see this. {@link ApiTestBase} assembles the real one.
 */
@DisplayName("the settings routes")
class SettingsRoutesTest extends ApiTestBase {

    @org.springframework.beans.factory.annotation.Autowired
    private com.asmolabs.vectispire.core.settings.SettingsService settingsStore;

    /** Every writing route, with a body each will accept if it gets that far. */
    private static Map<String, String> writingRoutes() {
        return Map.of(
                "/api/v1/settings", "{\"eol_warn_days\":\"30\"}",
                "/api/v1/settings/ticket-token", "{\"token\":\"probe\"}",
                "/api/v1/settings/webhook-secret", "{\"secret\":\"probe\"}",
                "/api/v1/settings/ticket-webhook-secret", "{\"secret\":\"probe\"}",
                "/api/v1/settings/ai-openai-key", "{\"secret\":\"probe\"}");
    }

    @Test
    @DisplayName("a plain account may read the catalog and write none of it")
    void aReaderWritesNothing() throws Exception {
        String reader = asReader();

        for (Map.Entry<String, String> route : writingRoutes().entrySet()) {
            int status = mvc.perform(authenticated(put(route.getKey()), reader)
                            .contentType(MediaType.APPLICATION_JSON)
                            .content(route.getValue()))
                    .andReturn().getResponse().getStatus();

            assertThat(status)
                    .as("PUT %s answered %d to an ordinary account. Every route here writes "
                            + "deployment configuration, and three of them write a credential — a "
                            + "reader clearing the tracker token stops ticket creation estate-wide, "
                            + "and a reader setting one points it at their own tracker",
                            route.getKey(), status)
                    .isEqualTo(403);
        }
    }

    @Test
    @DisplayName("an administrator may write all of it")
    void anAdministratorWritesAll() throws Exception {
        String admin = asAdmin();

        for (Map.Entry<String, String> route : writingRoutes().entrySet()) {
            int status = mvc.perform(authenticated(put(route.getKey()), admin)
                            .contentType(MediaType.APPLICATION_JSON)
                            .content(route.getValue()))
                    .andReturn().getResponse().getStatus();

            // The counterpart the refusal above needs to mean anything: a rule that refuses
            // everybody is not an authorization rule, and would pass the test above forever.
            assertThat(status)
                    .as("PUT %s answered %d to an administrator", route.getKey(), status)
                    .isEqualTo(200);
        }
    }

    @Test
    @DisplayName("the connection test is not a second way to read the endpoint")
    void theConnectionTestRefusesAReader() throws Exception {
        // `ai_review_ollama_url` is marked SECRET so the catalog withholds it from a
        // non-administrator: an internal model endpoint describes the estate's topology, and the
        // setting's own help text calls it the destination that receives source code. This route
        // reports on that endpoint and answers with its URL, so under the class marker alone it
        // handed a reader the value withheld four lines away — verified before it was narrowed.
        int status = mvc.perform(authenticated(post("/api/v1/settings/ollama-test"), asReader()))
                .andReturn().getResponse().getStatus();

        assertThat(status)
                .as("the connection test answered %d to an ordinary account; it reports the "
                        + "configured URL and makes the server dial it", status)
                .isEqualTo(403);
    }

    @Test
    @DisplayName("a CISO cannot move where the tracker token or the OpenAI key is sent")
    void aCisoCannotRedirectACredential() throws Exception {
        // The credentials are administrator-only, their destinations were not: pointing
        // ticket_base_url at one's own host made the next ticket carry the administrator's token
        // there.
        // A known starting point: the database is shared across the suite, and a switch another test
        // left on would make "true" an unchanged value here rather than a change.
        settingsStore.set(com.asmolabs.vectispire.common.domain.settings.Setting.TICKET_ALLOW_PRIVATE_URL, "false");
        settingsStore.set(com.asmolabs.vectispire.common.domain.settings.Setting.AI_REVIEW_ALLOW_REMOTE, "false");
        String ciso = asCiso();
        for (String body : new String[] {
            "{\"ticket_base_url\":\"https://tracker.attacker.example\"}",
            "{\"ticket_allow_private_url\":\"true\"}",
            "{\"ai_review_openai_url\":\"https://llm.attacker.example/v1\"}",
            "{\"ai_review_ollama_url\":\"http://10.0.0.1:11434\"}",
            "{\"ai_review_allow_remote_url\":\"true\"}"
        }) {
            mvc.perform(authenticated(put("/api/v1/settings"), ciso)
                            .contentType(MediaType.APPLICATION_JSON)
                            .content(body))
                    .andExpect(org.springframework.test.web.servlet.result.MockMvcResultMatchers.status().isForbidden());
        }

        // The rest of the section stays theirs, and so does saving a destination back unchanged —
        // a screen that submits every field it shows would otherwise lock them out of it.
        mvc.perform(authenticated(put("/api/v1/settings"), ciso)
                        .contentType(MediaType.APPLICATION_JSON)
                        .content("{\"eol_warn_days\":\"45\",\"ticket_allow_private_url\":\"false\"}"))
                .andExpect(org.springframework.test.web.servlet.result.MockMvcResultMatchers.status().isOk());

        // An administrator, who may set the credential, may move it.
        mvc.perform(authenticated(put("/api/v1/settings"), asAdmin())
                        .contentType(MediaType.APPLICATION_JSON)
                        .content("{\"ticket_base_url\":\"https://tracker.example.com\"}"))
                .andExpect(org.springframework.test.web.servlet.result.MockMvcResultMatchers.status().isOk());
    }

    @Test
    @DisplayName("a model endpoint carrying a query or a fragment is refused 400, and nothing is stored")
    void aModelEndpointIsAnApiRoot() throws Exception {
        String before = settingsStore.get(Setting.AI_REVIEW_OLLAMA_URL);
        MvcResult refused = mvc.perform(authenticated(put("/api/v1/settings"), asAdmin())
                        .contentType(MediaType.APPLICATION_JSON)
                        .content("{\"ai_review_ollama_url\":\"http://localhost:11434/x?y=\"}"))
                .andExpect(status().isBadRequest())
                .andReturn();
        assertThat(detailOf(refused)).contains("query or a fragment");
        assertThat(settingsStore.get(Setting.AI_REVIEW_OLLAMA_URL)).isEqualTo(before);
    }

    /**
     * The tracker's address is stored as a setting, not through the token's encrypting route: a user name or a
     * token typed into it would be a second copy of the credential, in the clear. Refused as a forge connection's
     * address refuses one, and nothing is stored.
     */
    @Test
    @DisplayName("the tracker's address is refused 400 when it carries a user name or a token")
    void theTrackerAddressCarriesNoCredential() throws Exception {
        settingsStore.set(Setting.TICKET_BASE_URL, "https://tracker.example.com");
        for (String typed : new String[] {
            "https://bot:not-a-real-token@tracker.example.com",
            "https://bot@tracker.example.com",
            "HTTP://user:pass@tracker.example.com/jira"
        }) {
            MvcResult refused = mvc.perform(authenticated(put("/api/v1/settings"), asAdmin())
                            .contentType(MediaType.APPLICATION_JSON)
                            .content(json.writeValueAsString(Map.of("ticket_base_url", typed))))
                    .andExpect(status().isBadRequest())
                    .andReturn();
            assertThat(detailOf(refused)).as(typed).contains("carries a user name or a token");
            assertThat(settingsStore.get(Setting.TICKET_BASE_URL)).isEqualTo("https://tracker.example.com");
        }
        // An address alone, with a path and a port, is still taken.
        mvc.perform(authenticated(put("/api/v1/settings"), asAdmin())
                        .contentType(MediaType.APPLICATION_JSON)
                        .content("{\"ticket_base_url\":\"https://tracker.example.com:8443/jira\"}"))
                .andExpect(status().isOk());
    }

    @Test
    @DisplayName("a CISO cannot choose the tracker project or the Jira account the token is used with")
    void aCisoCannotChooseWhereTheTokenActs() throws Exception {
        // The host was an administrator's, the project was not: the token reaches every project of
        // its host its owner can, so choosing the project chose where the administrator's token wrote.
        Setting project = Setting.TICKET_PROJECT;
        Setting user = Setting.TICKET_USER;
        settingsStore.set(project, "team/service");
        settingsStore.set(user, "bot@example.com");
        try {
            String ciso = asCiso();
            for (String body : new String[] {
                "{\"ticket_project\":\"someone-else/private-repo\"}",
                "{\"ticket_user\":\"other@example.com\"}"
            }) {
                mvc.perform(authenticated(put("/api/v1/settings"), ciso)
                                .contentType(MediaType.APPLICATION_JSON)
                                .content(body))
                        .andExpect(status().isForbidden());
            }
            assertThat(settingsStore.get(project)).isEqualTo("team/service");
            assertThat(settingsStore.get(user)).isEqualTo("bot@example.com");

            mvc.perform(authenticated(put("/api/v1/settings"), asAdmin())
                            .contentType(MediaType.APPLICATION_JSON)
                            .content("{\"ticket_project\":\"team/other\",\"ticket_user\":\"other@example.com\"}"))
                    .andExpect(status().isOk());
            assertThat(settingsStore.get(project)).isEqualTo("team/other");
        } finally {
            settingsStore.set(project, "");
            settingsStore.set(user, "");
        }
    }

    @Test
    @DisplayName("the tracker CA is an administrator's, read as a forge's CA is, and shown by its subject")
    void theTrackerCaIsAnAdministrators() throws Exception {
        String pem = CollectorPki.create("Tracker Test CA").caPem;
        com.fasterxml.jackson.databind.ObjectMapper json = new com.fasterxml.jackson.databind.ObjectMapper();
        // A known starting point: the database is shared across the suite.
        settingsStore.set(Setting.TICKET_CA, "");
        try {
            // It decides whom the tracker token is presented to over TLS: a CISO pinning a CA of their own
            // would have the next ticket carry the administrator's token to a server of their choosing.
            mvc.perform(authenticated(put("/api/v1/settings"), asCiso())
                            .contentType(MediaType.APPLICATION_JSON)
                            .content(json.writeValueAsString(Map.of("ticket_ca_pem", pem))))
                    .andExpect(status().isForbidden());
            assertThat(settingsStore.get(Setting.TICKET_CA)).isEmpty();

            // Refused at the save, in the forge connections' words, rather than logged by the next sweep.
            for (String refusedPem : new String[] {"not a certificate", "-----BEGIN CERTIFICATE-----\nAAAA\n-----END CERTIFICATE-----"}) {
                MvcResult refused = mvc.perform(authenticated(put("/api/v1/settings"), asAdmin())
                                .contentType(MediaType.APPLICATION_JSON)
                                .content(json.writeValueAsString(Map.of("ticket_ca_pem", refusedPem))))
                        .andExpect(status().isBadRequest())
                        .andReturn();
                assertThat(detailOf(refused)).startsWith("The tracker CA");
            }
            assertThat(settingsStore.get(Setting.TICKET_CA)).isEmpty();

            mvc.perform(authenticated(put("/api/v1/settings"), asAdmin())
                            .contentType(MediaType.APPLICATION_JSON)
                            .content(json.writeValueAsString(Map.of("ticket_ca_pem", pem))))
                    .andExpect(status().isOk());
            assertThat(settingsStore.get(Setting.TICKET_CA)).isEqualTo(pem.trim());

            MvcResult shown = mvc.perform(authenticated(
                            org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get("/api/v1/settings/ticket-ca"),
                            asAdmin()))
                    .andExpect(status().isOk())
                    .andReturn();
            com.fasterxml.jackson.databind.JsonNode state = json.readTree(shown.getResponse().getContentAsString());
            assertThat(state.path("pinned").asBoolean()).isTrue();
            assertThat(state.path("subject").asText()).isEqualTo("CN=Tracker Test CA");
            assertThat(state.path("notAfter").isNull()).isFalse();

            // Withheld from other roles, as the value is in the catalog.
            mvc.perform(authenticated(
                            org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get("/api/v1/settings/ticket-ca"),
                            asCiso()))
                    .andExpect(status().isForbidden());
        } finally {
            settingsStore.set(Setting.TICKET_CA, "");
        }
    }

    @Test
    @DisplayName("the tracker token's declared expiry is an administrator's, a date, and reported with the token's state")
    void theDeclaredExpiryIsAnAdministratorsDate() throws Exception {
        settingsStore.set(Setting.TICKET_TOKEN_EXPIRES_ON, "");
        try {
            mvc.perform(authenticated(put("/api/v1/settings"), asCiso())
                            .contentType(MediaType.APPLICATION_JSON)
                            .content("{\"ticket_token_expires_on\":\"2099-01-31\"}"))
                    .andExpect(status().isForbidden());

            MvcResult refused = mvc.perform(authenticated(put("/api/v1/settings"), asAdmin())
                            .contentType(MediaType.APPLICATION_JSON)
                            .content("{\"ticket_token_expires_on\":\"31/01/2099\"}"))
                    .andExpect(status().isBadRequest())
                    .andReturn();
            assertThat(detailOf(refused)).contains("2027-01-31");

            mvc.perform(authenticated(put("/api/v1/settings"), asAdmin())
                            .contentType(MediaType.APPLICATION_JSON)
                            .content("{\"ticket_token_expires_on\":\"2099-01-31\"}"))
                    .andExpect(status().isOk());

            // No provider is configured here, so nothing reports an expiry: the declared one is what is known.
            MvcResult state = mvc.perform(authenticated(
                            org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get("/api/v1/settings/ticket-token"),
                            asReader()))
                    .andExpect(status().isOk())
                    .andReturn();
            com.fasterxml.jackson.databind.JsonNode body =
                    new com.fasterxml.jackson.databind.ObjectMapper().readTree(state.getResponse().getContentAsString());
            assertThat(body.path("expirySource").asText()).isEqualTo("declared");
            assertThat(body.path("expiresAt").asText()).isEqualTo("2099-01-31T00:00:00Z");
            assertThat(body.has("configured")).isTrue();
        } finally {
            settingsStore.set(Setting.TICKET_TOKEN_EXPIRES_ON, "");
        }
    }

    @Test
    @DisplayName("a GitHub project is one owner/repository pair, nothing after it")
    void aGithubProjectIsOneRepository() throws Exception {
        // Pasted into /repos/<project>/issues as typed, "owner/repo/issues/12/comments#" made the
        // ticket a comment on an issue of the writer's choosing.
        String previousProvider = settingsStore.get(Setting.TICKET_PROVIDER);
        try {
            for (String steering : new String[] {
                "owner/repo/issues/12/comments#", "owner/repo?x=1", "owner/..", "../owner", "owner"
            }) {
                MvcResult refused = mvc.perform(authenticated(put("/api/v1/settings"), asAdmin())
                                .contentType(MediaType.APPLICATION_JSON)
                                .content("{\"ticket_provider\":\"github\",\"ticket_project\":\""
                                        + steering + "\"}"))
                        .andExpect(status().isBadRequest())
                        .andReturn();
                assertThat(detailOf(refused)).as(steering).contains("owner/repository");
            }
            assertThat(settingsStore.get(Setting.TICKET_PROJECT)).isEmpty();

            mvc.perform(authenticated(put("/api/v1/settings"), asAdmin())
                            .contentType(MediaType.APPLICATION_JSON)
                            .content("{\"ticket_provider\":\"github\",\"ticket_project\":\"asmo-labs/vecti.spire_x\"}"))
                    .andExpect(status().isOk());
        } finally {
            settingsStore.set(Setting.TICKET_PROVIDER, previousProvider);
            settingsStore.set(Setting.TICKET_PROJECT, "");
        }
    }

    @Test
    @DisplayName("only the platform governor sets how long the evidence of controls is kept")
    void theEvidenceWindowIsTheGovernors() throws Exception {
        // A CISO or an administrator could set it to one day, and the next tick purged every gate
        // verdict, compliance capture and OWASP week — the record that their own controls ran.
        Setting window = Setting.EVIDENCE_RETENTION_DAYS;
        settingsStore.set(window, "400");
        try {
            // The screen shows it read-only to everybody else by this flag.
            com.fasterxml.jackson.databind.JsonNode catalog = json.readTree(
                    mvc.perform(authenticated(org.springframework.test.web.servlet.request.MockMvcRequestBuilders
                                            .get("/api/v1/settings"), asAdmin()))
                            .andExpect(status().isOk())
                            .andReturn().getResponse().getContentAsString());
            assertThat(catalog.findValues("settings").stream()
                            .flatMap(section -> java.util.stream.StreamSupport.stream(section.spliterator(), false))
                            .filter(entry -> entry.path("key").asText().equals("evidence_retention_days"))
                            .map(entry -> entry.path("governor_only").asBoolean()))
                    .containsExactly(true);

            for (String writer : new String[] {asCiso(), asAdmin()}) {
                mvc.perform(authenticated(put("/api/v1/settings"), writer)
                                .contentType(MediaType.APPLICATION_JSON)
                                .content("{\"evidence_retention_days\":\"1\"}"))
                        .andExpect(status().isForbidden());
            }
            assertThat(settingsStore.get(window)).isEqualTo("400");

            mvc.perform(authenticated(put("/api/v1/settings"),
                                    tokenFor("governor-" + System.nanoTime(), Role.SUPERUSER, false))
                            .contentType(MediaType.APPLICATION_JSON)
                            .content("{\"evidence_retention_days\":\"730\"}"))
                    .andExpect(status().isOk());
            assertThat(settingsStore.get(window)).isEqualTo("730");
        } finally {
            settingsStore.set(window, "400");
        }
    }
}

