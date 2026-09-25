package com.asmolabs.vectispire.core.api;

import static org.assertj.core.api.Assertions.assertThat;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.patch;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;

import com.asmolabs.vectispire.common.domain.agents.AgentContract;
import com.asmolabs.vectispire.core.persistence.AgentEntity;
import com.asmolabs.vectispire.core.repositories.Agents;
import com.asmolabs.vectispire.core.repositories.ApiKeysRepository;
import com.fasterxml.jackson.databind.JsonNode;
import java.util.Map;
import java.util.UUID;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.MediaType;

/**
 * What an agent may be called, and what it may say about itself.
 *
 * <p>Two rules, because two people write these fields. The administrator's form is refused past a
 * column — the name against the key's column, since the key is called "Agent " and the name. The
 * agent's own announcement is clipped instead: nobody can correct it from here, and refusing it
 * would drop the heartbeat that keeps the agent online. On SQLite neither overflow is visible to the
 * database, so the assertions are the status and the stored length.
 */
@DisplayName("the bounds of an agent")
class AgentInputBoundsTest extends ApiTestBase {

    @Autowired
    private Agents agents;

    @Autowired
    private ApiKeysRepository keys;

    @Test
    @DisplayName("a name that would overflow its key's column is a 400, and one that fits is declared")
    void theNameFitsTheKey() throws Exception {
        String admin = asAdmin();

        assertThat(declare(admin, Map.of("name", "n".repeat(250)))).isEqualTo(400);
        assertThat(agents.findAll()).isEmpty();
        assertThat(keys.findAll()).isEmpty();

        assertThat(declare(admin, Map.of("name", "n".repeat(249)))).isEqualTo(200);
        assertThat(keys.findAll()).singleElement()
                .satisfies(key -> assertThat(key.getName()).hasSize(255));
    }

    @Test
    @DisplayName("a description or a label list past its column is a 400, on declaration and on change")
    void descriptionAndLabelsAreBounded() throws Exception {
        String admin = asAdmin();

        assertThat(declare(admin, Map.of("name", "edge", "description", "d".repeat(501)))).isEqualTo(400);
        assertThat(declare(admin, Map.of("name", "edge", "labels", "l".repeat(256)))).isEqualTo(400);
        assertThat(agents.findAll()).isEmpty();

        String id = json.readTree(mvc.perform(authenticated(post("/api/v1/admin/agents"), admin)
                                .contentType(MediaType.APPLICATION_JSON)
                                .content(write(Map.of("name", "edge"))))
                        .andReturn().getResponse().getContentAsString())
                .get("id").asText();
        int status = mvc.perform(authenticated(patch("/api/v1/admin/agents/" + id), admin)
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(write(Map.of("labels", "l".repeat(256)))))
                .andReturn().getResponse().getStatus();
        assertThat(status).isEqualTo(400);
        assertThat(agents.findById(UUID.fromString(id)).orElseThrow().getLabels()).isNull();
    }

    @Test
    @DisplayName("an agent's oversized self-description is clipped to its columns, and the hello answers")
    void theAnnouncementIsClipped() throws Exception {
        JsonNode declared = json.readTree(mvc.perform(authenticated(post("/api/v1/admin/agents"), asAdmin())
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(write(Map.of("name", "chatty"))))
                .andReturn().getResponse().getContentAsString());
        UUID id = UUID.fromString(declared.get("id").asText());

        int status = mvc.perform(post("/api/v1/agent/hello")
                        .header("Authorization", "Bearer " + declared.get("secret").asText())
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(write(Map.of(
                                "contract_version", AgentContract.VERSION,
                                "hostname", "h".repeat(300),
                                "platform", "p".repeat(300),
                                "version", "v".repeat(80),
                                "scanner_engine", "s".repeat(80)))))
                .andReturn().getResponse().getStatus();

        assertThat(status).as("a heartbeat is never refused over a display field").isEqualTo(200);
        AgentEntity stored = agents.findById(id).orElseThrow();
        assertThat(stored.getHostname()).hasSize(255);
        assertThat(stored.getPlatform()).hasSize(255);
        assertThat(stored.getVersion()).hasSize(50);
        assertThat(stored.getScannerEngine()).hasSize(50);
        assertThat(stored.getLastSeenAt()).isNotNull();
    }

    private int declare(String admin, Map<String, String> body) throws Exception {
        return mvc.perform(authenticated(post("/api/v1/admin/agents"), admin)
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(write(body)))
                .andReturn().getResponse().getStatus();
    }
}
