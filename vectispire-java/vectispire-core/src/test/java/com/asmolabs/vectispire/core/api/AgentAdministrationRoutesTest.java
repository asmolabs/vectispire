package com.asmolabs.vectispire.core.api;

import static org.assertj.core.api.Assertions.assertThat;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.delete;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.patch;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.jsonPath;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

import com.asmolabs.vectispire.common.domain.agents.AgentContract;
import com.asmolabs.vectispire.core.repositories.Agents;
import com.asmolabs.vectispire.core.repositories.ApiKeysRepository;
import com.fasterxml.jackson.databind.JsonNode;
import java.util.UUID;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.MediaType;

/**
 * Declaring, changing and removing an agent, through the routes.
 *
 * <p>Declaring writes a key and an agent that must commit together, and removing deletes both —
 * each audited outside that boundary, because the audit's own transaction would deadlock against
 * its parent on the SQLite file. The boundary moved from the controller into a service; only a
 * request through the real stack shows it still opens, commits and does not block.
 */
@DisplayName("the agent administration routes")
class AgentAdministrationRoutesTest extends ApiTestBase {

    @Autowired
    private Agents agents;

    @Autowired
    private ApiKeysRepository keys;

    @Test
    @DisplayName("declare, relabel, disable and delete an agent, taking its key with it")
    void agentLifecycle() throws Exception {
        JsonNode declared = json.readTree(mvc.perform(authenticated(post("/api/v1/admin/agents"), asAdmin())
                        .contentType(MediaType.APPLICATION_JSON)
                        .content("{\"name\": \"edge-1\", \"labels\": \" Customer , dmz \"}"))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.name").value("edge-1"))
                .andReturn().getResponse().getContentAsString());
        UUID id = UUID.fromString(declared.get("id").asText());
        assertThat(declared.get("secret").asText()).isNotBlank();

        UUID keyId = agents.findById(id).orElseThrow().getApiKeyId();
        assertThat(keys.findById(keyId)).isPresent();

        mvc.perform(authenticated(patch("/api/v1/admin/agents/" + id), asAdmin())
                        .contentType(MediaType.APPLICATION_JSON)
                        .content("{\"enabled\": false, \"labels\": \"dmz\"}"))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.id").value(id.toString()))
                .andExpect(jsonPath("$.enabled").value(false))
                .andExpect(jsonPath("$.labels").value("dmz"));

        mvc.perform(authenticated(get("/api/v1/admin/agents/activity"), asAdmin()))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.stats.totalAgents").value(1))
                .andExpect(jsonPath("$.runningScans").isArray())
                .andExpect(jsonPath("$.pendingScans").isArray());

        mvc.perform(authenticated(delete("/api/v1/admin/agents/" + id), asAdmin()))
                .andExpect(status().isNoContent());

        assertThat(agents.findById(id)).isEmpty();
        assertThat(keys.findById(keyId)).isEmpty();

        mvc.perform(authenticated(delete("/api/v1/admin/agents/" + id), asAdmin()))
                .andExpect(status().isNotFound());
    }

    @Test
    @DisplayName("an agent's hello is recorded when its contract matches, and refused with 409 when it does not")
    void hello() throws Exception {
        JsonNode declared = json.readTree(mvc.perform(authenticated(post("/api/v1/admin/agents"), asAdmin())
                        .contentType(MediaType.APPLICATION_JSON)
                        .content("{\"name\": \"edge-3\", \"max_concurrent\": 3}"))
                .andExpect(status().isOk())
                .andReturn().getResponse().getContentAsString());
        UUID id = UUID.fromString(declared.get("id").asText());
        String bearer = "Bearer " + declared.get("secret").asText();

        mvc.perform(post("/api/v1/agent/hello")
                        .header("Authorization", bearer)
                        .contentType(MediaType.APPLICATION_JSON)
                        .content("{\"contract_version\": \"0.0-never\"}"))
                .andExpect(status().isConflict());
        assertThat(agents.findById(id).orElseThrow().getLastSeenAt()).isNull();

        mvc.perform(post("/api/v1/agent/hello")
                        .header("Authorization", bearer)
                        .contentType(MediaType.APPLICATION_JSON)
                        .content("{\"contract_version\": \"" + AgentContract.VERSION + "\", \"sealing_public_key\": \"not-a-key\"}"))
                .andExpect(status().isBadRequest());

        mvc.perform(post("/api/v1/agent/hello")
                        .header("Authorization", bearer)
                        .contentType(MediaType.APPLICATION_JSON)
                        .content("{\"contract_version\": \"" + AgentContract.VERSION + "\", \"hostname\": \" edge-host \"}"))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.id").value(id.toString()))
                .andExpect(jsonPath("$.contractVersion").value(AgentContract.VERSION))
                .andExpect(jsonPath("$.maxConcurrent").value(3));

        assertThat(agents.findById(id).orElseThrow().getHostname()).isEqualTo("edge-host");
    }

    @Test
    @DisplayName("refuses an unknown credentials mode without writing anything")
    void refusesUnknownMode() throws Exception {
        mvc.perform(authenticated(post("/api/v1/admin/agents"), asAdmin())
                        .contentType(MediaType.APPLICATION_JSON)
                        .content("{\"name\": \"edge-2\", \"credentials_mode\": \"telepathy\"}"))
                .andExpect(status().isBadRequest());

        assertThat(agents.findAllByOrderByNameAsc()).isEmpty();
    }
}
