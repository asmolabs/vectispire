package com.asmolabs.vectispire.core.api;

import static com.asmolabs.vectispire.core.api.ForgeDiscoveriesRoutesTest.GROUPS;
import static com.asmolabs.vectispire.core.api.ForgeDiscoveriesRoutesTest.PROJECTS;
import static com.asmolabs.vectispire.core.api.ForgeDiscoveriesRoutesTest.TOKEN;
import static com.asmolabs.vectispire.core.api.ForgeDiscoveriesRoutesTest.project;
import static org.assertj.core.api.Assertions.assertThat;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.patch;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.put;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

import com.asmolabs.vectispire.common.domain.forges.ForgeKind;
import com.asmolabs.vectispire.common.domain.integrations.Integration;
import com.asmolabs.vectispire.core.forges.ForgeStub;
import com.asmolabs.vectispire.core.forges.ForgeStub.Reply;
import com.asmolabs.vectispire.core.forges.internal.DiscoveryExecution;
import com.asmolabs.vectispire.core.forges.internal.DiscoveryQueue;
import com.asmolabs.vectispire.core.forges.internal.DiscoveryWorker;
import com.asmolabs.vectispire.core.forges.persistence.ForgeConnectionEntity;
import com.asmolabs.vectispire.core.forges.persistence.ForgeConnectionRepository;
import com.asmolabs.vectispire.core.forges.persistence.ForgeDiscoveryEntity;
import com.asmolabs.vectispire.core.forges.persistence.ForgeDiscoveryRepository;
import com.asmolabs.vectispire.core.settings.Integrations;
import com.asmolabs.vectispire.core.targets.persistence.GitRepositoryRepository;
import com.fasterxml.jackson.databind.JsonNode;
import java.util.HashMap;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.UUID;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.Timeout;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.data.domain.PageRequest;
import org.springframework.http.MediaType;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.test.web.servlet.MvcResult;
import org.springframework.test.web.servlet.ResultActions;

/**
 * A GitLab connection when the governor switches {@code forge.gitlab} off (decision 0040 §1–2, lot I2), over HTTP,
 * against the self-managed GitLab on loopback the discovery suite uses: every gesture that would reach the forge or act
 * on what it said is refused 409 {@code integration-disabled}, nothing reaches the stub, and the connection already
 * kept reads {@code suspended} with its row and its token untouched — until the forge is switched back on, when it
 * resumes as it was, a discovery queued before the switch included.
 *
 * <p>{@code t_integration} is put back as it was found after each case ({@link IntegrationRows}).
 */
@DisplayName("a forge connection whose integration is disabled")
class ForgeSuspensionRoutesTest extends ApiTestBase {

    private static final String RECENT = "2026-09-20T10:00:00Z";
    private static final String DISABLED = "urn:vectispire:problem:integration-disabled";
    private static final Integration GITLAB = Integration.of(ForgeKind.GITLAB);

    @Autowired
    private Integrations integrations;

    @Autowired
    private DiscoveryWorker worker;

    @Autowired
    private DiscoveryQueue queue;

    @Autowired
    private DiscoveryExecution execution;

    @Autowired
    private ForgeConnectionRepository connections;

    @Autowired
    private ForgeDiscoveryRepository discoveries;

    @Autowired
    private GitRepositoryRepository repositories;

    @Autowired
    private JdbcTemplate jdbc;

    private IntegrationRows rows;
    private ForgeStub gitlab;
    private String connectionId;
    private long discoveryId;

    @BeforeEach
    void discovered() throws Exception {
        rows = IntegrationRows.remember(jdbc);
        gitlab = ForgeStub.start().gitlab("17.4.1", "[\"read_api\"]", true);
        gitlab.route(GROUPS, Reply.json("[{\"id\":1,\"full_path\":\"acme\"}]"));
        gitlab.route(PROJECTS, Reply.json("[" + project(42, "acme/app", "group", "main", false, 10L, false, RECENT) + "]"));
        connectionId = create("Internal GitLab").andExpect(status().isCreated()).andReturn().getResponse()
                .getContentAsString().transform(this::idOf);
        discoveryId = json.readTree(discover().andExpect(status().isAccepted()).andReturn().getResponse()
                .getContentAsString()).at("/id").asLong();
        assertThat(worker.drain()).isOne();
    }

    @AfterEach
    void putBack() {
        gitlab.close();
        rows.putBack();
    }

    @Test
    @DisplayName("creating one is refused 409 naming forge.gitlab; the one kept reads suspended, its row and token untouched")
    void creationRefusedAndKeptSuspended() throws Exception {
        ForgeConnectionEntity before = connections.findById(UUID.fromString(connectionId)).orElseThrow();
        assertThat(connection(connectionId).at("/state").asText()).isEqualTo("active");
        disable();
        gitlab.seen.clear();

        refused(create("Another GitLab"));

        assertThat(connections.count()).as("nothing created").isOne();
        assertThat(gitlab.seen).as("not probed: nothing reached the forge").isEmpty();
        JsonNode kept = connection(connectionId);
        assertThat(kept.at("/state").asText()).isEqualTo("suspended");
        assertThat(kept.at("/integration").asText()).isEqualTo("forge.gitlab");
        assertThat(kept.at("/lastDiscovery/state").asText()).as("what it discovered is kept").isEqualTo("completed");
        JsonNode listed = read(mvc.perform(authenticated(get("/api/v1/forge-connections"), asAdmin()))
                .andExpect(status().isOk()));
        assertThat(listed.get(0).at("/state").asText()).isEqualTo("suspended");
        ForgeConnectionEntity after = connections.findById(UUID.fromString(connectionId)).orElseThrow();
        assertThat(after.getToken()).as("the encrypted token is kept as it was").isEqualTo(before.getToken());
        assertThat(after.getUpdatedAt()).as("the switch writes nothing on the connection").isEqualTo(before.getUpdatedAt());
    }

    @Test
    @DisplayName("a discovery, an import's preview, an import and a new token are refused 409; nothing reaches the forge")
    void everyUseRefused() throws Exception {
        disable();
        gitlab.seen.clear();
        long targets = repositories.count();

        refused(discover());
        refused(postJson(base() + "/imports/preview", importOf("42")));
        refused(postJson(base() + "/imports", importOf("42")));
        refused(mvc.perform(authenticated(put(base() + "/token"), asAdmin()).contentType(MediaType.APPLICATION_JSON)
                .content(write(Map.of("token", TOKEN)))));
        refused(mvc.perform(authenticated(patch(base()), asAdmin()).contentType(MediaType.APPLICATION_JSON)
                .content(write(Map.of("internalNetwork", false)))));

        assertThat(gitlab.seen).isEmpty();
        assertThat(repositories.count()).as("nothing imported").isEqualTo(targets);
        assertThat(discoveries.findByConnectionIdOrderByRequestedAtDescIdDesc(UUID.fromString(connectionId),
                PageRequest.of(0, 10))).as("nothing queued").hasSize(1);
        // The snapshot it kept still reads, and a rename, which calls no forge, still goes through.
        mvc.perform(authenticated(get(base() + "/discoveries/" + discoveryId + "/selection"), asAdmin()))
                .andExpect(status().isOk());
        mvc.perform(authenticated(patch(base()), asAdmin()).contentType(MediaType.APPLICATION_JSON)
                        .content(write(Map.of("name", "Renamed GitLab"))))
                .andExpect(status().isOk());
        assertThat(gitlab.seen).isEmpty();
    }

    @Test
    @Timeout(value = 120, threadMode = Timeout.ThreadMode.SEPARATE_THREAD)
    @DisplayName("a discovery queued before the switch waits, neither failed nor counted, and runs once the forge is back")
    void queuedDiscoveryWaits() throws Exception {
        long queued = json.readTree(discover().andExpect(status().isAccepted()).andReturn().getResponse()
                .getContentAsString()).at("/id").asLong();
        disable();
        gitlab.seen.clear();

        assertThat(worker.drain()).as("passed over by the claim").isZero();
        ForgeDiscoveryEntity waiting = discoveries.findById(queued).orElseThrow();
        assertThat(waiting.getState()).isEqualTo("pending");
        assertThat(waiting.getAttempts()).isZero();
        assertThat(gitlab.seen).isEmpty();

        enable();
        assertThat(connection(connectionId).at("/state").asText()).isEqualTo("active");
        assertThat(worker.drain()).isOne();
        assertThat(discoveries.findById(queued).orElseThrow().getState()).isEqualTo("completed");
    }

    @Test
    @Timeout(value = 120, threadMode = Timeout.ThreadMode.SEPARATE_THREAD)
    @DisplayName("a run claimed just before the switch is given back waiting, its attempt not counted, the token not sent")
    void claimedBeforeTheSwitchIsGivenBack() throws Exception {
        long queued = json.readTree(discover().andExpect(status().isAccepted()).andReturn().getResponse()
                .getContentAsString()).at("/id").asLong();
        assertThat(queue.claim("east")).contains(queued);
        disable();
        gitlab.seen.clear();

        execution.execute(queued, "east");

        ForgeDiscoveryEntity given = discoveries.findById(queued).orElseThrow();
        assertThat(given.getState()).isEqualTo("pending");
        assertThat(given.getClaimedBy()).isNull();
        assertThat(given.getAttempts()).isZero();
        assertThat(gitlab.seen).isEmpty();
    }

    @Test
    @DisplayName("re-enabled, the connection resumes as it was: an import's preview answers again")
    void reEnabledResumes() throws Exception {
        disable();
        refused(postJson(base() + "/imports/preview", importOf("42")));
        enable();

        JsonNode preview = read(postJson(base() + "/imports/preview", importOf("42")).andExpect(status().isOk()));
        assertThat(preview.at("/targets/0/forgeId").asText()).isEqualTo("42");
    }

    // ---- Helpers.

    private void disable() {
        assertThat(integrations.switchTo(GITLAB, false, "test").changed()).isTrue();
    }

    private void enable() {
        integrations.switchTo(GITLAB, true, "test");
    }

    private void refused(ResultActions result) throws Exception {
        MvcResult answered = result.andExpect(status().isConflict()).andReturn();
        JsonNode problem = json.readTree(answered.getResponse().getContentAsString());
        assertThat(problem.at("/type").asText()).isEqualTo(DISABLED);
        assertThat(problem.at("/integration").asText()).isEqualTo("forge.gitlab");
    }

    private ResultActions create(String name) throws Exception {
        Map<String, Object> body = new HashMap<>();
        body.put("name", name);
        body.put("kind", "gitlab");
        body.put("baseUrl", gitlab.baseUrl());
        body.put("internalNetwork", true);
        body.put("caPem", gitlab.caPem);
        body.put("token", TOKEN);
        return postJson("/api/v1/forge-connections", body);
    }

    private JsonNode connection(String id) throws Exception {
        return read(mvc.perform(authenticated(get("/api/v1/forge-connections/" + id), asAdmin())).andExpect(status().isOk()));
    }

    private ResultActions discover() throws Exception {
        return mvc.perform(authenticated(post(base() + "/discoveries"), asAdmin()));
    }

    private Map<String, Object> importOf(String... forgeIds) {
        Map<String, Object> body = new LinkedHashMap<>();
        body.put("discoveryId", discoveryId);
        body.put("forgeIds", List.of(forgeIds));
        return body;
    }

    private String base() {
        return "/api/v1/forge-connections/" + connectionId;
    }

    private ResultActions postJson(String url, Object body) throws Exception {
        return mvc.perform(authenticated(post(url), asAdmin()).contentType(MediaType.APPLICATION_JSON).content(write(body)));
    }

    private String idOf(String created) {
        try {
            return json.readTree(created).at("/id").asText();
        } catch (Exception unreadable) {
            throw new IllegalStateException(unreadable);
        }
    }

    private JsonNode read(ResultActions result) throws Exception {
        return json.readTree(result.andReturn().getResponse().getContentAsString());
    }
}
