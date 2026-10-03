package com.asmolabs.vectispire.core.api;

import static org.assertj.core.api.Assertions.assertThat;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.delete;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.patch;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.put;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

import com.asmolabs.vectispire.common.domain.audit.AuditOperation;
import com.asmolabs.vectispire.common.domain.settings.Setting;
import com.asmolabs.vectispire.core.audit.persistence.AuditLogEntity;
import com.asmolabs.vectispire.core.audit.persistence.AuditLogRepository;
import com.asmolabs.vectispire.core.forges.ForgeStub;
import com.asmolabs.vectispire.core.forges.ForgeStub.Reply;
import com.asmolabs.vectispire.core.forges.persistence.ForgeConnectionRepository;
import com.asmolabs.vectispire.core.outbox.persistence.OutboxMessageRepository;
import com.asmolabs.vectispire.core.settings.SettingsService;
import com.asmolabs.vectispire.core.siem.SiemEvents;
import com.fasterxml.jackson.databind.JsonNode;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.UUID;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.system.CapturedOutput;
import org.springframework.boot.test.system.OutputCaptureExtension;
import org.springframework.http.MediaType;
import org.springframework.test.web.servlet.MvcResult;
import org.springframework.test.web.servlet.ResultActions;

/**
 * Forge connections over HTTP (decision 0037 §2, lot D1), against a self-managed GitLab on loopback behind a
 * private CA — the owner's case: an internal network, an internal CA, a group access token with {@code
 * read_api}. The token is probed through the real door, stored encrypted, and never comes back out: not in a
 * response, not in the audit trail, not in the SIEM's queue, not in the log.
 */
@DisplayName("forge connections")
@ExtendWith(OutputCaptureExtension.class)
class ForgeConnectionsRoutesTest extends ApiTestBase {

    private static final String TOKEN = "glpat-RouteSecret00000000001"; // gitleaks:allow
    private static final String NEW_TOKEN = "glpat-RouteSecret00000000002"; // gitleaks:allow

    @Autowired
    private ForgeConnectionRepository connections;

    @Autowired
    private AuditLogRepository auditLog;

    @Autowired
    private OutboxMessageRepository outbox;

    @Autowired
    private SettingsService settings;

    private ForgeStub gitlab;

    @BeforeEach
    void start() throws Exception {
        gitlab = ForgeStub.start().gitlab("17.4.1-ee", "[\"read_api\"]", true);
        // The SIEM export on, so that the events are queued and can be read from the outbox.
        settings.set(Setting.SIEM_ALLOW_PRIVATE_DESTINATION, "true");
        mvc.perform(authenticated(put("/api/v1/siem/config"), asAdmin())
                        .contentType(MediaType.APPLICATION_JSON)
                        .content("""
                                {"enabled": true, "protocol": "SYSLOG_UDP", "endpoint": "127.0.0.1:9", "minSeverity": "LOW"}"""))
                .andExpect(status().isOk());
        outbox.deleteAll();
    }

    @AfterEach
    void stop() {
        gitlab.close();
    }

    private Map<String, Object> gitlabConnection(boolean internal) {
        Map<String, Object> body = new HashMap<>();
        body.put("name", "Internal GitLab");
        body.put("kind", "gitlab");
        body.put("baseUrl", gitlab.baseUrl());
        body.put("internalNetwork", internal);
        body.put("caPem", gitlab.caPem);
        body.put("token", TOKEN);
        return body;
    }

    private ResultActions create(Map<String, Object> body, String as) throws Exception {
        return mvc.perform(authenticated(post("/api/v1/forge-connections"), as)
                .contentType(MediaType.APPLICATION_JSON)
                .content(write(body)));
    }

    private JsonNode body(ResultActions result) throws Exception {
        return json.readTree(result.andReturn().getResponse().getContentAsString());
    }

    private List<AuditLogEntity> entries(AuditOperation operation) {
        return auditLog.findAll().stream().filter(entry -> operation.wireName().equals(entry.getOperationType())).toList();
    }

    private List<JsonNode> queued(String eventType) {
        return outbox.findAll().stream()
                .filter(row -> SiemEvents.TYPE.equals(row.getMessageType()))
                .map(row -> {
                    try {
                        return json.readTree(row.getPayload());
                    } catch (Exception unreadable) {
                        throw new IllegalStateException(unreadable);
                    }
                })
                .filter(event -> event.get("eventType").asText().equals(eventType))
                .toList();
    }

    @Test
    @DisplayName("a self-managed GitLab on the internal network, behind its own CA, is probed and kept; the token never leaves")
    void createdAndTheTokenNeverLeaves(CapturedOutput output) throws Exception {
        JsonNode created = body(create(gitlabConnection(true), asAdmin()).andExpect(status().isCreated()));

        assertThat(created.at("/edition").asText()).isEqualTo("gitlab_self_managed");
        assertThat(created.at("/credentialKind").asText()).isEqualTo("gitlab_bot");
        assertThat(created.at("/scopes/0").asText()).isEqualTo("read_api");
        assertThat(created.at("/canWrite").asBoolean()).isFalse();
        assertThat(created.at("/forgeVersion").asText()).isEqualTo("17.4.1-ee");
        assertThat(created.at("/caSubject").asText()).contains("Forge Test CA");
        assertThat(created.at("/encryptionState").asText()).isEqualTo("current");
        assertThat(created.has("token")).isFalse();

        String id = created.at("/id").asText();
        String listed = mvc.perform(authenticated(get("/api/v1/forge-connections"), asAdmin()))
                .andExpect(status().isOk()).andReturn().getResponse().getContentAsString();
        String read = mvc.perform(authenticated(get("/api/v1/forge-connections/" + id), asAdmin()))
                .andExpect(status().isOk()).andReturn().getResponse().getContentAsString();
        assertThat(listed).contains("Internal GitLab").doesNotContain(TOKEN);
        assertThat(read).doesNotContain(TOKEN);
        assertThat(connections.findById(UUID.fromString(id)).orElseThrow().getToken())
                .startsWith("v2:").doesNotContain(TOKEN);

        assertThat(entries(AuditOperation.FORGE_CONNECTION_CHANGED)).singleElement().satisfies(entry -> {
            assertThat(entry.getDescription()).contains("Forge connection created: Internal GitLab")
                    .contains("gitlab bot token").doesNotContain(TOKEN);
            assertThat(entry.getUserId()).startsWith("admin");
        });
        assertThat(queued("FORGE_CONNECTION_CHANGED")).singleElement().satisfies(event ->
                assertThat(event.toString()).contains("Forge connection created").doesNotContain(TOKEN));
        assertThat(gitlab.seen).isNotEmpty();
        assertThat(output.getAll()).doesNotContain(TOKEN);
    }

    @Test
    @DisplayName("an internal address not stated as internal is blocked before any request, audited and signalled 036")
    void anInternalAddressIsRefusedAndSignalled(CapturedOutput output) throws Exception {
        MvcResult refused = create(gitlabConnection(false), asAdmin()).andExpect(status().isBadRequest()).andReturn();

        assertThat(detailOf(refused)).contains("private or local address").contains("internal network");
        assertThat(gitlab.seen).isEmpty();
        assertThat(connections.count()).isZero();
        assertThat(entries(AuditOperation.FORGE_CONNECTION_REFUSED)).singleElement().satisfies(entry ->
                assertThat(entry.getDescription()).contains("destination_blocked").doesNotContain(TOKEN));
        assertThat(queued("FORGE_CONNECTION_REFUSED")).singleElement().satisfies(event ->
                assertThat(event.toString()).contains("destination_blocked").doesNotContain(TOKEN));
        assertThat(output.getAll()).doesNotContain(TOKEN);
    }

    @Test
    @DisplayName("a token broader than read_api is refused, audited and signalled 036, and nothing is kept")
    void aWriteScopeIsRefusedAndSignalled() throws Exception {
        gitlab.gitlab("17.4.1-ee", "[\"read_api\",\"write_repository\"]", true);

        MvcResult refused = create(gitlabConnection(true), asAdmin()).andExpect(status().isBadRequest()).andReturn();

        assertThat(detailOf(refused)).contains("write_repository");
        assertThat(connections.count()).isZero();
        assertThat(entries(AuditOperation.FORGE_CONNECTION_REFUSED)).hasSize(1);
        assertThat(queued("FORGE_CONNECTION_REFUSED")).hasSize(1);
    }

    @Test
    @DisplayName("a token GitLab rejects is refused in words, and is nobody's security event")
    void aRejectedTokenIsNotAnEvent() throws Exception {
        gitlab.route("/api/v4/personal_access_tokens/self", Reply.status(401));

        MvcResult refused = create(gitlabConnection(true), asAdmin()).andExpect(status().isBadRequest()).andReturn();

        assertThat(detailOf(refused)).contains("rejected this token");
        assertThat(entries(AuditOperation.FORGE_CONNECTION_REFUSED)).isEmpty();
        assertThat(queued("FORGE_CONNECTION_REFUSED")).isEmpty();
    }

    @Test
    @DisplayName("the token is replaced in place, re-probed: same id, a new ciphertext, signalled 034")
    void theTokenIsRotatedInPlace() throws Exception {
        String id = body(create(gitlabConnection(true), asAdmin()).andExpect(status().isCreated())).at("/id").asText();
        String before = connections.findById(UUID.fromString(id)).orElseThrow().getToken();
        gitlab.seen.clear();
        outbox.deleteAll();

        JsonNode replaced = body(mvc.perform(authenticated(put("/api/v1/forge-connections/" + id + "/token"), asAdmin())
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(write(Map.of("token", NEW_TOKEN))))
                .andExpect(status().isOk()));

        assertThat(replaced.at("/id").asText()).isEqualTo(id);
        assertThat(gitlab.seen).allSatisfy(seen -> assertThat(seen.headers()).containsEntry("private-token", NEW_TOKEN));
        assertThat(connections.findById(UUID.fromString(id)).orElseThrow().getToken())
                .isNotEqualTo(before).doesNotContain(NEW_TOKEN);
        assertThat(entries(AuditOperation.FORGE_CONNECTION_CHANGED)).extracting(AuditLogEntity::getDescription)
                .anySatisfy(description -> assertThat(description).startsWith("Forge connection token replaced"));
        assertThat(queued("FORGE_CONNECTION_CHANGED")).hasSize(1);
    }

    @Test
    @DisplayName("a replacement token the forge refuses leaves the stored one in place")
    void aRefusedReplacementKeepsTheToken() throws Exception {
        String id = body(create(gitlabConnection(true), asAdmin()).andExpect(status().isCreated())).at("/id").asText();
        String before = connections.findById(UUID.fromString(id)).orElseThrow().getToken();
        gitlab.gitlab("17.4.1-ee", "[\"api\"]", true);

        mvc.perform(authenticated(put("/api/v1/forge-connections/" + id + "/token"), asAdmin())
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(write(Map.of("token", NEW_TOKEN))))
                .andExpect(status().isBadRequest());

        assertThat(connections.findById(UUID.fromString(id)).orElseThrow().getToken()).isEqualTo(before);
        assertThat(entries(AuditOperation.FORGE_CONNECTION_REFUSED)).singleElement()
                .satisfies(entry -> assertThat(entry.getResourceId()).isEqualTo(id));
    }

    @Test
    @DisplayName("a rename is audited and not signalled; unpinning the CA is probed again and refused here")
    void renameAndTrustChanges() throws Exception {
        String id = body(create(gitlabConnection(true), asAdmin()).andExpect(status().isCreated())).at("/id").asText();
        outbox.deleteAll();
        gitlab.seen.clear();

        mvc.perform(authenticated(patch("/api/v1/forge-connections/" + id), asAdmin())
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(write(Map.of("name", "GitLab (datacentre)"))))
                .andExpect(status().isOk());
        assertThat(gitlab.seen).isEmpty();
        assertThat(queued("FORGE_CONNECTION_CHANGED")).isEmpty();
        assertThat(entries(AuditOperation.FORGE_CONNECTION_CHANGED)).extracting(AuditLogEntity::getDescription)
                .anySatisfy(description -> assertThat(description).contains("renamed from Internal GitLab"));

        // Without the private CA the server's certificate is trusted by nothing: the change is refused, kept as was.
        mvc.perform(authenticated(patch("/api/v1/forge-connections/" + id), asAdmin())
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(write(Map.of("caPem", ""))))
                .andExpect(status().isBadRequest());
        assertThat(connections.findById(UUID.fromString(id)).orElseThrow().getCaPem()).isNotNull();
    }

    @Test
    @DisplayName("deleting a connection answers 204, then 404, and is signalled 034")
    void deleted() throws Exception {
        String id = body(create(gitlabConnection(true), asAdmin()).andExpect(status().isCreated())).at("/id").asText();
        outbox.deleteAll();

        mvc.perform(authenticated(delete("/api/v1/forge-connections/" + id), asAdmin())).andExpect(status().isNoContent());

        mvc.perform(authenticated(get("/api/v1/forge-connections/" + id), asAdmin())).andExpect(status().isNotFound());
        mvc.perform(authenticated(delete("/api/v1/forge-connections/" + id), asAdmin())).andExpect(status().isNotFound());
        assertThat(queued("FORGE_CONNECTION_CHANGED")).singleElement()
                .satisfies(event -> assertThat(event.toString()).contains("Forge connection deleted"));
    }

    @Test
    @DisplayName("is an administrator's alone: every other role is refused before the forge is called")
    void onlyAnAdministrator() throws Exception {
        for (String token : List.of(asCiso(), asAuditor(), asReader(), asSecurityChampion())) {
            mvc.perform(authenticated(get("/api/v1/forge-connections"), token)).andExpect(status().isForbidden());
            create(gitlabConnection(true), token).andExpect(status().isForbidden());
        }
        assertThat(gitlab.seen).isEmpty();
        assertThat(connections.count()).isZero();
    }

    @Test
    @DisplayName("refuses in words what the form gets wrong: http, a cloud said internal, a GitHub without its owner, a duplicate name")
    void formRefusals() throws Exception {
        Map<String, Object> http = gitlabConnection(true);
        http.put("baseUrl", "http://127.0.0.1:1");
        assertThat(detailOf(create(http, asAdmin()).andExpect(status().isBadRequest()).andReturn())).contains("https://");

        Map<String, Object> cloud = gitlabConnection(true);
        cloud.put("baseUrl", "");
        cloud.remove("caPem");
        assertThat(detailOf(create(cloud, asAdmin()).andExpect(status().isBadRequest()).andReturn()))
                .contains("not on your internal network");

        Map<String, Object> github = gitlabConnection(true);
        github.put("kind", "github");
        assertThat(detailOf(create(github, asAdmin()).andExpect(status().isBadRequest()).andReturn()))
                .contains("organisation or user");

        create(gitlabConnection(true), asAdmin()).andExpect(status().isCreated());
        assertThat(detailOf(create(gitlabConnection(true), asAdmin()).andExpect(status().isBadRequest()).andReturn()))
                .contains("already exists");
        assertThat(entries(AuditOperation.FORGE_CONNECTION_REFUSED)).isEmpty();
    }
}
