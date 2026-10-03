package com.asmolabs.vectispire.core.api;

import static org.assertj.core.api.Assertions.assertThat;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.delete;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.put;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

import com.asmolabs.vectispire.common.domain.audit.AuditOperation;
import com.asmolabs.vectispire.common.domain.settings.Setting;
import com.asmolabs.vectispire.core.audit.persistence.AuditLogEntity;
import com.asmolabs.vectispire.core.audit.persistence.AuditLogRepository;
import com.asmolabs.vectispire.core.forges.ForgeStub;
import com.asmolabs.vectispire.core.forges.ForgeStub.Reply;
import com.asmolabs.vectispire.core.forges.internal.DiscoveryExecution;
import com.asmolabs.vectispire.core.forges.internal.DiscoveryQueue;
import com.asmolabs.vectispire.core.forges.internal.DiscoveryWorker;
import com.asmolabs.vectispire.core.forges.persistence.ForgeDiscoveryEntity;
import com.asmolabs.vectispire.core.forges.persistence.ForgeDiscoveryRepository;
import com.asmolabs.vectispire.core.forges.persistence.ForgeRepositoryEntity;
import com.asmolabs.vectispire.core.forges.persistence.ForgeRepositoryRepository;
import com.asmolabs.vectispire.core.outbox.persistence.OutboxMessageRepository;
import com.asmolabs.vectispire.core.settings.SettingsService;
import com.asmolabs.vectispire.core.siem.SiemEvents;
import com.fasterxml.jackson.databind.JsonNode;
import java.net.URI;
import java.time.Instant;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.UUID;
import java.util.stream.StreamSupport;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.MediaType;
import org.springframework.test.web.servlet.ResultActions;

/**
 * Discovering a GitLab's repositories over HTTP (decision 0037 §3, lot D3), against a self-managed GitLab on
 * loopback behind a private CA — the owner's case — answering as GitLab answers: the groups by offset pages, the
 * projects by keyset {@code Link}, a language per project. The run is queued by the route and carried out by {@link
 * DiscoveryWorker#drain}, the worker's own turn on the test's thread, through the real door: what is pinned is what
 * reached the stub, what the snapshot holds, and what the routes say about it.
 */
@DisplayName("forge discoveries")
class ForgeDiscoveriesRoutesTest extends ApiTestBase {

    static final String TOKEN = "glpat-Discovery0000000000001"; // gitleaks:allow
    static final String GROUPS = "/api/v4/groups?min_access_level=10&order_by=id&sort=asc&per_page=100";
    static final String PROJECTS = "/api/v4/projects?membership=true&min_access_level=10&statistics=true"
            + "&pagination=keyset&order_by=id&sort=asc&per_page=100";

    @Autowired
    private DiscoveryWorker worker;

    @Autowired
    private DiscoveryQueue queue;

    @Autowired
    private DiscoveryExecution execution;

    @Autowired
    private ForgeDiscoveryRepository discoveries;

    @Autowired
    private ForgeRepositoryRepository snapshot;

    @Autowired
    private AuditLogRepository auditLog;

    @Autowired
    private OutboxMessageRepository outbox;

    @Autowired
    private SettingsService settings;

    private ForgeStub gitlab;
    private ForgeStub elsewhere;

    @BeforeEach
    void start() throws Exception {
        gitlab = ForgeStub.start().gitlab("17.4.1-ee", "[\"read_api\"]", true);
        elsewhere = ForgeStub.start();
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
        elsewhere.close();
    }

    // ---- The forge's answers.

    static String project(int id, String path, String namespaceKind, String branch, boolean archived,
            Long size, boolean fork, String activity) {
        String namespace = path.substring(0, path.lastIndexOf('/'));
        return "{\"id\":" + id + ",\"name\":\"" + path.substring(path.lastIndexOf('/') + 1) + "\",\"path_with_namespace\":\""
                + path + "\",\"namespace\":{\"full_path\":\"" + namespace + "\",\"kind\":\"" + namespaceKind + "\"},"
                + "\"default_branch\":" + (branch == null ? "null" : "\"" + branch + "\"") + ",\"archived\":" + archived
                + ",\"visibility\":\"private\",\"last_activity_at\":\"" + activity + "\","
                + (size == null ? "" : "\"statistics\":{\"repository_size\":" + size + "},")
                + (fork ? "\"forked_from_project\":{\"id\":1},\"" : "\"")
                + "http_url_to_repo\":\"https://git.example.org/" + path + ".git\",\"ssh_url_to_repo\":\"git@git.example.org:"
                + path + ".git\",\"web_url\":\"https://git.example.org/" + path + "\"}";
    }

    /** Two pages of groups by offset, the projects in keyset pages of the sizes given. */
    private void estate(List<List<String>> projectPages) {
        gitlab.route(GROUPS, Reply.json("[{\"id\":1,\"full_path\":\"acme\"},{\"id\":2,\"full_path\":\"acme/backend\"}]")
                .with("X-Next-Page", "2"));
        gitlab.route(GROUPS + "&page=2", Reply.json("[{\"id\":3,\"full_path\":\"acme/frontend\"}]").with("X-Next-Page", ""));
        for (int page = 0; page < projectPages.size(); page++) {
            String path = page == 0 ? PROJECTS : PROJECTS + "&id_after=" + page;
            Reply reply = Reply.json("[" + String.join(",", projectPages.get(page)) + "]");
            if (page + 1 < projectPages.size()) {
                reply = reply.with("Link", "<" + gitlab.baseUrl() + PROJECTS + "&id_after=" + (page + 1) + ">; rel=\"next\"");
            }
            gitlab.route(path, reply);
        }
    }

    // ---- The routes.

    private String connection() throws Exception {
        Map<String, Object> body = new HashMap<>();
        body.put("name", "Internal GitLab " + System.nanoTime());
        body.put("kind", "gitlab");
        body.put("baseUrl", gitlab.baseUrl());
        body.put("internalNetwork", true);
        body.put("caPem", gitlab.caPem);
        body.put("token", TOKEN);
        String created = mvc.perform(authenticated(post("/api/v1/forge-connections"), asAdmin())
                        .contentType(MediaType.APPLICATION_JSON).content(write(body)))
                .andExpect(status().isCreated()).andReturn().getResponse().getContentAsString();
        return json.readTree(created).at("/id").asText();
    }

    private ResultActions request(String connectionId, String as) throws Exception {
        return mvc.perform(authenticated(post("/api/v1/forge-connections/" + connectionId + "/discoveries"), as));
    }

    private JsonNode read(String url) throws Exception {
        return json.readTree(mvc.perform(authenticated(get(url), asAdmin())).andExpect(status().isOk())
                .andReturn().getResponse().getContentAsString());
    }

    /** Requests a discovery, lets the worker carry it out, and reads the run as a screen polling it would. */
    private JsonNode discover(String connectionId) throws Exception {
        JsonNode queued = json.readTree(request(connectionId, asAdmin()).andExpect(status().isAccepted())
                .andReturn().getResponse().getContentAsString());
        assertThat(queued.at("/state").asText()).isEqualTo("pending");
        assertThat(worker.drain()).isOne();
        return read("/api/v1/forge-connections/" + connectionId + "/discoveries/" + queued.at("/id").asLong());
    }

    private List<JsonNode> repositories(String connectionId, JsonNode run, String change) throws Exception {
        JsonNode page = read("/api/v1/forge-connections/" + connectionId + "/discoveries/" + run.at("/id").asLong()
                + "/repositories?change=" + change);
        return StreamSupport.stream(page.at("/items").spliterator(), false).toList();
    }

    private static JsonNode byId(List<JsonNode> repositories, String forgeId) {
        return repositories.stream().filter(repository -> repository.at("/forgeId").asText().equals(forgeId)).findFirst()
                .orElseThrow(() -> new AssertionError("no repository " + forgeId + " in " + repositories));
    }

    private List<AuditLogEntity> entries(AuditOperation operation) {
        return auditLog.findAll().stream().filter(entry -> operation.wireName().equals(entry.getOperationType())).toList();
    }

    private List<JsonNode> queued(String eventType) {
        List<JsonNode> events = new ArrayList<>();
        outbox.findAll().stream().filter(row -> SiemEvents.TYPE.equals(row.getMessageType())).forEach(row -> {
            try {
                JsonNode event = json.readTree(row.getPayload());
                if (event.get("eventType").asText().equals(eventType)) {
                    events.add(event);
                }
            } catch (Exception unreadable) {
                throw new IllegalStateException(unreadable);
            }
        });
        return events;
    }

    private static Map<String, String> query(String path) {
        Map<String, String> parameters = new HashMap<>();
        String raw = URI.create("https://x" + path).getRawQuery();
        for (String pair : raw == null ? new String[0] : raw.split("&")) {
            int equals = pair.indexOf('=');
            parameters.put(equals < 0 ? pair : pair.substring(0, equals), equals < 0 ? "" : pair.substring(equals + 1));
        }
        return parameters;
    }

    // ---- What a discovery does.

    @Test
    @DisplayName("lists the groups, then the projects the token is a member of, and keeps each with what GitLab said — unknown left null")
    void aFirstDiscovery() throws Exception {
        estate(List.of(
                List.of(project(11, "acme/backend/api", "group", "main", false, 2048L, false, "2026-09-01T10:00:00.000Z"),
                        project(12, "acme/frontend/web", "group", "main", false, null, true, "2026-09-02T10:00:00Z")),
                List.of(project(13, "ada/sandbox", "user", null, false, null, false, "2026-08-01T00:00:00Z"),
                        project(14, "acme/legacy", "group", "master", true, 10L, false, "2020-01-01T00:00:00Z"))));
        gitlab.route("/api/v4/projects/11/languages", Reply.json("{\"Java\":80.5,\"Shell\":19.5}"));
        gitlab.route("/api/v4/projects/12/languages", Reply.status(403));
        gitlab.route("/api/v4/projects/13/languages", Reply.json("{}"));
        gitlab.route("/api/v4/projects/14/languages", Reply.json("{\"COBOL\":100}"));
        String connectionId = connection();
        gitlab.seen.clear();

        JsonNode run = discover(connectionId);

        assertThat(run.at("/state").asText()).isEqualTo("completed");
        assertThat(run.at("/reason").isNull()).isTrue();
        assertThat(run.at("/namespacesSeen").asInt()).as("acme, acme/backend, acme/frontend and ada's own").isEqualTo(4);
        assertThat(run.at("/repositoriesSeen").asInt()).isEqualTo(4);
        assertThat(run.at("/requestsMade").asInt()).as("two pages of groups, two of projects, four languages").isEqualTo(8);
        assertThat(run.at("/newCount").asInt()).isEqualTo(4);
        assertThat(run.at("/changedCount").asInt()).isZero();
        assertThat(run.at("/goneCount").asInt()).isZero();
        assertThat(run.at("/attempts").asInt()).isOne();

        // The parameters that keep a discovery of gitlab.com to the token's own estate, asserted on the wire.
        List<String> paths = gitlab.seen.stream().map(ForgeStub.Seen::path).toList();
        assertThat(paths).filteredOn(path -> path.startsWith("/api/v4/groups")).hasSize(2)
                .allSatisfy(path -> assertThat(query(path)).containsEntry("min_access_level", "10"));
        assertThat(paths).filteredOn(path -> path.startsWith("/api/v4/projects?")).hasSize(2)
                .allSatisfy(path -> assertThat(query(path)).containsEntry("membership", "true")
                        .containsEntry("min_access_level", "10").containsEntry("pagination", "keyset"));
        assertThat(gitlab.seen).allSatisfy(seen -> assertThat(seen.headers()).containsEntry("private-token", TOKEN));

        List<JsonNode> listed = repositories(connectionId, run, "all");
        assertThat(listed).extracting(repository -> repository.at("/fullPath").asText())
                .containsExactly("acme/backend/api", "acme/frontend/web", "acme/legacy", "ada/sandbox");
        JsonNode api = byId(listed, "11");
        assertThat(api.at("/defaultBranch").asText()).isEqualTo("main");
        assertThat(api.at("/sizeBytes").asLong()).isEqualTo(2048);
        assertThat(api.at("/language").asText()).isEqualTo("Java");
        assertThat(api.at("/fork").isNull()).as("GitLab names a fork only when it is one and its source is readable")
                .isTrue();
        assertThat(api.at("/archived").asBoolean()).isFalse();
        assertThat(api.at("/visibility").asText()).isEqualTo("private");
        assertThat(api.at("/lastActivityAt").asText()).isEqualTo("2026-09-01T10:00:00Z");
        assertThat(api.at("/sshUrl").asText()).isEqualTo("git@git.example.org:acme/backend/api.git");
        assertThat(api.at("/personal").asBoolean()).isFalse();
        JsonNode web = byId(listed, "12");
        assertThat(web.at("/fork").asBoolean()).isTrue();
        assertThat(web.at("/sizeBytes").isNull()).as("no statistics for a Guest: unknown, not zero").isTrue();
        assertThat(web.at("/language").isNull()).as("a 403 on its languages: unknown").isTrue();
        JsonNode sandbox = byId(listed, "13");
        assertThat(sandbox.at("/personal").asBoolean()).isTrue();
        assertThat(sandbox.at("/namespacePath").asText()).isEqualTo("ada");
        assertThat(sandbox.at("/defaultBranch").isNull()).isTrue();
        assertThat(byId(listed, "14").at("/archived").asBoolean()).isTrue();

        JsonNode connectionRead = read("/api/v1/forge-connections/" + connectionId);
        assertThat(connectionRead.at("/lastDiscovery/id").asLong()).isEqualTo(run.at("/id").asLong());
        assertThat(connectionRead.at("/lastDiscovery/state").asText()).isEqualTo("completed");
    }

    @Test
    @DisplayName("the next run compares: new, renamed and re-branched, unarchived, gone — and a short rate limit waited out inside it")
    void theComparison() throws Exception {
        estate(List.of(List.of(
                project(11, "acme/backend/api", "group", "main", false, 1L, false, "2026-09-01T00:00:00Z"),
                project(12, "acme/frontend/web", "group", "main", false, 1L, false, "2026-09-01T00:00:00Z"),
                project(13, "acme/frontend/old", "group", "main", false, 1L, false, "2026-09-01T00:00:00Z"),
                project(14, "acme/legacy", "group", "main", true, 1L, false, "2026-09-01T00:00:00Z"))));
        for (int id = 11; id <= 15; id++) {
            gitlab.route("/api/v4/projects/" + id + "/languages", Reply.json("{\"Go\":100}"));
        }
        String connectionId = connection();
        JsonNode first = discover(connectionId);
        assertThat(first.at("/state").asText()).isEqualTo("completed");

        estate(List.of(List.of(
                project(11, "acme/platform/api", "group", "trunk", false, 1L, false, "2026-09-01T00:00:00Z"),
                project(12, "acme/frontend/web", "group", "main", false, 1L, false, "2026-10-01T00:00:00Z"),
                project(14, "acme/legacy", "group", "main", false, 1L, false, "2026-09-01T00:00:00Z"),
                project(15, "acme/backend/worker", "group", "main", false, 1L, false, "2026-10-02T00:00:00Z"))));
        gitlab.sequence(GROUPS, Reply.status(429).with("Retry-After", "1"));
        JsonNode second = discover(connectionId);

        assertThat(second.at("/state").asText()).isEqualTo("completed");
        assertThat(second.at("/rateLimitWaitSeconds").asLong()).isGreaterThanOrEqualTo(1);
        assertThat(second.at("/newCount").asInt()).isOne();
        assertThat(second.at("/changedCount").asInt()).isEqualTo(2);
        assertThat(second.at("/goneCount").asInt()).isOne();

        assertThat(repositories(connectionId, second, "new")).extracting(repository -> repository.at("/forgeId").asText())
                .containsExactly("15");
        assertThat(repositories(connectionId, second, "gone")).singleElement().satisfies(gone -> {
            assertThat(gone.at("/forgeId").asText()).isEqualTo("13");
            assertThat(gone.at("/goneBy").asLong()).isEqualTo(second.at("/id").asLong());
        });
        List<JsonNode> changed = repositories(connectionId, second, "changed");
        assertThat(changed).hasSize(2);
        assertThat(byId(changed, "11").at("/changeSummary").asText())
                .contains("renamed or moved from acme/backend/api").contains("default branch main → trunk");
        assertThat(byId(changed, "11").at("/firstSeenBy").asLong()).as("the same repository, by its id")
                .isEqualTo(first.at("/id").asLong());
        assertThat(byId(changed, "14").at("/changeSummary").asText()).isEqualTo("unarchived");
        assertThat(snapshot.count()).as("nothing deleted: the gone one stays").isEqualTo(5);

        // The language is asked again of a project active since, and not of one that was not.
        assertThat(gitlab.count("/api/v4/projects/12/languages")).isEqualTo(2);
        assertThat(gitlab.count("/api/v4/projects/11/languages")).isOne();
    }

    @Test
    @DisplayName("a rate limit longer than a minute ends the run partial, saying when it lifts — and marks nothing gone")
    void aPartialRunMarksNothingGone() throws Exception {
        estate(List.of(List.of(project(11, "acme/a", "group", "main", false, 1L, false, "2026-09-01T00:00:00Z")),
                List.of(project(12, "acme/b", "group", "main", false, 1L, false, "2026-09-01T00:00:00Z"))));
        String connectionId = connection();
        assertThat(discover(connectionId).at("/state").asText()).isEqualTo("completed");

        gitlab.route(PROJECTS + "&id_after=1", Reply.status(429).with("Retry-After", "3600"));
        Instant before = Instant.now();
        JsonNode partial = discover(connectionId);

        assertThat(partial.at("/state").asText()).isEqualTo("partial");
        assertThat(partial.at("/reason").asText()).isEqualTo("rate_limited");
        assertThat(Instant.parse(partial.at("/rateLimitResetAt").asText()))
                .isBetween(before.plusSeconds(3590), Instant.now().plusSeconds(3610));
        assertThat(partial.at("/goneCount").isNull()).as("not judged: null, not zero").isTrue();
        assertThat(snapshot.findAll()).allSatisfy(row -> assertThat(row.getGoneBy()).isNull());
        assertThat(detailOf(mvc.perform(authenticated(get("/api/v1/forge-connections/" + connectionId + "/discoveries/"
                        + partial.at("/id").asLong() + "/repositories?change=gone"), asAdmin()))
                .andExpect(status().isBadRequest()).andReturn())).contains("Only a completed discovery");
    }

    @Test
    @DisplayName("a 401 fails the run: the token is rejected")
    void aRejectedTokenFails() throws Exception {
        String connectionId = connection();
        gitlab.route(GROUPS, Reply.status(401));

        JsonNode run = discover(connectionId);

        assertThat(run.at("/state").asText()).isEqualTo("failed");
        assertThat(run.at("/reason").asText()).isEqualTo("token_rejected");
        assertThat(run.at("/detail").asText()).contains("rejected this token").doesNotContain(TOKEN);
        assertThat(snapshot.count()).isZero();
    }

    @Test
    @DisplayName("a 403 on a project's languages leaves its language unknown and the run goes on; a 403 on the listing fails it")
    void refusals() throws Exception {
        estate(List.of(List.of(project(11, "acme/a", "group", "main", false, 1L, false, "2026-09-01T00:00:00Z"))));
        gitlab.route("/api/v4/projects/11/languages", Reply.status(403));
        String connectionId = connection();
        JsonNode completed = discover(connectionId);
        assertThat(completed.at("/state").asText()).isEqualTo("completed");
        assertThat(byId(repositories(connectionId, completed, "all"), "11").at("/language").isNull()).isTrue();

        gitlab.route(PROJECTS, Reply.status(403));
        JsonNode refused = discover(connectionId);
        assertThat(refused.at("/state").asText()).isEqualTo("failed");
        assertThat(refused.at("/reason").asText()).isEqualTo("forge_refused");
        assertThat(refused.at("/detail").asText()).contains("HTTP 403");
    }

    @Test
    @DisplayName("a next page on another origin fails the run before anything is sent there, recorded and signalled 036")
    void nothingLeavesTheConnectionsHost() throws Exception {
        estate(List.of(List.of(project(11, "acme/a", "group", "main", false, 1L, false, "2026-09-01T00:00:00Z"))));
        gitlab.route(PROJECTS, Reply.json("[" + project(11, "acme/a", "group", "main", false, 1L, false,
                "2026-09-01T00:00:00Z") + "]").with("Link", "<" + elsewhere.baseUrl() + PROJECTS + "&id_after=11>; rel=\"next\""));
        String connectionId = connection();
        outbox.deleteAll();

        JsonNode run = discover(connectionId);

        assertThat(run.at("/state").asText()).isEqualTo("failed");
        assertThat(run.at("/reason").asText()).isEqualTo("cross_origin_page");
        assertThat(elsewhere.seen).as("the token never reached the other host").isEmpty();
        assertThat(entries(AuditOperation.FORGE_CONNECTION_REFUSED)).singleElement().satisfies(entry -> {
            assertThat(entry.getDescription()).contains("cross_origin_page").doesNotContain(TOKEN);
            assertThat(entry.getResourceId()).isEqualTo(connectionId);
        });
        // FORGE_CONNECTION_REFUSED is VECTI-SEC-036's event type.
        assertThat(queued("FORGE_CONNECTION_REFUSED")).singleElement()
                .satisfies(event -> assertThat(event.at("/message").asText()).contains("cross_origin_page"));
    }

    @Test
    @DisplayName("one discovery per connection at a time: a second request answers 409 with the first one's id")
    void oneAtATime() throws Exception {
        String connectionId = connection();
        long first = json.readTree(request(connectionId, asAdmin()).andExpect(status().isAccepted())
                .andReturn().getResponse().getContentAsString()).at("/id").asLong();

        JsonNode conflict = json.readTree(request(connectionId, asAdmin()).andExpect(status().isConflict())
                .andReturn().getResponse().getContentAsString());
        assertThat(conflict.at("/type").asText()).endsWith("forge-discovery-in-progress");
        assertThat(conflict.at("/discoveryId").asLong()).isEqualTo(first);
        assertThat(discoveries.count()).isOne();
        // Audited once, for the run queued: the 409 queued nothing and records nothing.
        assertThat(entries(AuditOperation.FORGE_DISCOVERY_REQUESTED)).singleElement().satisfies(entry -> {
            assertThat(entry.getResourceId()).isEqualTo(connectionId);
            assertThat(entry.getUserId()).startsWith("admin-");
            assertThat(entry.getDescription()).contains("Forge discovery " + first).contains(connectionId)
                    .doesNotContain(TOKEN);
        });
        assertThat(queued("FORGE_DISCOVERY_REQUESTED")).as("not a security event").isEmpty();
    }

    @Test
    @DisplayName("two instances: the one that took the run carries it out; a lapsed lease is resumed, three times at most")
    void theLease() throws Exception {
        estate(List.of(List.of(project(11, "acme/a", "group", "main", false, 1L, false, "2026-09-01T00:00:00Z"))));
        String connectionId = connection();
        long id = json.readTree(request(connectionId, asAdmin()).andExpect(status().isAccepted())
                .andReturn().getResponse().getContentAsString()).at("/id").asLong();

        assertThat(queue.claim("east")).contains(id);
        assertThat(queue.claim("west")).as("taken: nothing left for the other instance").isEmpty();
        execution.execute(id, "west");
        assertThat(discoveries.findById(id).orElseThrow().getState()).as("west holds no claim, so does nothing")
                .isEqualTo("running");
        assertThat(gitlab.count(PROJECTS)).isZero();

        // East dies: its lease lapses, and this instance's turn resumes the run from the first page.
        lapse(id, 1);
        assertThat(worker.drain()).isOne();
        JsonNode resumed = read("/api/v1/forge-connections/" + connectionId + "/discoveries/" + id);
        assertThat(resumed.at("/state").asText()).isEqualTo("completed");
        assertThat(resumed.at("/attempts").asInt()).isEqualTo(2);

        // East comes back and finishes what is no longer its own: nothing is written.
        execution.execute(id, "east");
        assertThat(discoveries.findById(id).orElseThrow().getState()).isEqualTo("completed");

        long next = json.readTree(request(connectionId, asAdmin()).andExpect(status().isAccepted())
                .andReturn().getResponse().getContentAsString()).at("/id").asLong();
        assertThat(queue.claim("east")).contains(next);
        lapse(next, 3);
        worker.drain();
        JsonNode lost = read("/api/v1/forge-connections/" + connectionId + "/discoveries/" + next);
        assertThat(lost.at("/state").asText()).isEqualTo("failed");
        assertThat(lost.at("/reason").asText()).isEqualTo("executor_lost");
        request(connectionId, asAdmin()).andExpect(status().isAccepted());
    }

    @Test
    @DisplayName("a resumed run compares with the run before it, not with what its own earlier attempt wrote")
    void aResumedRunIsNotItsOwnChange() throws Exception {
        estate(List.of(List.of(project(11, "acme/renamed", "group", "main", false, 1L, false, "2026-09-01T00:00:00Z"))));
        gitlab.route("/api/v4/projects/11/languages", Reply.json("{\"Go\":100}"));
        String connectionId = connection();
        long id = json.readTree(request(connectionId, asAdmin()).andExpect(status().isAccepted())
                .andReturn().getResponse().getContentAsString()).at("/id").asLong();
        // What a first attempt of this run wrote before its instance died: the repository, new in this run, under
        // the path it had then.
        ForgeRepositoryEntity written = new ForgeRepositoryEntity();
        written.setConnectionId(UUID.fromString(connectionId));
        written.setForgeId("11");
        written.setFullPath("acme/original");
        written.setNamespacePath("acme");
        written.setName("original");
        written.setFirstSeenBy(id);
        written.setFirstSeenAt(Instant.now());
        written.setLastSeenBy(id);
        written.setLastSeenAt(Instant.now());
        snapshot.saveAndFlush(written);

        assertThat(worker.drain()).isOne();
        JsonNode run = read("/api/v1/forge-connections/" + connectionId + "/discoveries/" + id);

        assertThat(run.at("/newCount").asInt()).isOne();
        assertThat(run.at("/changedCount").asInt()).as("new in this run, not also changed by it").isZero();
        assertThat(byId(repositories(connectionId, run, "all"), "11").at("/fullPath").asText()).isEqualTo("acme/renamed");
    }

    private void lapse(long id, int attempts) {
        ForgeDiscoveryEntity run = discoveries.findById(id).orElseThrow();
        run.setLeaseExpiresAt(Instant.now().minusSeconds(1));
        run.setAttempts(attempts);
        discoveries.saveAndFlush(run);
    }

    @Test
    @DisplayName("deleting the connection deletes its discoveries and its snapshot")
    void deletedWithTheConnection() throws Exception {
        estate(List.of(List.of(project(11, "acme/a", "group", "main", false, 1L, false, "2026-09-01T00:00:00Z"))));
        String connectionId = connection();
        discover(connectionId);
        String other = connection();
        discover(other);
        assertThat(snapshot.count()).isEqualTo(2);

        mvc.perform(authenticated(delete("/api/v1/forge-connections/" + connectionId), asAdmin()))
                .andExpect(status().isNoContent());

        assertThat(discoveries.findAll()).extracting(ForgeDiscoveryEntity::getConnectionId)
                .containsOnly(UUID.fromString(other));
        assertThat(snapshot.findAll()).allSatisfy(row -> assertThat(row.getConnectionId()).isEqualTo(UUID.fromString(other)));
        assertThat(snapshot.count()).isOne();
    }

    @Test
    @DisplayName("refuses in words: an unknown connection 404, a bad change 400")
    void refusedInWords() throws Exception {
        assertThat(detailOf(request(UUID.randomUUID().toString(), asAdmin()).andExpect(status().isNotFound()).andReturn()))
                .isEqualTo("Forge connection not found.");

        String connectionId = connection();
        JsonNode run = json.readTree(request(connectionId, asAdmin()).andReturn().getResponse().getContentAsString());
        String base = "/api/v1/forge-connections/" + connectionId + "/discoveries/";
        assertThat(detailOf(mvc.perform(authenticated(get(base + run.at("/id").asLong() + "/repositories?change=moved"),
                asAdmin())).andExpect(status().isBadRequest()).andReturn())).contains("all, new, changed or gone");
        assertThat(detailOf(mvc.perform(authenticated(get(base + "999999"), asAdmin())).andExpect(status().isNotFound())
                .andReturn())).isEqualTo("Forge discovery 999999 not found.");
        assertThat(detailOf(mvc.perform(authenticated(get(base + run.at("/id").asLong() + "/repositories?limit=501"),
                asAdmin())).andExpect(status().isBadRequest()).andReturn())).contains("between 1 and 500");
    }

    @Test
    @DisplayName("is an administrator's alone: every other role is refused, and nothing is queued")
    void onlyAnAdministrator() throws Exception {
        String connectionId = connection();
        for (String token : List.of(asCiso(), asAuditor(), asReader(), asSecurityChampion())) {
            request(connectionId, token).andExpect(status().isForbidden());
            mvc.perform(authenticated(get("/api/v1/forge-connections/" + connectionId + "/discoveries"), token))
                    .andExpect(status().isForbidden());
        }
        assertThat(discoveries.count()).isZero();
        assertThat(read("/api/v1/forge-connections/" + connectionId + "/discoveries")).isEmpty();
        assertThat(entries(AuditOperation.FORGE_DISCOVERY_REQUESTED)).isEmpty();
    }
}
