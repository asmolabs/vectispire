package com.asmolabs.vectispire.core.api;

import static com.asmolabs.vectispire.core.api.ForgeDiscoveriesRoutesTest.GROUPS;
import static com.asmolabs.vectispire.core.api.ForgeDiscoveriesRoutesTest.PROJECTS;
import static com.asmolabs.vectispire.core.api.ForgeDiscoveriesRoutesTest.TOKEN;
import static com.asmolabs.vectispire.core.api.ForgeDiscoveriesRoutesTest.project;
import static org.assertj.core.api.Assertions.assertThat;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.delete;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.put;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

import com.asmolabs.vectispire.common.domain.audit.AuditOperation;
import com.asmolabs.vectispire.common.domain.forges.DiscoveryState;
import com.asmolabs.vectispire.common.domain.settings.Setting;
import com.asmolabs.vectispire.common.domain.teams.TeamRules;
import com.asmolabs.vectispire.core.access.persistence.UserRepository;
import com.asmolabs.vectispire.core.access.persistence.UserTargetEntity;
import com.asmolabs.vectispire.core.access.persistence.UserTargetRepository;
import com.asmolabs.vectispire.core.audit.persistence.AuditLogEntity;
import com.asmolabs.vectispire.core.audit.persistence.AuditLogRepository;
import com.asmolabs.vectispire.core.forges.ForgeStub;
import com.asmolabs.vectispire.core.forges.ForgeStub.Reply;
import com.asmolabs.vectispire.core.forges.internal.DiscoveryWorker;
import com.asmolabs.vectispire.core.forges.persistence.ForgeDiscoveryEntity;
import com.asmolabs.vectispire.core.forges.persistence.ForgeDiscoveryRepository;
import com.asmolabs.vectispire.core.forges.persistence.ForgeImportLinkEntity;
import com.asmolabs.vectispire.core.forges.persistence.ForgeImportLinkRepository;
import com.asmolabs.vectispire.core.forges.persistence.ForgeRepositoryEntity;
import com.asmolabs.vectispire.core.forges.persistence.ForgeRepositoryRepository;
import com.asmolabs.vectispire.core.outbox.persistence.OutboxMessageRepository;
import com.asmolabs.vectispire.core.scanning.persistence.ScanEntity;
import com.asmolabs.vectispire.core.scanning.persistence.ScanRepository;
import com.asmolabs.vectispire.core.settings.SettingsService;
import com.asmolabs.vectispire.core.siem.SiemEvents;
import com.asmolabs.vectispire.core.targets.persistence.GitRepositoryRepository;
import com.asmolabs.vectispire.core.targets.persistence.RepositoryEntity;
import com.fasterxml.jackson.databind.JsonNode;
import java.time.Duration;
import java.time.Instant;
import java.util.ArrayList;
import java.util.Comparator;
import java.util.HashMap;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.stream.IntStream;
import java.util.stream.StreamSupport;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.MediaType;
import org.springframework.test.web.servlet.ResultActions;

/**
 * Selecting a GitLab's discovered repositories and importing them as targets (decision 0037 §4–5, lots D5 and D6),
 * over HTTP, against the same self-managed GitLab on loopback the discovery suite uses: groups and subgroups of two
 * top-level groups, a personal namespace, an archived repository, a fork, an empty one. The discovery is the real one
 * — requested by the route and carried out by the worker's own turn — so what is selected and imported is what
 * GitLab's mapping wrote into the snapshot.
 */
@DisplayName("forge selection and import")
class ForgeImportsRoutesTest extends ApiTestBase {

    private static final String RECENT = "2026-09-20T10:00:00Z";

    @Autowired
    private DiscoveryWorker worker;

    @Autowired
    private ForgeDiscoveryRepository discoveries;

    @Autowired
    private ForgeRepositoryRepository snapshot;

    @Autowired
    private ForgeImportLinkRepository links;

    @Autowired
    private GitRepositoryRepository repositories;

    @Autowired
    private ScanRepository scans;

    @Autowired
    private AuditLogRepository auditLog;

    @Autowired
    private OutboxMessageRepository outbox;

    @Autowired
    private SettingsService settings;

    @Autowired
    private UserRepository users;

    @Autowired
    private UserTargetRepository userTargets;

    private ForgeStub gitlab;
    private String connectionId;
    private long discoveryId;

    @BeforeEach
    void discovered() throws Exception {
        gitlab = ForgeStub.start().gitlab("17.4.1-ee", "[\"read_api\"]", true);
        settings.set(Setting.SIEM_ALLOW_PRIVATE_DESTINATION, "true");
        mvc.perform(authenticated(put("/api/v1/siem/config"), asAdmin())
                        .contentType(MediaType.APPLICATION_JSON)
                        .content("""
                                {"enabled": true, "protocol": "SYSLOG_UDP", "endpoint": "127.0.0.1:9", "minSeverity": "LOW"}"""))
                .andExpect(status().isOk());
        gitlab.route(GROUPS, Reply.json("[{\"id\":1,\"full_path\":\"acme\"},{\"id\":2,\"full_path\":\"acme/backend\"},"
                + "{\"id\":3,\"full_path\":\"acme/backend/payments\"},{\"id\":4,\"full_path\":\"acme/frontend\"},"
                + "{\"id\":5,\"full_path\":\"globex\"},{\"id\":6,\"full_path\":\"globex/platform\"}]"));
        gitlab.route(PROJECTS, Reply.json("[" + String.join(",", List.of(
                project(11, "acme/backend/payments/api", "group", "main", false, 10L, false, RECENT),
                project(12, "acme/backend/payments/worker", "group", "develop", false, 10L, false, RECENT),
                project(13, "acme/tools", "group", "main", false, 10L, false, RECENT),
                project(14, "acme/legacy", "group", "master", true, 10L, false, RECENT),
                project(15, "acme/frontend/web-fork", "group", "main", false, 10L, true, RECENT),
                project(16, "ada/sandbox", "user", "main", false, 10L, false, RECENT),
                project(17, "acme/empty", "group", null, false, null, false, RECENT),
                project(18, "globex/platform/core", "group", "trunk", false, 10L, false, "2020-01-01T00:00:00Z")))
                + "]"));
        gitlab.route("/api/v4/projects/11/languages", Reply.json("{\"Java\":90,\"Shell\":10}"));
        gitlab.route("/api/v4/projects/18/languages", Reply.json("{\"Go\":100}"));
        connectionId = connection();
        discoveryId = discover();
        outbox.deleteAll();
    }

    @AfterEach
    void stop() {
        gitlab.close();
    }

    // ---- Helpers.

    private String connection() throws Exception {
        Map<String, Object> body = new HashMap<>();
        body.put("name", "Internal GitLab");
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

    private long discover() throws Exception {
        JsonNode queued = json.readTree(mvc.perform(authenticated(
                        post("/api/v1/forge-connections/" + connectionId + "/discoveries"), asAdmin()))
                .andExpect(status().isAccepted()).andReturn().getResponse().getContentAsString());
        assertThat(worker.drain()).isOne();
        long id = queued.at("/id").asLong();
        assertThat(discoveries.findById(id).orElseThrow().getState()).isEqualTo("completed");
        return id;
    }

    private String base() {
        return "/api/v1/forge-connections/" + connectionId;
    }

    private JsonNode read(String url) throws Exception {
        return json.readTree(mvc.perform(authenticated(get(url), asAdmin())).andExpect(status().isOk())
                .andReturn().getResponse().getContentAsString());
    }

    private JsonNode candidates(String query) throws Exception {
        return read(base() + "/discoveries/" + discoveryId + "/selection" + query);
    }

    private ResultActions postJson(String url, Object body, String as) throws Exception {
        return mvc.perform(authenticated(post(url), as).contentType(MediaType.APPLICATION_JSON).content(write(body)));
    }

    private JsonNode ok(ResultActions result) throws Exception {
        return json.readTree(result.andExpect(status().isOk()).andReturn().getResponse().getContentAsString());
    }

    private JsonNode created(ResultActions result) throws Exception {
        return json.readTree(result.andExpect(status().isCreated()).andReturn().getResponse().getContentAsString());
    }

    private Map<String, Object> request(List<String> forgeIds) {
        Map<String, Object> body = new LinkedHashMap<>();
        body.put("discoveryId", discoveryId);
        body.put("forgeIds", forgeIds);
        return body;
    }

    private JsonNode preview(Map<String, Object> body) throws Exception {
        return ok(postJson(base() + "/imports/preview", body, asAdmin()));
    }

    private JsonNode importing(Map<String, Object> body) throws Exception {
        return ok(postJson(base() + "/imports", body, asAdmin()));
    }

    private static List<JsonNode> list(JsonNode array) {
        return StreamSupport.stream(array.spliterator(), false).toList();
    }

    private static JsonNode byForgeId(JsonNode array, String forgeId) {
        return list(array).stream()
                .filter(node -> forgeId.equals(node.has("repository") ? node.at("/repository/forgeId").asText()
                        : node.at("/forgeId").asText()))
                .findFirst().orElseThrow(() -> new AssertionError("no " + forgeId + " in " + array));
    }

    private static List<String> forgeIds(JsonNode array) {
        return list(array).stream().map(node -> node.has("repository") ? node.at("/repository/forgeId").asText()
                : node.at("/forgeId").asText()).toList();
    }

    private long repository(String url, String subPath) throws Exception {
        Map<String, Object> body = new HashMap<>();
        body.put("url", url);
        if (subPath != null) {
            body.put("subPath", subPath);
        }
        return ok(postJson("/api/v1/repositories", body, asAdmin())).at("/id").asLong();
    }

    private String gitToken(String host) throws Exception {
        return ok(postJson("/api/v1/git-tokens", Map.of("name", "token-" + System.nanoTime(), "host", host,
                "token", "glpat-clone-0000000000000001"), asAdmin())).at("/id").asText(); // gitleaks:allow
    }

    private String sshKey() throws Exception {
        return ok(postJson("/api/v1/ssh-keys", Map.of("name", "deploy-" + System.nanoTime(), "private_key",
                "-----BEGIN DUMMY PRIVATE KEY-----\nforge-import\n-----END DUMMY PRIVATE KEY-----"), asAdmin()))
                .at("/id").asText();
    }

    private List<AuditLogEntity> entries(AuditOperation operation) {
        return auditLog.findAll().stream().filter(entry -> operation.wireName().equals(entry.getOperationType())).toList();
    }

    private List<JsonNode> signalled(String eventType) {
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

    // ---- D5: the selection.

    @Test
    @DisplayName("the table: archived and forks hidden by default, the unknown counted, personal offered unticked, GitLab's layout proposed")
    void theTable() throws Exception {
        JsonNode page = candidates("");
        assertThat(page.at("/listed").asLong()).isEqualTo(8);
        assertThat(forgeIds(page.at("/items"))).as("by full path; 14 archived and 15 a fork, hidden")
                .containsExactly("11", "12", "17", "13", "16", "18");
        assertThat(page.at("/total").asLong()).isEqualTo(6);
        assertThat(page.at("/unjudged/fork").asLong())
                .as("GitLab names no fork's source but a fork's: every other one is unknown, kept and counted")
                .isEqualTo(6);

        JsonNode api = byForgeId(page.at("/items"), "11");
        assertThat(api.at("/proposedSolution").asText()).isEqualTo("acme");
        assertThat(api.at("/proposedProject").asText()).as("the parent group below the top-level one")
                .isEqualTo("backend/payments");
        assertThat(api.at("/selectable").asBoolean()).isTrue();
        assertThat(api.at("/offered").asBoolean()).isTrue();
        assertThat(api.at("/repository/language").asText()).isEqualTo("Java");
        JsonNode tools = byForgeId(page.at("/items"), "13");
        assertThat(tools.at("/proposedProject").asText()).as("directly under the group: a project named after it")
                .isEqualTo("acme");
        JsonNode sandbox = byForgeId(page.at("/items"), "16");
        assertThat(sandbox.at("/repository/personal").asBoolean()).isTrue();
        assertThat(sandbox.at("/selectable").asBoolean()).isTrue();
        assertThat(sandbox.at("/offered").asBoolean()).as("a personal namespace is offered unticked").isFalse();
        assertThat(sandbox.at("/proposedSolution").isNull()).isTrue();
        JsonNode empty = byForgeId(page.at("/items"), "17");
        assertThat(empty.at("/selectable").asBoolean()).isFalse();
        assertThat(empty.at("/notSelectable").asText()).isEqualTo("no_default_branch");
        assertThat(byForgeId(page.at("/items"), "18").at("/proposedSolution").asText()).isEqualTo("globex");

        assertThat(forgeIds(candidates("?archived=only").at("/items"))).containsExactly("14");
        assertThat(forgeIds(candidates("?forks=show&archived=show").at("/items"))).hasSize(8);
        assertThat(forgeIds(candidates("?inactiveDays=365").at("/items"))).doesNotContain("18").contains("11");
        JsonNode java = candidates("?language=JAVA");
        assertThat(forgeIds(java.at("/items"))).containsExactly("11");
        assertThat(java.at("/unjudged/language").asLong()).as("asked of every project but two, unknown").isEqualTo(4);
        assertThat(forgeIds(candidates("?namespace=acme/backend").at("/items"))).containsExactly("11", "12");
        assertThat(forgeIds(candidates("?path=acme/backend/*").at("/items"))).containsExactly("11", "12");
        assertThat(forgeIds(candidates("?path=TOOLS").at("/items"))).containsExactly("13");
        assertThat(forgeIds(candidates("?personal=hide").at("/items"))).doesNotContain("16");
        assertThat(forgeIds(candidates("?visibility=public").at("/items"))).isEmpty();
        JsonNode paged = candidates("?limit=2&offset=2");
        assertThat(forgeIds(paged.at("/items"))).containsExactly("17", "13");
        assertThat(paged.at("/total").asLong()).isEqualTo(6);
    }

    @Test
    @DisplayName("select proposed, all, none, invert, add and remove — only the selectable stays ticked")
    void theSelection() throws Exception {
        String url = base() + "/discoveries/" + discoveryId + "/selection";
        JsonNode proposed = ok(postJson(url, Map.of("operation", "proposed"), asAdmin()));
        assertThat(proposed.at("/selected")).extracting(JsonNode::asText)
                .as("selectable, default filters, personal left out").containsExactly("11", "12", "13", "18");

        JsonNode all = ok(postJson(url, Map.of("operation", "all", "selected", List.of("11")), asAdmin()));
        assertThat(all.at("/selected")).extracting(JsonNode::asText).containsExactly("11", "12", "13", "16", "18");

        JsonNode none = ok(postJson(url, Map.of("operation", "none", "selected", List.of("11", "12", "13"),
                "filters", Map.of("namespace", "acme/backend")), asAdmin()));
        assertThat(none.at("/selected")).extracting(JsonNode::asText).as("only what the filters match")
                .containsExactly("13");

        JsonNode inverted = ok(postJson(url, Map.of("operation", "invert", "selected", List.of("11", "16"),
                "filters", Map.of("path", "acme/*")), asAdmin()));
        assertThat(inverted.at("/selected")).extracting(JsonNode::asText).containsExactly("12", "13", "16");

        JsonNode added = ok(postJson(url, Map.of("operation", "add", "selected", List.of("11"),
                "forgeIds", List.of("14", "17", "999")), asAdmin()));
        assertThat(added.at("/selected")).extracting(JsonNode::asText)
                .as("archived is hidden by default, yet ticked by id: what is imported is what was ticked")
                .containsExactly("11", "14");
        assertThat(added.at("/dropped")).extracting(JsonNode::asText).containsExactly("17", "999");

        JsonNode removed = ok(postJson(url, Map.of("operation", "remove", "selected", List.of("11", "12"),
                "forgeIds", List.of("12")), asAdmin()));
        assertThat(removed.at("/selected")).extracting(JsonNode::asText).containsExactly("11");
        assertThat(removed.at("/count").asInt()).isOne();

        assertThat(detailOf(postJson(url, Map.of("operation", "add"), asAdmin()).andExpect(status().isBadRequest())
                .andReturn())).contains("Name the forge ids");
        assertThat(detailOf(postJson(url, Map.of("operation", "flip"), asAdmin()).andExpect(status().isBadRequest())
                .andReturn())).contains("proposed, all, none, invert, add or remove");
        List<String> tooMany = IntStream.rangeClosed(1, 20_001).mapToObj(String::valueOf).toList();
        assertThat(detailOf(postJson(url, Map.of("operation", "all", "selected", tooMany), asAdmin())
                .andExpect(status().isBadRequest()).andReturn())).contains("at most 20,000");
    }

    @Test
    @DisplayName("already present by identity, whatever the spelling, the branch or the sub-path: shown, not selectable, skipped")
    void presentByIdentity() throws Exception {
        long sshSpelled = repository("git@git.example.org:Acme/Backend/Payments/API", null);
        long monorepoA = repository("https://git.example.org/acme/tools.git", "services/a");
        long monorepoB = repository("https://GIT.example.org/acme/tools/", "services/b");

        JsonNode page = candidates("");
        JsonNode api = byForgeId(page.at("/items"), "11");
        assertThat(api.at("/presentAs")).extracting(JsonNode::asLong).containsExactly(sshSpelled);
        assertThat(api.at("/selectable").asBoolean()).isFalse();
        assertThat(api.at("/notSelectable").asText()).isEqualTo("already_present");
        assertThat(byForgeId(page.at("/items"), "13").at("/presentAs")).extracting(JsonNode::asLong)
                .as("a monorepo split into sub-path targets: present (2 targets)")
                .containsExactly(monorepoA, monorepoB);
        assertThat(forgeIds(candidates("?present=hide").at("/items"))).doesNotContain("11", "13");
        assertThat(forgeIds(candidates("?present=only").at("/items"))).containsExactly("11", "13");

        // A forge whose SSH host is not its HTTPS host: matched through the forge's own two URLs (§4).
        ForgeRepositoryEntity core = snapshot.findAll().stream().filter(row -> row.getForgeId().equals("18"))
                .findFirst().orElseThrow();
        core.setSshUrl("ssh://git@ssh.example.org:2222/globex/platform/core.git");
        snapshot.saveAndFlush(core);
        long overSsh = repository("git@ssh.example.org:globex/platform/core", null);
        assertThat(byForgeId(candidates("").at("/items"), "18").at("/presentAs")).extracting(JsonNode::asLong)
                .containsExactly(overSsh);

        JsonNode preview = preview(request(List.of("11", "12", "13")));
        assertThat(forgeIds(preview.at("/targets"))).containsExactly("12");
        JsonNode skipped = byForgeId(preview.at("/skipped"), "11");
        assertThat(skipped.at("/reason").asText()).isEqualTo("already_present");
        assertThat(skipped.at("/repositoryIds")).extracting(JsonNode::asLong).containsExactly(sshSpelled);
        assertThat(repositories.count()).as("a preview writes nothing").isEqualTo(4);
    }

    // ---- D6: the import.

    @Test
    @DisplayName("creates the targets, solutions and projects the preview showed, reusing a same-name solution, with no grant and no schedule of its own")
    void importAsPreviewed() throws Exception {
        long existing = created(postJson("/api/v1/solutions", Map.of("name", "ACME"), asAdmin())).at("/id").asLong();
        Map<String, Object> body = request(List.of("11", "12", "13", "16", "18"));
        body.put("mapping", List.of(Map.of("namespacePath", "globex", "solution", "Globex Corp"),
                Map.of("forgeId", "16", "noProject", true)));

        JsonNode preview = preview(body);
        assertThat(preview.at("/solutions")).hasSize(2);
        assertThat(byName(preview.at("/solutions"), "ACME").at("/existingId").asLong())
                .as("an existing solution of the same name, case aside, is reused").isEqualTo(existing);
        assertThat(byName(preview.at("/solutions"), "Globex Corp").at("/existingId").isNull()).isTrue();
        assertThat(list(preview.at("/projects"))).extracting(project -> project.at("/solution").asText() + " / "
                        + project.at("/name").asText())
                .containsExactlyInAnyOrder("ACME / backend/payments", "ACME / acme", "Globex Corp / platform");
        assertThat(byForgeId(preview.at("/targets"), "11").at("/branch").asText()).isEqualTo("main");
        assertThat(byForgeId(preview.at("/targets"), "12").at("/branch").asText()).as("the forge's default branch")
                .isEqualTo("develop");
        assertThat(byForgeId(preview.at("/targets"), "16").at("/project").isNull()).isTrue();
        assertThat(preview.at("/defaultIntervalDays").asLong()).isEqualTo(7);
        assertThat(preview.at("/firstScans").isNull()).as("off by default").isTrue();
        assertThat(repositories.count()).isZero();

        Instant before = Instant.now();
        JsonNode result = importing(body);

        assertThat(forgeIds(result.at("/created"))).containsExactlyElementsOf(forgeIds(preview.at("/targets")));
        assertThat(result.at("/solutionsCreated")).extracting(JsonNode::asText).containsExactly("Globex Corp");
        assertThat(result.at("/projectsCreated")).extracting(JsonNode::asText)
                .containsExactlyInAnyOrder("ACME / backend/payments", "ACME / acme", "Globex Corp / platform");
        assertThat(repositories.count()).isEqualTo(5);
        RepositoryEntity api = repositories.findById(byForgeId(result.at("/created"), "11").at("/repositoryId").asLong())
                .orElseThrow();
        assertThat(api.getUrl()).isEqualTo("https://git.example.org/acme/backend/payments/api.git");
        assertThat(api.getBranch()).isEqualTo("main");
        assertThat(api.getName()).isEqualTo("acme/backend/payments/api");
        assertThat(api.getProjectId()).isNotNull();
        assertThat(api.getScanIntervalMinutes()).isNull();
        assertThat(api.getScanCron()).isNull();
        assertThat(api.isScanManualOnly()).isFalse();
        assertThat(api.getLastScheduledScanAt())
                .as("stamped, so the default schedule takes it at its own slot rather than all of them at the next tick")
                .isNotNull().isAfterOrEqualTo(before.minusSeconds(5));
        assertThat(repositories.findById(byForgeId(result.at("/created"), "16").at("/repositoryId").asLong())
                .orElseThrow().getProjectId()).isNull();
        assertThat(userTargets.count()).as("no grant").isZero();
        assertThat(scans.count()).as("no first scan unless asked").isZero();

        assertThat(links.findAll()).hasSize(5).allSatisfy(link -> {
            assertThat(link.getConnectionId().toString()).isEqualTo(connectionId);
            assertThat(link.getDiscoveryId()).isEqualTo(discoveryId);
        });
        JsonNode table = candidates("");
        assertThat(byForgeId(table.at("/items"), "11").at("/importedAs").asLong()).isEqualTo(api.getId());
        assertThat(byForgeId(table.at("/items"), "11").at("/notSelectable").asText()).isEqualTo("already_imported");
        assertThat(read(base()).at("/importedTargets").asLong()).isEqualTo(5);
    }

    private static JsonNode byName(JsonNode array, String name) {
        return list(array).stream().filter(node -> name.equals(node.at("/name").asText())).findFirst().orElseThrow();
    }

    @Test
    @DisplayName("replayed, it creates nothing, reports everything already imported, and signals nothing")
    void idempotent() throws Exception {
        Map<String, Object> body = request(List.of("11", "12"));
        importing(body);
        long targets = repositories.count();
        outbox.deleteAll();

        JsonNode again = importing(body);

        assertThat(again.at("/created")).isEmpty();
        assertThat(list(again.at("/skipped"))).extracting(node -> node.at("/reason").asText())
                .containsExactly("already_imported", "already_imported");
        assertThat(repositories.count()).isEqualTo(targets);
        assertThat(links.count()).isEqualTo(2);
        assertThat(entries(AuditOperation.FORGE_IMPORT_APPLIED)).hasSize(2);
        assertThat(signalled("FORGE_IMPORT_APPLIED")).as("an import that created nothing is no event").isEmpty();
    }

    @Test
    @DisplayName("at most 1,000 repositories per import: a thousand is planned, a thousand and one refused whole")
    void theBound() throws Exception {
        ForgeDiscoveryEntity run = discoveries.findById(discoveryId).orElseThrow();
        List<ForgeRepositoryEntity> many = new ArrayList<>();
        for (int i = 0; i < 1_000; i++) {
            ForgeRepositoryEntity row = new ForgeRepositoryEntity();
            row.setConnectionId(run.getConnectionId());
            row.setForgeId("b" + i);
            row.setFullPath("bulk/repo-" + i);
            row.setNamespacePath("bulk");
            row.setName("repo-" + i);
            row.setDefaultBranch("main");
            row.setHttpUrl("https://git.example.org/bulk/repo-" + i + ".git");
            row.setFirstSeenBy(discoveryId);
            row.setFirstSeenAt(Instant.now());
            row.setLastSeenBy(discoveryId);
            row.setLastSeenAt(Instant.now());
            many.add(row);
        }
        snapshot.saveAll(many);
        List<String> thousand = many.stream().map(ForgeRepositoryEntity::getForgeId).toList();

        JsonNode preview = preview(request(thousand));
        assertThat(preview.at("/targets")).hasSize(1_000);

        List<String> oneMore = new ArrayList<>(thousand);
        oneMore.add("11");
        assertThat(detailOf(postJson(base() + "/imports", request(oneMore), asAdmin())
                .andExpect(status().isBadRequest()).andReturn()))
                .isEqualTo("An import takes at most 1,000 repositories; this one names 1,001. Import a larger "
                        + "selection in several parts.");
        assertThat(repositories.count()).isZero();
        assertThat(detailOf(postJson(base() + "/imports", request(List.of()), asAdmin())
                .andExpect(status().isBadRequest()).andReturn())).contains("at least one");
    }

    @Test
    @DisplayName("first scans, when asked, wait exactly k spacings each, through not_before")
    void staggeredFirstScans() throws Exception {
        Map<String, Object> body = request(List.of("11", "12", "13", "18"));
        body.put("firstScan", true);
        body.put("spacingSeconds", 90);

        JsonNode preview = preview(body);
        assertThat(preview.at("/firstScans/count").asInt()).isEqualTo(4);
        assertThat(preview.at("/firstScans/spacingSeconds").asInt()).isEqualTo(90);

        JsonNode result = importing(body);
        List<ScanEntity> queued = scans.findAll().stream()
                .sorted(Comparator.comparing(ScanEntity::getNotBefore)).toList();
        assertThat(queued).hasSize(4);
        List<Long> byPlan = list(result.at("/created")).stream().map(node -> node.at("/repositoryId").asLong()).toList();
        assertThat(queued).extracting(ScanEntity::getRepoId).as("in the table's order").containsExactlyElementsOf(byPlan);
        Instant first = queued.getFirst().getNotBefore();
        for (int k = 0; k < queued.size(); k++) {
            assertThat(queued.get(k).getNotBefore()).isEqualTo(first.plus(Duration.ofSeconds(90L * k)));
            assertThat(queued.get(k).getStatus()).isEqualTo("pending");
            assertThat(queued.get(k).getBranch()).isEqualTo(
                    repositories.findById(queued.get(k).getRepoId()).orElseThrow().getBranch());
        }
        assertThat(Instant.parse(byForgeId(result.at("/created"), "18").at("/firstScanNotBefore").asText()))
                .isEqualTo(queued.getLast().getNotBefore());

        body.put("spacingSeconds", 9);
        assertThat(detailOf(postJson(base() + "/imports/preview", body, asAdmin()).andExpect(status().isBadRequest())
                .andReturn())).contains("between 10 seconds and 10 minutes");
        body.put("spacingSeconds", 601);
        postJson(base() + "/imports/preview", body, asAdmin()).andExpect(status().isBadRequest());
    }

    @Test
    @DisplayName("the default spacing is sixty seconds")
    void defaultSpacing() throws Exception {
        Map<String, Object> body = request(List.of("11", "12"));
        body.put("firstScan", true);
        importing(body);
        List<ScanEntity> queued = scans.findAll().stream().sorted(Comparator.comparing(ScanEntity::getNotBefore)).toList();
        assertThat(Duration.between(queued.get(0).getNotBefore(), queued.get(1).getNotBefore()))
                .isEqualTo(Duration.ofSeconds(60));
    }

    @Test
    @DisplayName("the credential per host: the one token bound to the host proposed, an SSH key over the SSH URL, never the connection's token")
    void credentialsPerHost() throws Exception {
        String token = gitToken("git.example.org");
        JsonNode proposed = preview(request(List.of("11")));
        JsonNode host = proposed.at("/credentials/0");
        assertThat(host.at("/host").asText()).isEqualTo("git.example.org");
        assertThat(host.at("/credential/kind").asText()).isEqualTo("https_token");
        assertThat(host.at("/credential/id").asText()).isEqualTo(token);
        assertThat(host.at("/proposed").asBoolean()).isTrue();
        assertThat(byForgeId(proposed.at("/targets"), "11").at("/warning").isNull()).isTrue();

        JsonNode imported = importing(request(List.of("11")));
        RepositoryEntity https = repositories.findById(imported.at("/created/0/repositoryId").asLong()).orElseThrow();
        assertThat(https.getHttpsTokenId().toString()).isEqualTo(token);
        assertThat(https.getUrl()).startsWith("https://");

        String key = sshKey();
        Map<String, Object> withKey = request(List.of("12"));
        withKey.put("credentials", List.of(Map.of("host", "GIT.example.org", "sshKeyId", key)));
        JsonNode ssh = importing(withKey);
        RepositoryEntity overSsh = repositories.findById(ssh.at("/created/0/repositoryId").asLong()).orElseThrow();
        assertThat(overSsh.getUrl()).isEqualTo("git@git.example.org:acme/backend/payments/worker.git");
        assertThat(overSsh.getSshKeyId().toString()).isEqualTo(key);
        assertThat(overSsh.getHttpsTokenId()).isNull();

        Map<String, Object> none = request(List.of("13"));
        none.put("credentials", List.of(Map.of("host", "git.example.org")));
        JsonNode anonymous = preview(none);
        assertThat(anonymous.at("/credentials/0/credential/kind").asText()).isEqualTo("none");
        assertThat(anonymous.at("/credentials/0/proposed").asBoolean()).isFalse();
        assertThat(byForgeId(anonymous.at("/targets"), "13").at("/warning").asText())
                .contains("private").contains("requires authentication");

        String elsewhere = gitToken("gitlab.other.example");
        Map<String, Object> wrongHost = request(List.of("13"));
        wrongHost.put("credentials", List.of(Map.of("host", "git.example.org", "httpsTokenId", elsewhere)));
        assertThat(detailOf(postJson(base() + "/imports", wrongHost, asAdmin()).andExpect(status().isBadRequest())
                .andReturn())).contains("issued for another host");

        gitToken("git.example.org");
        JsonNode twoTokens = preview(request(List.of("13")));
        assertThat(twoTokens.at("/credentials/0/credential/kind").asText())
                .as("two tokens bound to the host: nothing is proposed").isEqualTo("none");
    }

    @Test
    @DisplayName("audited per creation as the forms write it, summarised once, and VECTI-SEC-035 signalled once")
    void auditAndSiem() throws Exception {
        importing(request(List.of("11", "12", "13")));

        List<AuditLogEntity> added = entries(AuditOperation.SETTING_UPDATED).stream()
                .filter(entry -> entry.getDescription().startsWith("Repository added: ")).toList();
        assertThat(added).hasSize(3).allSatisfy(entry -> assertThat(entry.getDescription())
                .contains("imported from connection Internal GitLab, discovery " + discoveryId));
        assertThat(entries(AuditOperation.SOLUTION_UPDATED)).extracting(AuditLogEntity::getDescription)
                .containsExactly("Solution created: acme");
        assertThat(entries(AuditOperation.PROJECT_UPDATED)).extracting(AuditLogEntity::getDescription)
                .containsExactlyInAnyOrder("Project created: acme / backend/payments", "Project created: acme / acme");
        List<AuditLogEntity> summary = entries(AuditOperation.FORGE_IMPORT_APPLIED);
        assertThat(summary).hasSize(1);
        assertThat(summary.getFirst().getResourceId()).isEqualTo(connectionId);
        assertThat(summary.getFirst().getDescription()).contains("3 target(s) created").contains("1 solution(s) and 2 "
                + "project(s) created").contains("no grant");
        assertThat(summary.getFirst().getUserId()).startsWith("admin-");

        assertThat(signalled("FORGE_IMPORT_APPLIED")).as("once per import, never once per target").hasSize(1);
        assertThat(signalled("ACCESS_GRANT_CHANGED")).as("filing at creation is no grant change").isEmpty();
    }

    @Test
    @DisplayName("who will see the new targets: administrators, and a reused project's grantees, counted")
    void whoWillSee() throws Exception {
        settings.set(Setting.TARGET_VISIBILITY, "assigned");
        long solution = created(postJson("/api/v1/solutions", Map.of("name", "acme"), asAdmin())).at("/id").asLong();
        long project = created(postJson("/api/v1/solutions/" + solution + "/projects", Map.of("name", "backend/payments"),
                asAdmin())).at("/id").asLong();
        asReader();
        long reader = users.findAll().stream().filter(user -> user.getUsername().startsWith("reader"))
                .findFirst().orElseThrow().getId();
        userTargets.save(new UserTargetEntity(reader, TeamRules.KIND_PROJECT, project));

        JsonNode preview = preview(request(List.of("11", "13", "16")));
        JsonNode reused = list(preview.at("/projects")).stream()
                .filter(node -> node.at("/existingId").asLong() == project).findFirst().orElseThrow();
        assertThat(reused.at("/accounts").asLong()).isOne();
        assertThat(reused.at("/teams").asLong()).isZero();
        assertThat(preview.at("/visibilityMode").asText()).isEqualTo("assigned");
        assertThat(byForgeId(preview.at("/targets"), "11").at("/visibleTo").asText())
                .contains("1 account(s) and 0 team(s) granted project acme / backend/payments");
        assertThat(byForgeId(preview.at("/targets"), "13").at("/visibleTo").asText())
                .contains("only").contains("is new and nobody holds a grant");
        assertThat(byForgeId(preview.at("/targets"), "16").at("/visibleTo").asText()).contains("no project");

        settings.set(Setting.TARGET_VISIBILITY, "everyone");
        assertThat(byForgeId(preview(request(List.of("11"))).at("/targets"), "11").at("/visibleTo").asText())
                .startsWith("every signed-in account");
    }

    @Test
    @DisplayName("a repository the form would refuse is listed by the preview and refuses the import whole")
    void refusedWhole() throws Exception {
        Map<String, Object> body = request(List.of("11", "12"));
        body.put("requiredAgentLabel", "x".repeat(256));
        JsonNode preview = preview(body);
        assertThat(preview.at("/targets")).isEmpty();
        assertThat(list(preview.at("/refused"))).hasSize(2)
                .allSatisfy(refused -> assertThat(refused.at("/refusal").asText())
                        .isEqualTo("The required agent label is longer than 255 characters."));
        assertThat(detailOf(postJson(base() + "/imports", body, asAdmin())
                .andExpect(status().isBadRequest()).andReturn())).startsWith("2 of the selected repositories would be "
                        + "refused");
        assertThat(repositories.count()).as("everything or nothing").isZero();
        assertThat(entries(AuditOperation.FORGE_IMPORT_APPLIED)).isEmpty();

        Map<String, Object> halfMapped = request(List.of("16"));
        halfMapped.put("mapping", List.of(Map.of("forgeId", "16", "project", "Notes")));
        JsonNode half = preview(halfMapped);
        assertThat(half.at("/refused/0/refusal").asText()).contains("name the solution");
        postJson(base() + "/imports", halfMapped, asAdmin()).andExpect(status().isBadRequest());
    }

    @Test
    @DisplayName("deleting an imported target drops its link: the repository is offered again")
    void targetDeletedDropsTheLink() throws Exception {
        JsonNode result = importing(request(List.of("11", "12")));
        long api = byForgeId(result.at("/created"), "11").at("/repositoryId").asLong();

        mvc.perform(authenticated(delete("/api/v1/repositories/" + api), asAdmin())).andExpect(status().isNoContent());

        assertThat(links.findAll()).extracting(ForgeImportLinkEntity::getForgeId).containsExactly("12");
        JsonNode table = candidates("");
        assertThat(byForgeId(table.at("/items"), "11").at("/selectable").asBoolean()).isTrue();
        assertThat(byForgeId(table.at("/items"), "11").at("/importedAs").isNull()).isTrue();
        assertThat(read(base()).at("/importedTargets").asLong()).isOne();
    }

    @Test
    @DisplayName("deleting the connection keeps the targets and drops their links")
    void connectionDeletedKeepsTheTargets() throws Exception {
        importing(request(List.of("11", "12")));
        mvc.perform(authenticated(delete(base()), asAdmin())).andExpect(status().isNoContent());
        assertThat(repositories.count()).isEqualTo(2);
        assertThat(links.count()).isZero();
    }

    @Test
    @DisplayName("from the latest discovery that completed or ended partial — any other is refused with its cause")
    void whichDiscovery() throws Exception {
        String url = base() + "/discoveries/" + discoveryId + "/selection";
        ForgeDiscoveryEntity running = new ForgeDiscoveryEntity();
        running.setConnectionId(java.util.UUID.fromString(connectionId));
        running.setState(DiscoveryState.RUNNING.wireName());
        running.setRequestedAt(Instant.now());
        running.setRequestedBy("ada");
        long runningId = discoveries.saveAndFlush(running).getId();

        assertThat(read(url).at("/listed").asLong()).as("a run still going does not supersede the last ended one")
                .isEqualTo(8);
        var refused = mvc.perform(authenticated(get(base() + "/discoveries/" + runningId + "/selection"), asAdmin()))
                .andExpect(status().isConflict()).andReturn();
        assertThat(json.readTree(refused.getResponse().getContentAsString()).at("/type").asText())
                .endsWith("forge-discovery-not-selectable");

        ForgeDiscoveryEntity ended = discoveries.findById(runningId).orElseThrow();
        ended.setState(DiscoveryState.PARTIAL.wireName());
        discoveries.saveAndFlush(ended);
        var superseded = mvc.perform(authenticated(get(url), asAdmin())).andExpect(status().isConflict()).andReturn();
        JsonNode problem = json.readTree(superseded.getResponse().getContentAsString());
        assertThat(problem.at("/type").asText()).endsWith("forge-discovery-superseded");
        assertThat(problem.at("/latestDiscoveryId").asLong()).isEqualTo(runningId);
        assertThat(read(base() + "/discoveries/" + runningId + "/selection").at("/listed").asLong())
                .as("a partial run is selectable: it listed nothing, here").isZero();

        postJson(base() + "/imports/preview", request(List.of("11")), asAdmin()).andExpect(status().isConflict());
        mvc.perform(authenticated(get("/api/v1/forge-connections/" + java.util.UUID.randomUUID() + "/discoveries/"
                + discoveryId + "/selection"), asAdmin())).andExpect(status().isNotFound());
        mvc.perform(authenticated(get(base() + "/discoveries/999999/selection"), asAdmin()))
                .andExpect(status().isNotFound());
        Map<String, Object> unknown = request(List.of("424242"));
        unknown.put("discoveryId", runningId);
        assertThat(detailOf(postJson(base() + "/imports/preview", unknown, asAdmin())
                .andExpect(status().isBadRequest()).andReturn())).contains("not listed by discovery " + runningId);
    }

    @Test
    @DisplayName("is an administrator's alone: every other role is refused, and nothing is created")
    void onlyAnAdministrator() throws Exception {
        for (String token : List.of(asCiso(), asAuditor(), asReader(), asSecurityChampion())) {
            mvc.perform(authenticated(get(base() + "/discoveries/" + discoveryId + "/selection"), token))
                    .andExpect(status().isForbidden());
            postJson(base() + "/discoveries/" + discoveryId + "/selection", Map.of("operation", "all"), token)
                    .andExpect(status().isForbidden());
            postJson(base() + "/imports/preview", request(List.of("11")), token).andExpect(status().isForbidden());
            postJson(base() + "/imports", request(List.of("11")), token).andExpect(status().isForbidden());
        }
        mvc.perform(post(base() + "/imports").contentType(MediaType.APPLICATION_JSON).content(write(request(List.of("11")))))
                .andExpect(status().isUnauthorized());
        assertThat(repositories.count()).isZero();
        assertThat(links.count()).isZero();
    }
}
