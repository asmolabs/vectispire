package com.asmolabs.vectispire.core.api;

import static com.asmolabs.vectispire.core.api.ForgeDiscoveriesRoutesTest.GROUPS;
import static com.asmolabs.vectispire.core.api.ForgeDiscoveriesRoutesTest.PROJECTS;
import static com.asmolabs.vectispire.core.api.ForgeDiscoveriesRoutesTest.TOKEN;
import static org.assertj.core.api.Assertions.assertThat;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.delete;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.put;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

import ch.qos.logback.classic.Logger;
import ch.qos.logback.classic.spi.ILoggingEvent;
import ch.qos.logback.core.read.ListAppender;
import com.asmolabs.vectispire.common.domain.access.VisibilityMode;
import com.asmolabs.vectispire.common.domain.forges.ForgeKind;
import com.asmolabs.vectispire.common.domain.integrations.Integration;
import com.asmolabs.vectispire.common.domain.settings.Setting;
import com.asmolabs.vectispire.common.domain.users.Role;
import com.asmolabs.vectispire.core.forges.ForgeReviewService;
import com.asmolabs.vectispire.core.forges.ForgeStub;
import com.asmolabs.vectispire.core.forges.ForgeStub.Reply;
import com.asmolabs.vectispire.core.forges.internal.DiscoveryWorker;
import com.asmolabs.vectispire.core.forges.persistence.ForgeImportLinkEntity;
import com.asmolabs.vectispire.core.forges.persistence.ForgeImportLinkRepository;
import com.asmolabs.vectispire.core.forges.persistence.ForgeReviewReadingEntity;
import com.asmolabs.vectispire.core.forges.persistence.ForgeReviewReadingRepository;
import com.asmolabs.vectispire.core.settings.Integrations;
import com.asmolabs.vectispire.core.settings.SettingsService;
import com.asmolabs.vectispire.core.targets.persistence.GitRepositoryRepository;
import com.asmolabs.vectispire.core.targets.persistence.RepositoryEntity;
import com.fasterxml.jackson.databind.JsonNode;
import java.time.Duration;
import java.time.Instant;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.UUID;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.slf4j.LoggerFactory;
import org.springframework.http.MediaType;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.test.web.servlet.MvcResult;

/**
 * A {@code change_review} line from the forge to the checklist (decision 0037, lot G3), over HTTP, against a
 * self-managed GitLab on loopback answering as a Community Edition does: no approval settings (404), the merged merge
 * requests and each one's {@code approved_by}. The reading is the real one — the hourly task's service, through the
 * connection's pager — and the line is read through the checklist's route.
 *
 * <p>One target is linked by its import (the provenance link), one by its URL's identity with a repository the
 * discovery listed, one by neither.
 */
@DisplayName("change-review lines, from the forge to the checklist")
class ChangeReviewRoutesTest extends ApiTestBase {

    private static final String TEMPLATES = "/api/v1/checklist-templates";
    private static final String RECENT = "2026-09-20T10:00:00Z";

    private static final Map<String, Object> EVERY_CHANGE = Map.of("kind", "change_review", "maxAgeDays", 1,
            "minimumApprovals", 1, "windowDays", 30, "minimumRatio", 1);

    @Autowired
    private DiscoveryWorker worker;

    @Autowired
    private ForgeReviewService reviews;

    @Autowired
    private ForgeReviewReadingRepository readings;

    @Autowired
    private ForgeImportLinkRepository links;

    @Autowired
    private GitRepositoryRepository repositories;

    @Autowired
    private SettingsService settings;

    @Autowired
    private Integrations integrations;

    @Autowired
    private JdbcTemplate jdbc;

    private ForgeStub gitlab;
    private String connectionId;
    private String developer;
    private long project;
    private long imported;
    private long byUrl;

    @BeforeEach
    void estate() throws Exception {
        settings.set(Setting.FOUR_EYES_APPROVAL_REQUIRED, "false");
        settings.set(Setting.CHECKLIST_AUTO_ANSWER, "false");
        settings.set(Setting.TARGET_VISIBILITY, VisibilityMode.EVERYONE.wireName());
        gitlab = ForgeStub.start().gitlab("17.4.1", "[\"read_api\"]", true);
        gitlab.route(GROUPS, Reply.json("[{\"id\":1,\"full_path\":\"acme\"}]"));
        gitlab.route(PROJECTS, Reply.json("[" + ForgeDiscoveriesRoutesTest.project(42, "acme/app", "group", "main", false, 10L, false, RECENT) + ","
                + ForgeDiscoveriesRoutesTest.project(43, "acme/web", "group", "trunk", false, 10L, false, RECENT) + "]"));
        connectionId = connection();
        mvc.perform(authenticated(post("/api/v1/forge-connections/" + connectionId + "/discoveries"), asAdmin()))
                .andExpect(status().isAccepted());
        assertThat(worker.drain()).isOne();

        developer = tokenFor("developer-" + System.nanoTime(), Role.USER, false);
        project = project("Checkout");
        imported = repository("https://example.invalid/imported-under-another-name.git");
        link(imported, "42");
        // The discovery listed acme/web with this clone URL: the same repository, by its identity.
        byUrl = repository("https://git.example.org/acme/web.git");
        file(project, imported);
        file(project, byUrl);
    }

    @AfterEach
    void stop() {
        gitlab.close();
    }

    // ---------------------------------------------------------------- the forge's answers

    private static String ago(Duration duration) {
        return Instant.now().minus(duration).toString();
    }

    private static String mergeRequest(int iid, Duration mergedAgo, int author) {
        return "{\"iid\":" + iid + ",\"state\":\"merged\",\"merged_at\":\"" + ago(mergedAgo) + "\",\"updated_at\":\""
                + ago(mergedAgo) + "\",\"author\":{\"id\":" + author + "}}";
    }

    private static String approvedBy(int... users) {
        StringBuilder by = new StringBuilder();
        for (int user : users) {
            by.append(by.isEmpty() ? "" : ",").append("{\"user\":{\"id\":").append(user).append("}}");
        }
        return "{\"approved\":" + (users.length > 0) + ",\"approved_by\":[" + by + "]}";
    }

    /** A Community Edition project: its default branch, no approval settings, these merge requests. */
    private void communityEdition(int id, String branch, String mergeRequests) {
        gitlab.route("/api/v4/projects/" + id, Reply.json("{\"id\":" + id + ",\"path_with_namespace\":\"acme/p" + id
                + "\",\"default_branch\":\"" + branch + "\"}"));
        gitlab.route("/api/v4/projects/" + id + "/approvals", Reply.status(404));
        gitlab.routePrefix(mergeRequestsPath(id, branch), Reply.json(mergeRequests));
    }

    private static String mergeRequestsPath(int id, String branch) {
        return "/api/v4/projects/" + id + "/merge_requests?state=merged&target_branch=" + branch + "&updated_after=";
    }

    // ---------------------------------------------------------------- the cases

    @Test
    @DisplayName("Community Edition: every merged merge request approved by a peer passes, on the imported and the URL-matched target")
    void communityEditionPasses() throws Exception {
        communityEdition(42, "main", "[" + mergeRequest(5, Duration.ofDays(1), 7) + "," + mergeRequest(4, Duration.ofDays(9), 7)
                + "]");
        communityEdition(43, "trunk", "[" + mergeRequest(2, Duration.ofDays(2), 8) + "]");
        gitlab.route("/api/v4/projects/42/merge_requests/5/approvals", Reply.json(approvedBy(8)));
        gitlab.route("/api/v4/projects/42/merge_requests/4/approvals", Reply.json(approvedBy(7, 9)));
        gitlab.route("/api/v4/projects/43/merge_requests/2/approvals", Reply.json(approvedBy(7)));
        publishWithRule(EVERY_CHANGE);
        open(project);

        assertThat(measurement().at("/reason").asText()).as("nothing read yet: no data, never a pass")
                .isEqualTo("never_examined");

        assertThat(readAll()).isEqualTo(2);

        JsonNode measured = measurement();
        assertThat(measured.at("/outcome").asText()).isEqualTo("pass");
        assertThat(measured.at("/evidence/summary").asText())
                .contains("2 of 2 merged merge requests approved by a peer in 30 days")
                .contains("1 of 1 merged merge requests approved by a peer in 30 days")
                .contains("Community Edition or Free tier");
        assertThat(measured.at("/evidence/repositories")).allSatisfy(look -> {
            assertThat(look.at("/source").asText()).isEqualTo("forge_review");
            assertThat(look.at("/digest").asText()).hasSize(64);
        });
        assertThat(gitlab.seen).allSatisfy(request -> assertThat(request.headers()).containsEntry("private-token", TOKEN));
        assertThat(gitlab.seen).as("the paid tiers' rules are not asked once the settings answered 404")
                .noneMatch(request -> request.path().contains("approval_rules"));
        assertThat(readingOf(byUrl).getForgeId()).as("matched by the identity of its URL").isEqualTo("43");

        long requests = gitlab.seen.size();
        assertThat(reviews.readDue()).as("read an hour ago: not due again").isZero();
        assertThat(gitlab.seen).hasSize((int) requests);
    }

    @Test
    @DisplayName("an approval by the merge request's own author is not a review: the line fails and names it")
    void selfApprovalFails() throws Exception {
        communityEdition(42, "main", "[" + mergeRequest(5, Duration.ofDays(1), 7) + "]");
        communityEdition(43, "trunk", "[" + mergeRequest(2, Duration.ofDays(2), 8) + "]");
        gitlab.route("/api/v4/projects/42/merge_requests/5/approvals", Reply.json(approvedBy(7)));
        gitlab.route("/api/v4/projects/43/merge_requests/2/approvals", Reply.json(approvedBy(9)));
        publishWithRule(EVERY_CHANGE);
        open(project);

        readAll();

        JsonNode measured = measurement();
        assertThat(measured.at("/outcome").asText()).isEqualTo("fail");
        assertThat(measured.at("/evidence/summary").asText()).contains("0 of 1 merged merge requests approved by a peer")
                .contains("approved by their author too, not counted").contains("without: !5");
    }

    @Test
    @DisplayName("a target no connection knows, and a token refused the merge requests: no data, each with its reason")
    void unlinkedAndRefused() throws Exception {
        long elsewhere = repository("https://example.invalid/elsewhere.git");
        file(project, elsewhere);
        communityEdition(42, "main", "[]");
        gitlab.routePrefix(mergeRequestsPrefix(43), Reply.status(403));
        gitlab.route("/api/v4/projects/43", Reply.json("{\"id\":43,\"path_with_namespace\":\"acme/web\","
                + "\"default_branch\":\"trunk\"}"));
        gitlab.route("/api/v4/projects/43/approvals", Reply.status(404));
        publishWithRule(EVERY_CHANGE);
        open(project);

        readAll();

        JsonNode measured = measurement();
        assertThat(measured.at("/outcome").asText()).isEqualTo("no_data");
        assertThat(measured.at("/reason").asText()).isEqualTo("forge_unlinked");
        Map<Long, JsonNode> looks = new HashMap<>();
        measured.at("/evidence/repositories").forEach(look -> looks.put(look.at("/repositoryId").asLong(), look));
        assertThat(looks.get(elsewhere).at("/status").asText()).isEqualTo("forge_unlinked");
        assertThat(looks.get(elsewhere).at("/detail").asText()).contains("no forge connection imported this repository");
        assertThat(looks.get(byUrl).at("/status").asText()).isEqualTo("forge_unreadable");
        assertThat(looks.get(byUrl).at("/detail").asText()).contains("HTTP 403").contains("Reporter");
        assertThat(looks.get(imported).at("/status").asText()).as("nothing merged in thirty days is no data too")
                .isEqualTo("no_change_merged");
    }

    @Test
    @DisplayName("forge.gitlab disabled: a line that passed reads no data, forge_integration_disabled; nothing is read; re-enabled it passes again")
    void disabledForge() throws Exception {
        communityEdition(42, "main", "[" + mergeRequest(5, Duration.ofDays(1), 7) + "]");
        communityEdition(43, "trunk", "[" + mergeRequest(2, Duration.ofDays(2), 8) + "]");
        gitlab.route("/api/v4/projects/42/merge_requests/5/approvals", Reply.json(approvedBy(8)));
        gitlab.route("/api/v4/projects/43/merge_requests/2/approvals", Reply.json(approvedBy(7)));
        publishWithRule(EVERY_CHANGE);
        open(project);
        assertThat(readAll()).isEqualTo(2);
        assertThat(measurement().at("/outcome").asText()).isEqualTo("pass");

        IntegrationRows rows = IntegrationRows.remember(jdbc);
        try {
            integrations.switchTo(Integration.of(ForgeKind.GITLAB), false, "test");

            JsonNode suspended = measurement();
            assertThat(suspended.at("/outcome").asText()).as("the reading that passed is not judged").isEqualTo("no_data");
            assertThat(suspended.at("/reason").asText()).isEqualTo("forge_integration_disabled");
            assertThat(suspended.at("/evidence/repositories")).hasSize(2).allSatisfy(look -> {
                assertThat(look.at("/status").asText()).isEqualTo("forge_integration_disabled");
                assertThat(look.at("/detail").asText()).contains("forge.gitlab integration is disabled");
            });
            assertThat(suspended.at("/evidence/summary").asText()).contains("forge.gitlab integration is disabled");

            // Due again: the turn claims, sends nothing, keeps the readings and says so once for both.
            readings.findAll().forEach(row -> {
                row.setReadAt(Instant.now().minus(Duration.ofDays(2)));
                readings.save(row);
            });
            gitlab.seen.clear();
            ListAppender<ILoggingEvent> logged = new ListAppender<>();
            Logger logger = (Logger) LoggerFactory.getLogger(ForgeReviewService.class);
            logged.start();
            logger.addAppender(logged);
            try {
                assertThat(readAll()).isZero();
            } finally {
                logger.detachAppender(logged);
            }
            assertThat(gitlab.seen).as("nothing sent to a disabled forge").isEmpty();
            assertThat(logged.list).filteredOn(event -> event.getFormattedMessage().contains("integration(s) disabled"))
                    .singleElement()
                    .satisfies(event -> assertThat(event.getFormattedMessage()).contains("2 not taken")
                            .contains("forge.gitlab"));
            assertThat(readings.findAll()).allSatisfy(row -> {
                assertThat(row.getState()).as("the reading is kept").isEqualTo("read");
                assertThat(row.getClaimedUntil()).as("the claim is let go").isNull();
            });
            assertThat(measurement().at("/reason").asText()).isEqualTo("forge_integration_disabled");
        } finally {
            rows.putBack();
        }

        assertThat(readAll()).as("re-enabled: read again, as it was due").isEqualTo(2);
        assertThat(measurement().at("/outcome").asText()).isEqualTo("pass");
    }

    @Test
    @DisplayName("a reading goes with its target, and with a repository no line asks about any more")
    void readingsFollowTheirTargets() throws Exception {
        communityEdition(42, "main", "[]");
        communityEdition(43, "trunk", "[]");
        publishWithRule(EVERY_CHANGE);
        open(project);
        readAll();
        assertThat(readings.findAll()).extracting(ForgeReviewReadingEntity::getRepositoryId)
                .containsExactlyInAnyOrder(imported, byUrl);

        mvc.perform(authenticated(delete("/api/v1/repositories/" + imported), asAdmin())).andExpect(status().isNoContent());
        assertThat(readings.findAll()).extracting(ForgeReviewReadingEntity::getRepositoryId).containsExactly(byUrl);

        mvc.perform(authenticated(delete("/api/v1/projects/" + project + "/repositories/" + byUrl), asAdmin()))
                .andExpect(status().isNoContent());
        reviews.readDue();
        assertThat(readings.findAll()).as("filed out of the project: no line asks").isEmpty();
    }

    @Test
    @DisplayName("a change-review rule is bound with its parameters, and refused in words without them")
    void binding() throws Exception {
        mvc.perform(authenticated(post(TEMPLATES + "/release/versions"), asAdmin())
                        .contentType(MediaType.APPLICATION_OCTET_STREAM).content(ChecklistWorkbooks.of(ChecklistWorkbooks.FIRST)))
                .andExpect(status().isCreated());
        JsonNode laid = layOut();
        Map<String, Object> missing = new LinkedHashMap<>(EVERY_CHANGE);
        missing.remove("windowDays");
        MvcResult refused = bind(laid, missing).andExpect(status().isBadRequest()).andReturn();
        assertThat(detailOf(refused)).contains("windowDays");

        Map<String, Object> named = new LinkedHashMap<>(EVERY_CHANGE);
        named.put("branch", "release/2026");
        JsonNode bound = read(bind(laid, named).andExpect(status().isOk()));
        JsonNode rule = bound.at("/items/0/boundRule");
        assertThat(rule.at("/kind").asText()).isEqualTo("change_review");
        assertThat(rule.at("/branch").asText()).isEqualTo("release/2026");
        assertThat(rule.at("/minimumApprovals").asInt()).isOne();
        assertThat(rule.at("/windowDays").asInt()).isEqualTo(30);
    }

    // ---------------------------------------------------------------- helpers

    private static String mergeRequestsPrefix(int id) {
        return "/api/v4/projects/" + id + "/merge_requests";
    }

    private int readAll() {
        return reviews.readDue();
    }

    private ForgeReviewReadingEntity readingOf(long repositoryId) {
        return readings.findByRepositoryIdAndWantedBranch(repositoryId, ForgeReviewReadingEntity.DEFAULT_BRANCH)
                .orElseThrow();
    }

    private JsonNode measurement() throws Exception {
        return read(mvc.perform(authenticated(get("/api/v1/projects/" + project + "/checklists/1/measurements"), developer))
                .andExpect(status().isOk())).at("/lines/0/measurement");
    }

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

    private void link(long repositoryId, String forgeId) {
        ForgeImportLinkEntity link = new ForgeImportLinkEntity();
        link.setRepositoryId(repositoryId);
        link.setConnectionId(UUID.fromString(connectionId));
        link.setForgeId(forgeId);
        link.setDiscoveryId(1L);
        link.setImportedAt(Instant.now());
        link.setImportedBy("admin");
        links.save(link);
    }

    private long project(String name) throws Exception {
        long solution = idOf(mvc.perform(authenticated(post("/api/v1/solutions"), asAdmin())
                        .contentType(MediaType.APPLICATION_JSON).content(write(Map.of("name", name + " " + System.nanoTime()))))
                .andExpect(status().isCreated()));
        return idOf(mvc.perform(authenticated(post("/api/v1/solutions/" + solution + "/projects"), asAdmin())
                        .contentType(MediaType.APPLICATION_JSON).content(write(Map.of("name", name))))
                .andExpect(status().isCreated()));
    }

    private long repository(String url) {
        RepositoryEntity entity = new RepositoryEntity();
        entity.setUrl(url);
        entity.setName(url.substring(url.lastIndexOf('/') + 1));
        entity.setBranch("main");
        entity.setScanIntervalMinutes(1_440);
        return repositories.save(entity).getId();
    }

    private void file(long projectId, long repositoryId) throws Exception {
        mvc.perform(authenticated(put("/api/v1/projects/" + projectId + "/repositories/" + repositoryId), asAdmin()))
                .andExpect(status().isNoContent());
    }

    private JsonNode layOut() throws Exception {
        Map<String, Object> layout = new LinkedHashMap<>();
        layout.put("sheet", "Checklist");
        layout.put("columns", Map.of("domain", "A", "objective", "B", "control", "C", "contact", "D", "kpi", "E",
                "answer", "F", "comment", "G"));
        layout.put("firstItemRow", ChecklistWorkbooks.FIRST_ITEM_ROW);
        layout.put("lastItemRow", ChecklistWorkbooks.FIRST_ITEM_ROW + ChecklistWorkbooks.FIRST.size() - 1);
        layout.put("header", Map.of(
                "date", Map.of("label", "A2", "value", "B2"),
                "product", Map.of("label", "A3", "value", "B3"),
                "author", Map.of("label", "A4", "value", "B4")));
        layout.put("answers", Map.of("yes", "Done", "no", "Not done"));
        return read(mvc.perform(authenticated(put(TEMPLATES + "/release/versions/1/layout"), asAdmin())
                        .param("revision", "1").contentType(MediaType.APPLICATION_JSON).content(write(layout)))
                .andExpect(status().isOk()));
    }

    private org.springframework.test.web.servlet.ResultActions bind(JsonNode laid, Map<String, Object> rule)
            throws Exception {
        Map<String, Object> line = new LinkedHashMap<>();
        line.put("itemKey", laid.at("/items/0/itemKey").asText());
        line.put("rule", rule);
        return mvc.perform(authenticated(put(TEMPLATES + "/release/versions/1/rules"), asAdmin())
                .param("revision", String.valueOf(laid.at("/version/revision").asInt()))
                .contentType(MediaType.APPLICATION_JSON).content(write(Map.of("items", List.of(line)))));
    }

    private void publishWithRule(Map<String, Object> rule) throws Exception {
        mvc.perform(authenticated(post(TEMPLATES + "/release/versions"), asAdmin())
                        .contentType(MediaType.APPLICATION_OCTET_STREAM).content(ChecklistWorkbooks.of(ChecklistWorkbooks.FIRST)))
                .andExpect(status().isCreated());
        JsonNode bound = read(bind(layOut(), rule).andExpect(status().isOk()));
        mvc.perform(authenticated(post(TEMPLATES + "/release/versions/1/publish"), asAdmin())
                        .contentType(MediaType.APPLICATION_JSON)
                        .content("{\"revision\":" + bound.at("/version/revision").asInt() + "}"))
                .andExpect(status().isOk());
    }

    private void open(long projectId) throws Exception {
        Map<String, Object> body = new LinkedHashMap<>();
        body.put("template", "release");
        body.put("version", 1);
        body.put("edition", null);
        mvc.perform(authenticated(post("/api/v1/projects/" + projectId + "/checklists"), developer)
                        .contentType(MediaType.APPLICATION_JSON).content(write(body)))
                .andExpect(status().isCreated());
    }

    private long idOf(org.springframework.test.web.servlet.ResultActions result) throws Exception {
        return read(result).path("id").asLong();
    }

    private JsonNode read(org.springframework.test.web.servlet.ResultActions result) throws Exception {
        return json.readTree(result.andReturn().getResponse().getContentAsString());
    }
}
