package com.asmolabs.vectispire.core.api;

import static org.assertj.core.api.Assertions.assertThat;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.put;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

import com.asmolabs.vectispire.common.domain.access.VisibilityMode;
import com.asmolabs.vectispire.common.domain.settings.Setting;
import com.asmolabs.vectispire.common.domain.users.Role;
import com.asmolabs.vectispire.core.access.persistence.UserRepository;
import com.asmolabs.vectispire.core.reportplugins.persistence.ReportRunEntity;
import com.asmolabs.vectispire.core.reportplugins.persistence.ReportRunRepository;
import com.asmolabs.vectispire.core.settings.SettingsService;
import com.asmolabs.vectispire.core.targets.persistence.ContainerEntity;
import com.asmolabs.vectispire.core.targets.persistence.ContainerRepository;
import com.asmolabs.vectispire.core.targets.persistence.GitRepositoryRepository;
import com.asmolabs.vectispire.core.targets.persistence.RepositoryEntity;
import com.fasterxml.jackson.databind.JsonNode;
import java.time.Instant;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import java.util.stream.StreamSupport;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.MediaType;
import org.springframework.test.web.servlet.MvcResult;

/**
 * The inventory lists that page on request (0.11.1), through the real routes.
 *
 * <p><b>Asked nothing, each answers what 0.11.0 answered</b> — the whole list, as the same array — so a client
 * written against that release, the interface's own pickers included, does not move. Asked a page, it answers
 * the same array cut in pieces, the caller's visibility applied before the cut, and refuses a page it cannot
 * serve with a 400 rather than a quietly shorter one.
 */
@DisplayName("the lists that page on request")
class ListPagingRoutesTest extends ApiTestBase {

    @Autowired
    private GitRepositoryRepository repositories;

    @Autowired
    private ContainerRepository containers;

    @Autowired
    private ReportRunRepository runs;

    @Autowired
    private UserRepository users;

    @Autowired
    private SettingsService settings;

    @Test
    @DisplayName("repositories: asked nothing, every one; asked pages, the same list cut in pieces")
    void repositoriesPage() throws Exception {
        List<Long> filed = new ArrayList<>();
        for (int i = 0; i < 5; i++) {
            filed.add(repository("paged-" + i));
        }
        String admin = asAdmin();

        assertThat(ids(read("/api/v1/repositories", admin))).containsExactlyElementsOf(filed);
        assertThat(ids(read("/api/v1/repositories?limit=2", admin))).containsExactly(filed.get(0), filed.get(1));
        assertThat(ids(read("/api/v1/repositories?limit=2&offset=2", admin)))
                .containsExactly(filed.get(2), filed.get(3));
        assertThat(ids(read("/api/v1/repositories?limit=2&offset=4", admin))).containsExactly(filed.get(4));
        assertThat(ids(read("/api/v1/repositories?limit=2&offset=6", admin))).isEmpty();
    }

    @Test
    @DisplayName("repositories: a restricted reader's pages are cut from what they see, and hold nothing else")
    void repositoryPagesKeepTheVisibility() throws Exception {
        settings.set(Setting.TARGET_VISIBILITY, VisibilityMode.ASSIGNED.wireName());
        List<Long> filed = new ArrayList<>();
        for (int i = 0; i < 5; i++) {
            filed.add(repository("restricted-" + i));
        }
        String readerName = "pager-" + System.nanoTime();
        String reader = tokenFor(readerName, Role.USER, false);
        grant(idOf(readerName), List.of(filed.get(1), filed.get(3), filed.get(4)));

        // The second page starts at the reader's third repository, not at the estate's third row: counted over
        // the estate, it would have started among targets the reader cannot see and come back short.
        assertThat(ids(read("/api/v1/repositories?limit=2", reader))).containsExactly(filed.get(1), filed.get(3));
        assertThat(ids(read("/api/v1/repositories?limit=2&offset=2", reader))).containsExactly(filed.get(4));
        assertThat(ids(read("/api/v1/repositories", reader)))
                .containsExactly(filed.get(1), filed.get(3), filed.get(4));
    }

    @Test
    @DisplayName("repositories: a key restricted to one repository pages within it")
    void aRestrictedKeyPagesWithinItsTarget() throws Exception {
        long mine = repository("key-mine");
        repository("key-other");
        String key = json.readTree(mvc.perform(authenticated(post("/api/v1/api-keys"), asAdmin())
                                .contentType(MediaType.APPLICATION_JSON)
                                .content(write(Map.of("name", "ci", "scopes", List.of("read"),
                                        "target_kind", "repository", "target_id", mine))))
                        .andExpect(status().isOk())
                        .andReturn().getResponse().getContentAsString())
                .get("secret").asText();

        assertThat(ids(read("/api/v1/repositories?limit=1", key))).containsExactly(mine);
        assertThat(ids(read("/api/v1/repositories?limit=1&offset=1", key))).isEmpty();
    }

    @Test
    @DisplayName("containers: the same, visibility included")
    void containersPage() throws Exception {
        List<Long> filed = new ArrayList<>();
        for (int i = 0; i < 3; i++) {
            filed.add(container("paged-" + i));
        }
        String admin = asAdmin();
        assertThat(ids(read("/api/v1/containers", admin))).containsExactlyElementsOf(filed);
        assertThat(ids(read("/api/v1/containers?limit=2&offset=2", admin))).containsExactly(filed.get(2));

        settings.set(Setting.TARGET_VISIBILITY, VisibilityMode.ASSIGNED.wireName());
        String readerName = "pager-" + System.nanoTime();
        String reader = tokenFor(readerName, Role.USER, false);
        mvc.perform(authenticated(put("/api/v1/users/" + idOf(readerName) + "/targets"), admin)
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(write(List.of(Map.of("kind", "container", "id", filed.get(2))))))
                .andExpect(status().isOk());
        assertThat(ids(read("/api/v1/containers?limit=2", reader))).containsExactly(filed.get(2));
    }

    @Test
    @DisplayName("agents, teams and API keys: asked nothing, every one; asked pages, the same list cut")
    void administrationListsPage() throws Exception {
        String admin = asAdmin();
        for (String name : List.of("agent-c", "agent-a", "agent-b")) {
            mvc.perform(authenticated(post("/api/v1/admin/agents"), admin)
                            .contentType(MediaType.APPLICATION_JSON)
                            .content(write(Map.of("name", name))))
                    .andExpect(status().isOk());
        }
        for (String name : List.of("team-c", "team-a", "team-b")) {
            mvc.perform(authenticated(post("/api/v1/teams"), admin)
                            .contentType(MediaType.APPLICATION_JSON)
                            .content(write(Map.of("name", name + "-" + System.nanoTime()))))
                    .andExpect(status().isCreated());
        }
        for (String name : List.of("key-1", "key-2", "key-3")) {
            mvc.perform(authenticated(post("/api/v1/api-keys"), admin)
                            .contentType(MediaType.APPLICATION_JSON)
                            .content(write(Map.of("name", name, "scopes", List.of("read")))))
                    .andExpect(status().isOk());
        }

        for (String route : List.of("/api/v1/admin/agents", "/api/v1/teams", "/api/v1/api-keys")) {
            JsonNode every = read(route, admin);
            assertThat(every.isArray()).as(route).isTrue();
            List<String> whole = StreamSupport.stream(every.spliterator(), false)
                    .map(node -> node.path("id").asText()).toList();
            assertThat(whole).as(route).hasSizeGreaterThanOrEqualTo(3);
            List<String> paged = new ArrayList<>();
            for (int offset = 0; offset < whole.size() + 2; offset += 2) {
                JsonNode page = read(route + "?limit=2&offset=" + offset, admin);
                assertThat(page.size()).as(route + " page at " + offset).isLessThanOrEqualTo(2);
                page.forEach(node -> paged.add(node.path("id").asText()));
            }
            assertThat(paged).as(route).containsExactlyElementsOf(whole);
        }
        assertThat(names(read("/api/v1/admin/agents?limit=2", admin))).containsExactly("agent-a", "agent-b");
    }

    @Test
    @DisplayName("users: the listing keeps its shape, counts every account, and pages its users")
    void usersPage() throws Exception {
        String admin = asAdmin();
        tokenFor("pager-a-" + System.nanoTime(), Role.USER, false);
        tokenFor("pager-b-" + System.nanoTime(), Role.USER, false);
        long accounts = users.count();

        JsonNode every = read("/api/v1/users", admin);
        assertThat(every.path("users").size()).isEqualTo((int) accounts);
        assertThat(every.path("total").asLong()).isEqualTo(accounts);
        assertThat(every.path("currentUserId").isNumber()).isTrue();

        JsonNode first = read("/api/v1/users?limit=2", admin);
        assertThat(first.path("users").size()).isEqualTo(2);
        assertThat(first.path("total").asLong()).isEqualTo(accounts);
        assertThat(usernames(first)).containsExactlyElementsOf(usernames(every).subList(0, 2));
        assertThat(usernames(read("/api/v1/users?limit=2&offset=2", admin)))
                .containsExactlyElementsOf(usernames(every).subList(2, Math.min(4, (int) accounts)));
    }

    @Test
    @DisplayName("report runs: asked nothing, the latest 200; asked a page, older ones too; a hidden project 404s first")
    void reportRunsPage() throws Exception {
        String admin = asAdmin();
        long solution = idOf(mvc.perform(authenticated(post("/api/v1/solutions"), admin)
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(write(Map.of("name", "Paged " + System.nanoTime()))))
                .andExpect(status().isCreated()).andReturn());
        long project = idOf(mvc.perform(authenticated(post("/api/v1/solutions/" + solution + "/projects"), admin)
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(write(Map.of("name", "Paged"))))
                .andExpect(status().isCreated()).andReturn());
        String requesterName = "requester-" + System.nanoTime();
        tokenFor(requesterName, Role.ADMIN, false);
        long requester = idOf(requesterName);
        Instant start = Instant.parse("2026-10-01T00:00:00Z");
        List<Long> newestFirst = new ArrayList<>();
        for (int i = 0; i < 205; i++) {
            newestFirst.addFirst(run(project, requester, start.plusSeconds(i)));
        }
        String route = "/api/v1/projects/" + project + "/reports";

        assertThat(ids(read(route, admin))).containsExactlyElementsOf(newestFirst.subList(0, 200));
        assertThat(ids(read(route + "?limit=100&offset=200", admin)))
                .containsExactlyElementsOf(newestFirst.subList(200, 205));

        // The project's refusal comes before the parameters': a reader who sees nothing of it is told what an
        // absent project tells, whatever the window — never a 400 that would confirm it exists.
        settings.set(Setting.TARGET_VISIBILITY, VisibilityMode.ASSIGNED.wireName());
        String reader = tokenFor("pager-" + System.nanoTime(), Role.USER, false);
        MvcResult hidden = mvc.perform(authenticated(get(route + "?limit=9999"), reader))
                .andExpect(status().isNotFound()).andReturn();
        MvcResult absent = mvc.perform(authenticated(get("/api/v1/projects/987654321/reports?limit=9999"), reader))
                .andExpect(status().isNotFound()).andReturn();
        assertThat(detailOf(hidden)).isEqualTo(detailOf(absent));
    }

    @Test
    @DisplayName("refuses a page it cannot serve with a 400 that says why, on every route")
    void refusesWhatItCannotServe() throws Exception {
        String admin = asAdmin();
        long solution = idOf(mvc.perform(authenticated(post("/api/v1/solutions"), admin)
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(write(Map.of("name", "Bounds " + System.nanoTime()))))
                .andExpect(status().isCreated()).andReturn());
        long project = idOf(mvc.perform(authenticated(post("/api/v1/solutions/" + solution + "/projects"), admin)
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(write(Map.of("name", "Bounds"))))
                .andExpect(status().isCreated()).andReturn());

        for (String route : List.of("/api/v1/repositories", "/api/v1/containers", "/api/v1/admin/agents",
                "/api/v1/users", "/api/v1/teams", "/api/v1/api-keys", "/api/v1/projects/" + project + "/reports")) {
            assertThat(refusal(route + "?limit=501", admin)).as(route).isEqualTo("The limit is between 1 and 500.");
            assertThat(refusal(route + "?limit=0", admin)).as(route).isEqualTo("The limit is between 1 and 500.");
            assertThat(refusal(route + "?limit=10&offset=5", admin)).as(route)
                    .isEqualTo("The offset is zero or a multiple of the limit.");
            assertThat(refusal(route + "?limit=10&offset=-10", admin)).as(route)
                    .isEqualTo("The offset is zero or a multiple of the limit.");
            assertThat(refusal(route + "?offset=10", admin)).as(route).contains("with a limit");
            mvc.perform(authenticated(get(route + "?limit=500"), admin)).andExpect(status().isOk());
        }
    }

    private String refusal(String route, String token) throws Exception {
        return detailOf(mvc.perform(authenticated(get(route), token)).andExpect(status().isBadRequest()).andReturn());
    }

    private JsonNode read(String route, String token) throws Exception {
        return json.readTree(mvc.perform(authenticated(get(route), token))
                .andExpect(status().isOk())
                .andReturn().getResponse().getContentAsString());
    }

    private static List<Long> ids(JsonNode array) {
        assertThat(array.isArray()).as("still an array").isTrue();
        return StreamSupport.stream(array.spliterator(), false).map(node -> node.path("id").asLong()).toList();
    }

    private static List<String> names(JsonNode array) {
        return StreamSupport.stream(array.spliterator(), false).map(node -> node.path("name").asText()).toList();
    }

    private static List<String> usernames(JsonNode listing) {
        return StreamSupport.stream(listing.path("users").spliterator(), false)
                .map(node -> node.path("username").asText()).toList();
    }

    private long idOf(MvcResult result) throws Exception {
        return json.readTree(result.getResponse().getContentAsString()).path("id").asLong();
    }

    private long idOf(String username) {
        return users.findByUsername(username).orElseThrow().getId();
    }

    private void grant(long accountId, List<Long> repositoryIds) throws Exception {
        mvc.perform(authenticated(put("/api/v1/users/" + accountId + "/targets"), asAdmin())
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(write(repositoryIds.stream()
                                .map(id -> Map.of("kind", "repository", "id", id))
                                .toList())))
                .andExpect(status().isOk());
    }

    private long repository(String name) {
        RepositoryEntity repository = new RepositoryEntity();
        repository.setUrl("https://example.invalid/" + name + "-" + System.nanoTime() + ".git");
        repository.setBranch("main");
        return repositories.save(repository).getId();
    }

    private long container(String name) {
        ContainerEntity container = new ContainerEntity();
        container.setImageName("registry.example.invalid/" + name);
        container.setTag("1.0.0");
        return containers.save(container).getId();
    }

    private long run(long projectId, long requesterId, Instant requestedAt) {
        ReportRunEntity run = new ReportRunEntity();
        run.setProjectId(projectId);
        run.setProjectName("Paged");
        run.setPluginId("summary");
        run.setState("failed");
        run.setRequestedAt(requestedAt);
        run.setRequestedBy("admin");
        run.setRequestedById(requesterId);
        return runs.save(run).getId();
    }
}
