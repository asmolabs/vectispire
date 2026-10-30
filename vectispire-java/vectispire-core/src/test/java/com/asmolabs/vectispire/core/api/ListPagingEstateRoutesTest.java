package com.asmolabs.vectispire.core.api;

import static org.assertj.core.api.Assertions.assertThat;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.put;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

import com.asmolabs.vectispire.common.domain.access.VisibilityMode;
import com.asmolabs.vectispire.common.domain.crypto.SecretCipher;
import com.asmolabs.vectispire.common.domain.forges.DiscoveryState;
import com.asmolabs.vectispire.common.domain.issues.FindingType;
import com.asmolabs.vectispire.common.domain.issues.IssueState;
import com.asmolabs.vectispire.common.domain.issues.Severity;
import com.asmolabs.vectispire.common.domain.issues.TriageStatus;
import com.asmolabs.vectispire.common.domain.settings.Setting;
import com.asmolabs.vectispire.common.domain.users.Role;
import com.asmolabs.vectispire.core.access.persistence.UserRepository;
import com.asmolabs.vectispire.core.crypto.EncryptionService;
import com.asmolabs.vectispire.core.forges.persistence.ForgeConnectionEntity;
import com.asmolabs.vectispire.core.forges.persistence.ForgeConnectionRepository;
import com.asmolabs.vectispire.core.forges.persistence.ForgeDiscoveryEntity;
import com.asmolabs.vectispire.core.forges.persistence.ForgeDiscoveryRepository;
import com.asmolabs.vectispire.core.issues.persistence.IssueEntity;
import com.asmolabs.vectispire.core.issues.persistence.IssueRepository;
import com.asmolabs.vectispire.core.settings.SettingsService;
import com.asmolabs.vectispire.core.targets.persistence.GitRepositoryRepository;
import com.asmolabs.vectispire.core.targets.persistence.ProjectEntity;
import com.asmolabs.vectispire.core.targets.persistence.ProjectRepository;
import com.asmolabs.vectispire.core.targets.persistence.RepositoryEntity;
import com.asmolabs.vectispire.core.targets.persistence.SolutionEntity;
import com.asmolabs.vectispire.core.targets.persistence.SolutionRepository;
import com.fasterxml.jackson.databind.JsonNode;
import java.time.Instant;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import java.util.UUID;
import java.util.stream.StreamSupport;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.MediaType;
import org.springframework.test.web.servlet.request.MockHttpServletRequestBuilder;

/**
 * The lists that page on request since 1.0 froze {@code /api/v1}: a team's members and targets, an account's
 * targets, the Git tokens and SSH keys, the duplicated targets, an issue's tickets, the plugin catalogue and its
 * activations, the SARIF sources, the report plugins and a project's activations of them, the forge connections
 * and their discoveries, the checklist templates, a project's checklist revisions and contact candidates, and a
 * repository's SARIF, coverage, test-report and build-SBOM imports.
 *
 * <p>The contract of {@link ListPagingRoutesTest}: asked nothing, each answers what it answered — the whole list,
 * or the latest fifty of a history that was capped — and asked a page, that list cut from what the caller sees,
 * a page it cannot serve refused with a 400 that says why. After 1.0 a route may only grow: a default page smaller
 * than the list could never be introduced later, so none is.
 */
@DisplayName("the estate's lists that page on request")
class ListPagingEstateRoutesTest extends ApiTestBase {

    private static final Instant START = Instant.parse("2026-10-01T00:00:00Z");

    @Autowired
    private GitRepositoryRepository repositories;

    @Autowired
    private SolutionRepository solutions;

    @Autowired
    private ProjectRepository projects;

    @Autowired
    private IssueRepository issues;

    @Autowired
    private ForgeDiscoveryRepository discoveries;

    @Autowired
    private ForgeConnectionRepository connections;

    @Autowired
    private EncryptionService encryption;

    @Autowired
    private UserRepository users;

    @Autowired
    private SettingsService settings;

    @Test
    @DisplayName("refuses a page it cannot serve with a 400 that says why, on every route, and serves the largest")
    void refusesWhatItCannotServe() throws Exception {
        String governor = governor();
        long project = project();
        long repository = repository("refusals");
        long team = team();
        String connection = connection();
        String plugin = plugin(governor);
        String admin = asAdmin();
        List<String> routes = List.of(
                "/api/v1/teams/" + team + "/members",
                "/api/v1/teams/" + team + "/targets",
                "/api/v1/users/" + accountOf("refused-" + System.nanoTime()) + "/targets",
                "/api/v1/git-tokens",
                "/api/v1/ssh-keys",
                "/api/v1/repositories/duplicates",
                "/api/v1/issues/" + issue(repository) + "/tickets",
                "/api/v1/plugins",
                "/api/v1/plugins/" + plugin + "/projects",
                "/api/v1/projects/" + project + "/plugins",
                "/api/v1/sarif-sources",
                "/api/v1/report-plugins",
                "/api/v1/projects/" + project + "/report-plugins",
                "/api/v1/forge-connections",
                "/api/v1/forge-connections/" + connection + "/discoveries",
                "/api/v1/checklist-templates",
                "/api/v1/projects/" + project + "/checklists",
                "/api/v1/projects/" + project + "/checklists/contacts/candidates",
                "/api/v1/repositories/" + repository + "/sarif-imports",
                "/api/v1/repositories/" + repository + "/coverage-imports",
                "/api/v1/repositories/" + repository + "/test-report-imports",
                "/api/v1/repositories/" + repository + "/build-sbom-imports");

        for (String route : routes) {
            assertThat(refusal(route + "?limit=501", admin)).as(route).isEqualTo("The limit is between 1 and 500.");
            assertThat(refusal(route + "?limit=0", admin)).as(route).isEqualTo("The limit is between 1 and 500.");
            assertThat(refusal(route + "?limit=10&offset=5", admin)).as(route)
                    .isEqualTo("The offset is zero or a multiple of the limit.");
            assertThat(refusal(route + "?offset=10", admin)).as(route).contains("with a limit");
            read(route + "?limit=500", admin);
            read(route, admin);
        }
    }

    @Test
    @DisplayName("a team's members and targets, an account's targets: the pages are the list cut, by id and by kind")
    void grantsPage() throws Exception {
        String admin = asAdmin();
        long team = team();
        List<Long> members = new ArrayList<>();
        for (int i = 0; i < 5; i++) {
            members.add(accountOf("member-" + i + "-" + System.nanoTime()));
        }
        List<Long> granted = new ArrayList<>();
        for (int i = 0; i < 5; i++) {
            granted.add(repository("granted-" + i));
        }
        List<Map<String, Object>> grants = granted.reversed().stream()
                .map(id -> Map.<String, Object>of("kind", "repository", "id", id))
                .toList();
        send(put("/api/v1/teams/" + team + "/members"), admin, members.reversed());
        send(put("/api/v1/teams/" + team + "/targets"), admin, grants);
        long account = accountOf("grantee-" + System.nanoTime());
        send(put("/api/v1/users/" + account + "/targets"), admin, grants);

        String membersRoute = "/api/v1/teams/" + team + "/members";
        assertThat(longs(read(membersRoute, admin))).containsExactlyElementsOf(members);
        assertThat(pages(membersRoute, admin, 2)).isEqualTo(rows(read(membersRoute, admin)));
        assertThat(longs(read(membersRoute + "?limit=2&offset=4", admin))).containsExactly(members.get(4));

        for (String route : List.of("/api/v1/teams/" + team + "/targets", "/api/v1/users/" + account + "/targets")) {
            List<JsonNode> every = rows(read(route, admin));
            assertThat(longs(read(route, admin), "id")).as(route).containsExactlyElementsOf(granted);
            assertThat(pages(route, admin, 2)).as(route).isEqualTo(every);
        }
    }

    @Test
    @DisplayName("Git tokens, an issue's tickets, forge connections: the pages are the list cut")
    void inventoriesPage() throws Exception {
        String admin = asAdmin();
        for (int i = 0; i < 3; i++) {
            send(post("/api/v1/git-tokens"), admin, Map.of(
                    "name", "token-" + i, "host", "git" + i + ".example.invalid", "token", "planted-" + i));
            connection();
        }
        long issue = issue(repository("ticketed"));
        for (int i = 0; i < 5; i++) {
            send(post("/api/v1/issues/" + issue + "/tickets"), admin, Map.of(
                    "provider", "jira", "ticketKey", "SEC-" + i, "ticketUrl", "https://jira.example.invalid/browse/SEC-" + i));
        }

        for (String route : List.of("/api/v1/git-tokens", "/api/v1/issues/" + issue + "/tickets", "/api/v1/forge-connections")) {
            List<JsonNode> every = rows(read(route, admin));
            assertThat(every.size()).as(route).isGreaterThanOrEqualTo(3);
            assertThat(pages(route, admin, 2)).as(route).isEqualTo(every);
        }
        // Linked in the same instant or not, they are in one order: newest first, the later id among equals.
        assertThat(rows(read("/api/v1/issues/" + issue + "/tickets", admin)))
                .extracting(ticket -> ticket.path("ticketKey").asText())
                .containsExactly("SEC-4", "SEC-3", "SEC-2", "SEC-1", "SEC-0");
    }

    @Test
    @DisplayName("a history that answered its latest fifty still does, and a page reaches the older ones")
    void aCappedHistoryPagesPastItsCap() throws Exception {
        String admin = asAdmin();
        String connection = connection();
        List<Long> newestFirst = new ArrayList<>();
        for (int i = 0; i < 53; i++) {
            ForgeDiscoveryEntity run = new ForgeDiscoveryEntity();
            run.setConnectionId(UUID.fromString(connection));
            run.setState(DiscoveryState.COMPLETED.wireName());
            // Two runs per instant: the identifier decides between them, newest first.
            run.setRequestedAt(START.plusSeconds(i / 2));
            run.setRequestedBy("admin");
            newestFirst.addFirst(discoveries.save(run).getId());
        }
        String route = "/api/v1/forge-connections/" + connection + "/discoveries";

        assertThat(longs(read(route, admin), "id")).containsExactlyElementsOf(newestFirst.subList(0, 50));
        assertThat(longs(read(route + "?limit=50&offset=50", admin), "id"))
                .containsExactlyElementsOf(newestFirst.subList(50, 53));
        assertThat(pages(route, admin, 10)).extracting(run -> run.path("id").asLong())
                .containsExactlyElementsOf(newestFirst);
    }

    @Test
    @DisplayName("a target the caller cannot see is the 404 an absent one is, whatever the window")
    void aHiddenParentIsRefusedBeforeTheWindow() throws Exception {
        long hidden = repository("hidden");
        long hiddenIssue = issue(hidden);
        settings.set(Setting.TARGET_VISIBILITY, VisibilityMode.ASSIGNED.wireName());
        String reader = tokenFor("pager-" + System.nanoTime(), Role.USER, false);
        for (String suffix : List.of("/sarif-imports", "/coverage-imports", "/test-report-imports", "/build-sbom-imports")) {
            String seen = detailOf(mvc.perform(authenticated(
                            get("/api/v1/repositories/" + hidden + suffix + "?limit=9999"), reader))
                    .andExpect(status().isNotFound()).andReturn());
            String absent = detailOf(mvc.perform(authenticated(
                            get("/api/v1/repositories/987654321" + suffix + "?limit=9999"), reader))
                    .andExpect(status().isNotFound()).andReturn());
            // Each names the identifier it was asked; nothing else tells them apart.
            assertThat(seen.replace(String.valueOf(hidden), "N")).as(suffix).isEqualTo(absent.replace("987654321", "N"));
        }
        mvc.perform(authenticated(get("/api/v1/issues/" + hiddenIssue + "/tickets?limit=9999"), reader))
                .andExpect(status().isNotFound());
    }

    // --- helpers ------------------------------------------------------------------------------------------

    private List<JsonNode> pages(String route, String token, int limit) throws Exception {
        List<JsonNode> paged = new ArrayList<>();
        for (int offset = 0; ; offset += limit) {
            List<JsonNode> page = rows(read(route + "?limit=" + limit + "&offset=" + offset, token));
            assertThat(page.size()).isLessThanOrEqualTo(limit);
            paged.addAll(page);
            if (page.size() < limit) {
                return paged;
            }
        }
    }

    private String refusal(String route, String token) throws Exception {
        return detailOf(mvc.perform(authenticated(get(route), token)).andExpect(status().isBadRequest()).andReturn());
    }

    private JsonNode read(String route, String token) throws Exception {
        JsonNode body = json.readTree(mvc.perform(authenticated(get(route), token))
                .andExpect(status().isOk())
                .andReturn().getResponse().getContentAsString());
        assertThat(body.isArray()).as(route + " still an array").isTrue();
        return body;
    }

    private JsonNode send(MockHttpServletRequestBuilder request, String token, Object body) throws Exception {
        String answer = mvc.perform(authenticated(request, token)
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(write(body)))
                .andExpect(status().is2xxSuccessful())
                .andReturn().getResponse().getContentAsString();
        return answer.isEmpty() ? json.nullNode() : json.readTree(answer);
    }

    private static List<JsonNode> rows(JsonNode array) {
        return StreamSupport.stream(array.spliterator(), false).toList();
    }

    private static List<Long> longs(JsonNode array) {
        return rows(array).stream().map(JsonNode::asLong).toList();
    }

    private static List<Long> longs(JsonNode array, String field) {
        return rows(array).stream().map(node -> node.path(field).asLong()).toList();
    }

    private String governor() {
        return tokenFor("governor-" + System.nanoTime(), Role.SUPERUSER, false);
    }

    /** An account of that name, signed in once so that it exists. */
    private long accountOf(String username) {
        tokenFor(username, Role.USER, false);
        return users.findByUsername(username).orElseThrow().getId();
    }

    private long team() throws Exception {
        return send(post("/api/v1/teams"), asAdmin(), Map.of("name", "team-" + System.nanoTime())).path("id").asLong();
    }

    /** A connection as the route keeps one once probed: the route itself would probe a forge this suite has not. */
    private String connection() {
        Instant now = Instant.now();
        UUID id = UUID.randomUUID();
        ForgeConnectionEntity entity = new ForgeConnectionEntity();
        entity.setId(id);
        entity.setName("forge-" + System.nanoTime());
        entity.setKind("gitlab");
        entity.setEdition("gitlab_self_managed");
        entity.setBaseUrl("https://gitlab.example.invalid");
        entity.setInternalNetwork(false);
        // Invented, as every token of this suite.
        entity.setToken(encryption.encrypt("planted-forge-token", SecretCipher.forgeConnectionContext(id.toString())));
        entity.setCredentialKind("gitlab_bot");
        entity.setProbedAt(now);
        entity.setCreatedAt(now);
        entity.setCreatedBy("admin");
        entity.setUpdatedAt(now);
        entity.setUpdatedBy("admin");
        return connections.save(entity).getId().toString();
    }

    private String plugin(String governor) throws Exception {
        String id = "pager-" + System.nanoTime();
        send(post("/api/v1/plugins"), governor, PluginsRoutesTest.manifest(id, PluginsRoutesTest.DIGEST));
        return id;
    }

    private long project() {
        SolutionEntity solution = new SolutionEntity();
        solution.setName("solution-" + System.nanoTime());
        solution.setCreatedAt(Instant.now());
        ProjectEntity project = new ProjectEntity();
        project.setSolutionId(solutions.save(solution).getId());
        project.setName("project-" + System.nanoTime());
        project.setCreatedAt(Instant.now());
        return projects.save(project).getId();
    }

    private long repository(String name) {
        RepositoryEntity repository = new RepositoryEntity();
        repository.setName(name);
        repository.setUrl("https://example.invalid/" + name + "-" + System.nanoTime() + ".git");
        repository.setBranch("main");
        return repositories.save(repository).getId();
    }

    private long issue(long repositoryId) {
        IssueEntity issue = new IssueEntity();
        issue.setRepoId(repositoryId);
        issue.setFingerprint("fp-pager-" + System.nanoTime());
        issue.setType(FindingType.VULNERABILITY.wireName());
        issue.setIdentifier("CVE-2026-0001");
        issue.setSeverity(Severity.HIGH.wireName());
        issue.setState(IssueState.OPEN.wireName());
        issue.setTriageStatus(TriageStatus.UNDER_REVIEW.wireName());
        issue.setFirstSeenAt(START);
        issue.setLastSeenAt(START);
        issue.setTimesSeen(1);
        return issues.save(issue).getId();
    }
}
