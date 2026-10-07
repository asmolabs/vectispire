package com.asmolabs.vectispire.core.api;

import static org.assertj.core.api.Assertions.assertThat;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

import com.asmolabs.vectispire.common.domain.forges.ForgeKind;
import com.asmolabs.vectispire.common.domain.integrations.Integration;
import com.asmolabs.vectispire.core.forges.ForgeStub;
import com.asmolabs.vectispire.core.forges.ForgeStub.Reply;
import com.asmolabs.vectispire.core.forges.internal.DiscoveryWorker;
import com.asmolabs.vectispire.core.forges.persistence.ForgeImportLinkRepository;
import com.asmolabs.vectispire.core.forges.persistence.ForgeRepositoryEntity;
import com.asmolabs.vectispire.core.forges.persistence.ForgeRepositoryRepository;
import com.asmolabs.vectispire.core.settings.Integrations;
import com.asmolabs.vectispire.core.targets.persistence.GitRepositoryRepository;
import com.asmolabs.vectispire.core.targets.persistence.RepositoryEntity;
import com.fasterxml.jackson.databind.JsonNode;
import java.util.HashMap;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.stream.StreamSupport;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.MediaType;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.test.web.servlet.ResultActions;

/**
 * Discovering a GitHub Enterprise Server's repositories over HTTP and importing them (decision 0037 §3–5, lot D4),
 * against a server on loopback behind a private CA answering as GitHub answers: its API at {@code /api/v3} under the
 * web address, pages by {@code Link}, one listing per organisation, a 403 with {@code X-GitHub-SSO} for an
 * organisation enforcing single sign-on. The discovery is the real one — requested by the route, carried out by
 * {@link DiscoveryWorker#drain} through the real door — and what is selected, previewed and imported is what GitHub's
 * listing wrote into the snapshot. The clouds, whose hosts a test cannot stand up, are {@code GitHubListerTest}'s.
 */
@DisplayName("forge discoveries: GitHub")
class ForgeGitHubRoutesTest extends ApiTestBase {

    /** A classic token: GitHub Enterprise Server may offer no fine-grained ones (answer 2). */
    static final String CLASSIC = "ghp_Discovery000000000000000000000001"; // gitleaks:allow
    static final String FINE_GRAINED = "github_pat_11DISCOVERY000000000000_github"; // gitleaks:allow
    static final String API = "/api/v3";
    static final String ORGS = API + "/user/orgs?per_page=100";
    static final String USER_REPOS = API + "/user/repos?affiliation=owner&visibility=all&sort=full_name&per_page=100";

    @Autowired
    private DiscoveryWorker worker;

    @Autowired
    private ForgeRepositoryRepository snapshot;

    @Autowired
    private ForgeImportLinkRepository links;

    @Autowired
    private GitRepositoryRepository repositories;

    @Autowired
    private Integrations integrations;

    @Autowired
    private JdbcTemplate jdbc;

    private ForgeStub github;

    @BeforeEach
    void start() throws Exception {
        github = ForgeStub.start();
    }

    @AfterEach
    void stop() {
        github.close();
    }

    // ---- The forge's answers.

    static String repository(long id, String fullName, String visibility, boolean fork, boolean archived) {
        String owner = fullName.substring(0, fullName.indexOf('/'));
        return "{\"id\":" + id + ",\"name\":\"" + fullName.substring(fullName.indexOf('/') + 1) + "\",\"full_name\":\""
                + fullName + "\",\"owner\":{\"login\":\"" + owner + "\"},\"private\":" + !"public".equals(visibility)
                + ",\"visibility\":\"" + visibility + "\",\"fork\":" + fork + ",\"archived\":" + archived
                + ",\"default_branch\":\"main\",\"pushed_at\":\"2026-09-20T10:00:00Z\",\"language\":\"Go\",\"size\":4,"
                + "\"clone_url\":\"https://git.example.org/" + fullName + ".git\",\"ssh_url\":\"git@git.example.org:"
                + fullName + ".git\",\"html_url\":\"https://git.example.org/" + fullName + "\"}";
    }

    private static String orgRepos(String org) {
        return API + "/orgs/" + org + "/repos?type=all&sort=full_name&per_page=100";
    }

    private static Reply list(String... repositories) {
        return Reply.json("[" + String.join(",", repositories) + "]");
    }

    /** The server's own answers: the probe's owner, the token's user — its scopes stated when it is classic. */
    private void server(String token) {
        Reply owner = Reply.json("{\"login\":\"acme\",\"type\":\"Organization\"}")
                .with("X-GitHub-Enterprise-Version", "3.14.2");
        Reply user = Reply.json("{\"login\":\"ada\",\"type\":\"User\"}").with("X-GitHub-Enterprise-Version", "3.14.2");
        if (token.equals(CLASSIC)) {
            owner = owner.with("X-OAuth-Scopes", "repo, read:org");
            user = user.with("X-OAuth-Scopes", "repo, read:org");
        }
        github.route(API + "/users/acme", owner);
        github.route(API + "/user", user);
    }

    // ---- The routes.

    private String connection(String token) throws Exception {
        server(token);
        Map<String, Object> body = new HashMap<>();
        body.put("name", "Internal GitHub " + System.nanoTime());
        body.put("kind", "github");
        body.put("baseUrl", github.baseUrl());
        body.put("owner", "acme");
        body.put("internalNetwork", true);
        body.put("caPem", github.caPem);
        body.put("token", token);
        String created = mvc.perform(authenticated(post("/api/v1/forge-connections"), asAdmin())
                        .contentType(MediaType.APPLICATION_JSON).content(write(body)))
                .andExpect(status().isCreated()).andReturn().getResponse().getContentAsString();
        return json.readTree(created).at("/id").asText();
    }

    private JsonNode read(String url) throws Exception {
        return json.readTree(mvc.perform(authenticated(get(url), asAdmin())).andExpect(status().isOk())
                .andReturn().getResponse().getContentAsString());
    }

    private JsonNode discover(String connectionId) throws Exception {
        JsonNode queued = json.readTree(mvc.perform(authenticated(
                        post("/api/v1/forge-connections/" + connectionId + "/discoveries"), asAdmin()))
                .andExpect(status().isAccepted()).andReturn().getResponse().getContentAsString());
        assertThat(worker.drain()).isOne();
        return read("/api/v1/forge-connections/" + connectionId + "/discoveries/" + queued.at("/id").asLong());
    }

    private List<String> changed(String connectionId, JsonNode run, String change) throws Exception {
        JsonNode page = read("/api/v1/forge-connections/" + connectionId + "/discoveries/" + run.at("/id").asLong()
                + "/repositories?change=" + change);
        return StreamSupport.stream(page.at("/items").spliterator(), false).map(item -> item.at("/forgeId").asText())
                .toList();
    }

    private ForgeRepositoryEntity row(String forgeId) {
        return snapshot.findAll().stream().filter(row -> row.getForgeId().equals(forgeId)).findFirst().orElseThrow();
    }

    private ResultActions postJson(String url, Object body) throws Exception {
        return mvc.perform(authenticated(post(url), asAdmin()).contentType(MediaType.APPLICATION_JSON).content(write(body)));
    }

    private JsonNode ok(ResultActions result) throws Exception {
        return json.readTree(result.andExpect(status().isOk()).andReturn().getResponse().getContentAsString());
    }

    private static JsonNode byForgeId(JsonNode array, String forgeId) {
        return StreamSupport.stream(array.spliterator(), false)
                .filter(node -> forgeId.equals(node.has("repository") ? node.at("/repository/forgeId").asText()
                        : node.at("/forgeId").asText()))
                .findFirst().orElseThrow(() -> new AssertionError("no " + forgeId + " in " + array));
    }

    // ---- What a discovery does.

    @Test
    @DisplayName("forge.gitlab disabled: a GitHub connection is made, reads active and discovers — the switch is per forge")
    void anotherForgeSwitchedOff() throws Exception {
        IntegrationRows rows = IntegrationRows.remember(jdbc);
        try {
            integrations.switchTo(Integration.of(ForgeKind.GITLAB), false, "test");
            String connectionId = connection(FINE_GRAINED);
            assertThat(read("/api/v1/forge-connections/" + connectionId).at("/state").asText()).isEqualTo("active");
            assertThat(read("/api/v1/forge-connections/" + connectionId).at("/integration").asText())
                    .isEqualTo("forge.github");
            github.route(ORGS, Reply.json("[{\"login\":\"acme\"}]"));
            github.route(orgRepos("acme"), list(repository(101, "acme/api", "private", false, false)));
            github.route(USER_REPOS, list());

            assertThat(discover(connectionId).at("/state").asText()).isEqualTo("completed");
        } finally {
            rows.putBack();
        }
    }

    @Test
    @DisplayName("a classic token: every organisation, the user's own flagged personal, at /api/v3, page by page")
    void aClassicTokenOnEnterpriseServer() throws Exception {
        String connectionId = connection(CLASSIC);
        github.route(ORGS, Reply.json("[{\"login\":\"acme\"},{\"login\":\"globex\"}]"));
        github.route(orgRepos("acme"), list(repository(101, "acme/api", "private", false, false),
                repository(102, "acme/portal", "internal", false, false))
                .with("Link", "<" + github.baseUrl() + API + "/organizations/1/repos?page=2>; rel=\"next\""));
        github.route(API + "/organizations/1/repos?page=2", list(repository(103, "acme/legacy", "private", false, true)));
        github.route(orgRepos("globex"), list(repository(201, "globex/core", "private", true, false)));
        github.route(USER_REPOS, list(repository(401, "ada/dotfiles", "public", false, false)));
        github.seen.clear();

        JsonNode run = discover(connectionId);

        assertThat(run.at("/state").asText()).isEqualTo("completed");
        assertThat(run.at("/namespacesSeen").asInt()).as("acme, globex and ada's own").isEqualTo(3);
        assertThat(run.at("/repositoriesSeen").asInt()).isEqualTo(5);
        assertThat(run.at("/requestsMade").asInt()).as("the user, the organisations, three pages, the user's own")
                .isEqualTo(6);
        assertThat(run.at("/unreadableNamespaces")).isEmpty();
        assertThat(run.at("/detail").isNull()).isTrue();
        assertThat(github.seen).allSatisfy(seen -> {
            assertThat(seen.path()).startsWith(API + "/");
            assertThat(seen.headers()).containsEntry("authorization", "Bearer " + CLASSIC)
                    .containsEntry("x-github-api-version", "2022-11-28");
        });
        assertThat(row("102").getVisibility()).isEqualTo("internal");
        assertThat(row("103").getArchived()).isTrue();
        assertThat(row("201").getFork()).isTrue();
        assertThat(row("101").getLanguage()).as("the listing's own, no request per repository").isEqualTo("Go");
        assertThat(row("101").getSizeBytes()).isEqualTo(4096);
        assertThat(row("401").getPersonal()).isTrue();
        assertThat(row("401").getNamespacePath()).isEqualTo("ada");
        assertThat(row("101").getPersonal()).isFalse();
    }

    @Test
    @DisplayName("an organisation behind single sign-on is unreadable, not the run failed — and its repositories are not gone")
    void thePerOrganisationRefusal() throws Exception {
        String connectionId = connection(CLASSIC);
        github.route(ORGS, Reply.json("[{\"login\":\"acme\"},{\"login\":\"secure\"}]"));
        github.route(orgRepos("acme"), list(repository(101, "acme/api", "private", false, false),
                repository(102, "acme/retired", "private", false, false)));
        github.route(orgRepos("secure"), list(repository(301, "secure/vault", "private", false, false)));
        github.route(USER_REPOS, list(repository(401, "ada/dotfiles", "public", false, false)));
        assertThat(discover(connectionId).at("/state").asText()).isEqualTo("completed");

        // The organisation now enforces single sign-on; acme/retired is deleted on the forge.
        github.route(orgRepos("acme"), list(repository(101, "acme/api", "private", false, false)));
        github.route(orgRepos("secure"), Reply.status(403)
                .with("X-GitHub-SSO", "required; url=https://git.example.org/orgs/secure/sso?authorization_request=A1")
                .with("X-RateLimit-Remaining", "4987"));
        JsonNode second = discover(connectionId);

        assertThat(second.at("/state").asText()).isEqualTo("completed");
        assertThat(second.at("/reason").isNull()).isTrue();
        assertThat(second.at("/unreadableNamespaces")).singleElement().satisfies(unreadable -> {
            assertThat(unreadable.at("/path").asText()).isEqualTo("secure");
            assertThat(unreadable.at("/reason").asText()).contains("SAML single sign-on").contains("authorise the token")
                    .doesNotContain("authorization_request");
        });
        assertThat(second.at("/detail").asText()).contains("1 namespace could not be read").contains("secure");
        assertThat(second.at("/goneCount").asInt()).as("acme/retired alone: secure/vault was refused, not absent")
                .isOne();
        assertThat(changed(connectionId, second, "gone")).containsExactly("102");
        assertThat(row("301").getGoneBy()).isNull();
        assertThat(row("401").getGoneBy()).isNull();

        // Single sign-on now filters the organisations unnamed: nothing outside what was read is marked gone.
        github.route(ORGS, Reply.json("[{\"login\":\"acme\"}]").with("X-GitHub-SSO", "partial-results; organizations=77"));
        github.route(USER_REPOS, list());
        JsonNode third = discover(connectionId);

        assertThat(third.at("/state").asText()).isEqualTo("completed");
        assertThat(third.at("/unreadableNamespaces")).singleElement().satisfies(withheld -> {
            assertThat(withheld.at("/path").isNull()).isTrue();
            assertThat(withheld.at("/reason").asText()).contains("id 77").contains("single sign-on");
        });
        assertThat(changed(connectionId, third, "gone")).as("ada's own was read, and is empty; secure was not named")
                .containsExactly("401");
        assertThat(row("301").getGoneBy()).isNull();
    }

    @Test
    @DisplayName("rate limits: GitHub's secondary limit and a primary one that resets within the minute are waited out")
    void rateLimits() throws Exception {
        String connectionId = connection(FINE_GRAINED);
        github.sequence(orgRepos("acme"), Reply.status(403).with("Retry-After", "1"),
                Reply.status(403).with("X-RateLimit-Remaining", "0")
                        .with("X-RateLimit-Reset", String.valueOf(java.time.Instant.now().getEpochSecond() + 1)));
        github.route(orgRepos("acme"), list(repository(101, "acme/api", "private", false, false)));

        JsonNode run = discover(connectionId);

        assertThat(run.at("/state").asText()).isEqualTo("completed");
        assertThat(run.at("/rateLimitWaitSeconds").asLong()).isGreaterThanOrEqualTo(2);
        assertThat(run.at("/unreadableNamespaces")).as("a limit is not a refusal").isEmpty();
        assertThat(github.count(ORGS)).as("a fine-grained token has one owner: no list of organisations").isZero();
        assertThat(github.count(USER_REPOS)).as("nor the user's own, when the owner is an organisation").isZero();

        github.route(orgRepos("acme"), Reply.status(429).with("X-RateLimit-Remaining", "0")
                .with("X-RateLimit-Reset", String.valueOf(java.time.Instant.now().getEpochSecond() + 3600)));
        JsonNode limited = discover(connectionId);
        assertThat(limited.at("/state").asText()).isEqualTo("partial");
        assertThat(limited.at("/reason").asText()).isEqualTo("rate_limited");
    }

    // ---- From discovery to import.

    @Test
    @DisplayName("discovered, selected, previewed and imported: the organisation a solution, each repository its project")
    void fromDiscoveryToImport() throws Exception {
        String connectionId = connection(CLASSIC);
        github.route(ORGS, Reply.json("[{\"login\":\"acme\"}]"));
        github.route(orgRepos("acme"), list(repository(101, "acme/api", "private", false, false),
                repository(102, "acme/portal", "internal", false, false),
                repository(103, "acme/legacy", "private", false, true),
                repository(104, "acme/upstream-fork", "public", true, false)));
        github.route(USER_REPOS, list(repository(401, "ada/dotfiles", "public", false, false)));
        long discoveryId = discover(connectionId).at("/id").asLong();
        String base = "/api/v1/forge-connections/" + connectionId;

        JsonNode table = read(base + "/discoveries/" + discoveryId + "/selection");
        JsonNode api = byForgeId(table.at("/items"), "101");
        assertThat(api.at("/proposedSolution").asText()).isEqualTo("acme");
        assertThat(api.at("/proposedProject").asText()).as("one project per repository, named after it").isEqualTo("api");
        assertThat(api.at("/offered").asBoolean()).isTrue();
        JsonNode dotfiles = byForgeId(table.at("/items"), "401");
        assertThat(dotfiles.at("/offered").asBoolean()).as("a personal namespace is offered unticked").isFalse();
        assertThat(dotfiles.at("/proposedSolution").isNull()).isTrue();
        assertThat(table.at("/unjudged/fork").asLong()).as("GitHub states every fork: nothing unjudged").isZero();

        JsonNode proposed = ok(postJson(base + "/discoveries/" + discoveryId + "/selection",
                Map.of("operation", "proposed")));
        assertThat(proposed.at("/selected")).extracting(JsonNode::asText)
                .as("archived and forks hidden by default, the personal one left out").containsExactly("101", "102");

        Map<String, Object> body = new LinkedHashMap<>();
        body.put("discoveryId", discoveryId);
        body.put("forgeIds", List.of("101", "102"));
        JsonNode preview = ok(postJson(base + "/imports/preview", body));
        assertThat(preview.at("/solutions")).singleElement()
                .satisfies(solution -> assertThat(solution.at("/name").asText()).isEqualTo("acme"));
        assertThat(StreamSupport.stream(preview.at("/projects").spliterator(), false)
                .map(project -> project.at("/solution").asText() + " / " + project.at("/name").asText()))
                .containsExactlyInAnyOrder("acme / api", "acme / portal");
        assertThat(repositories.count()).as("a preview writes nothing").isZero();

        JsonNode result = ok(postJson(base + "/imports", body));

        assertThat(result.at("/created")).hasSize(2);
        assertThat(result.at("/solutionsCreated")).extracting(JsonNode::asText).containsExactly("acme");
        RepositoryEntity imported = repositories.findById(byForgeId(result.at("/created"), "101").at("/repositoryId")
                .asLong()).orElseThrow();
        assertThat(imported.getUrl()).isEqualTo("https://git.example.org/acme/api.git");
        assertThat(imported.getBranch()).isEqualTo("main");
        assertThat(imported.getProjectId()).isNotNull();
        assertThat(links.count()).isEqualTo(2);
        assertThat(byForgeId(read(base + "/discoveries/" + discoveryId + "/selection").at("/items"), "101")
                .at("/notSelectable").asText()).isEqualTo("already_imported");
    }
}
